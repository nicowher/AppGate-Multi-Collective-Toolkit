"""Reusable SSH sessions for appliance work.

Password auth first; keyboard-interactive is the fallback some AppGate
boxes require (allowed_types has keyboard-interactive but not password).
kbd-int uses Transport, so host keys are checked with the same policy.
Connect, channel reads, and the exit-status wait use SSH_TIMEOUT.
SSH_STRICT_HOST_KEY follows
LAB_MODE: lab uses WarningPolicy; production rejects unknown keys and
requires SSH_KNOWN_HOSTS or ssh_host_keys. Never input() from a worker.
"""
from core.utils import ensure_package, run_target_batch

try:
    import paramiko
except ImportError:
    ensure_package("paramiko", "paramiko")
    import paramiko

import ipaddress
import logging
import os
import shlex
import socket
import sys
import threading
from getpass import getpass

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence, Tuple, Union

# SHA-1, CBC, and group14-sha1 are below the SSH STIG floor. Fail closed if the box needs them.
_SSH_DISABLED = {
    "kex": [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    ],
    "ciphers": [
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "blowfish-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
    ],
    "macs": ["hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"],
    "keys": ["ssh-rsa", "ssh-dss"],
    "pubkeys": ["ssh-rsa", "ssh-dss"],
}


def _exit_status(stdout, wait: int) -> int:
    """recv_exit_status() waits forever. Bound it to the same SSH timeout."""
    if not stdout.channel.status_event.wait(wait):
        raise TimeoutError("SSH exit status timed out")
    return stdout.channel.recv_exit_status()


from config import (
    DEBUG,
    LAB_MODE,
    SSH_AUTH_TIMEOUT,
    SSH_KNOWN_HOSTS,
    SSH_KNOWN_HOSTS_MODE,
    SSH_LOG_PREVIEW,
    SSH_PORT,
    SSH_STRICT_HOST_KEY,
    SSH_PRIME_TIMEOUT,
    SSH_TIMEOUT,
    YES_ANSWERS,
)


def _addr_is_ip(value: str) -> bool:
    text = (value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _ssh_display_name(addrs: Sequence[str]) -> str:
    """Hostname/FQDN for operator prompts — never the last IPv6 tried."""
    for addr in addrs:
        if addr and not _addr_is_ip(addr):
            return addr
    return addrs[0] if addrs else ""


def _host_resolves(host: str) -> bool:
    """False if DNS fails (Windows 11001). Skip FQDN, try ssh_ip — not a password problem."""
    name = (host or "").strip()
    if name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    if not name:
        return False
    try:
        socket.getaddrinfo(name, SSH_PORT, type=socket.SOCK_STREAM)
        return True
    except (socket.gaierror, OSError, ValueError):
        return False


_ssh_progress_active = False


class SSHSession:
    def __init__(self, ssh_user: str, ssh_password: str) -> None:
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password
        self._ssh_fail_kind = ""
        self._log_label = ""
        self._last_reason = ""

    @staticmethod
    def _unwrap(host: Any) -> Tuple[Any, List[str]]:
        if getattr(host, "ssh_endpoints", None) is not None and not isinstance(
            host, (str, bytes, list, tuple)
        ):
            return host, [h for h in host.ssh_endpoints() if h]
        if isinstance(host, str):
            return None, [host] if host else []
        return None, [h for h in host if h]

    @staticmethod
    def _pin(target: Any, addr: str) -> None:
        if target is not None and addr:
            target.ssh_ok_host = addr

    def _set_log_label(self, target: Any) -> None:
        self._log_label = ""
        if target is not None and hasattr(target, "label"):
            self._log_label = target.label() or ""

    def _tag(self, addr: str = "") -> str:
        if self._log_label and addr:
            return f"{self._log_label} {addr}"
        return self._log_label or addr

    def _log(self, msg: str, *, noise: bool = False) -> None:
        """DEBUG: every line, uncolored. Otherwise hide noise; color only the status word."""
        if noise and not DEBUG:
            return
        if DEBUG:
            print(f"      {msg}", file=sys.stderr)
            return
        if _ssh_progress_active:
            sys.stderr.write("\n")
        from core.color import fail, ok, warn

        low = msg.lower()
        if msg.endswith(" ok") or low.endswith(" ok"):
            painted = msg[: msg.rfind(" ")] + " " + ok("ok")
        elif "auth failed" in low:
            painted = msg.replace("auth failed", fail("auth failed"))
        elif "timeout" in low:
            idx = low.rfind("timeout")
            painted = msg[:idx] + warn("timeout") + msg[idx + 7 :]
        else:
            painted = msg
        print(f"      {painted}", file=sys.stderr)

    @staticmethod
    def _net_reason(exc: BaseException) -> str:
        text = str(exc).lower()
        name = type(exc).__name__
        if name in ("TimeoutError", "timeout") or "timed out" in text:
            return "timeout"
        if "10051" in str(exc) or "unreachable" in text:
            return "unreachable"
        if name == "gaierror" or "getaddrinfo" in text or "11001" in str(exc):
            return "no DNS"
        return name

    def _apply_host_key_policy(self, client: paramiko.SSHClient) -> None:
        """SSH_STRICT_HOST_KEY follows LAB_MODE. Strict rejects unknown keys. Lab accepts any."""
        if not SSH_STRICT_HOST_KEY:
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            return
        if not host_key_store_provisioned():
            raise paramiko.SSHException(
                "SSH_STRICT_HOST_KEY is on. Set SSH_KNOWN_HOSTS or ssh_host_keys "
                "before connecting. Unknown keys are not accepted."
            )
        path = _known_hosts_path()
        try:
            client.load_host_keys(path)
        except OSError as exc:
            raise paramiko.SSHException(f"Could not load known_hosts {path}: {exc}") from exc
        # System known_hosts is not the production pin. A planted key there must not pass.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    def prime_host_keys(self, hosts: Union[str, Sequence[str]]) -> bool:
        """Try hosts until one SSH session works. Short timeout. True if any connected.

        A name already in known_hosts still gets a connect attempt. Returning
        early on a cached FQDN used to skip this box's working private IP.
        Pins the address that answered on the Target for later SSH steps.
        """
        target, addrs = self._unwrap(hosts)
        self._set_log_label(target)
        for host in addrs:
            if not _host_resolves(host):
                self._log(f"{self._tag(host)} skip (no DNS)", noise=True)
                continue
            # print(f"DEBUG prime: try {host!r}")
            if self._with_ssh(host, lambda _c: True, timeout=SSH_PRIME_TIMEOUT) is not None:
                if DEBUG:
                    self._log(f"{self._tag(host)} ok")
                self._pin(target, host)
                return True
            self._log(f"{self._tag(host)} {self._last_reason or self._ssh_fail_kind or 'fail'}")
            if self._ssh_fail_kind in ("auth", "keyonly", "hostkey"):
                self._pin(target, host)
                return False
        return False

    def _with_ssh(self, ip: str, fn, timeout: Optional[int] = None):
        """Open an SSH session, run *fn(client)*, then close.

        Password auth first; keyboard-interactive is the fallback some
        AppGate boxes require.
        """
        client = paramiko.SSHClient()
        self._apply_host_key_policy(client)
        wait = SSH_TIMEOUT if timeout is None else timeout
        try:
            client.connect(
                hostname=ip,
                port=SSH_PORT,
                username=self.ssh_user,
                password=self.ssh_password,
                timeout=wait,
                allow_agent=False,
                look_for_keys=False,
                auth_timeout=min(wait, SSH_AUTH_TIMEOUT),
                disabled_algorithms=_SSH_DISABLED,
            )
            self._ssh_fail_kind = ""
            self._last_reason = "ok"
            return fn(client)
        except paramiko.BadAuthenticationType as exc:
            allowed = [str(a).lower() for a in (exc.allowed_types or [])]
            if "keyboard-interactive" in allowed:
                self._log(
                    f"{self._tag(ip)}: password not offered; keyboard-interactive",
                    noise=True,
                )
                return self._with_ssh_keyboard_interactive(ip, fn)
            if "password" not in allowed:
                self._ssh_fail_kind = "keyonly"
                self._last_reason = "key-only"
                return None
            self._ssh_fail_kind = "auth"
            self._last_reason = "auth failed"
            return None
        except paramiko.AuthenticationException:
            self._ssh_fail_kind = "auth"
            self._last_reason = "auth failed"
            return None
        except paramiko.BadHostKeyException:
            self._ssh_fail_kind = "hostkey"
            self._last_reason = "host key mismatch"
            return None
        except (socket.gaierror, OSError, socket.timeout, TimeoutError) as exc:
            self._ssh_fail_kind = "network"
            self._last_reason = self._net_reason(exc)
            self._log(f"{self._tag(ip)} {type(exc).__name__}: {exc}", noise=True)
        except paramiko.SSHException as exc:
            if "host key" in str(exc).lower():
                self._ssh_fail_kind = "hostkey"
                self._last_reason = "host key mismatch"
            elif self._ssh_fail_kind != "hostkey":
                self._ssh_fail_kind = "network"
                self._last_reason = type(exc).__name__
            self._log(
                f"{self._tag(ip)} {type(exc).__name__}: {str(exc)[:SSH_LOG_PREVIEW]}",
                noise=True,
            )
        finally:
            try:
                client.close()
            except OSError:
                pass
        return None

    def _verify_transport_host_key(self, client, ip: str, remote_key) -> None:
        """Transport.connect skips SSHClient host-key checks — apply the same policy."""
        known = client.get_host_keys()
        name = remote_key.get_name()
        entry = known.lookup(ip)
        stored = entry.get(name) if entry is not None else None
        # print(f"DEBUG ssh: kbd-int hostkey ip={ip!r} name={name!r} known={stored is not None}")
        if stored is not None:
            if stored != remote_key:
                self._ssh_fail_kind = "hostkey"
                raise paramiko.SSHException(f"Host key mismatch for {ip}")
            return
        client._policy.missing_host_key(client, ip, remote_key)

    def _with_ssh_keyboard_interactive(self, ip: str, fn):
        """Password-auth fallback. TCP connect uses SSH_TIMEOUT so a dead IP cannot hang."""
        def handler(title, instructions, prompt_list):
            responses = []
            for prompt in prompt_list:
                if "password" in prompt[0].lower():
                    responses.append(self.ssh_password)
                else:
                    responses.append("")
            return responses

        transport = None
        sock = None
        client = paramiko.SSHClient()
        self._apply_host_key_policy(client)
        try:
            sock = socket.create_connection((ip, SSH_PORT), timeout=SSH_TIMEOUT)
            sock.settimeout(SSH_TIMEOUT)
            transport = paramiko.Transport(sock, disabled_algorithms=_SSH_DISABLED)
            transport.banner_timeout = SSH_TIMEOUT
            transport.auth_timeout = SSH_AUTH_TIMEOUT
            transport.start_client(timeout=SSH_TIMEOUT)
            remote_key = transport.get_remote_server_key()
            self._verify_transport_host_key(client, ip, remote_key)
            transport.auth_interactive(self.ssh_user, handler)
            self._ssh_fail_kind = ""
            self._last_reason = "ok"
            client._transport = transport
            return fn(client)
        except paramiko.AuthenticationException:
            self._ssh_fail_kind = "auth"
            self._last_reason = "auth failed"
            # print(f"DEBUG ssh: kbd-int auth failed ip={ip!r}")
        except (paramiko.SSHException, OSError, socket.timeout, TimeoutError) as exc:
            if not self._ssh_fail_kind:
                self._ssh_fail_kind = "network"
            self._last_reason = self._net_reason(exc)
            self._log(
                f"{self._tag(ip)} keyboard-interactive {type(exc).__name__}: {exc}",
                noise=True,
            )
        finally:
            try:
                client.close()
            except OSError:
                pass
            if transport is not None:
                try:
                    transport.close()
                except OSError:
                    pass
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return None

    def _with_ssh_endpoints(
        self,
        host: Union[str, Sequence[str]],
        fn,
        *,
        error: str = "SSH failed",
        prompt_password: bool = True,
    ):
        """Try FQDN then IP.

        None = connect miss, try the next address.
        False = connected but the work failed — do not retry the other NIC
        (that would bounce snmpd / re-run ACAS on the same box).
        Auth failure stops the IP walk (same wrong password on every NIC
        trips SSHBRUTE). Main thread may then ask for a new password.
        """
        target, addrs = self._unwrap(host)
        self._set_log_label(target)
        if not addrs:
            raise ValueError("No SSH endpoint")
        self._ssh_fail_kind = ""
        label = _ssh_display_name(addrs)
        if target is not None:
            label = target.label() or label
        last = addrs[-1]
        auth_hit = ""
        for i, addr in enumerate(addrs):
            if not _host_resolves(addr):
                self._log(f"{self._tag(addr)} skip (no DNS)", noise=True)
                continue
            last = addr
            result = self._with_ssh(addr, fn)
            if result is False:
                raise ValueError(f"{error} (connected but failed) ({label or addr})")
            if result is not None:
                if DEBUG:
                    self._log(f"{self._tag(addr)} ok")
                self._pin(target, addr)
                return result
            self._log(f"{self._tag(addr)} {self._last_reason or self._ssh_fail_kind or 'fail'}")
            if self._ssh_fail_kind in ("auth", "keyonly", "hostkey"):
                auth_hit = addr
                self._pin(target, addr)
                break
            self._log(f"{self._tag(addr)} trying next", noise=True)
        if (
            prompt_password
            and self._ssh_fail_kind == "auth"
            and threading.current_thread() is threading.main_thread()
        ):
            new_pw = prompt_retry_ssh_password(label or last)
            if new_pw:
                self.ssh_password = new_pw
                retry_host = target if target is not None else (
                    [auth_hit] + [a for a in addrs if a != auth_hit] if auth_hit else addrs
                )
                return self._with_ssh_endpoints(
                    retry_host, fn, error=error, prompt_password=False
                )
        kind = self._ssh_fail_kind or "network"
        raise ValueError(f"{error} ({kind}) ({label or last})")

    def _sudo_skips_password(self, client: paramiko.SSHClient) -> bool:
        """True when sudo -n works. The SSH password must not share that stdin."""
        try:
            _stdin, stdout, _stderr = client.exec_command("sudo -n true", timeout=10)
            stdout.channel.settimeout(10)
            return _exit_status(stdout, 10) == 0
        except (OSError, TimeoutError, socket.timeout):
            return False

    def _sudo(self, client: paramiko.SSHClient, command: str, check: bool = True) -> str:
        return self._run(client, f"sudo -S {command}", sudo=True, check=check)

    def _sudo_script(
        self,
        client: paramiko.SSHClient,
        script: str,
        timeout: Optional[int] = None,
        extra_stdin: str = "",
    ) -> Optional[Tuple[int, str]]:
        wait = SSH_TIMEOUT if timeout is None else timeout
        nopass = self._sudo_skips_password(client)
        # print(f"DEBUG sudo: nopass={nopass}")
        if nopass:
            cmd = f"sudo -n bash -c {shlex.quote(script)}"
        else:
            cmd = f"sudo -S bash -c {shlex.quote(script)}"
        stdin, stdout, stderr = client.exec_command(cmd, timeout=wait)
        stdout.channel.settimeout(wait)
        stderr.channel.settimeout(wait)
        if not nopass:
            stdin.write(self.ssh_password + "\n")
        if extra_stdin:
            if not extra_stdin.endswith("\n"):
                extra_stdin += "\n"
            stdin.write(extra_stdin)
        stdin.flush()
        try:
            stdin.channel.shutdown_write()
        except Exception:
            pass
        try:
            output = stdout.read().decode("utf-8", errors="replace")
            err_output = stderr.read().decode("utf-8", errors="replace")
            exit_status = _exit_status(stdout, wait)
        except (OSError, TimeoutError, socket.timeout) as exc:
            print(
                f"      SSH script timed out or failed ({type(exc).__name__}): {exc}",
                file=sys.stderr,
            )
            return (-1, f"timeout:{type(exc).__name__}")
        # if DEBUG:
        #     print(f"DEBUG sudo_script rc={exit_status} out={(output or '')[:80]!r}", file=sys.stderr)
        if DEBUG:
            print(
                f"      DEBUG sudo_script rc={exit_status} "
                f"out={(output or '')[:SSH_LOG_PREVIEW]!r} "
                f"err={(err_output or '')[:SSH_LOG_PREVIEW]!r}",
                file=sys.stderr,
            )
        return exit_status, (output + "\n" + err_output).strip()

    def _run(
        self,
        client: paramiko.SSHClient,
        command: str,
        sudo: bool = False,
        check: bool = True,
        timeout: Optional[int] = None,
    ) -> str:
        wait = SSH_TIMEOUT if timeout is None else timeout
        stdin, stdout, stderr = client.exec_command(command, timeout=wait)
        stdout.channel.settimeout(wait)
        stderr.channel.settimeout(wait)
        if sudo:
            stdin.write(self.ssh_password + "\n")
            stdin.flush()
        try:
            output = stdout.read().decode("utf-8", errors="replace")
            err_output = stderr.read().decode("utf-8", errors="replace")
            exit_status = _exit_status(stdout, wait)
        except (socket.timeout, TimeoutError, OSError) as exc:
            print(f"      SSH command timed out or failed ({type(exc).__name__}): {exc}", file=sys.stderr)
            return "timeout"
        if check and exit_status not in (0, 1):
            print(
                f"      SSH command failed (exit {exit_status}): "
                f"{err_output.strip()[:SSH_LOG_PREVIEW]}",
                file=sys.stderr,
            )
        # if DEBUG:
        #     print(f"DEBUG ssh: cmd={command!r} rc={exit_status} out={output[:80]!r}", file=sys.stderr)
        return output


_oob_known_hosts = ""


def host_key_store_provisioned() -> bool:
    """True when an out-of-band known_hosts file or ssh_host_keys was supplied."""
    return bool(SSH_KNOWN_HOSTS.strip() or _oob_known_hosts)


def _known_hosts_path() -> str:
    if _oob_known_hosts:
        return _oob_known_hosts
    path = SSH_KNOWN_HOSTS.strip() or str(Path.home() / ".ssh" / "known_hosts")
    return os.path.expanduser(path)


def _checked_host_key_line(line: str) -> str:
    """A wildcard or negation in known_hosts would trust more than the pinned box."""
    from paramiko.hostkeys import HostKeyEntry

    text = (line or "").strip()
    entry = HostKeyEntry.from_line(text)
    if entry is None:
        raise ValueError("ssh_host_keys line is not a known_hosts entry")
    names = getattr(entry, "hostnames", None) or []
    for name in names:
        if "*" in name or "?" in name or str(name).startswith("!"):
            raise ValueError(f"Refusing wildcard or negated host key pattern: {name}")
    return text


def install_oob_host_keys(collectives) -> None:
    """Load appliance host keys from credentials. Not from the Controller API."""
    global _oob_known_hosts
    lines = []
    for col in collectives or []:
        raw = col.get("ssh_host_keys")
        if raw is None:
            raw = col.get("ssh_host_key")
        if isinstance(raw, str) and raw.strip():
            lines.append(raw.strip())
        elif isinstance(raw, list):
            lines.extend(str(item).strip() for item in raw if str(item).strip())
    path = SSH_KNOWN_HOSTS.strip()
    if not lines and not path:
        return
    if not path:
        from core.utils import REPO_ROOT

        path = os.path.join(REPO_ROOT, "certs", "known_hosts")
        _oob_known_hosts = path
    else:
        path = os.path.expanduser(path)
        _oob_known_hosts = path
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    existing = ""
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            existing = fh.read()
    accepted = [_checked_host_key_line(line) for line in lines]
    with open(path, "a", encoding="utf-8") as fh:
        for line in accepted:
            if line not in existing:
                fh.write(line + "\n")
                existing += line + "\n"
    try:
        os.chmod(path, SSH_KNOWN_HOSTS_MODE)
    except OSError as exc:
        raise ValueError(f"Could not restrict {path}: {exc}") from exc


def prime_target_host_keys(targets, collectives) -> None:
    """Main thread: connect each box once and pin ssh_ok_host.

    Stops after the first working address so overlay IPs do not add timeouts.
    Success lines are DEBUG-only. Failures (timeout, auth) always print.
    """
    from core.prompts import collective_for_target

    install_oob_host_keys(collectives)
    # print(f"DEBUG prime_keys: n={len(targets)}")
    print(
        "      SSH: checking host keys before parallel work starts.",
        file=sys.stderr,
    )
    for target in targets:
        col = collective_for_target(target, collectives)
        session = SSHSession(col["ssh_username"], ssh_password_for(target, col))
        session.prime_host_keys(target)


def ssh_password_for(target, col: dict) -> str:
    override = getattr(target, "ssh_password_override", None)
    if override:
        return override
    return col.get("ssh_password") or ""


def prompt_retry_ssh_password(label: str) -> str:
    """Wrong password on a reachable box. Main thread only. Empty = skip host."""
    # print(f"DEBUG ssh: password retry prompt for {label}")
    ans = input(
        f"      SSH password failed for {label}. Try a different password? [y/N]: "
    ).strip().lower()
    if ans not in YES_ANSWERS:
        return ""
    while True:
        pw = getpass(f"      SSH Password ({label}): ").strip()
        if not pw:
            skip = input("      Empty password. Skip this host? [y/N]: ").strip().lower()
            if skip in YES_ANSWERS:
                return ""
            continue
        confirm = getpass(f"      SSH Password confirm ({label}): ").strip()
        if pw != confirm:
            print("      Passwords did not match. Try again.", file=sys.stderr)
            continue
        return pw


def run_ssh_batch(
    targets: list,
    worker: Callable,
    concurrency: int,
    on_fail: Callable,
) -> None:
    """Pool first. Quiet mode: SSH n/N. DEBUG: every host line, no counter.
    Failures retry on the main thread with a password prompt.
    """
    failed = []

    def _capture(target, exc) -> None:
        failed.append((target, exc))

    def _progress(done: int, n: int) -> None:
        global _ssh_progress_active
        if DEBUG or n < 2:
            return
        _ssh_progress_active = done < n
        sys.stderr.write(f"\r      SSH {done}/{n}")
        sys.stderr.flush()
        if done >= n:
            sys.stderr.write("\n")
            sys.stderr.flush()

    run_target_batch(targets, worker, concurrency, _capture, progress=_progress)
    for target, exc in failed:
        label = target.label() if hasattr(target, "label") else str(target)
        msg = str(exc).lower()
        sshish = "(auth)" in msg and "(keyonly)" not in msg
        if (
            sshish
            and threading.current_thread() is threading.main_thread()
        ):
            new_pw = prompt_retry_ssh_password(label)
            if new_pw:
                target.ssh_password_override = new_pw
                try:
                    worker(target)
                    continue
                except Exception as exc2:
                    on_fail(target, exc2)
                    continue
        on_fail(target, exc)
