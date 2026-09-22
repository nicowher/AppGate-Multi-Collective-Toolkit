"""Reusable SSH sessions for appliance work.

Password auth first; keyboard-interactive is the fallback some AppGate
boxes require (allowed_types has keyboard-interactive but not password).
kbd-int uses Transport, so host keys are verified separately (fingerprint
printed on TOFU). Timeouts come from config (SSH_TIMEOUT / SSH_AUTH_TIMEOUT)
so a dead host cannot hang the toolkit. Host-key policy is
SSH_STRICT_HOST_KEY (lab WarningPolicy / production TOFU: prompt on the
main thread, then save ~/.ssh/known_hosts). Never input() from a worker.
"""
from core.utils import ensure_package, run_target_batch

try:
    import paramiko
except ImportError:
    ensure_package("paramiko", "paramiko")
    import paramiko

import base64
import hashlib
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

from config import (
    DEBUG,
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
        if noise and not DEBUG:
            return
        print(f"      {msg}", file=sys.stderr)

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
        path = SSH_KNOWN_HOSTS.strip() or str(Path.home() / ".ssh" / "known_hosts")
        path = os.path.expanduser(path)
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            if not os.path.isfile(path):
                fd = os.open(
                    path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, SSH_KNOWN_HOSTS_MODE
                )
                os.close(fd)
            client.load_host_keys(path)
        except OSError as exc:
            print(f"      Could not prepare known_hosts {path}: {exc}", file=sys.stderr)
        try:
            client.load_system_host_keys()
        except OSError:
            pass
        # Strict: trust-on-first-use (add unknown, reject changed keys).
        # Lab: WarningPolicy (do not persist).
        if SSH_STRICT_HOST_KEY:
            if threading.current_thread() is threading.main_thread():
                client.set_missing_host_key_policy(_PromptAddHostKeyPolicy())
            else:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.WarningPolicy())

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
                self._log(f"{self._tag(host)} skip (no DNS)")
                continue
            # print(f"DEBUG prime: try {host!r} known={_hostname_known(host)}")
            if self._with_ssh(host, lambda _c: True, timeout=SSH_PRIME_TIMEOUT) is not None:
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
            transport = paramiko.Transport(sock)
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
                self._log(f"{self._tag(addr)} skip (no DNS)")
                continue
            last = addr
            result = self._with_ssh(addr, fn)
            if result is False:
                raise ValueError(f"{error} (connected but failed) ({label or addr})")
            if result is not None:
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

    def _sudo(self, client: paramiko.SSHClient, command: str, check: bool = True) -> str:
        return self._run(client, f"sudo -S {command}", sudo=True, check=check)

    def _sudo_script(
        self,
        client: paramiko.SSHClient,
        script: str,
        timeout: Optional[int] = None,
        extra_stdin: str = "",
    ) -> Optional[Tuple[int, str]]:
        cmd = f"sudo -S bash -c {shlex.quote(script)}"
        wait = SSH_TIMEOUT if timeout is None else timeout
        stdin, stdout, stderr = client.exec_command(cmd)
        stdout.channel.settimeout(wait)
        stderr.channel.settimeout(wait)
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
            exit_status = stdout.channel.recv_exit_status()
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
        stdin, stdout, stderr = client.exec_command(command)
        stdout.channel.settimeout(wait)
        stderr.channel.settimeout(wait)
        if sudo:
            stdin.write(self.ssh_password + "\n")
            stdin.flush()
        try:
            output = stdout.read().decode("utf-8", errors="replace")
            err_output = stderr.read().decode("utf-8", errors="replace")
            exit_status = stdout.channel.recv_exit_status()
        except (socket.timeout, TimeoutError, OSError) as exc:
            print(f"      SSH command timed out or failed ({type(exc).__name__}): {exc}", file=sys.stderr)
            return ""
        if check and exit_status not in (0, 1):
            print(
                f"      SSH command failed (exit {exit_status}): "
                f"{err_output.strip()[:SSH_LOG_PREVIEW]}",
                file=sys.stderr,
            )
        # if DEBUG:
        #     print(f"DEBUG ssh: cmd={command!r} rc={exit_status} out={output[:80]!r}", file=sys.stderr)
        return output


def _known_hosts_path() -> str:
    path = SSH_KNOWN_HOSTS.strip() or str(Path.home() / ".ssh" / "known_hosts")
    return os.path.expanduser(path)


def _hostname_known(hostname: str) -> bool:
    path = _known_hosts_path()
    if not os.path.isfile(path):
        return False
    try:
        keys = paramiko.HostKeys(path)
        return keys.lookup(hostname) is not None
    except OSError:
        return False


def _save_host_key(client, hostname, key) -> None:
    client.get_host_keys().add(hostname, key.get_name(), key)
    path = getattr(client, "_host_keys_filename", None) or _known_hosts_path()
    try:
        client.save_host_keys(path)
    except OSError as exc:
        print(f"      Could not save known_hosts: {exc}", file=sys.stderr)


class _PromptAddHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """TOFU: prompt on the main thread only (worker input() deadlocks)."""

    def missing_host_key(self, client, hostname, key) -> None:
        digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        print(
            f"      SSH host key for {hostname} is not in known_hosts.",
            file=sys.stderr,
        )
        print(
            f"      {key.get_name()} SHA256:{digest}",
            file=sys.stderr,
        )
        ans = input("      Trust and save this host key? [y/N]: ").strip().lower()
        if ans not in YES_ANSWERS:
            print(
                f"ERROR E07: SSH host key for {hostname} rejected.",
                file=sys.stderr,
            )
            print(
                "      Next: answer y to Trust and save, or add the key to ~/.ssh/known_hosts.",
                file=sys.stderr,
            )
            raise paramiko.SSHException(f"Host key for {hostname} rejected")
        _save_host_key(client, hostname, key)
        print(f"      Saved host key for {hostname}.", file=sys.stderr)


def prime_target_host_keys(targets, collectives) -> None:
    """Main thread: try each appliance's SSH endpoints until one connects.

    Stops after the first working address so overlay/data-plane IPs do not
    add 10s timeouts (SSH_PRIME_TIMEOUT). Unresolvable FQDNs are skipped.
    """
    from core.prompts import collective_for_target

    # print(f"DEBUG prime_keys: n={len(targets)}")
    print(
        "      SSH host keys: accept each new host before parallel work starts.",
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
    """Pool first; SSH failures retry on the main thread with a password prompt."""
    failed = []

    def _capture(target, exc) -> None:
        failed.append((target, exc))

    run_target_batch(targets, worker, concurrency, _capture)
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
