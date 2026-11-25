"""Reusable SSH sessions for appliance work.

Password auth first; keyboard-interactive is the fallback some AppGate
boxes require (allowed_types has keyboard-interactive but not password).
kbd-int uses Transport, so host keys are checked with the same policy.
Connect, channel reads, and the exit-status wait use SSH_TIMEOUT.
SSH_STRICT_HOST_KEY follows LAB_MODE. The main thread asks once per appliance before connect. A worker must not ask.
Before parallel work, prime_target_host_keys finds one answering address per box
by reading host keys without a password, and keeps it in memory for the session.
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
import tempfile
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
import threading
import shlex
import socket
import sys
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


# CNSA_STRICT allow-lists. Everything paramiko offers outside these is disabled.
_CNSA_ALLOW = {
    "ciphers": ("aes256-ctr", "aes256-gcm@openssh.com"),
    "macs": ("hmac-sha2-512", "hmac-sha2-512-etm@openssh.com"),
    "kex": (
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
    ),
    "keys": ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512"),
}
_CNSA_RSA_MIN_BITS = 3072


def _cnsa_on() -> bool:
    """Read at each connect, so a menu C change applies in this session."""
    import config as _config

    return bool(getattr(_config, "CNSA_STRICT", False))


def _ssh_disabled() -> dict:
    """Algorithms to refuse for this connection: the STIG floor, plus everything outside CNSA when CNSA_STRICT is on."""
    if not _cnsa_on():
        return _SSH_DISABLED
    preferred = {
        "ciphers": paramiko.Transport._preferred_ciphers,
        "macs": paramiko.Transport._preferred_macs,
        "kex": paramiko.Transport._preferred_kex,
        "keys": paramiko.Transport._preferred_keys,
    }
    out = {kind: [a for a in algs if a not in _CNSA_ALLOW[kind]] for kind, algs in preferred.items()}
    out["pubkeys"] = list(out["keys"])
    # print(f"DEBUG cnsa: disabled={ {k: len(v) for k, v in out.items()} }")
    return out


def _cnsa_key_problem(key) -> str:
    """Why this host key is below CNSA, or empty. RSA must be 3072 bits or more."""
    if key is None or not _cnsa_on():
        return ""
    name = key.get_name()
    if name.startswith("rsa") or name == "ssh-rsa":
        bits = key.get_bits()
        if bits < _CNSA_RSA_MIN_BITS:
            return f"host key is RSA-{bits}, below the CNSA minimum of {_CNSA_RSA_MIN_BITS}"
    elif name not in _CNSA_ALLOW["keys"]:
        return f"host key type {name} is not CNSA-grade"
    return ""


def _cnsa_reason(exc: BaseException) -> str:
    """A negotiation failure under CNSA_STRICT gets a plain reason instead of paramiko's text."""
    text = str(exc).lower()
    if _cnsa_on() and ("incompatible" in text or "no acceptable" in text or "no matching" in text):
        return "the box offers no CNSA-grade SSH algorithm (CNSA_STRICT is on)"
    return ""


def _close_channel(stdout) -> None:
    """The session stays open. Each command still needs its channel released."""
    try:
        stdout.channel.close()
    except Exception:
        pass


def _exit_status(stdout, wait: int) -> int:
    """recv_exit_status() waits forever. Bound it to the same SSH timeout."""
    if not stdout.channel.status_event.wait(wait):
        raise TimeoutError("SSH exit status timed out")
    return stdout.channel.recv_exit_status()


from config import (
    DEBUG,
    LAB_MODE,
    SSH_AUTH_FAIL_CAP,
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
    """Prompts name a box by hostname when one exists, not by the last IPv6 tried."""
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
    """False if DNS fails (Windows 11001). Skip FQDN, try ssh_ip — not a password problem.

    getaddrinfo has no timeout of its own, so it runs in a helper thread and waits
    at most SSH_PRIME_TIMEOUT. A slow or dead resolver then counts as "no DNS" and
    the next address (usually the admin IP) is tried, instead of stalling the
    address search on the main thread. An IP address resolves at once.
    """
    # print(f"DEBUG dns: resolve {host!r}")
    name = (host or "").strip()
    if name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    if not name:
        return False
    if _addr_is_ip(name.split("%", 1)[0]):
        return True
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        fut = pool.submit(socket.getaddrinfo, name, SSH_PORT, type=socket.SOCK_STREAM)
        fut.result(timeout=SSH_PRIME_TIMEOUT)
        return True
    except (socket.gaierror, OSError, ValueError, FuturesTimeout):
        return False
    finally:
        # A lookup still waiting on the OS is left to finish in the background.
        pool.shutdown(wait=False, cancel_futures=True)


_ssh_progress_active = False


class SSHSession:
    """One user and password for SSH work on appliances. Address order, host-key policy and retry rules live here so every tool behaves the same."""
    def __init__(self, ssh_user: str, ssh_password: str) -> None:
        """Fail kind and reason come from the last attempt, and the label tags log lines with the appliance."""
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password
        self._ssh_fail_kind = ""
        self._log_label = ""
        self._last_reason = ""
        self._tls = threading.local()

    @staticmethod
    def _unwrap(host: Any) -> Tuple[Any, List[str]]:
        """Accept a Target (use its address list and pin), one address, or a list of addresses."""
        if getattr(host, "ssh_endpoints", None) is not None and not isinstance(
            host, (str, bytes, list, tuple)
        ):
            return host, [h for h in host.ssh_endpoints() if h]
        if isinstance(host, str):
            return None, [host] if host else []
        return None, [h for h in host if h]

    @staticmethod
    def _pin(target: Any, addr: str) -> None:
        """Later steps and later menus in this session go straight to this address."""
        if target is None or not addr:
            return
        if hasattr(target, "pin_ssh_host"):
            target.pin_ssh_host(addr)
        else:
            target.ssh_ok_host = addr

    def _set_log_label(self, target: Any) -> None:
        """Every log line names its appliance, because SSH work runs in parallel."""
        self._log_label = ""
        if target is not None and hasattr(target, "label"):
            self._log_label = target.label() or ""

    def _tag(self, addr: str = "") -> str:
        """Log prefix: appliance label plus the address being tried."""
        if self._log_label and addr:
            return f"{self._log_label} {addr}"
        return self._log_label or addr

    def _mark_ssh(self, kind: str, reason: str) -> None:
        """Record the connect result. A prime thread keeps its own copy so two probes do not overwrite each other."""
        self._ssh_fail_kind = kind
        self._last_reason = reason
        box = getattr(self._tls, "box", None)
        if isinstance(box, dict):
            box["kind"] = kind
            box["reason"] = reason

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
        """Short reason (timeout, unreachable, no DNS, else the error type) for the failure line. A traceback is not useful to the operator."""
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
                disabled_algorithms=_ssh_disabled(),
            )
            self._mark_ssh("", "ok")
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
                self._mark_ssh("keyonly", "key-only")
                return None
            self._mark_ssh("auth", "auth failed")
            return None
        except paramiko.AuthenticationException:
            self._mark_ssh("auth", "auth failed")
            return None
        except paramiko.BadHostKeyException:
            self._mark_ssh("hostkey", "host key mismatch")
            return None
        except (socket.gaierror, OSError, socket.timeout, TimeoutError) as exc:
            self._ssh_fail_kind = "network"
            self._last_reason = self._net_reason(exc)
            self._log(f"{self._tag(ip)} {type(exc).__name__}: {exc}", noise=True)
        except paramiko.SSHException as exc:
            cnsa = _cnsa_reason(exc)
            if cnsa:
                self._mark_ssh("cnsa", cnsa)
            elif "host key" in str(exc).lower():
                self._mark_ssh("hostkey", "host key mismatch")
            elif self._ssh_fail_kind != "hostkey":
                self._mark_ssh("network", type(exc).__name__)
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
            transport = paramiko.Transport(sock, disabled_algorithms=_ssh_disabled())
            transport.banner_timeout = SSH_TIMEOUT
            transport.auth_timeout = SSH_AUTH_TIMEOUT
            transport.start_client(timeout=SSH_TIMEOUT)
            remote_key = transport.get_remote_server_key()
            self._verify_transport_host_key(client, ip, remote_key)
            transport.auth_interactive(self.ssh_user, handler)
            self._mark_ssh("", "ok")
            client._transport = transport
            return fn(client)
        except paramiko.AuthenticationException:
            self._ssh_fail_kind = "auth"
            self._last_reason = "auth failed"
            # print(f"DEBUG ssh: kbd-int auth failed ip={ip!r}")
        except (paramiko.SSHException, OSError, socket.timeout, TimeoutError) as exc:
            if not self._ssh_fail_kind:
                self._mark_ssh("network", self._net_reason(exc))
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
        """Try the session address first, then the rest of the list, one pass.

        None = connect miss, try the next address. If the address remembered
        for this session stopped answering, the walk goes on down the list and
        pins the first one that works.
        False = connected but the work failed — do not retry the other NIC
        (that would bounce snmpd / re-run ACAS on the same box).
        Auth failure stops the IP walk (same wrong password on every NIC
        trips SSHBRUTE). Main thread may then ask for a new password.
        A host-key mismatch also stops: the box gets no password on any address.
        A fallback address only gets the password once it shows the same key
        as an address already approved for this box.
        If every address misses, the session address is forgotten so the next
        menu run searches again.
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

            if i > 0 and not _login_allowed(addr, addrs[:i]):
                self._log(f"{self._tag(addr)} skip (no answer or a different host key)", noise=True)
                continue

            last = addr
            # print(f"DEBUG ssh_endpoints: {self._tag(addr)} try {i + 1}/{len(addrs)}")
            result = self._with_ssh(addr, fn)
            if result is False:
                raise ValueError(f"{error} (connected but failed) ({label or addr})")
            if result is not None:
                if DEBUG:
                    self._log(f"{self._tag(addr)} ok")
                self._pin(target, addr)
                return result
            self._log(f"{self._tag(addr)} {self._last_reason or self._ssh_fail_kind or 'fail'}")
            if self._ssh_fail_kind in ("auth", "keyonly"):
                if self._ssh_fail_kind == "auth":
                    _note_auth_fail()
                auth_hit = addr
                self._pin(target, addr)
                break
            if self._ssh_fail_kind in ("hostkey", "cnsa"):
                break
            if i + 1 < len(addrs):
                self._log(f"{self._tag(addr)} trying next", noise=True)
        if self._ssh_fail_kind in ("network", "") and target is not None and hasattr(target, "forget_ssh_host"):
            target.forget_ssh_host()
        if (
            prompt_password
            and self._ssh_fail_kind == "auth"
            and _auth_retry_allowed()
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
            try:
                return _exit_status(stdout, 10) == 0
            finally:
                _close_channel(stdout)
        except (OSError, TimeoutError, socket.timeout):
            return False

    def _sudo(self, client: paramiko.SSHClient, command: str, check: bool = True) -> str:
        """Always writes the SSH password. The script path probes sudo -n first so a NOPASSWD window does not leave the password on stdin."""
        return self._run(client, f"sudo -S {command}", sudo=True, check=check)

    def _sudo_script(
        self,
        client: paramiko.SSHClient,
        script: str,
        timeout: Optional[int] = None,
        extra_stdin: str = "",
    ) -> Optional[Tuple[int, str]]:
        """Run a script under sudo. If sudo -n works the password is not written, so it is never left on stdin for the script to read."""
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
        finally:
            _close_channel(stdout)
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
        """Exit 1 is not a failure: some appliance helpers use it for a skipped step. Timeout is a sentinel so an empty read is not success."""
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
        finally:
            _close_channel(stdout)
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


def _attach_existing_known_hosts() -> None:
    """A key accepted on a previous run lives in certs/known_hosts. Load it before the strict check."""
    global _oob_known_hosts
    if _oob_known_hosts:
        return
    path = SSH_KNOWN_HOSTS.strip()
    if path:
        _oob_known_hosts = os.path.expanduser(path)
        return
    from core.utils import REPO_ROOT

    path = os.path.join(REPO_ROOT, "certs", "known_hosts")
    if os.path.isfile(path) and os.path.getsize(path) > 0:
        _oob_known_hosts = path


def host_key_store_provisioned() -> bool:
    """True when an out-of-band known_hosts file or ssh_host_keys was supplied."""
    return bool(SSH_KNOWN_HOSTS.strip() or _oob_known_hosts)


def _known_hosts_path() -> str:
    """The toolkit store set by install_oob_host_keys, else SSH_KNOWN_HOSTS or the user file."""
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
            os.makedirs(parent, mode=0o700, exist_ok=True)
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
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


def _host_key_fingerprint(key) -> str:
    """SHA256 fingerprint only. The raw key is not shown."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


# Why the last host-key read failed, when that reason is worth showing (CNSA). Main thread only.
_last_key_read_error = ""


def _read_remote_host_key(host: str, timeout: int = SSH_PRIME_TIMEOUT):
    """Read the server key without authenticating. A password here would spend a lockout attempt."""
    sock = None
    transport = None
    global _last_key_read_error
    _last_key_read_error = ""
    try:
        sock = socket.create_connection((host, SSH_PORT), timeout=timeout)
        transport = paramiko.Transport(sock, disabled_algorithms=_ssh_disabled())
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    except (OSError, paramiko.SSHException) as exc:
        _last_key_read_error = _cnsa_reason(exc)
        return None
    finally:
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


def _ensure_known_hosts_path() -> str:
    """Toolkit store, not the user known_hosts file. An empty SSH_KNOWN_HOSTS must not trust that file."""
    global _oob_known_hosts
    path = SSH_KNOWN_HOSTS.strip()
    if path:
        path = os.path.expanduser(path)
    else:
        from core.utils import REPO_ROOT

        path = os.path.join(REPO_ROOT, "certs", "known_hosts")
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    _oob_known_hosts = path
    return path


def _any_stored_key(host: str):
    """A previous yes is enough. A timed-out probe must not throw that pin away."""
    path = _ensure_known_hosts_path()
    if not os.path.isfile(path):
        return None
    from paramiko.hostkeys import HostKeys

    known = HostKeys()
    known.load(path)
    entry = known.lookup(host)
    if not entry:
        return None
    for key in entry.values():
        return key
    return None


def _stored_host_key(host: str, key):
    """The saved key of the same type as the one the server showed, or None."""
    path = _ensure_known_hosts_path()
    if not os.path.isfile(path):
        return None
    from paramiko.hostkeys import HostKeys

    known = HostKeys()
    known.load(path)
    entry = known.lookup(host)
    if not entry:
        return None
    return entry.get(key.get_name())


# One writer at a time for the toolkit known_hosts file (see _save_host_key).
_KNOWN_HOSTS_LOCK = threading.Lock()


def _save_host_key(host: str, key) -> None:
    """Append one accepted key. A wildcard name is already refused by the line check.

    The address search saves on the main thread, and a fallback address saves from
    SSH worker threads. The lock keeps two saves from losing each other's key. The
    new file is written beside the old one and swapped in with os.replace, so a
    reader in another thread sees the old file or the new one, never half of it.
    """
    # print(f"DEBUG known_hosts: save host={host!r} type={key.get_name()} thread={threading.current_thread().name}")
    from paramiko.hostkeys import HostKeys

    path = _ensure_known_hosts_path()
    with _KNOWN_HOSTS_LOCK:
        known = HostKeys()
        if os.path.isfile(path):
            known.load(path)
        known.add(host, key.get_name(), key)
        fd, tmp = tempfile.mkstemp(prefix=".known_hosts.", dir=os.path.dirname(path) or ".")
        os.close(fd)
        try:
            known.save(tmp)
            try:
                os.chmod(tmp, SSH_KNOWN_HOSTS_MODE)
            except OSError:
                pass
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise


def _box_key(names: Sequence[str]):
    """The key already approved for this appliance under any of its names, or None."""
    for name in names:
        key = _any_stored_key(name)
        if key is not None:
            return key
    return None


def _login_allowed(host: str, pinned: list) -> bool:
    """Send the password only if this address already has a saved key, or presents that same key.

    One unauthenticated key read per fallback address. A timeout there returns
    False, so a dead NIC is skipped without a password attempt.
    """
    if _any_stored_key(host) is not None:
        return True
    expected = _box_key(pinned)
    if expected is None:
        return True
    remote = _read_remote_host_key(host)
    if remote is not None and remote == expected:
        _save_host_key(host, remote)
        return True
    return False


def _find_ssh_address(target) -> bool:
    """Main thread, before parallel work. Pick this box's SSH address without sending a password.

    1. An address found earlier in this toolkit session is reused with no probe.
    2. Otherwise each address is tried in order, reading the server key only
       (no login). No DNS, a timeout, or a refused port moves to the next one.
    3. The first address that answers decides. A key that matches the one saved
       for this box pins it. An unknown or changed key is shown once: yes saves
       it and pins the address, no skips the box.
    The worker then logs in once on the pinned address. A separate test login
    here used to double the SSH connections per box and trip SSHBRUTE.
    """
    from config import YES_ANSWERS

    pinned = target.session_ssh_host()
    if pinned and _any_stored_key(pinned) is not None:
        target.pin_ssh_host(pinned)
        print(f"      {target.label()}: using {pinned} (found earlier this session)", file=sys.stderr)
        return True
    names = target.ssh_endpoints()
    missed = []
    for host in names:
        if not _host_resolves(host):
            missed.append(f"{host} (no DNS)")
            continue
        # print(f"DEBUG find_addr: {target.label()} probe {host}")
        key = _read_remote_host_key(host)
        if key is None and _last_key_read_error:
            # Every NIC runs the same sshd, so another address cannot do better.
            target.status = "failed"
            target.error = f"{host}: {_last_key_read_error}"
            print(f"      {target.label()}: {target.error}", file=sys.stderr)
            return False
        if key is None:
            missed.append(f"{host} (no answer)")
            print(f"      {target.label()}: {host} did not answer on port {SSH_PORT}; trying next", file=sys.stderr)
            continue
        problem = _cnsa_key_problem(key)
        if problem:
            target.status = "failed"
            target.error = f"{host}: {problem} (CNSA_STRICT is on)"
            print(f"      {target.label()}: {target.error}", file=sys.stderr)
            return False
        stored = _stored_host_key(host, key)
        if stored is not None and stored == key:
            target.pin_ssh_host(host)
            print(f"      {target.label()}: using {host} (stored host key)", file=sys.stderr)
            return True
        if _any_stored_key(host) is None and _box_key([n for n in names if n != host]) == key:
            # Same box under another name. That name's key was already approved.
            _save_host_key(host, key)
            target.pin_ssh_host(host)
            print(f"      {target.label()}: using {host} (same host key as this box's other name)", file=sys.stderr)
            return True
        if not sys.stdin.isatty():
            target.status = "failed"
            target.error = "SSH host key prompt needs a terminal"
            return False
        changed = _any_stored_key(host) is not None
        print(
            f"      {target.label()}: {'changed' if changed else 'unknown'} SSH host key for {host}",
            file=sys.stderr,
        )
        print(f"      {key.get_name()} {_host_key_fingerprint(key)}", file=sys.stderr)
        verb = "Replace the stored key" if changed else "Store this key and continue"
        ans = input(f"      {verb}? [y/N]: ").strip().lower()
        if ans not in YES_ANSWERS:
            target.status = "failed"
            target.error = "SSH host key was not stored"
            return False
        _save_host_key(host, key)
        target.pin_ssh_host(host)
        return True
    target.status = "failed"
    target.error = "No SSH address answered: " + (", ".join(missed) or "no address")
    print(f"      {target.label()}: {target.error}", file=sys.stderr)
    return False


def prime_target_host_keys(targets, collectives) -> None:
    """Main thread: find one working address per appliance and check its host key.

    Workers must not ask. A missing username or no answering address fails that
    box and the next one is still checked. Callers must skip boxes left failed.
    """
    from core.prompts import collective_for_target

    install_oob_host_keys(collectives)
    _attach_existing_known_hosts()
    # print(f"DEBUG prime_keys: n={len(targets)}")
    print(
        "      SSH: finding each appliance's address and checking host keys before parallel work starts.",
        file=sys.stderr,
    )
    for target in targets:
        try:
            col = collective_for_target(target, collectives)
            if not (col.get("ssh_username") or "").strip():
                raise KeyError("ssh_username")
        except (KeyError, ValueError, RuntimeError) as exc:
            target.status = "failed"
            target.error = f"missing SSH setting {exc}"
            print(f"      {target.label()}: {target.error}", file=sys.stderr)
            continue
        print(f"      {target.label()}: checking SSH address and host key", file=sys.stderr)
        try:
            _find_ssh_address(target)
        except (OSError, paramiko.SSHException, ValueError) as exc:
            target.status = "failed"
            target.error = str(exc)
            print(f"      {target.label()}: {exc}", file=sys.stderr)


def ssh_password_for(target, col: dict) -> str:
    """A retry password the operator typed for this box wins over the credentials file."""
    override = getattr(target, "ssh_password_override", None)
    if override:
        return override
    return col.get("ssh_password") or ""


_auth_failures = 0


def _auth_retry_allowed() -> bool:
    """A wrong password must fail before SSHBRUTE drops this host."""
    return _auth_failures < SSH_AUTH_FAIL_CAP


def _note_auth_fail() -> None:
    """Count wrong-password attempts across the run so retries stop before the appliance lockout."""
    global _auth_failures
    _auth_failures += 1


def prompt_retry_ssh_password(label: str) -> str:
    """Wrong password on a reachable box. Main thread only. Empty = skip host."""
    # print(f"DEBUG ssh: password retry prompt for {label}")
    ans = input(
        f"      SSH password failed for {label}. Try a different password? [y/N]: "
    ).strip().lower()
    if ans not in YES_ANSWERS:
        return ""
    while True:
        if not sys.stdin.isatty():
            raise RuntimeError("Password prompt requires a terminal")
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
            and _auth_retry_allowed()
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
