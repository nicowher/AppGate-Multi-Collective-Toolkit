"""Reusable SSH sessions for appliance work.

Password auth first; keyboard-interactive is the fallback some AppGate
boxes require (allowed_types has keyboard-interactive but not password).
kbd-int uses Transport, so host keys are checked with the same policy.
Connect, channel reads, and the exit-status wait use SSH_TIMEOUT.
SSH_STRICT_HOST_KEY follows LAB_MODE. The main thread asks once per appliance before connect. A worker must not ask.
Before parallel work, prime_target_host_keys finds one answering address per box
by reading host keys without a password (all boxes at once, addresses in order
within a box), and keeps it in memory for the session.
"""
from core.utils import ensure_package, is_ip, resolve_with_timeout, run_target_batch, stop_pool_early
from core.inventory import STATUS_FAILED

try:
    import paramiko
except ImportError:
    ensure_package("paramiko", "paramiko")
    import paramiko

import base64
import hashlib
import logging
import os
import tempfile
import threading
import shlex
from contextlib import contextmanager
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

    # Missing from an older config.py means the default, which is on.
    return bool(getattr(_config, "CNSA_STRICT", True))


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
    """Prompts name a box by hostname when one exists, not by the last IPv6 tried. Same test as core.utils.is_ip."""
    return is_ip(value)


def _ssh_display_name(addrs: Sequence[str]) -> str:
    """Hostname/FQDN for operator prompts — never the last IPv6 tried."""
    for addr in addrs:
        if addr and not _addr_is_ip(addr):
            return addr
    return addrs[0] if addrs else ""


def _resolved_list(host: str) -> List[str]:
    """DEBUG: the addresses a name resolves to, so a stale DNS record is visible (empty when it fails)."""
    infos = resolve_with_timeout(host, SSH_PORT, SSH_PRIME_TIMEOUT, socktype=socket.SOCK_STREAM) or []
    out: List[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in out:
            out.append(addr)
    return out


# DEBUG: SSH connections per address this run (logins and host-key reads), because
# SSHBRUTE counts connections to port 22. Guarded by its own lock (worker threads).
_CONN_COUNTS: dict = {}
_CONN_LOCK = threading.Lock()


def _count_conn(addr: str, kind: str) -> None:
    """Add one connection of kind ("login" or "key read") for addr."""
    with _CONN_LOCK:
        per = _CONN_COUNTS.setdefault((addr or "?").lower(), {})
        per[kind] = per.get(kind, 0) + 1


def _debug_conn_report() -> None:
    """DEBUG: print and clear the per-address connection counts at the end of a run."""
    with _CONN_LOCK:
        counts = dict(_CONN_COUNTS)
        _CONN_COUNTS.clear()
    if not DEBUG or not counts:
        return
    print("      DEBUG ssh connections this run (SSHBRUTE counts these):", file=sys.stderr)
    for addr in sorted(counts):
        parts = ", ".join(f"{n} {k}{'s' if n != 1 else ''}" for k, n in sorted(counts[addr].items()))
        print(f"      DEBUG   {addr}: {parts}", file=sys.stderr)


# DEBUG: agreed key exchange per paramiko transport thread. paramiko drops its
# kex object once the exchange ends; the name survives only in its log line.
_KEX_BY_THREAD: dict = {}


class _KexCapture(logging.Handler):
    """Keep paramiko's "Kex: <name>" log line per transport thread, and nothing else."""

    def emit(self, record: logging.LogRecord) -> None:
        """Store the name; every other paramiko record is dropped (it never reaches the console)."""
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - a log record must never break a connection
            return
        if msg.startswith("Kex: "):
            _KEX_BY_THREAD[record.thread] = msg[5:].strip()


def _capture_kex() -> None:
    """DEBUG only, once: let paramiko.transport log DEBUG into _KexCapture alone.

    propagate=False keeps paramiko's own debug and warnings off the console,
    as the CRITICAL level did before. Without DEBUG nothing changes.
    """
    if not DEBUG:
        return
    log = logging.getLogger("paramiko.transport")
    if any(isinstance(h, _KexCapture) for h in log.handlers):
        return
    log.addHandler(_KexCapture())
    log.setLevel(logging.DEBUG)
    log.propagate = False


def _negotiated_ssh(transport) -> str:
    """DEBUG: the crypto this session actually uses, the evidence for CNSA_STRICT on a box."""
    if transport is None:
        return "no transport"
    captured = _KEX_BY_THREAD.pop(getattr(transport, "ident", None), "")
    engine = getattr(transport, "kex_engine", None)
    kex = captured or next(
        (name for name, cls in getattr(transport, "_kex_info", {}).items() if engine is not None and type(engine) is cls),
        type(engine).__name__ if engine is not None else "?",
    )
    return (
        f"cipher={getattr(transport, 'remote_cipher', '?')} mac={getattr(transport, 'remote_mac', '?')} "
        f"kex={kex} hostkey={getattr(transport, 'host_key_type', '?')}"
    )


def _host_resolves(host: str) -> bool:
    """False if DNS fails (Windows 11001). Skip FQDN, try ssh_ip — not a password problem.

    The lookup waits at most SSH_PRIME_TIMEOUT (core.utils.resolve_with_timeout).
    A slow or dead resolver then counts as "no DNS" and the next address (usually
    the admin IP) is tried, instead of stalling the address search on the main
    thread. An IP address resolves at once.
    """
    # print(f"DEBUG dns: resolve {host!r}")
    name = (host or "").strip()
    if name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    if not name:
        return False
    if _addr_is_ip(name):
        return True
    return resolve_with_timeout(name, SSH_PORT, SSH_PRIME_TIMEOUT, socktype=socket.SOCK_STREAM) is not None


_ssh_progress_active = False

# Per-run SSH session pool (see ssh_session_pool). None when no menu run owns one.
# Keyed by (user, sha256 of the password, address). A session is taken out while a
# step uses it, so two workers never share one channel set.
_POOL: Optional[dict] = None
_POOL_LOCK = threading.Lock()
_POOL_KEEPALIVE_SEC = 15


@contextmanager
def ssh_session_pool():
    """One SSH login per box for a whole menu run instead of one per step.

    Every login counts toward SSHBRUTE on the box. With the pool, menu 1 reads the
    engine ID and later purges USM on the same session, and menu 5 restarts the
    NTP service and verifies on the same one. All pooled sessions are closed when
    the run ends, including on Ctrl+C or an error. A nested call reuses the pool.
    """
    global _POOL
    with _POOL_LOCK:
        owner = _POOL is None
        if owner:
            _POOL = {}
    try:
        yield
    finally:
        if owner:
            with _POOL_LOCK:
                clients, _POOL = list((_POOL or {}).values()), None
            # print(f"DEBUG ssh pool: closing {len(clients)} session(s)")
            _debug_conn_report()
            for client in clients:
                try:
                    client.close()
                except Exception:  # noqa: BLE001 - closing must not fail the run
                    pass


def _pool_key(user: str, password: str, addr: str):
    """The password is hashed: a different password (menu 4 verify) must get its own login."""
    return (user or "", hashlib.sha256((password or "").encode("utf-8")).hexdigest(), (addr or "").lower())


def _pool_take(key):
    """Check a live session out of the pool, or None. A dead one is closed and dropped."""
    if key is None:
        return None
    with _POOL_LOCK:
        client = (_POOL or {}).pop(key, None)
    if client is None:
        return None
    transport = client.get_transport()
    if transport is not None and transport.is_active():
        return client
    # The box dropped the idle session; a new login replaces it.
    # print(f"DEBUG ssh pool: dropped dead session for {key[2]}")
    try:
        client.close()
    except Exception:  # noqa: BLE001
        pass
    return None


def _pool_put(key, client) -> bool:
    """Return a session to the pool. False when there is no pool (the caller closes it)."""
    if key is None:
        return False
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        return False
    with _POOL_LOCK:
        if _POOL is None:
            return False
        old = _POOL.pop(key, None)
        _POOL[key] = client
    if old is not None and old is not client:
        try:
            old.close()
        except Exception:  # noqa: BLE001
            pass
    return True


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
        # No newline before the line: batch output is buffered per box and printed
        # after the progress counter line is cleared (core.utils.run_target_batch).
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

    def _with_ssh(self, ip: str, fn, timeout: Optional[int] = None, fresh: bool = False):
        """Open an SSH session, run *fn(client)*, then close it or return it to the run's pool.

        Password auth first; keyboard-interactive is the fallback some
        AppGate boxes require. Inside ssh_session_pool a live session for the
        same user, password and address is reused (no new login). A session is
        checked for life before fn runs; fn is never re-run after it started.
        fresh=True always opens a new login and does not pool it (harden's
        recheck after the cz-configd restart).
        """
        key = None if (fresh or _POOL is None) else _pool_key(self.ssh_user, self.ssh_password, ip)
        client = _pool_take(key)
        reused = client is not None
        keep = False
        if not reused:
            client = paramiko.SSHClient()
            self._apply_host_key_policy(client)
        wait = SSH_TIMEOUT if timeout is None else timeout
        try:
            if not reused:
                _count_conn(ip, "login")
                _capture_kex()
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
                if key is not None:
                    transport = client.get_transport()
                    if transport is not None:
                        # Keeps the session alive between steps (engine read, then purge).
                        transport.set_keepalive(_POOL_KEEPALIVE_SEC)
            if reused:
                self._log(f"{self._tag(ip)} reused pooled session (no new login)", noise=True)
            else:
                self._log(f"{self._tag(ip)} new login; {_negotiated_ssh(client.get_transport())}", noise=True)
            self._mark_ssh("", "ok")
            result = fn(client)
            keep = key is not None
            return result
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
            self._last_reason = ssh_failure_kind(exc)
            self._log(f"{self._tag(ip)} {type(exc).__name__}: {exc}", noise=True)
        except paramiko.SSHException as exc:
            cnsa = _cnsa_reason(exc)
            if cnsa:
                self._mark_ssh("cnsa", cnsa)
            elif "host key" in str(exc).lower():
                self._mark_ssh("hostkey", "host key mismatch")
            elif self._ssh_fail_kind != "hostkey":
                self._mark_ssh("network", ssh_failure_kind(exc))
            self._log(
                f"{self._tag(ip)} {type(exc).__name__}: {str(exc)[:SSH_LOG_PREVIEW]}",
                noise=True,
            )
        finally:
            if not (keep and _pool_put(key, client)):
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
            """Answers only a prompt that asks for a password; any other prompt gets an empty reply so the password is never sent to an unexpected question."""
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
            _count_conn(ip, "login")
            _capture_kex()
            sock = socket.create_connection((ip, SSH_PORT), timeout=SSH_TIMEOUT)
            sock.settimeout(SSH_TIMEOUT)
            transport = paramiko.Transport(sock, disabled_algorithms=_ssh_disabled())
            transport.banner_timeout = SSH_TIMEOUT
            transport.auth_timeout = SSH_AUTH_TIMEOUT
            transport.start_client(timeout=SSH_TIMEOUT)
            remote_key = transport.get_remote_server_key()
            self._verify_transport_host_key(client, ip, remote_key)
            transport.auth_interactive(self.ssh_user, handler)
            self._log(f"{self._tag(ip)} new login (keyboard-interactive); {_negotiated_ssh(transport)}", noise=True)
            self._mark_ssh("", "ok")
            client._transport = transport
            return fn(client)
        except paramiko.AuthenticationException:
            self._ssh_fail_kind = "auth"
            self._last_reason = "auth failed"
            # print(f"DEBUG ssh: kbd-int auth failed ip={ip!r}")
        except (paramiko.SSHException, OSError, socket.timeout, TimeoutError) as exc:
            if not self._ssh_fail_kind:
                self._mark_ssh("network", ssh_failure_kind(exc))
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
        fresh: bool = False,
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
            result = self._with_ssh(addr, fn, fresh=fresh)
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
                    retry_host, fn, error=error, prompt_password=False, fresh=fresh
                )
        kind = self._ssh_fail_kind or "network"
        # The kind tag stays first, for ssh_failure_reason; a network failure also
        # carries its ssh_failure_kind word, so the message names what happened.
        why = f": {self._last_reason}" if kind == "network" and self._last_reason else ""
        raise ValueError(f"{error} ({kind}) ({label or last}){why}")

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


# The words ssh_failure_kind can return for a network-level failure, longest first
# so "SSH banner timed out" is matched before "timed out". core.run uses this list
# to word its messages, so every step and every menu says the same thing.
SSH_FAILURE_WORDS = (
    "SSH handshake failed",
    "SSH banner timed out",
    "connection refused",
    "connection reset",
    "network error",
    "unreachable",
    "timed out",
    "no DNS",
)


def ssh_failure_kind(exc: BaseException) -> str:
    """One name for an SSH connect failure, used by the address search and by every SSH session.

    Before, the address search said "timed out" and a session said "timeout"
    (and "unreachable" or the exception type) for the same failure, so the
    operator saw two wordings depending on the step. The name tells a firewall
    or SSHBRUTE drop (timed out) from a stopped sshd (connection refused) and a
    dropped connection (reset, handshake failed). No password is on this path,
    so the text never holds a secret.
    """
    text = str(exc).lower()
    if isinstance(exc, (socket.timeout, TimeoutError)) or "timed out" in text:
        if isinstance(exc, paramiko.SSHException):
            return "SSH banner timed out"
        return "timed out"
    if isinstance(exc, socket.gaierror) or "getaddrinfo" in text or "11001" in text:
        return "no DNS"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, ConnectionResetError):
        return "connection reset"
    if isinstance(exc, paramiko.SSHException):
        if "timeout" in text:
            return "SSH banner timed out"
        return "SSH handshake failed"
    if "10051" in text or "unreachable" in text:
        return "unreachable"
    if isinstance(exc, OSError):
        return f"network error ({exc.strerror or type(exc).__name__})"
    return type(exc).__name__


def _read_remote_host_key(host: str, timeout: int = SSH_PRIME_TIMEOUT):
    """Read the server key without authenticating. A password here would spend a lockout attempt.

    Returns (key, cnsa_reason, kind). key is None on any failure; cnsa_reason is
    set only when CNSA_STRICT refused the algorithms (no other address can do
    better), and kind names the failure (timed out, connection refused, ...).
    The reason travels with the result because SSH worker threads call this too:
    a shared "last error" could be overwritten by another thread before it is read.
    """
    sock = None
    transport = None
    _count_conn(host, "key read")
    try:
        sock = socket.create_connection((host, SSH_PORT), timeout=timeout)
        transport = paramiko.Transport(sock, disabled_algorithms=_ssh_disabled())
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key(), "", ""
    except (OSError, paramiko.SSHException) as exc:
        kind = ssh_failure_kind(exc)
        # print(f"DEBUG key read: host={host} kind={kind!r} exc={type(exc).__name__}")
        return None, _cnsa_reason(exc), kind
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


# One parsed copy of the toolkit known_hosts file: (path, mtime_ns, size, HostKeys).
_known_cache = None
_KNOWN_CACHE_LOCK = threading.Lock()


def _load_known():
    """The parsed toolkit known_hosts, or None when the file does not exist.

    The address search asks several questions per box (any key for this name,
    the key of this type, any key under the box's other names), and each used to
    read and parse the whole file again. The parsed copy is reused until the
    file's mtime or size changes or _save_host_key drops it, so an edit made
    outside the toolkit is still picked up. Callers only read the object.
    """
    global _known_cache
    path = _ensure_known_hosts_path()
    try:
        st = os.stat(path)
    except OSError:
        return None
    with _KNOWN_CACHE_LOCK:
        cached = _known_cache
        if cached and cached[0] == path and cached[1] == st.st_mtime_ns and cached[2] == st.st_size:
            return cached[3]
        from paramiko.hostkeys import HostKeys

        known = HostKeys()
        known.load(path)
        # print(f"DEBUG known_hosts: parsed {path} entries={len(known)}")
        _known_cache = (path, st.st_mtime_ns, st.st_size, known)
        return known


def _drop_known_cache() -> None:
    """Forget the parsed copy, so the next lookup sees a key just saved."""
    global _known_cache
    with _KNOWN_CACHE_LOCK:
        _known_cache = None


def _any_stored_key(host: str):
    """A previous yes is enough. A timed-out probe must not throw that pin away."""
    known = _load_known()
    if known is None:
        return None
    entry = known.lookup(host)
    if not entry:
        return None
    for key in entry.values():
        return key
    return None


def _stored_host_key(host: str, key):
    """The saved key of the same type as the one the server showed, or None."""
    known = _load_known()
    if known is None:
        return None
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
            _drop_known_cache()
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
    remote, _reason, _kind = _read_remote_host_key(host)
    if remote is not None and remote == expected:
        _save_host_key(host, remote)
        return True
    return False


def _session_pin_ok(target) -> bool:
    """True when this box's address from earlier this session still has a saved key, so no probe is needed."""
    pinned = target.session_ssh_host()
    return bool(pinned) and _any_stored_key(pinned) is not None


def _probe_box(target) -> dict:
    """Network part of the address search: read host keys in address order, no login, no prompt.

    Safe in a worker thread: it prints nothing and changes nothing on the
    target. It stops at the first address that shows a key, or at a CNSA
    refusal (every NIC runs the same sshd), so a box costs the same connections
    as before: one for a good admin address. The console lines are returned and
    printed later, in box order, by the main thread.
    """
    out = {"host": "", "key": None, "cnsa": "", "kind": "", "missed": [], "lines": []}
    for host in target.ssh_endpoints():
        if DEBUG and not _addr_is_ip(host):
            found = _resolved_list(host)
            out["lines"].append(f"      DEBUG dns {host} -> {', '.join(found) or 'no answer'}")
        if not _host_resolves(host):
            out["missed"].append(f"{host} (no DNS)")
            continue
        # print(f"DEBUG find_addr: {target.label()} probe {host}")
        key, cnsa_reason, kind = _read_remote_host_key(host)
        if key is None and cnsa_reason:
            out.update(host=host, cnsa=cnsa_reason, kind=kind)
            return out
        if key is None:
            kind = kind or "no answer"
            out["missed"].append(f"{host} ({kind})")
            out["lines"].append(f"      {target.label()}: {host} port {SSH_PORT}: {kind}; trying next")
            continue
        out.update(host=host, key=key)
        return out
    return out


def _find_ssh_address(target, probe: Optional[dict] = None) -> bool:
    """Main thread. Pick this box's SSH address without sending a password.

    1. An address found earlier in this toolkit session is reused with no probe.
    2. Otherwise the host keys are read in address order (_probe_box, no login);
       prime_target_host_keys does that for all boxes in parallel and passes the
       result in. No DNS, a timeout, or a refused port moves to the next address.
    3. The first address that answers decides. A key that matches the one saved
       for this box pins it. An unknown or changed key is shown once: yes saves
       it and pins the address, no skips the box.
    The worker then logs in once on the pinned address. A separate test login
    here used to double the SSH connections per box and trip SSHBRUTE.
    """
    from config import YES_ANSWERS

    if _session_pin_ok(target):
        pinned = target.session_ssh_host()
        target.pin_ssh_host(pinned)
        print(f"      {target.label()}: using {pinned} (found earlier this session)", file=sys.stderr)
        return True
    if probe is None:
        probe = _probe_box(target)
    for line in probe["lines"]:
        print(line, file=sys.stderr)
    names = target.ssh_endpoints()
    missed = probe["missed"]
    host, key = probe["host"], probe["key"]
    if host and key is None and probe["cnsa"]:
        target.status = STATUS_FAILED
        target.error = f"{host}: {probe['cnsa']}"
        target.code = "E18"
        target.detail = f"host key read on {host}:{SSH_PORT}: {probe['kind'] or 'failed'}"
        print(f"      {target.label()}: {target.code} {target.error}", file=sys.stderr)
        return False
    if host and key is not None:
        problem = _cnsa_key_problem(key)
        if problem:
            target.status = STATUS_FAILED
            target.error = f"{host}: {problem} (CNSA_STRICT is on)"
            target.code = "E18"
            target.detail = f"host key on {host}: {key.get_name()}"
            print(f"      {target.label()}: {target.code} {target.error}", file=sys.stderr)
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
            target.status = STATUS_FAILED
            target.error = "SSH host key prompt needs a terminal"
            target.code = "E07"
            target.detail = f"{host}: " + "SSH host key prompt needs a terminal"
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
            target.status = STATUS_FAILED
            target.error = "SSH host key was not stored"
            target.code = "E07"
            target.detail = f"{host}: " + "SSH host key was not stored"
            return False
        _save_host_key(host, key)
        target.pin_ssh_host(host)
        return True
    target.status = STATUS_FAILED
    target.error = "No SSH address answered: " + (", ".join(missed) or "no address")
    target.code = "E07"
    # The report's detail keeps the per-address reasons even when a caller rewrites error.
    target.detail = f"port {SSH_PORT}: " + (", ".join(missed) or "no address")
    print(f"      {target.label()}: {target.code} {target.error}", file=sys.stderr)
    if missed and all("timed out" in m for m in missed):
        print(
            f"      {target.label()}: every address timed out; check SSHBRUTE or a firewall from the appliance console.",
            file=sys.stderr,
        )
    return False


def iter_primed_targets(targets, collectives):
    """Yield each appliance as soon as its SSH address and host key are settled, before any password.

    Host keys are read for all boxes in parallel (SSH_CONCURRENCY at a time, no
    login, addresses in order within a box). Each box is decided on the main
    thread as soon as its own read finishes, so a reachable box can start its
    SSH work while an unreachable box is still timing out (before, every box
    waited for the slowest search). Host-key prompts stay on the main thread;
    workers must not ask. Boxes are decided in the order their reads finish.
    A box that fails (missing username, no answering address, key refused) is
    marked failed and not yielded.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    import config as _config
    from core.prompts import collective_for_target

    install_oob_host_keys(collectives)
    _attach_existing_known_hosts()
    # print(f"DEBUG prime_keys: n={len(targets)}")
    print(
        "      SSH: finding each appliance's address and checking host keys before parallel work starts.",
        file=sys.stderr,
    )
    ready = []
    for target in targets:
        try:
            col = collective_for_target(target, collectives)
            if not (col.get("ssh_username") or "").strip():
                raise KeyError("ssh_username")
        except (KeyError, ValueError, RuntimeError) as exc:
            target.status = STATUS_FAILED
            target.error = f"missing SSH setting {exc}"
            target.code = "E21"
            target.detail = target.error
            print(f"      {target.label()}: {target.code} {target.error}", file=sys.stderr)
            continue
        ready.append(target)

    def _decide(target, probe=None, exc=None) -> bool:
        """Main thread: settle one box from its read (or reuse its session address)."""
        print(f"      {target.label()}: checking SSH address and host key", file=sys.stderr)
        try:
            if exc is not None:
                raise exc
            return bool(_find_ssh_address(target, probe))
        except (OSError, paramiko.SSHException, ValueError) as err:
            target.status = STATUS_FAILED
            target.error = str(err)
            target.detail = f"address search: {type(err).__name__}: {err}"
            target.code = "E07"
            print(f"      {target.label()}: {err}", file=sys.stderr)
            return False

    # Boxes with an address from earlier this session need no read: first out.
    to_probe = []
    for target in ready:
        if _session_pin_ok(target):
            if _decide(target):
                yield target
        else:
            to_probe.append(target)
    if not to_probe:
        return
    width = max(1, min(int(getattr(_config, "SSH_CONCURRENCY", 5) or 1), len(to_probe)))
    pool = ThreadPoolExecutor(max_workers=width, thread_name_prefix="ssh-probe")
    finished = False
    futures = {}
    try:
        futures.update({pool.submit(_probe_box, t): t for t in to_probe})
        for future in as_completed(futures):
            target = futures[future]
            try:
                probe, err = future.result(), None
            except (OSError, paramiko.SSHException, ValueError) as exc:
                probe, err = None, exc
            if _decide(target, probe, err):
                yield target
        finished = True
    finally:
        # After Ctrl+C (or a caller that stops early) do not wait for the reads
        # still running: each has its own timeout and sends no password.
        # print(f"DEBUG prime_keys: finished={finished}")
        if finished:
            pool.shutdown(wait=True)
        else:
            stop_pool_early(pool, futures, wait_running=False)


def prime_target_host_keys(targets, collectives) -> None:
    """Settle every box's SSH address and host key, for a caller that is not a parallel SSH batch.

    Menu 5 uses this before its PUTs. Parallel SSH steps pass
    iter_primed_targets straight to run_ssh_batch instead, so reachable boxes
    start work early. Callers must skip boxes left failed.
    """
    for _target in iter_primed_targets(targets, collectives):
        pass


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
        """Collect worker failures for the main thread, which alone may prompt for a retry password."""
        failed.append((target, exc))

    def _progress(done: int, n: int) -> None:
        """One-line SSH n/N counter when DEBUG is off; DEBUG prints every try instead, so the counter would only interleave."""
        global _ssh_progress_active
        if DEBUG or n < 2:
            return
        _ssh_progress_active = done < n
        sys.stderr.write(f"\r      SSH {done}/{n}")
        sys.stderr.flush()
        if done >= n:
            sys.stderr.write("\n")
            sys.stderr.flush()

    try:
        run_target_batch(targets, worker, concurrency, _capture, progress=_progress)
    except BaseException:
        # The batch ended early (Ctrl+C or an error). Record every failure it
        # collected, so the report shows those boxes as failed, not unreached;
        # no retry prompt now, since the run is stopping.
        # print(f"DEBUG ssh batch: early stop with {len(failed)} failure(s) to record")
        for target, exc in failed:
            on_fail(target, exc)
        raise
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
