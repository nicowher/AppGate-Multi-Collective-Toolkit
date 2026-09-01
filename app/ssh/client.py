"""Reusable SSH sessions for appliance work.

Password auth first; keyboard-interactive is the fallback some AppGate
boxes require. Timeouts come from config (SSH_TIMEOUT / SSH_AUTH_TIMEOUT)
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

import os
import shlex
import socket
import sys
import threading
from getpass import getpass
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple, Union

from config import (
    DEBUG,
    SSH_AUTH_TIMEOUT,
    SSH_KNOWN_HOSTS,
    SSH_LOG_PREVIEW,
    SSH_PORT,
    SSH_STRICT_HOST_KEY,
    SSH_TIMEOUT,
    YES_ANSWERS,
)


class SSHSession:
    def __init__(self, ssh_user: str, ssh_password: str) -> None:
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password

    @staticmethod
    def _hosts(host: Union[str, Sequence[str]]) -> List[str]:
        if isinstance(host, str):
            return [host] if host else []
        return [h for h in host if h]

    def _apply_host_key_policy(self, client: paramiko.SSHClient) -> None:
        path = SSH_KNOWN_HOSTS.strip() or str(Path.home() / ".ssh" / "known_hosts")
        path = os.path.expanduser(path)
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            if not os.path.isfile(path):
                fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
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

    def prime_host_keys(self, hosts: Union[str, Sequence[str]]) -> None:
        """Accept unknown keys on this thread (call from main before a pool)."""
        for host in self._hosts(hosts):
            if _hostname_known(host):
                continue
            print(f"      Checking SSH host key for {host}...", file=sys.stderr)
            self._with_ssh(host, lambda _c: True)

    def _with_ssh(self, ip: str, fn):
        """Open an SSH session, run *fn(client)*, then close.

        Password auth first; keyboard-interactive is the fallback some
        AppGate boxes require.
        """
        client = paramiko.SSHClient()
        self._apply_host_key_policy(client)
        try:
            client.connect(
                hostname=ip,
                port=SSH_PORT,
                username=self.ssh_user,
                password=self.ssh_password,
                timeout=SSH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
                auth_timeout=SSH_AUTH_TIMEOUT,
            )
            return fn(client)
        except paramiko.AuthenticationException as exc:
            print(
                f"      SSH authentication failed: {exc}. "
                "Trying keyboard-interactive fallback...",
                file=sys.stderr,
            )
            return self._with_ssh_keyboard_interactive(ip, fn)
        except paramiko.SSHException as exc:
            print(
                f"      SSH connection error ({type(exc).__name__}): "
                f"{str(exc)[:SSH_LOG_PREVIEW]}",
                file=sys.stderr,
            )
            # print(f"DEBUG ssh: connect fail host={ip} user={self.ssh_user}")
        except (OSError, socket.timeout, TimeoutError) as exc:
            print(f"      SSH network error ({type(exc).__name__}): {exc}", file=sys.stderr)
        finally:
            try:
                client.close()
            except OSError:
                pass
        return None

    def _with_ssh_keyboard_interactive(self, ip: str, fn):
        def handler(title, instructions, prompt_list):
            responses = []
            for prompt in prompt_list:
                if "password" in prompt[0].lower():
                    responses.append(self.ssh_password)
                else:
                    responses.append("")
            return responses

        transport = None
        client = paramiko.SSHClient()
        self._apply_host_key_policy(client)
        try:
            transport = paramiko.Transport((ip, SSH_PORT))
            transport.banner_timeout = SSH_TIMEOUT
            transport.auth_timeout = SSH_AUTH_TIMEOUT
            transport.start_client(timeout=SSH_TIMEOUT)
            transport.auth_interactive(self.ssh_user, handler)
            client._transport = transport
            return fn(client)
        except (paramiko.SSHException, OSError, socket.timeout, TimeoutError) as exc:
            print(
                f"      Keyboard-interactive SSH failed ({type(exc).__name__}): {exc}",
                file=sys.stderr,
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
        After the last IP fails, main thread may ask for a new SSH password.
        """
        addrs = self._hosts(host)
        if not addrs:
            raise ValueError("No SSH endpoint")
        for i, addr in enumerate(addrs):
            result = self._with_ssh(addr, fn)
            if result is False:
                raise ValueError(f"{error} (connected but failed) ({addr})")
            if result is not None:
                return result
            if i < len(addrs) - 1:
                print(f"      SSH {addr} failed; trying next endpoint...", file=sys.stderr)
        last = addrs[-1]
        if (
            prompt_password
            and threading.current_thread() is threading.main_thread()
        ):
            new_pw = prompt_retry_ssh_password(last)
            if new_pw:
                self.ssh_password = new_pw
                return self._with_ssh_endpoints(
                    host, fn, error=error, prompt_password=False
                )
        raise ValueError(f"{error} ({last})")

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
            print(f"      DEBUG sudo_script rc={exit_status} out_len={len(output)}", file=sys.stderr)
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
        print(
            f"      SSH host key for {hostname} is not in known_hosts.",
            file=sys.stderr,
        )
        ans = input("      Trust and save this host key? [y/N]: ").strip().lower()
        if ans not in YES_ANSWERS:
            raise paramiko.SSHException(f"Host key for {hostname} rejected")
        _save_host_key(client, hostname, key)
        print(f"      Saved host key for {hostname}.", file=sys.stderr)


def prime_target_host_keys(targets, collectives) -> None:
    """Prompt for unknown FQDN keys on the main thread before a worker pool."""
    from core.prompts import collective_for_target

    # print(f"DEBUG prime_keys: n={len(targets)}")
    print(
        "      SSH host keys: accept each new host before parallel work starts.",
        file=sys.stderr,
    )
    seen = set()
    for target in targets:
        col = collective_for_target(target, collectives)
        host = target.ssh_fqdn or (
            target.ssh_endpoints()[0] if target.ssh_endpoints() else ""
        )
        marker = (col.get("ssh_username"), host)
        if not host or marker in seen:
            continue
        seen.add(marker)
        SSHSession(col["ssh_username"], col["ssh_password"]).prime_host_keys([host])


def ssh_password_for(target, col: dict) -> str:
    override = getattr(target, "ssh_password_override", None)
    if override:
        return override
    return col.get("ssh_password") or ""


def prompt_retry_ssh_password(label: str) -> str:
    """After FQDN and IP failed. Main thread only. Empty = skip."""
    # print(f"DEBUG ssh: password retry prompt for {label}")
    ans = input(
        f"      SSH failed for {label} after FQDN and IP. Try a new password? [y/N]: "
    ).strip().lower()
    if ans not in YES_ANSWERS:
        return ""
    pw = getpass("      SSH Password: ").strip()
    confirm = getpass("      SSH Password (confirm): ").strip()
    if not pw or pw != confirm:
        print("      Passwords did not match or empty.", file=sys.stderr)
        return ""
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
        sshish = "connected but failed" not in msg and (
            "ssh failed" in msg
            or "authentication" in msg
            or "engine id via ssh" in msg
            or "no ssh endpoint" in msg
        )
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
