"""SSH: engine-ID read (after API type-3 pin) and later USM purge.

  get_engine_id()
      restart snmpd, read oldEngineID, check RFC 3411 type 3 vs ETH_IFACE MAC

  purge_persistent_user()
      after API createUser: delete ALL persistent usmUser rows for the user,
      restart snmpd so /etc createUser writes new keys (net-snmp will not
      update an existing usmUser password)
"""
from utils import ensure_package

try:
    import paramiko
except ImportError:
    ensure_package("paramiko", "paramiko")
    import paramiko

import re
import socket
import sys
import time
from typing import List, Optional, Sequence, Union

from config import (
    ENGINE_ID_TYPE,
    ETH_IFACE,
    SNMP_NAME_RE,
    SNMP_PERSISTENT_CONF,
    SNMP_PERSISTENT_CONF_ALT,
    SNMP_RELOAD_DELAY,
    SNMPD_STOP_RETRIES,
    USM_RECREATE_WAITS,
    USM_SED_RETRIES,
    SSH_AUTH_TIMEOUT,
    SSH_PORT,
    SSH_STRICT_HOST_KEY,
    SSH_TIMEOUT,
)

OLD_ENGINE_RE = re.compile(r"oldEngineID\s+(?:0x)?([0-9a-fA-F]+)", re.IGNORECASE)
MAC_RE = re.compile(r"link/ether\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


class SNMPEngineFetcher:
    def __init__(self, ssh_user: str, ssh_password: str) -> None:
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password

    @staticmethod
    def _hosts(host: Union[str, Sequence[str]]) -> List[str]:
        if isinstance(host, str):
            return [host] if host else []
        return [h for h in host if h]

    def get_engine_id(
        self, host: Union[str, Sequence[str]], *, restart_snmpd: bool = True
    ) -> str:
        """Step 4: SSH FQDN first, then IP. Read oldEngineID, match MAC.

        restart_snmpd=False skips the snmpd bounce (used for DRY_RUN preview).
        """
        if not self.ssh_user or not self.ssh_password:
            raise ValueError("SSH credentials are required to retrieve the Engine ID")
        addrs = self._hosts(host)
        last = None
        for i, addr in enumerate(addrs):
            engine = self._ssh_query_engine_id(addr, restart_snmpd=restart_snmpd)
            if engine:
                return engine
            last = addr
            if i < len(addrs) - 1:
                print(f"      SSH {addr} failed; trying next endpoint...", file=sys.stderr)
        raise ValueError(
            f"Could not retrieve Engine ID via SSH ({last or host})"
        )

    def purge_persistent_user(
        self, host: Union[str, Sequence[str]], user: str, keep_hash: str = ""
    ) -> None:
        """Delete every persistent usmUser for *user*, then restart snmpd.

        net-snmp ignores createUser in /etc/snmp/snmpd.conf when a usmUser
        already exists in /var/lib/snmp. Always strip those rows so the
        new createUser (already pushed via API) is applied on restart.
        """
        if not re.fullmatch(SNMP_NAME_RE, user):
            raise ValueError(f"Unsafe SNMP username for remote edit: {user!r}")
        keep = (keep_hash or "").lower()
        if keep and not re.fullmatch(r"[0-9a-f]+", keep):
            keep = ""

        def _purge(client: paramiko.SSHClient) -> bool:
            # Stop first. A running snmpd rewrites persistent conf on exit
            # and would undo sed (Wrong SNMP PDU digest on the next walk).
            print(f"      Stopping snmpd before editing persistent USM...", file=sys.stderr)
            if not self._stop_snmpd(client):
                return False
            paths = (SNMP_PERSISTENT_CONF, SNMP_PERSISTENT_CONF_ALT)
            for path in paths:
                self._sudo(
                    client,
                    f"sed -i '/usmUser.*\"{user}\"/d' {path} || true",
                    check=False,
                )
                self._sudo(
                    client,
                    f"sed -i '/createUser[[:space:]]\\+{user}\\b/d' {path} || true",
                    check=False,
                )
            leftover = ""
            for _try in range(USM_SED_RETRIES):
                leftover = self._sudo(
                    client,
                    f"grep -h 'usmUser.*\"{user}\"' {SNMP_PERSISTENT_CONF} "
                    f"{SNMP_PERSISTENT_CONF_ALT} 2>/dev/null || true",
                    check=False,
                )
                if not leftover.strip():
                    break
                print(
                    f"      usmUser still present; retrying delete ({_try + 1}/{USM_SED_RETRIES})...",
                    file=sys.stderr,
                )
                for path in paths:
                    self._sudo(
                        client,
                        f"sed -i '/usmUser.*\"{user}\"/d' {path} || true",
                        check=False,
                    )
            if leftover.strip():
                print(f"      usmUser still present after purge:\n{leftover}", file=sys.stderr)
                self._start_snmpd(client)
                return False
            print(
                f"      Removed persistent usmUser '{user}'. Starting snmpd "
                "so createUser can recreate it...",
                file=sys.stderr,
            )
            if not self._start_snmpd(client):
                return False
            if not keep:
                return True
            for attempt in range(1, USM_RECREATE_WAITS + 1):
                time.sleep(SNMP_RELOAD_DELAY)
                created = self._sudo(
                    client,
                    f"grep -h 'usmUser.*\"{user}\"' {SNMP_PERSISTENT_CONF} "
                    f"{SNMP_PERSISTENT_CONF_ALT} 2>/dev/null || true",
                    check=False,
                )
                # print(f"DEBUG step7: recreate attempt={attempt} keep={keep[:8]} file={(created or '')[:80]!r}")
                if keep in (created or "").lower():
                    print(
                        f"      snmpd recreated usmUser '{user}' with the new key.",
                        file=sys.stderr,
                    )
                    return True
                print(
                    f"      Waiting for createUser to persist "
                    f"(attempt {attempt}/{USM_RECREATE_WAITS})...",
                    file=sys.stderr,
                )
            print(
                "      createUser has not written the new key yet; walk may fail.",
                file=sys.stderr,
            )
            return True

        last_result = None
        for addr in self._hosts(host):
            last_result = self._with_ssh(addr, _purge)
            if last_result is True:
                time.sleep(SNMP_RELOAD_DELAY)
                return
            if last_result is False:
                raise RuntimeError(
                    f"Could not purge persistent SNMP user '{user}' on {addr}"
                )
            print(f"      SSH {addr} failed; trying next endpoint...", file=sys.stderr)
        raise RuntimeError(f"Could not purge persistent SNMP user '{user}' via SSH")

    def _apply_host_key_policy(self, client: paramiko.SSHClient) -> None:
        try:
            client.load_system_host_keys()
        except OSError:
            pass
        policy = paramiko.RejectPolicy() if SSH_STRICT_HOST_KEY else paramiko.WarningPolicy()
        client.set_missing_host_key_policy(policy)

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
            print(f"      SSH connection error ({type(exc).__name__}): {exc}", file=sys.stderr)
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

    def _ssh_query_engine_id(self, ip: str, *, restart_snmpd: bool = True) -> Optional[str]:
        def _reader(client: paramiko.SSHClient) -> Optional[str]:
            return self._configure_and_read_engine_id(client, restart_snmpd=restart_snmpd)

        return self._with_ssh(ip, _reader)

    def _configure_and_read_engine_id(
        self, client: paramiko.SSHClient, *, restart_snmpd: bool = True
    ) -> Optional[str]:
        # 1) restart so snmpd picks up engineIDType 3 from cz-configd (skipped in DRY_RUN)
        if restart_snmpd:
            print(
                f"      Restarting snmpd so it applies engineIDType {ENGINE_ID_TYPE}...",
                file=sys.stderr,
            )
            if not self._restart_snmpd(client):
                print("      snmpd restart failed.", file=sys.stderr)
                return None
            time.sleep(SNMP_RELOAD_DELAY)
        else:
            print("      Reading existing oldEngineID (no snmpd restart)...", file=sys.stderr)

        # 2) oldEngineID is written to persistent conf after a clean start
        raw = self._sudo(client, f"grep -E '^oldEngineID' {SNMP_PERSISTENT_CONF} | tail -n 1")
        match = OLD_ENGINE_RE.search(raw or "")
        if not match:
            print(
                f"      No oldEngineID in {SNMP_PERSISTENT_CONF} after restart. "
                f"Output: {(raw or '').strip()[:200]}",
                file=sys.stderr,
            )
            return None
        engine_id = match.group(1).lower()
        print(f"      oldEngineID: {engine_id}", file=sys.stderr)
        # print(f"DEBUG step4: raw oldEngineID line={raw!r}")

        # 3) type 3 must embed this interface's MAC
        mac = self._read_iface_mac(client)
        if not mac:
            print(f"      Could not read {ETH_IFACE} MAC via ip addr.", file=sys.stderr)
            return None
        print(f"      {ETH_IFACE} MAC: {mac}", file=sys.stderr)

        expected_suffix = mac.replace(":", "").lower()
        if not self._engine_id_matches_mac(engine_id, expected_suffix):
            print(
                "      Engine ID does not match RFC 3411 type-3 MAC calculation "
                f"(expected ...03{expected_suffix}, got {engine_id}).",
                file=sys.stderr,
            )
            return None
        print(f"      Engine ID matches {ETH_IFACE} MAC (engineIDType {ENGINE_ID_TYPE}).", file=sys.stderr)
        return engine_id

    def _stop_snmpd(self, client: paramiko.SSHClient) -> bool:
        for _ in range(SNMPD_STOP_RETRIES):
            self._sudo(client, "systemctl stop snmpd", check=False)
            self._sudo(client, "service snmpd stop", check=False)
            self._sudo(client, "killall -q snmpd || true", check=False)
            time.sleep(1)
            status = (self._sudo(client, "systemctl is-active snmpd || true") or "").strip()
            if status != "active":
                return True
        print("      snmpd still active after stop attempts.", file=sys.stderr)
        return False

    def _start_snmpd(self, client: paramiko.SSHClient) -> bool:
        self._sudo(client, "systemctl start snmpd", check=False)
        status = (self._sudo(client, "systemctl is-active snmpd || true") or "").strip()
        if status == "active":
            return True
        self._sudo(client, "service snmpd start", check=False)
        status = (self._sudo(client, "systemctl is-active snmpd || true") or "").strip()
        return status == "active"

    def _restart_snmpd(self, client: paramiko.SSHClient) -> bool:
        """systemctl first; `service snmpd restart` if the unit is not active."""
        out = self._sudo(client, "systemctl restart snmpd", check=False)
        status = (self._sudo(client, "systemctl is-active snmpd || true") or "").strip()
        if status == "active":
            return True
        print(f"      systemctl restart snmpd: {out.strip()[:200]}", file=sys.stderr)
        self._sudo(client, "service snmpd restart", check=False)
        status = (self._sudo(client, "systemctl is-active snmpd || true") or "").strip()
        fallback = (self._sudo(client, "service snmpd status || true") or "").lower()
        return status == "active" or "is running" in fallback or "active (running)" in fallback

    def _read_iface_mac(self, client: paramiko.SSHClient) -> Optional[str]:
        output = self._run(client, f"ip -o link show {ETH_IFACE}")
        match = MAC_RE.search(output or "")
        if match:
            return match.group(1).lower()
        output = self._run(client, f"ip addr show {ETH_IFACE}")
        match = MAC_RE.search(output or "")
        return match.group(1).lower() if match else None

    @staticmethod
    def _engine_id_matches_mac(engine_id: str, mac_hex: str) -> bool:
        """RFC 3411 type 3: 4-byte enterprise (MSB set) + 0x03 + 6-byte MAC."""
        try:
            raw = bytes.fromhex(engine_id)
        except ValueError:
            return False
        if len(raw) < 11:
            return False
        if raw[4] != ENGINE_ID_TYPE:
            return False
        return raw[5:11].hex() == mac_hex

    def _sudo(self, client: paramiko.SSHClient, command: str, check: bool = True) -> str:
        return self._run(client, f"sudo -S {command}", sudo=True, check=check)

    def _run(
        self,
        client: paramiko.SSHClient,
        command: str,
        sudo: bool = False,
        check: bool = True,
    ) -> str:
        stdin, stdout, stderr = client.exec_command(command)
        stdout.channel.settimeout(SSH_TIMEOUT)
        stderr.channel.settimeout(SSH_TIMEOUT)
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
                f"      SSH command failed (exit {exit_status}): {err_output.strip()[:300]}",
                file=sys.stderr,
            )
        return output
