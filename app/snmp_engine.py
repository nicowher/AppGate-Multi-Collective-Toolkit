from utils import ensure_package

try:
    import paramiko
except ImportError:
    ensure_package("paramiko", "paramiko")
    import paramiko

import re
import sys
import time
from typing import Optional

from config import SNMP_RELOAD_DELAY, SSH_AUTH_TIMEOUT, SSH_TIMEOUT

# RFC 3411 SnmpEngineID: octet 5 == 3 means the following 6 octets are a MAC.
ENGINE_ID_TYPE_MAC = 3
NET_SNMP_CONF = "/etc/snmp/snmpd.conf"
PERSISTENT_CONF = "/var/lib/snmp/snmpd.conf"
ETH_IFACE = "eth0"

OLD_ENGINE_RE = re.compile(r"oldEngineID\s+(?:0x)?([0-9a-fA-F]+)", re.IGNORECASE)
MAC_RE = re.compile(r"link/ether\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


class SNMPEngineFetcher:
    def __init__(self, ssh_user: str, ssh_password: str) -> None:
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password

    def get_engine_id(self, ip: str) -> str:
        """Force engineIDType 3, restart snmpd, read oldEngineID, check vs eth0 MAC."""
        if not self.ssh_user or not self.ssh_password:
            raise ValueError("SSH credentials are required to retrieve the Engine ID")

        engine = self._ssh_query_engine_id(ip)
        if not engine:
            raise ValueError("Could not retrieve Engine ID from appliance via SSH")
        return engine

    def purge_persistent_user(self, ip: str, user: str) -> None:
        """Remove every usmUser/createUser row for *user* from net-snmp persistent store.

        AppGate deleteUser only edits the API snmpd.conf. net-snmp keeps USM
        users in /var/lib/snmp/snmpd.conf; leftover rows make createUser a no-op
        and leave the old localized keys (Wrong SNMP PDU digest).
        """
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", user):
            raise ValueError(f"Unsafe SNMP username for remote edit: {user!r}")

        def _purge(client: paramiko.SSHClient) -> bool:
            paths = (PERSISTENT_CONF, "/var/net-snmp/snmpd.conf", NET_SNMP_CONF)
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
            leftover = self._sudo(
                client,
                f"grep -h 'usmUser.*\"{user}\"' {PERSISTENT_CONF} "
                f"/var/net-snmp/snmpd.conf 2>/dev/null || true",
                check=False,
            )
            if leftover.strip():
                print(f"      usmUser still present after purge:\n{leftover}", file=sys.stderr)
                return False
            print(f"      Purged persistent usmUser '{user}'. Restarting snmpd...", file=sys.stderr)
            return self._restart_snmpd(client)

        if not self._with_ssh(ip, _purge):
            raise RuntimeError(f"Could not purge persistent SNMP user '{user}' via SSH")
        time.sleep(SNMP_RELOAD_DELAY)

    def _with_ssh(self, ip: str, fn):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        try:
            client.connect(
                hostname=ip,
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
            print(f"      SSH connection error: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"      SSH error: {exc}", file=sys.stderr)
        finally:
            try:
                client.close()
            except Exception:
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
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        try:
            transport = paramiko.Transport((ip, 22))
            transport.banner_timeout = SSH_TIMEOUT
            transport.auth_timeout = SSH_AUTH_TIMEOUT
            transport.start_client(timeout=SSH_TIMEOUT)
            transport.auth_interactive(self.ssh_user, handler)
            client._transport = transport
            return fn(client)
        except Exception as exc:
            print(f"      Keyboard-interactive SSH also failed: {exc}", file=sys.stderr)
        finally:
            try:
                client.close()
            except Exception:
                pass
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
        return None

    def _ssh_query_engine_id(self, ip: str) -> Optional[str]:
        return self._with_ssh(ip, self._configure_and_read_engine_id)

    def _configure_and_read_engine_id(self, client: paramiko.SSHClient) -> Optional[str]:
        print("      Setting engineIDType 3 (RFC 3411 MAC format)...", file=sys.stderr)
        self._ensure_engine_id_type3(client)

        print("      Restarting snmpd so it regenerates oldEngineID...", file=sys.stderr)
        if not self._restart_snmpd(client):
            print("      snmpd restart failed.", file=sys.stderr)
            return None
        time.sleep(SNMP_RELOAD_DELAY)

        raw = self._sudo(client, f"grep -E '^oldEngineID' {PERSISTENT_CONF} | tail -n 1")
        match = OLD_ENGINE_RE.search(raw or "")
        if not match:
            print(
                f"      No oldEngineID in {PERSISTENT_CONF} after restart. "
                f"Output: {(raw or '').strip()[:200]}",
                file=sys.stderr,
            )
            return None
        engine_id = match.group(1).lower()
        print(f"      oldEngineID: {engine_id}", file=sys.stderr)

        mac = self._read_eth0_mac(client)
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
        print("      Engine ID matches eth0 MAC (engineIDType 3).", file=sys.stderr)
        return engine_id

    def _ensure_engine_id_type3(self, client: paramiko.SSHClient) -> None:
        # exactEngineID / engineID would pin a random ID and block type-3 generation.
        self._sudo(
            client,
            f"sed -i -E '/^[[:space:]]*(exactEngineID|engineID)[[:space:]]/d' {NET_SNMP_CONF}",
        )
        current = self._sudo(
            client,
            f"grep -iE '^[[:space:]]*engineIDType[[:space:]]+' {NET_SNMP_CONF} || true",
        )
        if re.search(r"engineIDType\s+3\b", current or "", re.IGNORECASE):
            print(f"      {NET_SNMP_CONF} already has engineIDType 3.", file=sys.stderr)
            return
        self._sudo(
            client,
            f"sed -i -E '/^[[:space:]]*engineIDType[[:space:]]/d' {NET_SNMP_CONF}",
        )
        self._sudo(client, f"sh -c 'printf \"%s\\n\" \"engineIDType 3\" >> {NET_SNMP_CONF}'")
        print(f"      Wrote engineIDType 3 to {NET_SNMP_CONF}.", file=sys.stderr)

    def _restart_snmpd(self, client: paramiko.SSHClient) -> bool:
        out = self._sudo(client, "systemctl restart snmpd", check=False)
        status = self._sudo(client, "systemctl is-active snmpd || true")
        if "active" in (status or ""):
            return True
        print(f"      systemctl restart snmpd: {(out or '').strip()[:200]}", file=sys.stderr)
        self._sudo(client, "service snmpd restart", check=False)
        status = self._sudo(client, "systemctl is-active snmpd || service snmpd status || true")
        return "active" in (status or "") or "running" in (status or "").lower()

    def _read_eth0_mac(self, client: paramiko.SSHClient) -> Optional[str]:
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
        if raw[4] != ENGINE_ID_TYPE_MAC:
            return False
        return raw[5:11].hex() == mac_hex

    @staticmethod
    def expected_engine_id(mac: str, enterprise: int = 8072) -> str:
        """Build a net-snmp-style type-3 engine ID from a MAC (enterprise 8072)."""
        mac_hex = mac.replace(":", "").replace("-", "").lower()
        enterprise_bytes = (enterprise | 0x80000000).to_bytes(4, "big")
        return (enterprise_bytes + bytes([ENGINE_ID_TYPE_MAC]) + bytes.fromhex(mac_hex)).hex()

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
        if sudo:
            stdin.write(self.ssh_password + "\n")
            stdin.flush()
        output = stdout.read().decode("utf-8", errors="replace")
        err_output = stderr.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        if check and exit_status not in (0, 1):
            print(
                f"      SSH command failed (exit {exit_status}): {err_output.strip()[:300]}",
                file=sys.stderr,
            )
        return output
