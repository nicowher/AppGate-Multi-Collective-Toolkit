"""SSH helpers for configure steps 4 and 7.

  get_engine_id(host, restart_snmpd=True)   — step 4
      Why: localized USM keys (Kul) bind to the SNMP engine ID. FQDN first for
      admin-hostname best practice; IP fallback when DNS/NAT is wrong.
      Live run restarts snmpd so engineIDType 3 is active before reading
      oldEngineID. Dry-run skips restart so preview does not bounce snmpd.
      MAC check proves type-3 (enterprise + 0x03 + eth MAC) per RFC 3411.

  purge_persistent_user(host, user, keep_hash)  — step 7
      Why this exists at all:
        - AppGate API createUser only lands in /etc/snmp/snmpd.conf (via cz-configd).
        - net-snmp's *running* user DB is /var/lib/snmp/snmpd.conf (usmUser lines).
        - If a usmUser row already exists, snmpd ignores createUser on reload —
          so password rotations never apply and walks get Wrong SNMP PDU digest.
      Why stop → sed → start (not sed while running):
        - A live snmpd rewrites persistent conf on shutdown and undoes sed.
      Why wait for keep_hash:
        - createUser is applied asynchronously on start; walking too early
          still sees the old key or an empty DB.
"""
from core.utils import ensure_package

try:
    import paramiko
except ImportError:
    ensure_package("paramiko", "paramiko")
    import paramiko

import re
import sys
import time
from typing import Optional, Sequence, Union

from config import (
    DEBUG,
    ENGINE_ID_TYPE,
    ETH_IFACE,
    SNMP_NAME_RE,
    SNMP_PERSISTENT_CONF,
    SNMP_PERSISTENT_CONF_ALT,
    SNMP_RELOAD_DELAY,
    SSH_LOG_PREVIEW,
    SNMPD_STOP_POLL_SEC,
    SNMPD_STOP_RETRIES,
    USM_RECREATE_WAITS,
    USM_SED_RETRIES,
)

from .client import SSHSession

OLD_ENGINE_RE = re.compile(r"oldEngineID\s+(?:0x)?([0-9a-fA-F]+)", re.IGNORECASE)
MAC_RE = re.compile(r"link/ether\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


class SNMPEngineFetcher(SSHSession):
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
        """Force snmpd to honor the new createUser by clearing persistent USM.

        keep_hash: after start, wait until this hex appears in usmUser (proves
        the new localized key was written, not a stale row).
        """
        if not re.fullmatch(SNMP_NAME_RE, user):
            raise ValueError(f"Unsafe SNMP username for remote edit: {user!r}")
        keep = (keep_hash or "").lower()
        if keep and not re.fullmatch(r"[0-9a-f]+", keep):
            keep = ""

        def _purge(client: paramiko.SSHClient) -> bool:
            # Must stop first — running snmpd flushes USM back to disk on exit
            # and would resurrect the rows we are about to delete.
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

    def _ssh_query_engine_id(self, ip: str, *, restart_snmpd: bool = True) -> Optional[str]:
        def _reader(client: paramiko.SSHClient) -> Optional[str]:
            return self._configure_and_read_engine_id(client, restart_snmpd=restart_snmpd)

        return self._with_ssh(ip, _reader)

    def _configure_and_read_engine_id(
        self, client: paramiko.SSHClient, *, restart_snmpd: bool = True
    ) -> Optional[str]:
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
        if DEBUG:
            print(f"      DEBUG step4: oldEngineID={engine_id} restart={restart_snmpd}", file=sys.stderr)

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
            time.sleep(SNMPD_STOP_POLL_SEC)
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
        print(f"      systemctl restart snmpd: {out.strip()[:SSH_LOG_PREVIEW]}", file=sys.stderr)
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
