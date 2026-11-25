"""SSH helpers for configure steps 4 and 7.

  get_engine_id(host, restart_snmpd=True)   — step 4
      Why: localized USM keys (Kul) bind to the SNMP engine ID. SSH uses the
      address found for this box this session (admin hostname, admin IP,
      then the other NIC IPs) so DNS or NAT problems on one name are skipped.
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
import shlex
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
    """SSH helpers for menu 1 steps 4 and 7: read the engine ID, and purge persistent USM rows."""
    def get_engine_id(
        self, host: Union[str, Sequence[str]], *, restart_snmpd: bool = True
    ) -> str:
        """Step 4: SSH to the session address (fallbacks in Target.ssh_endpoints). Read oldEngineID, match MAC.

        restart_snmpd=False skips the snmpd bounce (used for DRY_RUN preview).
        """
        if not self.ssh_user or not self.ssh_password:
            raise ValueError("SSH credentials are required to retrieve the Engine ID")
        return self._with_ssh_endpoints(
            host,
            lambda c: self._configure_and_read_engine_id(
                c, restart_snmpd=restart_snmpd
            ),
            error="Could not retrieve Engine ID via SSH",
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
        # sed and grep read the name as a regex. SNMP_NAME_RE allows ".", which would
        # match any character and delete another user's row ("a.b" also hits "axb").
        pat = user.replace(".", r"\.")
        # print(f"DEBUG step7: purge pattern={pat!r}")
        keep = (keep_hash or "").lower()
        if keep and not re.fullmatch(r"[0-9a-f]+", keep):
            keep = ""

        def _purge(client: paramiko.SSHClient) -> bool:
            # Purges run in parallel. Each line names its box, or the lines cannot be told apart.
            tag = self._tag() or "snmpd"
            # Must stop first — running snmpd flushes USM back to disk on exit
            # and would resurrect the rows we are about to delete.
            print(f"      {tag}: Stopping snmpd before editing persistent USM...", file=sys.stderr)
            if not self._stop_snmpd(client):
                return False
            paths = (SNMP_PERSISTENT_CONF, SNMP_PERSISTENT_CONF_ALT)
            # Keep this user's current rows so they can be put back if the new key
            # never appears. Without them a failed recreate leaves the box with no
            # SNMP user. The rows hold localized keys and are never printed.
            backup = {}
            for path in paths:
                rows = self._sudo(
                    client,
                    f"grep -h -e 'usmUser.*\"{pat}\"' -e 'createUser[[:space:]]\\+{pat}\\b' {path} 2>/dev/null || true",
                    check=False,
                )
                lines = [ln for ln in (rows or "").splitlines() if ln.strip() and not ln.startswith("[sudo]")]
                if lines:
                    backup[path] = lines
            # print(f"DEBUG step7: backup files={list(backup)} rows={sum(len(v) for v in backup.values())}")
            for path in paths:
                self._sudo(
                    client,
                    f"sed -i '/usmUser.*\"{pat}\"/d' {path} || true",
                    check=False,
                )
                self._sudo(
                    client,
                    f"sed -i '/createUser[[:space:]]\\+{pat}\\b/d' {path} || true",
                    check=False,
                )
            leftover = ""
            for _try in range(USM_SED_RETRIES):
                leftover = self._sudo(
                    client,
                    f"grep -h 'usmUser.*\"{pat}\"' {SNMP_PERSISTENT_CONF} "
                    f"{SNMP_PERSISTENT_CONF_ALT} 2>/dev/null || true",
                    check=False,
                )
                if not leftover.strip():
                    break
                print(
                    f"      {tag}: usmUser still present; retrying delete ({_try + 1}/{USM_SED_RETRIES})...",
                    file=sys.stderr,
                )
                for path in paths:
                    self._sudo(
                        client,
                        f"sed -i '/usmUser.*\"{pat}\"/d' {path} || true",
                        check=False,
                    )
            if leftover.strip():
                n_left = len([ln for ln in leftover.splitlines() if ln.strip()])
                print(
                    f"      {tag}: usmUser still present after purge ({n_left} line(s); keys redacted)",
                    file=sys.stderr,
                )
                # print(f"DEBUG step7: leftover usmUser redacted count={n_left}")
                self._start_snmpd(client)
                return False
            print(
                f"      {tag}: Removed persistent usmUser '{user}'. Starting snmpd "
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
                    f"grep -h 'usmUser.*\"{pat}\"' {SNMP_PERSISTENT_CONF} "
                    f"{SNMP_PERSISTENT_CONF_ALT} 2>/dev/null || true",
                    check=False,
                )
                # print(f"DEBUG step7: recreate attempt={attempt} keep={keep[:8]} file={(created or '')[:80]!r}")
                if keep in (created or "").lower():
                    print(
                        f"      {tag}: snmpd recreated usmUser '{user}' with the new key.",
                        file=sys.stderr,
                    )
                    return True
                print(
                    f"      {tag}: Waiting for createUser to persist "
                    f"(attempt {attempt}/{USM_RECREATE_WAITS})...",
                    file=sys.stderr,
                )
            print(
                f"      {tag}: createUser has not written the new key yet; leaving the API line in place.",
                file=sys.stderr,
            )
            self._restore_usm_rows(client, tag, user, backup)
            return False

        ok = self._with_ssh_endpoints(
            host,
            _purge,
            error=f"Could not purge persistent SNMP user '{user}' via SSH",
        )
        if not ok:
            raise RuntimeError(f"Could not purge persistent SNMP user '{user}' via SSH")
        time.sleep(SNMP_RELOAD_DELAY)

    def _restore_usm_rows(self, client: paramiko.SSHClient, tag: str, user: str, backup: dict) -> bool:
        """Put back the rows saved before the purge, so a failed recreate keeps the old user.

        snmpd is stopped first: a running snmpd rewrites the file on exit and would
        drop the rows again. The rows go to the remote shell on stdin, not on the
        command line, because they hold localized keys.
        """
        if not backup:
            print(f"      {tag}: no earlier usmUser rows for '{user}' to restore.", file=sys.stderr)
            return False
        if not self._stop_snmpd(client):
            print(f"      {tag}: could not stop snmpd to restore '{user}'; the box may have no SNMP user.", file=sys.stderr)
            return False
        ok = True
        for path, lines in backup.items():
            rc, _out = self._sudo_script(
                client,
                f"cat >> {shlex.quote(path)}",
                extra_stdin="\n".join(lines),
            ) or (-1, "")
            # print(f"DEBUG step7: restore path={path} rows={len(lines)} rc={rc}")
            ok = ok and rc == 0
        started = self._start_snmpd(client)
        if ok and started:
            print(f"      {tag}: put back the previous usmUser rows for '{user}'; the box keeps its old SNMP key.", file=sys.stderr)
            return True
        print(f"      {tag}: could not restore the previous usmUser rows for '{user}'; check SNMP on this box.", file=sys.stderr)
        return False

    def _configure_and_read_engine_id(
        self, client: paramiko.SSHClient, *, restart_snmpd: bool = True
    ) -> Optional[str]:
        """Live run restarts snmpd first so engineIDType 3 is active, then reads oldEngineID. Preview reads only."""
        tag = self._tag() or "snmpd"
        if restart_snmpd:
            self._log(f"{tag}: restarting snmpd...")
            if not self._restart_snmpd(client):
                self._log(f"{tag}: snmpd restart failed")
                return False
            time.sleep(SNMP_RELOAD_DELAY)
        else:
            self._log(f"{tag}: reading oldEngineID (no snmpd restart)")

        raw = self._sudo(
            client,
            f"grep -hE '^oldEngineID' {SNMP_PERSISTENT_CONF} "
            f"{SNMP_PERSISTENT_CONF_ALT} 2>/dev/null | tail -n 1",
            check=False,
        )
        match = OLD_ENGINE_RE.search(raw or "")
        if not match:
            self._log(
                f"{tag}: no oldEngineID in {SNMP_PERSISTENT_CONF} "
                f"{(raw or '').strip()[:200]}"
            )
            return False
        engine_id = match.group(1).lower()
        # print(f"DEBUG step4: raw oldEngineID line={raw!r}")
        self._log(f"{tag}: oldEngineID {engine_id}", noise=True)

        mac = self._read_iface_mac(client)
        if not mac:
            self._log(f"{tag}: could not read {ETH_IFACE} MAC")
            return False
        self._log(f"{tag}: {ETH_IFACE} MAC {mac}", noise=True)

        expected_suffix = mac.replace(":", "").lower()
        if not self._engine_id_matches_mac(engine_id, expected_suffix):
            self._log(
                f"{tag}: engine ID is not RFC 3411 type-3 yet "
                f"(expected ...03{expected_suffix}, got {engine_id})"
            )
            if not restart_snmpd:
                self._log(
                    f"{tag}: dry-run — using current engine ID; live run pins "
                    f"engineIDType {ENGINE_ID_TYPE} then restarts snmpd"
                )
                return engine_id
            return False
        self._log(
            f"{tag}: engine ID matches {ETH_IFACE} MAC", noise=True
        )
        return engine_id

    def _stop_snmpd(self, client: paramiko.SSHClient) -> bool:
        """Stop snmpd and confirm it is down before editing persistent USM. A running snmpd writes its rows back on exit."""
        for _ in range(SNMPD_STOP_RETRIES):
            self._sudo(client, "systemctl stop snmpd", check=False)
            self._sudo(client, "service snmpd stop", check=False)
            self._sudo(client, "killall -q snmpd || true", check=False)
            time.sleep(SNMPD_STOP_POLL_SEC)
            status = (self._sudo(client, "systemctl is-active snmpd || true") or "").strip()
            if status == "timeout":
                return False
            if status != "active":
                return True
        print("      snmpd still active after stop attempts.", file=sys.stderr)
        return False

    def _start_snmpd(self, client: paramiko.SSHClient) -> bool:
        """Start snmpd and confirm it is active, so createUser runs and writes the new key."""
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
        """MAC of ETH_IFACE. A type-3 engine ID must end with it (RFC 3411)."""
        iface = shlex.quote(ETH_IFACE)
        output = self._run(client, f"ip -o link show {iface}")
        match = MAC_RE.search(output or "")
        if match:
            return match.group(1).lower()
        output = self._run(client, f"ip addr show {iface}")
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
