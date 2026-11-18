"""SNMP appliance PUT helpers (mixin on AppGateClient)."""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, Optional

from config import (
    ENGINE_ID_TYPE,
    SNMP_AUTH_PROTOCOL,
    SNMP_NAME_RE,
    SNMP_PRIV_PROTOCOL,
    STRIP_V1V2_COMMUNITIES,
)
from core.utils import write_replaced_snapshot

from .errors import AppliancePutError

_HASH_RE = re.compile(r"^[0-9a-fA-F]+$")
_ROUSER_RE = re.compile(r"^rouser\s+[A-Za-z0-9_.-]+\s+priv$")

SNMP_PUT_ALLOWED = ("snmpServer.snmpd.conf", "snmpServer.enabled")


class SnmpMixin:
    @staticmethod
    def _snmpd_lines_without_user(appliance: Dict[str, Any], user: str) -> list:
        """Return snmpd.conf lines with this user's entries and engine-ID pins removed."""
        existing_conf = appliance.get("snmpServer", {}).get("snmpd.conf", "")
        lines = existing_conf.splitlines() if existing_conf else []
        drop = (
            rf"^createUser\s+{re.escape(user)}\b",
            rf"^rouser\s+{re.escape(user)}\b",
            rf"^rwuser\s+{re.escape(user)}\b",
            rf"^deleteUser\s+{re.escape(user)}\b",
            *SnmpMixin._engine_pin_patterns(),
            *SnmpMixin._community_patterns(),
        )
        return [line for line in lines if not any(re.match(pat, line) for pat in drop)]

    @staticmethod
    def _snmpd_lines_without_all_users(appliance: Dict[str, Any]) -> list:
        """Replace mode: drop every USM user line. rwuser is write access and must not survive."""
        existing_conf = appliance.get("snmpServer", {}).get("snmpd.conf", "")
        lines = existing_conf.splitlines() if existing_conf else []
        drop = (
            r"^createUser\s+",
            r"^rouser\s+",
            r"^rwuser\s+",
            r"^deleteUser\s+",
            *SnmpMixin._engine_pin_patterns(),
            *SnmpMixin._community_patterns(),
        )
        return [line for line in lines if not any(re.match(pat, line) for pat in drop)]

    @staticmethod
    def _engine_pin_patterns() -> tuple:
        return (
            r"(?i)^exactEngineID\s+",
            r"(?i)^engineIDType\s+",
            r"(?i)^engineID\s+",
        )

    @staticmethod
    def _community_patterns() -> tuple:
        if not STRIP_V1V2_COMMUNITIES:
            return ()
        return (
            r"(?i)^rocommunity6?\b",
            r"(?i)^rwcommunity6?\b",
            r"(?i)^com2sec6?\b",
            r"(?i)^com2sec6?unix\b",
            r"(?i)^authcommunity\b",
            r"(?i)^authuser\b",
        )

    @staticmethod
    def _snmpd_lines_without_engine_pins(appliance: Dict[str, Any]) -> list:
        existing_conf = appliance.get("snmpServer", {}).get("snmpd.conf", "")
        lines = existing_conf.splitlines() if existing_conf else []
        drop = SnmpMixin._engine_pin_patterns() + SnmpMixin._community_patterns()
        return [line for line in lines if not any(re.match(pat, line) for pat in drop)]

    def ensure_engine_id_type3(self, appliance_id: Optional[str] = None) -> None:
        """Pin engineIDType via API before SSH reads oldEngineID."""
        appliance = self._get_appliance(appliance_id)
        lines = self._snmpd_lines_without_engine_pins(appliance)
        lines.append(f"engineIDType {ENGINE_ID_TYPE}")
        self._put_snmpd_conf(appliance, "\n".join(lines), enabled=True)

    @staticmethod
    def _require_snmp_line(user: str, auth_hash: str = "", priv_hash: str = "", rouser_line: str = "") -> None:
        """A newline in these fields becomes another snmpd.conf directive."""
        # print(f"DEBUG snmp token: user_len={len(user or '')} rouser={bool(rouser_line)}")
        blob = "\n".join((user or "", auth_hash or "", priv_hash or "", rouser_line or ""))
        if "\n" in blob or "\r" in blob:
            raise AppliancePutError("Refusing SNMP line with a newline")
        if not re.fullmatch(SNMP_NAME_RE, user or ""):
            raise AppliancePutError("Refusing SNMP user; it must match SNMP_NAME_RE")
        for label, value in (("auth hash", auth_hash), ("priv hash", priv_hash)):
            if value and not _HASH_RE.fullmatch(value):
                raise AppliancePutError(f"Refusing SNMP {label}; expected hex")
        if rouser_line and not _ROUSER_RE.fullmatch(rouser_line.strip()):
            raise AppliancePutError("Refusing rouser line; expected one 'rouser <name> priv'")

    def delete_snmp_user(self, user: str, appliance_id: Optional[str] = None) -> bool:
        """Push deleteUser + engineIDType. createUser is a later PUT.

        Persistent usmUser rows are purged over SSH *after* createUser
        so snmpd re-reads the new keys on restart.
        """
        self._require_snmp_line(user)
        appliance = self._get_appliance(appliance_id)
        lines = self._snmpd_lines_without_user(appliance, user)
        lines.append(f"deleteUser {user}")
        # Do not pin exactEngineID — AppGate/cz-configd truncates it (16 hex)
        # and that breaks RFC 3411 type-3 (11-byte) IDs. Type 3 + oldEngineID is enough.
        lines.append(f"engineIDType {ENGINE_ID_TYPE}")
        self._put_snmpd_conf(appliance, "\n".join(lines), enabled=True)
        return True

    def update_snmp_config(
        self,
        user: str,
        auth_hash: str,
        priv_hash: str,
        rouser_line: str = "",
        enabled: bool = True,
        appliance_id: Optional[str] = None,
        replace: bool = False,
        snapshot_label: str = "",
    ) -> bool:
        """Step 6: PUT createUser + optional rouser + engineIDType 3 (live run only).

        Add: keep other USM users, replace this username.
        Replace: drop all createUser/rouser lines, write only this user.
        """
        # Hashes are localized; the username is still a snmpd.conf token.
        # print(f"DEBUG snmp put: user_len={len(user)} replace={replace} auth={SNMP_AUTH_PROTOCOL}")
        self._require_snmp_line(user, auth_hash, priv_hash, rouser_line)
        create_user_line = (
            f"createUser {user} {SNMP_AUTH_PROTOCOL} -l 0x{auth_hash} "
            f"{SNMP_PRIV_PROTOCOL} -l 0x{priv_hash}"
        )

        appliance = self._get_appliance(appliance_id)
        if replace:
            write_replaced_snapshot(
                "snmp",
                snapshot_label or str(appliance.get("name") or appliance_id or user),
                appliance,
            )
            lines = self._snmpd_lines_without_all_users(appliance)
        else:
            lines = self._snmpd_lines_without_user(appliance, user)
        if rouser_line:
            lines.append(rouser_line)
        lines.append(create_user_line)
        lines.append(f"engineIDType {ENGINE_ID_TYPE}")
        self._put_snmpd_conf(appliance, "\n".join(lines), enabled=enabled)
        return True

    def _put_snmpd_conf(self, appliance: Dict[str, Any], new_conf: str, enabled: bool) -> None:
        """GET body + snmpd.conf only. Keep site/NICs/tcpPort exactly as retrieved."""
        original = copy.deepcopy(appliance)
        existing = appliance.get("snmpServer")
        if not isinstance(existing, dict):
            existing = {}
        snmp = dict(existing)
        snmp["enabled"] = enabled
        snmp["snmpd.conf"] = new_conf
        appliance["snmpServer"] = snmp
        body = self._sanitize_appliance_for_put(appliance)
        self._assert_put_safe(
            original,
            body,
            allowed=SNMP_PUT_ALLOWED,
            what="SNMP config",
        )
        self._put_appliance_body(body, what="SNMP config")

