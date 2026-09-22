"""SNMP appliance PUT helpers (mixin on AppGateClient)."""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, Optional

from config import ENGINE_ID_TYPE, SNMP_AUTH_PROTOCOL, SNMP_PRIV_PROTOCOL, STRIP_V1V2_COMMUNITIES
from core.utils import write_replaced_snapshot

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
            rf"^deleteUser\s+{re.escape(user)}\b",
            *SnmpMixin._engine_pin_patterns(),
            *SnmpMixin._community_patterns(),
        )
        return [line for line in lines if not any(re.match(pat, line) for pat in drop)]

    @staticmethod
    def _snmpd_lines_without_all_users(appliance: Dict[str, Any]) -> list:
        """Replace mode: drop every createUser/rouser/deleteUser, keep the rest."""
        existing_conf = appliance.get("snmpServer", {}).get("snmpd.conf", "")
        lines = existing_conf.splitlines() if existing_conf else []
        drop = (
            r"^createUser\s+",
            r"^rouser\s+",
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

    def _paged_get(self, path: str) -> list:
        """GET a 6.7 collection. range is a query param; total is in JSON 'range' (0-49/123)."""
        items: list = []
        start = 0
        page = APPLIANCE_LIST_PAGE
        while True:
            end = start + page - 1
            response = requests.get(
                f"{self.base_url}{path}",
                headers=self.headers,
                params={"range": f"{start}-{end}"},
                verify=_tls_verify,
                timeout=API_TIMEOUT,
            )
            if response.status_code not in (200, 206):
                response.raise_for_status()
            try:
                payload = response.json()
            except ValueError:
                break
            body_range = ""
            if isinstance(payload, list):
                chunk = payload
            elif isinstance(payload, dict):
                chunk = payload.get("data")
                body_range = str(payload.get("range") or "")
            else:
                chunk = []
            if not isinstance(chunk, list):
                chunk = []
            # print(f"DEBUG paged_get: path={path} start={start} n={len(chunk)}")
            if not chunk:
                break
            if items and chunk and items[0] == chunk[0]:
                break
            items.extend(chunk)
            if len(items) >= APPLIANCE_LIST_MAX:
                return items[:APPLIANCE_LIST_MAX]
            total = None
            if "/" in body_range:
                try:
                    total = int(body_range.rsplit("/", 1)[-1])
                except ValueError:
                    total = None
            if total is not None:
                if len(items) >= total:
                    break
                start = len(items)
                continue
            if len(chunk) < page:
                break
            start += len(chunk)
            if start > APPLIANCE_LIST_MAX:
                break
        return items

    def get_appliances(self) -> list:
        """Every appliance this token can view. Paginate if JSON range says so."""
        response = requests.get(
            f"{self.base_url}/appliances",
            headers=self.headers,
            verify=_tls_verify,
            timeout=API_TIMEOUT,
        )
        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError:
            raise RuntimeError("GET /appliances returned non-JSON")
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            return []
        chunk = payload.get("data")
        if not isinstance(chunk, list):
            chunk = []
        body_range = str(payload.get("range") or "")
        if "/" in body_range:
            try:
                total = int(body_range.rsplit("/", 1)[-1])
            except ValueError:
                total = 0
            if total > len(chunk):
                return self._paged_get("/appliances")
        return chunk

    def get_appliance_status(self) -> Dict[str, Dict[str, Any]]:
        """6.3+ replacement for GET /stats/appliances → GET /appliances/status."""
        try:
            # print(f"DEBUG step2: GET {APPLIANCE_STATUS_PATH} host={self.agip}")
            if DEBUG:
                print(f"      DEBUG step2: GET {APPLIANCE_STATUS_PATH} on {self.agip}", file=sys.stderr)
            items = self._paged_get(APPLIANCE_STATUS_PATH)
        except (requests.RequestException, ValueError, OSError):
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            # API may key by id, applianceId, or nest under appliance.
            aid = (
                item.get("id")
                or item.get("applianceId")
                or item.get("appliance_id")
            )
            if not aid and isinstance(item.get("appliance"), dict):
                aid = item["appliance"].get("id")
            if aid:
                out[str(aid)] = item
        return out

    def list_targets(
        self,
        collective: int = 1,
        fallback_ip: str = "",
        collective_fqdn: str = "",
    ) -> List[Target]:
        """Activated appliances this token can view, tagged with *collective* index."""
        raw = self.get_appliances()
        status_by_id = self.get_appliance_status()
        print(
            f"      [{collective}] {self.fqdn or self.agip}: {len(raw)} appliance(s)",
            file=sys.stderr,
        )
        targets: List[Target] = []
        for appliance in raw:
            name = str(appliance.get("name") or appliance.get("id") or "?")
            aid = appliance.get("id") or ""
            if not aid:
                continue
            if appliance.get("activated") is False:
                print(
                    f"      skip {name}: not activated",
                    file=sys.stderr,
                )
                continue
            health = appliance_health(appliance, status_by_id.get(aid, {}))
            if not is_selectable(health, APPLIANCE_SKIP_STATUS):
                print(
                    f"      skip {name}: not healthy (status={health!r})",
                    file=sys.stderr,
                )
                continue
            ssh_fqdn, ssh_ips = appliance_hosts(appliance)
            ssh_ip = ssh_ips[0] if ssh_ips else ""
            if not ssh_fqdn and not ssh_ip:
                print(f"      skip {name}: no FQDN or IP for SSH", file=sys.stderr)
                continue
            targets.append(
                Target(
                    appliance_id=aid,
                    hostname=name,
                    ssh_fqdn=ssh_fqdn,
                    ssh_ip=ssh_ip,
                    ssh_ips=ssh_ips,
                    collective=collective,
                    collective_fqdn=collective_fqdn or self.fqdn,
                    collective_ip=fallback_ip or self.fallback_ip,
                    functions=appliance_functions(appliance),
                    health=health,
                    self_ips=_merge_self_ips(ssh_ips, status_by_id.get(aid, {})),
                )
            )
        return targets

    def delete_snmp_user(self, user: str, appliance_id: Optional[str] = None) -> bool:
        """Push deleteUser + engineIDType. createUser is a later PUT.

        Persistent usmUser rows are purged over SSH *after* createUser
        so snmpd re-reads the new keys on restart.
        """
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
    ) -> bool:
        """Step 6: PUT createUser + optional rouser + engineIDType 3 (live run only).

        Add: keep other USM users, replace this username.
        Replace: drop all createUser/rouser lines, write only this user.
        """
        create_user_line = (
            f"createUser {user} {SNMP_AUTH_PROTOCOL} -l 0x{auth_hash} "
            f"{SNMP_PRIV_PROTOCOL} -l 0x{priv_hash}"
        )

        appliance = self._get_appliance(appliance_id)
        if replace:
            write_replaced_snapshot(
                "snmp",
                str(appliance.get("name") or appliance_id or user),
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

