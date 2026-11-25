"""NTP appliance PUT helpers (mixin on AppGateClient)."""
from __future__ import annotations

import copy
import sys
from typing import Any, Dict, List, Optional

from config import (
    DEBUG,
    LAB_MODE,
    NTP_KEY_HEX_PREFIX,
    NTP_KEY_TYPE_MAP,
    NTP_WEAK_KEY_TYPES,
)
from core.utils import write_replaced_snapshot

NTP_PUT_ALLOWED = ("ntp", "ntpServers", "ntpServer")


class NtpMixin:
    @staticmethod
    def _ntp_key_for_api(entry: Dict[str, Any]) -> Dict[str, Any]:
        """6.7 GET shape: ntp.servers[].hostname, optional keyType/keyNo/key (SHA256 → HEX:)."""
        host = str(entry.get("hostname") or "").strip()
        out: Dict[str, Any] = {"hostname": host}
        key_type = str(entry.get("keyType") or "").strip()
        key_no = entry.get("keyNo")
        key = str(entry.get("key") or "").strip()
        if key_type:
            compact = key_type.replace("-", "").upper()
            mapped = NTP_KEY_TYPE_MAP.get(compact, key_type)
            if str(mapped).upper() in NTP_WEAK_KEY_TYPES:
                msg = (
                    f"NTP keyType {mapped} is not DISA SNMP STIG / CNSA 1.0 (use SHA256). "
                    f"hostname={host}"
                )
                if not LAB_MODE:
                    raise ValueError(msg)
                print(f"      WARNING: {msg}", file=sys.stderr)
            out["keyType"] = mapped
        if key_no not in ("", None):
            try:
                out["keyNo"] = int(key_no)
            except (TypeError, ValueError):
                out["keyNo"] = key_no
        if key:
            if not key_type and not LAB_MODE:
                raise ValueError(
                    f"NTP key set but keyType empty for {host}; DISA requires SHA256"
                )
            compact = (out.get("keyType") or key_type).replace("-", "").upper()
            prefix = NTP_KEY_HEX_PREFIX
            if compact == "SHA256" and not key.upper().startswith(prefix.upper()):
                key = prefix + key
            out["key"] = key
        return out

    @staticmethod
    def _ntp_hostname(entry: Any) -> str:
        if isinstance(entry, str):
            return entry.strip()
        if isinstance(entry, dict):
            return str(
                entry.get("hostname") or entry.get("src") or entry.get("server") or ""
            ).strip()
        return ""

    @staticmethod
    def _ntp_list_from_appliance(appliance: Dict[str, Any]) -> List[Any]:
        """6.7: appliance.ntp.servers is the list (ntp is an object)."""
        raw = appliance.get("ntp")
        if isinstance(raw, dict) and isinstance(raw.get("servers"), list):
            return raw["servers"]
        if isinstance(raw, list):
            return raw
        for key in ("ntpServers", "ntpServer"):
            legacy = appliance.get(key)
            if isinstance(legacy, list):
                return legacy
        return []

    def peek_ntp(self, appliance_id: str) -> List[str]:
        """Hostnames currently on the appliance (no keys)."""
        appliance = self._get_appliance(appliance_id)
        raw = appliance.get("ntp")
        servers = self._ntp_list_from_appliance(appliance)
        if DEBUG:
            print(
                f"      DEBUG ntp GET: type={type(raw).__name__} n={len(servers)}",
                file=sys.stderr,
            )
        return [h for h in (self._ntp_hostname(x) for x in servers) if h]

    def peek_ntp_state(self, appliance_id: str) -> List[Dict[str, Any]]:
        """Hostname plus key slot, not the key. Dry run must see a key change."""
        appliance = self._get_appliance(appliance_id)
        out = []
        for row in self._ntp_list_from_appliance(appliance):
            if not isinstance(row, dict):
                continue
            host = self._ntp_hostname(row)
            if not host:
                continue
            key_no = row.get("keyNo")
            out.append(
                {
                    "hostname": host.lower(),
                    "keyType": str(row.get("keyType") or ""),
                    "keyNo": "" if key_no in ("", None) else str(key_no),
                    "has_key": bool(row.get("key")),
                }
            )
        return out

    def update_ntp_servers(
        self,
        appliance_id: str,
        servers: List[Dict[str, Any]],
        *,
        overwrite: bool,
        snapshot_label: str = "",
    ) -> List[Dict[str, Any]]:
        """PUT appliance.ntp so cz-configd applies (survives reboot)."""
        appliance = self._get_appliance(appliance_id)
        original = copy.deepcopy(appliance)
        self.note_rollback(appliance_id, original, NTP_PUT_ALLOWED, "NTP servers")
        existing_list = self._ntp_list_from_appliance(appliance)
        desired = [self._ntp_key_for_api(s) for s in servers if self._ntp_hostname(s)]
        if overwrite:
            write_replaced_snapshot(
                "ntp",
                snapshot_label or str(original.get("name") or appliance_id),
                original,
            )
            merged = desired
        else:
            by_host: Dict[str, Any] = {}
            for item in existing_list:
                host = self._ntp_hostname(item)
                if host:
                    by_host[host.lower()] = item if isinstance(item, dict) else {"hostname": host}
            for item in desired:
                host = item["hostname"].lower()
                if host in by_host and isinstance(by_host[host], dict):
                    # A hostname-only row means the old key is no longer wanted.
                    if not any(k in item for k in ("key", "keyType", "keyNo")):
                        for k in ("key", "keyType", "keyNo"):
                            by_host[host].pop(k, None)
                    by_host[host].update(item)
                else:
                    by_host[host] = item
            merged = list(by_host.values())
        for row in merged:
            if not isinstance(row, dict):
                continue
            raw = str(row.get("keyType") or "").strip()
            compact = raw.replace("-", "").upper()
            if compact in NTP_WEAK_KEY_TYPES:
                raise ValueError(f"NTP keyType {raw} is not allowed")
        appliance.pop("ntpServers", None)
        appliance.pop("ntpServer", None)
        ntp_obj = appliance.get("ntp")
        if not isinstance(ntp_obj, dict):
            ntp_obj = {}
        ntp_obj["servers"] = merged
        appliance["ntp"] = ntp_obj
        if DEBUG:
            safe = [
                {
                    "hostname": self._ntp_hostname(x),
                    "keyType": x.get("keyType") if isinstance(x, dict) else "",
                    "keyNo": x.get("keyNo") if isinstance(x, dict) else "",
                    "has_key": bool(isinstance(x, dict) and x.get("key")),
                }
                for x in merged
            ]
            print(
                f"      DEBUG ntp PUT ntp.servers={safe!r}",
                file=sys.stderr,
            )
        body = self._sanitize_appliance_for_put(appliance)
        self._assert_put_safe(
            original,
            body,
            allowed=NTP_PUT_ALLOWED,
            what="NTP servers",
        )
        self._put_appliance_body(body, what="NTP servers")
        return merged

    def strip_ntp_keys(self, appliance_id: str) -> None:
        """Chrony already has the key. A later GET must not return it."""
        appliance = self._get_appliance(appliance_id)
        original = copy.deepcopy(appliance)
        servers = self._ntp_list_from_appliance(appliance)
        removed = False
        for row in servers:
            if isinstance(row, dict) and row.pop("key", None) not in (None, ""):
                removed = True
        if not removed:
            return
        ntp_obj = appliance.get("ntp")
        if not isinstance(ntp_obj, dict):
            ntp_obj = {}
        ntp_obj["servers"] = servers
        appliance["ntp"] = ntp_obj
        body = self._sanitize_appliance_for_put(appliance)
        self._assert_put_safe(original, body, allowed=NTP_PUT_ALLOWED, what="NTP keys")
        self._put_appliance_body(body, what="NTP keys")

