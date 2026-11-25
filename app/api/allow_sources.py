"""allowSources PUT helpers (mixin on AppGateClient)."""
from __future__ import annotations

import copy
from typing import Any, Dict, List

from config import ALLOW_SOURCES_PUT_ALLOWED, ALLOW_SOURCES_SLOT_PARENT
from core.utils import debug_log, normalize_allow_source, write_replaced_snapshot

from .errors import AppliancePutError

ALLOW_SOURCES_PARENTS = tuple(sorted(set(ALLOW_SOURCES_SLOT_PARENT.values())))


class AllowSourcesMixin:
    """Menu 6 reads and PUTs of allowSources. Mixed into AppGateClient so it reuses that client's token, CA pin and If-Match handling."""
    @staticmethod
    def _allow_source_key(entry: Any) -> tuple:
        """Same rule as the preview merge. A second copy here used to accept a row the other path dropped."""
        try:
            row = normalize_allow_source(entry)
        except ValueError:
            # print("DEBUG allow: rejected row")
            return ("", -1, "")
        return (row["address"], int(row["netmask"]), row.get("nic") or "")

    @staticmethod
    def _allow_source_body(entry: Any) -> Dict[str, Any]:
        """GUI blank NIC = Any: omit nic. Empty string 422s (must not be empty)."""
        key = AllowSourcesMixin._allow_source_key(entry)
        if not key[0] or key[1] < 1:
            raise AppliancePutError("allowSources address or netmask is invalid")
        out: Dict[str, Any] = {"address": key[0], "netmask": key[1]}
        if key[2]:
            out["nic"] = key[2]
        return out

    def peek_allow_sources(self, appliance_id: str) -> List[Dict[str, Any]]:
        """Preview must see every parent. A hostname-only peek would hide a key or nic change."""
        appliance = self._get_appliance(appliance_id)
        return self._collect_allow_sources(appliance)

    @staticmethod
    def _collect_allow_sources(appliance: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Exclude-self has to see every slot, or a /32 on one parent is left in place."""
        found: List[Dict[str, Any]] = []
        seen = set()
        for parent in ALLOW_SOURCES_PARENTS:
            block = appliance.get(parent)
            if not isinstance(block, dict):
                continue
            rows = block.get("allowSources")
            if not isinstance(rows, list):
                continue
            for item in rows:
                key = AllowSourcesMixin._allow_source_key(item)
                if key[0] and key not in seen:
                    seen.add(key)
                    found.append(
                        {
                            "address": key[0],
                            "netmask": key[1],
                            "nic": key[2],
                        }
                    )
        return found

    def update_allow_sources(
        self,
        appliance_id: str,
        desired_by_parent: Dict[str, List[Dict[str, Any]]],
        *,
        overwrite: bool,
        snapshot_label: str = "",
    ) -> Dict[str, int]:
        """PUT each slot onto its parent.allowSources only if that array already exists."""
        appliance = self._get_appliance(appliance_id)
        original = copy.deepcopy(appliance)
        self.note_rollback(appliance_id, original, ALLOW_SOURCES_PUT_ALLOWED, "allowSources")
        nonempty = {p: rows for p, rows in desired_by_parent.items() if rows}
        if overwrite and not nonempty:
            raise AppliancePutError(
                "Refusing replace with empty allowSources (admin lockout)"
            )
        if overwrite:
            write_replaced_snapshot(
                "allow-sources",
                snapshot_label or str(appliance.get("name") or appliance_id),
                original,
            )
        debug_log(f"allowSources: overwrite={overwrite} parents={list(nonempty)}")
        wrote = False
        counts: Dict[str, int] = {}
        for parent, desired in nonempty.items():
            block = appliance.get(parent)
            if not isinstance(block, dict) or "allowSources" not in block:
                continue
            rows = block.get("allowSources")
            if not isinstance(rows, list):
                rows = []
            built = [self._allow_source_body(x) for x in desired]
            if overwrite and not built:
                raise AppliancePutError(
                    "Refusing replace that would empty allowSources (admin lockout)"
                )
            if overwrite:
                new_rows = built
            else:
                seen = {self._allow_source_key(x) for x in rows}
                new_rows = [x for x in rows if isinstance(x, dict)]
                for body in built:
                    key = self._allow_source_key(body)
                    if key[0] and key not in seen:
                        seen.add(key)
                        new_rows.append(body)
            block["allowSources"] = new_rows
            appliance[parent] = block
            counts[parent] = len(new_rows)
            wrote = True
        if not wrote:
            raise AppliancePutError(
                "No matching allowSources arrays on this appliance GET"
            )
        body = self._sanitize_appliance_for_put(appliance)
        self._assert_put_safe(
            original,
            body,
            allowed=ALLOW_SOURCES_PUT_ALLOWED,
            what="allowSources",
        )
        self._put_appliance_body(body, what="allowSources")
        return counts
