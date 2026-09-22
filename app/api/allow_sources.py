"""allowSources PUT helpers (mixin on AppGateClient)."""
from __future__ import annotations

import copy
from typing import Any, Dict, List

from config import ALLOW_SOURCES_PUT_ALLOWED, ALLOW_SOURCES_SLOT_PARENT
from core.utils import debug_log, write_replaced_snapshot

from .errors import AppliancePutError

ALLOW_SOURCES_PARENTS = tuple(sorted(set(ALLOW_SOURCES_SLOT_PARENT.values())))


class AllowSourcesMixin:
    @staticmethod
    def _allow_source_key(entry: Any) -> tuple:
        if not isinstance(entry, dict):
            return ("", -1, "")
        try:
            mask = int(entry.get("netmask"))
        except (TypeError, ValueError):
            mask = -1
        return (
            str(entry.get("address") or "").strip(),
            mask,
            str(entry.get("nic") or "").strip(),
        )

    def peek_allow_sources(self, appliance_id: str) -> List[Dict[str, Any]]:
        appliance = self._get_appliance(appliance_id)
        return self._collect_allow_sources(appliance)

    @staticmethod
    def _collect_allow_sources(appliance: Dict[str, Any]) -> List[Dict[str, Any]]:
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
            if overwrite:
                new_rows = [dict(x) for x in desired]
            else:
                seen = {self._allow_source_key(x) for x in rows}
                new_rows = [dict(x) for x in rows if isinstance(x, dict)]
                for item in desired:
                    key = self._allow_source_key(item)
                    if key[0] and key not in seen:
                        seen.add(key)
                        new_rows.append(
                            {
                                "address": key[0],
                                "netmask": key[1],
                                "nic": key[2],
                            }
                        )
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
