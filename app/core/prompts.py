"""Shared credential / Controller prompts used by more than one tool.

Lives in ``core/``. Step 0 for SNMP credentials and walk-inventory: turn
credentials.json into a
numbered Controller list. `_require` never exits on bad input (re-prompt).
`_parse_collectives` prefers collectives[]; old single-controller files still
work. Duplicate FQDNs warn but still run (operator may have copied a row).
"""
import os
import sys
from typing import Dict, List, Optional

from config import CREDENTIALS_FILENAME, DEBUG, YES_ANSWERS
from core.utils import REPO_ROOT, is_valid_host, prompt_until_valid

CREDENTIALS_PATH = os.path.join(REPO_ROOT, CREDENTIALS_FILENAME)


def _require(
    creds: dict,
    field: str,
    prompt: str,
    sensitive: bool = False,
    required: bool = True,
    min_len: int = 0,
    pattern: Optional[str] = None,
    pattern_msg: str = "Invalid format. Try again.",
    validator=None,
    validator_msg: str = "Enter IPv4, IPv6, or an FQDN (e.g. host.example.com).",
) -> str:
    """Use credentials.json if valid; otherwise keep asking (never exit)."""
    return prompt_until_valid(
        creds,
        field,
        prompt,
        sensitive=sensitive,
        required=required,
        min_len=min_len,
        pattern=pattern,
        pattern_msg=pattern_msg,
        validator=validator,
        validator_msg=validator_msg,
    )


def _parse_collectives(creds: dict) -> List[Dict[str, str]]:
    """Turn credentials into a numbered list of Controllers.

    Prefer collectives[]. Each needs fqdn (API/SSH/walk primary) and optional
    agip (connect fallback). Array order is the name: 1, 2, …. Duplicate
    FQDNs warn; we still run both. Old files with only agip still prompt for FQDN.
    """
    raw = creds.get("collectives")
    rows: List[Dict[str, str]] = []
    if isinstance(raw, list) and raw:
        for item in raw:
            if not isinstance(item, dict):
                continue
            rows.append({
                "fqdn": str(item.get("fqdn") or item.get("hostname") or "").strip(),
                "agip": str(item.get("agip") or "").strip(),
                "admin_username": str(item.get("admin_username") or "").strip(),
                "admin_password": str(item.get("admin_password") or ""),
            })
    else:
        rows.append({
            "fqdn": str(creds.get("fqdn") or creds.get("hostname") or "").strip(),
            "agip": str(creds.get("agip") or "").strip(),
            "admin_username": str(creds.get("admin_username") or "").strip(),
            "admin_password": str(creds.get("admin_password") or ""),
        })

    seen: Dict[str, int] = {}
    out: List[Dict[str, str]] = []

    def _add(i: int, row: Dict[str, str]) -> None:
        fqdn = _require(
            row,
            "fqdn",
            f"Collective {i} Controller FQDN",
            validator=is_valid_host,
            validator_msg="Enter the Controller admin FQDN (e.g. hit-agr-001.hit.local).",
        )
        agip = _require(
            row,
            "agip",
            f"Collective {i} Controller IP (fallback)",
            required=False,
            validator=is_valid_host,
        )
        user = _require(row, "admin_username", f"Collective {i} Admin Username")
        label = f"{fqdn} - {agip}" if agip else fqdn
        password = _require(
            row, "admin_password", f"Collective {i} ({label}) Admin Password",
            sensitive=True,
        )
        key = fqdn.lower()
        if key in seen:
            print(
                f"WARNING: collectives {seen[key]} and {i} share FQDN {fqdn}. "
                "The same collective will be configured twice.",
                file=sys.stderr,
            )
        else:
            seen[key] = i
        out.append({
            "index": str(i),
            "fqdn": fqdn,
            "agip": agip,
            "admin_username": user,
            "admin_password": password,
        })

    from_file = os.path.isfile(CREDENTIALS_PATH) and any(
        (r.get("fqdn") or r.get("agip") or r.get("admin_username")) for r in rows
    )
    # print(f"DEBUG collectives: from_file={from_file} rows={len(rows)}")
    if DEBUG:
        print(f"      DEBUG collectives: {len(rows)} row(s) from file={from_file}", file=sys.stderr)
    for i, row in enumerate(rows, 1):
        _add(i, row)

    first_ask = True
    while True:
        if first_ask and from_file:
            print(f"\n      Found {CREDENTIALS_FILENAME} with {len(out)} Controller(s):")
            for col in out:
                extra = f" - {col['agip']}" if col.get("agip") else ""
                print(f"        {col['index']}) {col['fqdn']}{extra}")
            more = input(
                "      Add another Controller besides those in the file? [y/N]: "
            ).strip().lower()
            first_ask = False
        else:
            more = input("      Add another Controller? [y/N]: ").strip().lower()
        if more not in YES_ANSWERS:
            break
        _add(
            len(out) + 1,
            {"fqdn": "", "agip": "", "admin_username": "", "admin_password": ""},
        )
    return out
