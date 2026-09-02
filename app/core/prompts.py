"""Shared credential / Controller prompts used by more than one tool.

Lives in ``core/``. Step 0 for SNMP credentials and walk-inventory: turn
credentials.json into a
numbered Controller list. `_require` never exits on bad input (re-prompt).
`_parse_collectives` prefers collectives[]; old single-controller files still
work. Duplicate FQDNs warn but still run (operator may have copied a row).
"""
import os
import re
import sys
from typing import Any, Dict, List, Optional

from config import (
    CREDENTIALS_FILENAME,
    DEBUG,
    LAB_MODE,
    SNMP_MIN_PASSPHRASE_LEN,
    STIG_PASSWORD_MIN_LEN,
    YES_ANSWERS,
)
from getpass import getpass

from core.utils import REPO_ROOT, is_valid_host, prompt_until_valid

CREDENTIALS_PATH = os.path.join(REPO_ROOT, CREDENTIALS_FILENAME)

# Optional per-collective strings. Omitted/empty inherits top-level credentials.json.
COLLECTIVE_OPTIONAL_STR = (
    "ssh_username",
    "ssh_password",
    "ssh_password_new",
    "api_username",
    "api_password",
    "snmp_user",
    "snmp_auth",
    "snmp_priv",
    "rouser",
)


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


def _optional_str(item: dict, key: str) -> str:
    val = item.get(key)
    if val is None or isinstance(val, (list, dict)):
        return ""
    return str(val).strip()


def _parse_mibs(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(x).strip() for x in value if str(x).strip()]


def resolve_field(col: dict, creds: dict, key: str) -> str:
    """Collective override if set, else top-level credentials.json."""
    local = col.get(key)
    if isinstance(local, str) and local.strip():
        return local.strip()
    top = creds.get(key)
    if isinstance(top, str) and top.strip():
        return top.strip()
    return ""


def stig_password_errors(password: str) -> List[str]:
    """DISA/Ubuntu STIG-style rules (minlen 15, upper, lower, digit, special)."""
    pw = password or ""
    errors: List[str] = []
    if len(pw) < STIG_PASSWORD_MIN_LEN:
        errors.append(f"at least {STIG_PASSWORD_MIN_LEN} characters")
    if not re.search(r"[A-Z]", pw):
        errors.append("an uppercase letter")
    if not re.search(r"[a-z]", pw):
        errors.append("a lowercase letter")
    if not re.search(r"[0-9]", pw):
        errors.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", pw):
        errors.append("a special character")
    return errors


def resolve_mibs(col: dict, creds: dict) -> List[str]:
    local = col.get("mibs")
    if isinstance(local, list) and local:
        return _parse_mibs(local)
    return _parse_mibs(creds.get("mibs"))


def _parse_ntp_servers(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        return []
    out: List[Dict[str, str]] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(
                {"hostname": item.strip(), "keyType": "", "keyNo": "", "key": ""}
            )
            continue
        if not isinstance(item, dict):
            continue
        host = str(item.get("hostname") or "").strip()
        if not host:
            continue
        kn = item.get("keyNo")
        out.append(
            {
                "hostname": host,
                "keyType": str(item.get("keyType") or "").strip(),
                "keyNo": "" if kn is None else str(kn).strip(),
                "key": str(item.get("key") or "").strip(),
            }
        )
    return out


def resolve_ntp_servers(col: dict, creds: dict) -> List[Dict[str, str]]:
    local = col.get("ntp_servers")
    if isinstance(local, list) and local:
        return _parse_ntp_servers(local)
    return _parse_ntp_servers(creds.get("ntp_servers"))


def ensure_ntp_servers(col: dict, creds: dict) -> List[Dict[str, str]]:
    """NTP tool: inherit, or prompt until at least one hostname exists."""
    servers = resolve_ntp_servers(col, creds)
    if servers:
        col["ntp_servers"] = servers
        return servers
    print(
        f"      Collective {col.get('index', '?')} NTP servers "
        "(hostname required; keyType/keyNo/key optional):"
    )
    servers = []
    while True:
        host = input("      hostname: ").strip()
        if not host:
            if servers:
                break
            print("      At least one NTP hostname is required.", file=sys.stderr)
            continue
        key_type = input("      keyType (e.g. SHA256, empty if none): ").strip()
        key_no = input("      keyNo (empty if none): ").strip()
        key = ""
        if key_type:
            key = getpass("      key: ").strip()
            confirm = getpass("      key (confirm): ").strip()
            if key != confirm:
                print("      Keys did not match. Try again.", file=sys.stderr)
                continue
        servers.append(
            {
                "hostname": host,
                "keyType": key_type,
                "keyNo": key_no,
                "key": key,
            }
        )
        more = input("      Add another NTP server? [y/N]: ").strip().lower()
        if more not in YES_ANSWERS:
            break
    col["ntp_servers"] = servers
    return servers


def _row_from_item(item: dict) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "fqdn": str(item.get("fqdn") or item.get("hostname") or "").strip(),
        "agip": str(item.get("agip") or "").strip(),
        "mibs": _parse_mibs(item.get("mibs")),
        "ntp_servers": _parse_ntp_servers(item.get("ntp_servers")),
    }
    for key in COLLECTIVE_OPTIONAL_STR:
        row[key] = _optional_str(item, key)
    if not row.get("api_username"):
        row["api_username"] = _optional_str(item, "admin_username")
    if not row.get("api_password"):
        row["api_password"] = str(item.get("admin_password") or "")
    return row


def _parse_collectives(creds: dict) -> List[Dict[str, Any]]:
    """Turn credentials into a numbered list of Controllers.

    Prefer collectives[]. Required: fqdn (prompted). agip optional but preferred
    for IP fallback. Extra keys (ssh_*, snmp_*, mibs, ssh_password_new) are
    kept if present; omitted keys inherit top-level via resolve_field.
    """
    raw = creds.get("collectives")
    rows: List[Dict[str, Any]] = []
    if isinstance(raw, list) and raw:
        for item in raw:
            if not isinstance(item, dict):
                continue
            rows.append(_row_from_item(item))
    else:
        rows.append(_row_from_item(creds))

    seen: Dict[str, int] = {}
    out: List[Dict[str, Any]] = []

    def _add(i: int, row: Dict[str, Any]) -> None:
        fqdn = _require(
            row,
            "fqdn",
            f"Collective {i} Controller FQDN",
            validator=is_valid_host,
            validator_msg="Enter the Controller admin FQDN (e.g. ctrl-a.example.com).",
        )
        agip = _require(
            row,
            "agip",
            f"Collective {i} Controller IP (fallback)",
            required=False,
            validator=is_valid_host,
        )
        if not row.get("api_username"):
            row["api_username"] = (
                _optional_str(creds, "api_username") or _optional_str(creds, "admin_username")
            )
        if not row.get("api_password"):
            row["api_password"] = (
                _optional_str(creds, "api_password") or str(creds.get("admin_password") or "")
            )
        user = _require(row, "api_username", f"Collective {i} API Username")
        label = f"{fqdn} - {agip}" if agip else fqdn
        password = _require(
            row, "api_password", f"Collective {i} ({label}) API Password",
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
        entry: Dict[str, Any] = {
            "index": str(i),
            "fqdn": fqdn,
            "agip": agip,
            "api_username": user,
            "api_password": password,
            "mibs": list(row.get("mibs") or []),
            "ntp_servers": list(row.get("ntp_servers") or []),
        }
        for key in COLLECTIVE_OPTIONAL_STR:
            entry[key] = _optional_str(row, key)
        out.append(entry)

    from_file = os.path.isfile(CREDENTIALS_PATH) and any(
        (r.get("fqdn") or r.get("agip") or r.get("api_username")) for r in rows
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
            out = _exclude_collectives(out)
            if not out:
                raise ValueError("Nothing left after excluding collectives")
            more = input(
                "      Add another Controller besides those in the file? [y/N]: "
            ).strip().lower()
            first_ask = False
        else:
            more = input("      Add another Controller? [y/N]: ").strip().lower()
        if more not in YES_ANSWERS:
            break
        _add(len(out) + 1, _row_from_item({}))
    return out


def _exclude_collectives(cols: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Same idea as appliance exclude: Enter keeps all. Tokens: index or FQDN/IP."""
    if len(cols) < 2:
        return cols
    raw = input(
        "      Exclude collectives (comma-separated numbers or FQDN; Enter for all): "
    ).strip()
    if not raw:
        return cols
    # print(f"DEBUG collectives: exclude raw={raw!r}")
    tokens = {part.strip().lower() for part in raw.split(",") if part.strip()}
    kept: List[Dict[str, Any]] = []
    for col in cols:
        keys = {
            str(col.get("index") or "").lower(),
            (col.get("fqdn") or "").lower(),
            (col.get("agip") or "").lower(),
        }
        if tokens & keys:
            print(f"      Excluding collective {col.get('index')} {col.get('fqdn')}", flush=True)
            continue
        kept.append(col)
    return kept


def collective_for_target(target: Any, collectives: List[Dict[str, Any]]) -> Dict[str, Any]:
    idx = int(getattr(target, "collective", 1) or 1)
    for col in collectives:
        try:
            if int(col.get("index") or 0) == idx:
                return col
        except (TypeError, ValueError):
            continue
    return collectives[0]


def _prompt_cred_scope(count: int) -> str:
    """1=global 2=per-collective 3=global then override selected. One box = global."""
    if count < 2:
        return "global"
    print("\nCredential entry:")
    print("  1) Global (same for every collective)")
    print("  2) Per collective")
    print("  3) Global, then override selected collectives")
    choice = ""
    while choice not in ("1", "2", "3"):
        choice = input("Select 1, 2, or 3: ").strip()
    return {"1": "global", "2": "per", "3": "override"}[choice]


def _require_new_password(bucket: dict, label: str) -> str:
    while True:
        value = _require(
            bucket, "ssh_password_new", f"{label} New SSH Password", sensitive=True
        )
        if LAB_MODE:
            return value
        errs = stig_password_errors(value)
        if not errs:
            return value
        print(
            "      STIG password check failed (needs "
            + ", ".join(errs)
            + "). LAB_MODE=False.",
            file=sys.stderr,
        )
        bucket["ssh_password_new"] = ""


def _fill_secret_fields(
    bucket: dict,
    label: str,
    *,
    need_snmp: bool,
    need_new_password: bool,
) -> None:
    bucket["ssh_username"] = _require(bucket, "ssh_username", f"{label} SSH Username")
    bucket["ssh_password"] = _require(
        bucket, "ssh_password", f"{label} SSH Password", sensitive=True
    )
    if need_snmp:
        bucket["snmp_user"] = _require(bucket, "snmp_user", f"{label} SNMP User")
        bucket["snmp_auth"] = _require(
            bucket,
            "snmp_auth",
            f"{label} SNMP Auth",
            sensitive=True,
            min_len=SNMP_MIN_PASSPHRASE_LEN,
        )
        priv = (bucket.get("snmp_priv") or "").strip()
        if not priv or len(priv) < SNMP_MIN_PASSPHRASE_LEN:
            bucket["snmp_priv"] = bucket["snmp_auth"]
            print(
                f"      {label} SNMP Priv missing or short — using SNMP Auth.",
                file=sys.stderr,
            )
        else:
            bucket["snmp_priv"] = _require(
                bucket,
                "snmp_priv",
                f"{label} SNMP Priv",
                sensitive=True,
                min_len=SNMP_MIN_PASSPHRASE_LEN,
            )
    if need_new_password:
        bucket["ssh_password_new"] = _require_new_password(bucket, label)


def _copy_secret_fields(
    src: dict, dest: dict, *, need_snmp: bool, need_new_password: bool
) -> None:
    dest["ssh_username"] = src.get("ssh_username") or ""
    dest["ssh_password"] = src.get("ssh_password") or ""
    if need_snmp:
        dest["snmp_user"] = src.get("snmp_user") or ""
        dest["snmp_auth"] = src.get("snmp_auth") or ""
        dest["snmp_priv"] = src.get("snmp_priv") or ""
    if need_new_password:
        dest["ssh_password_new"] = src.get("ssh_password_new") or ""


def _clear_secret_fields(col: dict, *, need_snmp: bool, need_new_password: bool) -> None:
    for key in ("ssh_username", "ssh_password"):
        col[key] = ""
    if need_snmp:
        for key in ("snmp_user", "snmp_auth", "snmp_priv"):
            col[key] = ""
    if need_new_password:
        col["ssh_password_new"] = ""


def prepare_collectives(
    creds: dict,
    collectives: List[Dict[str, Any]],
    *,
    need_snmp: bool = False,
    need_new_password: bool = False,
) -> List[Dict[str, Any]]:
    """SSH (always), SNMP, and new-password: global, per-collective, or override.

    File values win first. Then a scope prompt (2+ collectives). Global entry
    is stored on creds and copied; override re-prompts only the selected rows.
    """
    had_local_new = any((c.get("ssh_password_new") or "").strip() for c in collectives)
    global_new = (creds.get("ssh_password_new") or "").strip()
    # print(f"DEBUG prepare: n={len(collectives)} snmp={need_snmp} newpw={need_new_password} lab={LAB_MODE}")
    if need_new_password and global_new and not had_local_new:
        print(
            "WARNING: ssh_password_new is only set globally; "
            "every collective will use the same new cz password.",
            file=sys.stderr,
        )

    for col in collectives:
        for key in COLLECTIVE_OPTIONAL_STR:
            if not (col.get(key) or "").strip():
                inherited = resolve_field(col, creds, key)
                if (
                    key in ("snmp_auth", "snmp_priv")
                    and inherited
                    and len(inherited) < SNMP_MIN_PASSPHRASE_LEN
                ):
                    inherited = ""
                col[key] = inherited
        if not col.get("mibs"):
            col["mibs"] = resolve_mibs(col, creds)
        if not col.get("ntp_servers"):
            col["ntp_servers"] = resolve_ntp_servers(col, creds)

    flags = {"need_snmp": need_snmp, "need_new_password": need_new_password}
    scope = _prompt_cred_scope(len(collectives))
    # print(f"DEBUG prepare: scope={scope}")

    if scope == "per":
        for col in collectives:
            _fill_secret_fields(col, f"Collective {col.get('index', '?')}", **flags)
        return collectives

    _fill_secret_fields(creds, "Global", **flags)
    for col in collectives:
        _copy_secret_fields(creds, col, **flags)

    if scope == "override":
        raw = input(
            "      Re-enter secrets for which collectives? "
            "(e.g. 1,3,4; Enter = all keep global): "
        ).strip()
        tokens = {part.strip().lower() for part in raw.split(",") if part.strip()}
        for col in collectives:
            keys = {
                str(col.get("index") or "").lower(),
                (col.get("fqdn") or "").lower(),
            }
            if not (tokens & keys):
                continue
            print(
                f"      Collective {col.get('index')} {col.get('fqdn')}: "
                "re-enter SSH/SNMP (others keep global).",
                flush=True,
            )
            _clear_secret_fields(col, **flags)
            _fill_secret_fields(
                col, f"Collective {col.get('index', '?')} only", **flags
            )
    return collectives
