"""Shared credential / Controller prompts used by more than one tool.

Lives in ``core/``. Step 0 for SNMP credentials and walk-inventory: turn
credentials.json into a numbered Controller list. `_require` never exits on
bad input (re-prompt). `_parse_collectives` prefers collectives[]; old
single-controller files still work. Duplicate FQDNs warn but still run
(operator may have copied a row).

``prepare_collectives`` inherits omitted keys from top-level, then prompts
only for gaps. If every collective already has a field, that field is not
asked globally (one collective with per-row secrets never sees "Global …").
Walk passes ``need_ssh=False``.
"""
import os
import re
import sys
from typing import Any, Dict, List, Optional

from config import (
    CREDENTIALS_FILENAME,
    DEBUG,
    LAB_MODE,
    NTP_WEAK_KEY_TYPES,
    SNMP_MIN_PASSPHRASE_LEN,
    SNMP_NAME_RE,
    STIG_PASSWORD_MIN_LEN,
    YES_ANSWERS,
)
from getpass import getpass

from core.utils import REPO_ROOT, expand_exclude_tokens, halt, is_valid_host, prompt_until_valid, prompt_yes

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
    """A missing, null, list or object value reads as empty, so a malformed field inherits the top-level value instead of becoming its Python text."""
    val = item.get(key)
    if val is None or isinstance(val, (list, dict)):
        return ""
    if isinstance(val, (bool, float)):
        # str(True) is "True", which would be sent as a password or user name.
        halt(
            "E21",
            f"credentials.json collectives row: {key} is {type(val).__name__}, not text",
            "Write it as a quoted string.",
        )
    return str(val).strip()


def _parse_mibs(value: Any) -> List[str]:
    """MIB list for walks. A non-list is ignored rather than split into characters."""
    if not isinstance(value, list):
        return []
    bad = [x for x in value if not isinstance(x, (str, int)) or isinstance(x, bool)]
    if bad:
        # str(None) is "None", which would be walked as a MIB name.
        halt("E21", "credentials.json mibs must be a list of names", "Remove null, true/false, and nested values.")
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
    """The collective's MIB list wins when it is set; otherwise the top-level list."""
    local = col.get("mibs")
    if isinstance(local, list) and local:
        return _parse_mibs(local)
    return _parse_mibs(creds.get("mibs"))


def _reject_controls(label: str, text: str) -> str:
    """A newline in an NTP field can become a second chrony line."""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise ValueError(f"NTP {label} contains a control character")
    return text


def _parse_ntp_servers(value: Any) -> List[Dict[str, str]]:
    """A bad row must stop the load with a halt. A traceback hides the row the operator has to fix."""
    try:
        return _parse_ntp_servers_checked(value)
    except ValueError as exc:
        halt(
            "E12",
            str(exc),
            "Each ntp_servers entry must be a hostname or an object with hostname.",
        )


def _parse_ntp_servers_checked(value: Any) -> List[Dict[str, str]]:
    """Raise on a bad row or a non-array so the caller can halt. Ignoring an object would look like no servers were set.

    Only control characters are refused here. A hostname that is not an IP or FQDN
    passes this check and is sent to the Controller. The IP-or-FQDN check runs only
    later, at the chronyc verify step.
    """
    # print(f"DEBUG ntp rows: n={len(value) if isinstance(value, list) else type(value).__name__}")
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("ntp_servers must be an array")
    out: List[Dict[str, str]] = []
    for item in value:
        if isinstance(item, str):
            host = _reject_controls("hostname", item.strip())
            if not host:
                raise ValueError("NTP row is empty")
            if not is_valid_host(host):
                raise ValueError(f"NTP hostname is not an IP or FQDN: {host!r}")
            out.append({"hostname": host, "keyType": "", "keyNo": "", "key": ""})
            continue
        if not isinstance(item, dict):
            raise ValueError("NTP row must be a hostname or an object")
        host = _reject_controls("hostname", str(item.get("hostname") or "").strip())
        if not host:
            raise ValueError("NTP row is missing hostname")
        if not is_valid_host(host):
            raise ValueError(f"NTP hostname is not an IP or FQDN: {host!r}")
        kn = item.get("keyNo")
        if isinstance(kn, (bool, float, list, dict)):
            raise ValueError(f"NTP keyNo for {host} must be a whole number or text")
        key_no = "" if kn is None else _reject_controls("keyNo", str(kn).strip())
        out.append(
            {
                "hostname": host,
                "keyType": _reject_controls("keyType", str(item.get("keyType") or "").strip()),
                "keyNo": key_no,
                "key": _reject_controls("key", str(item.get("key") or "").strip()),
            }
        )
    return out


def resolve_allowed_sources(col: dict, creds: dict) -> Dict[str, list]:
    """An empty row inherits the global map. A missing map stays empty so the tool halts before login."""
    local = col.get("allowed_sources")
    if isinstance(local, dict) and local:
        return local
    top = creds.get("allowed_sources")
    return top if isinstance(top, dict) else {}


def resolve_ntp_servers(col: dict, creds: dict) -> List[Dict[str, str]]:
    """The collective's NTP list wins when it is non-empty; otherwise top-level. Both go through the same row checks, and a bad row halts with E12."""
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
        if not is_valid_host(host):
            # Checked before the PUT. The chronyc verify step used to be the first check.
            print("      Enter an IP address or an FQDN (e.g. ntp.example.com).", file=sys.stderr)
            continue
        key_type = input("      keyType (e.g. SHA256, empty if none): ").strip()
        if key_type.replace("-", "").upper() in NTP_WEAK_KEY_TYPES and not LAB_MODE:
            print("      DISA/CNSA: MD5/SHA1 NTP keys are rejected. Use SHA256.", file=sys.stderr)
            continue
        key_no = input("      keyNo (empty if none): ").strip()
        key = ""
        if key_type:
            if not sys.stdin.isatty():
                raise RuntimeError("Password prompt requires a terminal")
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
        if not prompt_yes("      Add another NTP server? [y/N]: "):
            break
    col["ntp_servers"] = servers
    return servers


def _row_from_item(item: dict) -> Dict[str, Any]:
    """Normalize one collectives[] row, or a single-Controller file. Old admin_* keys map to api_* so older files still load."""
    row: Dict[str, Any] = {
        "fqdn": str(item.get("fqdn") or item.get("hostname") or "").strip(),
        "agip": str(item.get("agip") or "").strip(),
        "mibs": _parse_mibs(item.get("mibs")),
        "ntp_servers": _parse_ntp_servers(item.get("ntp_servers")),
        "ssh_host_keys": item.get("ssh_host_keys", item.get("ssh_host_key")),
    }
    for key in COLLECTIVE_OPTIONAL_STR:
        row[key] = _optional_str(item, key)
    if not row.get("api_username"):
        row["api_username"] = _optional_str(item, "admin_username")
    if not row.get("api_password"):
        row["api_password"] = str(item.get("admin_password") or "")
    src = item.get("allowed_sources")
    if isinstance(src, dict) and src:
        row["allowed_sources"] = src
    return row


def _parse_collectives(creds: dict) -> List[Dict[str, Any]]:
    """Turn credentials into a numbered list of Controllers.

    Prefer collectives[]. Required: fqdn (prompted). agip optional but preferred
    for IP fallback. Extra keys (ssh_*, snmp_*, mibs, ssh_password_new) are
    kept if present; omitted keys inherit top-level via resolve_field.
    allowed_sources on a collective row is copied (was dropped, which caused E19).
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
            halt(
                "E05",
                f"Collective {i} reuses FQDN {fqdn} (already index {seen[key]})",
                "Use a different Controller, or exclude the duplicate before adding.",
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
        if isinstance(row.get("allowed_sources"), dict) and row["allowed_sources"]:
            entry["allowed_sources"] = row["allowed_sources"]
        host_keys = row.get("ssh_host_keys")
        if host_keys is None:
            host_keys = row.get("ssh_host_key") or creds.get("ssh_host_keys") or creds.get("ssh_host_key")
        if host_keys:
            entry["ssh_host_keys"] = host_keys
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
                halt(
                    "E05",
                    "Nothing left after excluding collectives",
                    "Press Enter to keep all Controllers, or exclude fewer numbers/FQDNs.",
                )
            more_yes = prompt_yes(
                "      Add another Controller besides those in the file? [y/N]: "
            )
            first_ask = False
        else:
            more_yes = prompt_yes("      Add another Controller? [y/N]: ")
        if not more_yes:
            break
        used = set()
        for col in out:
            try:
                used.add(int(col.get("index") or 0))
            except (TypeError, ValueError):
                continue
        nxt = max(used or {0}) + 1
        while nxt in used:
            nxt += 1
        _add(nxt, _row_from_item({}))
    return out


def _exclude_collectives(cols: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Same idea as appliance exclude: Enter keeps all. Tokens: index, range, FQDN/IP.

    A comma part that matches no collective is listed and the question is asked
    again, so a typo cannot leave a Controller in the run unnoticed.
    """
    if len(cols) < 2:
        return cols

    def _keys(col: Dict[str, Any]) -> set:
        keys = {
            str(col.get("index") or "").lower(),
            (col.get("fqdn") or "").lower(),
            (col.get("agip") or "").lower(),
        }
        keys.discard("")
        return keys

    all_keys = set().union(*(_keys(c) for c in cols))
    while True:
        raw = input(
            "      Exclude collectives (e.g. 1,3 or 1-3 or FQDN; Enter for all): "
        ).strip()
        if not raw:
            return cols
        # print(f"DEBUG collectives: exclude raw={raw!r}")
        try:
            tokens = expand_exclude_tokens(raw)
        except ValueError as exc:
            print(f"      {exc}", file=sys.stderr)
            continue
        unmatched = [
            part.strip() for part in raw.split(",")
            if part.strip() and not (expand_exclude_tokens(part) & all_keys)
        ]
        if not unmatched:
            break
        print(f"      No collective matches: {', '.join(unmatched)}. Enter the list again.", file=sys.stderr)
    kept: List[Dict[str, Any]] = []
    for col in cols:
        if tokens & _keys(col):
            print(f"      Excluding collective {col.get('index')} {col.get('fqdn')}", flush=True)
            continue
        kept.append(col)
    return kept


def collective_for_target(target: Any, collectives: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The credentials row that owns this appliance. Settings must come from that row, never another collective. A missing row is an error, not a default."""
    idx = int(getattr(target, "collective", 1) or 1)
    for col in collectives:
        try:
            if int(col.get("index") or 0) == idx:
                return col
        except (TypeError, ValueError):
            continue
    raise RuntimeError(f"No collective matching index {idx}")


def _prompt_cred_scope(count: int) -> str:
    """1=global 2=per-collective 3=global then override. Not used when 0–1 collectives."""
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
    """A reused password would look like a rotation. Checked even in lab mode."""
    while True:
        value = _require(
            bucket, "ssh_password_new", f"{label} New SSH Password", sensitive=True
        )
        current = str(bucket.get("ssh_password") or "")
        if current and value == current:
            print("      New SSH password must differ from the current one.", file=sys.stderr)
            bucket["ssh_password_new"] = ""
            continue
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


def _field_filled(bucket: dict, key: str, *, min_len: int = 0) -> bool:
    """A secret counts as present only when it meets the minimum length, so a too-short value is asked for again."""
    val = (bucket.get(key) or "").strip()
    return bool(val) and (not min_len or len(val) >= min_len)


def _secret_keys(*, need_ssh: bool, need_snmp: bool, need_new_password: bool) -> List[str]:
    """Secret fields this tool needs, so a tool never prompts for secrets it does not use."""
    keys: List[str] = []
    if need_ssh:
        keys.extend(("ssh_username", "ssh_password"))
    if need_snmp:
        keys.extend(("snmp_user", "snmp_auth", "snmp_priv"))
    if need_new_password:
        keys.append("ssh_password_new")
    return keys


def _col_secrets_ready(
    col: dict, *, need_ssh: bool, need_snmp: bool, need_new_password: bool
) -> bool:
    """Ready means the prompt can be skipped. Priv is required with auth so a missing passphrase is asked here, not at hash time."""
    if need_ssh and not (
        _field_filled(col, "ssh_username") and _field_filled(col, "ssh_password")
    ):
        return False
    if need_snmp and not (
        _field_filled(col, "snmp_user")
        and _field_filled(col, "snmp_auth", min_len=SNMP_MIN_PASSPHRASE_LEN)
        and _field_filled(col, "snmp_priv", min_len=SNMP_MIN_PASSPHRASE_LEN)
    ):
        return False
    if need_new_password:
        pw = (col.get("ssh_password_new") or "").strip()
        if not pw or pw == (col.get("ssh_password") or "").strip():
            return False
        if not LAB_MODE and stig_password_errors(pw):
            return False
    return True


def _global_skip_keys(
    collectives: List[Dict[str, Any]],
    *,
    need_ssh: bool,
    need_snmp: bool,
    need_new_password: bool,
) -> set:
    """Fields every collective already has. Those are not asked globally, so a global prompt never covers for per-row secrets that are already set."""
    skip = set()
    for key in _secret_keys(
        need_ssh=need_ssh, need_snmp=need_snmp, need_new_password=need_new_password
    ):
        min_len = SNMP_MIN_PASSPHRASE_LEN if key in ("snmp_auth", "snmp_priv") else 0
        if key == "snmp_priv":
            if all(_field_filled(c, "snmp_priv", min_len=min_len) for c in collectives):
                skip.add(key)
            continue
        if all(_field_filled(c, key, min_len=min_len) for c in collectives):
            skip.add(key)
    return skip


def _fill_secret_fields(
    bucket: dict,
    label: str,
    *,
    need_ssh: bool = True,
    need_snmp: bool,
    need_new_password: bool,
    skip: Optional[set] = None,
) -> None:
    """Prompt for the secrets missing from one bucket (global or one collective). Fields in skip are not asked."""
    skip = skip or set()
    if need_ssh:
        if "ssh_username" not in skip:
            bucket["ssh_username"] = _require(
                bucket, "ssh_username", f"{label} SSH Username"
            )
        if "ssh_password" not in skip:
            bucket["ssh_password"] = _require(
                bucket, "ssh_password", f"{label} SSH Password", sensitive=True
            )
    if need_snmp:
        if "snmp_user" not in skip:
            bucket["snmp_user"] = _require(
                bucket,
                "snmp_user",
                f"{label} SNMP User",
                pattern=SNMP_NAME_RE,
                pattern_msg="Use 1-32 letters, digits, underscore, dot, or hyphen.",
            )
        if "snmp_auth" not in skip:
            bucket["snmp_auth"] = _require(
                bucket,
                "snmp_auth",
                f"{label} SNMP Auth",
                sensitive=True,
                min_len=SNMP_MIN_PASSPHRASE_LEN,
                validator=snmp_secret_ok,
                validator_msg="No spaces or control characters in an SNMP passphrase.",
            )
        if "snmp_priv" not in skip:
            bucket["snmp_priv"] = _require(
                bucket,
                "snmp_priv",
                f"{label} SNMP Priv",
                sensitive=True,
                min_len=SNMP_MIN_PASSPHRASE_LEN,
                validator=snmp_secret_ok,
                validator_msg="No spaces or control characters in an SNMP passphrase.",
            )
    if need_new_password and "ssh_password_new" not in skip:
        bucket["ssh_password_new"] = _require_new_password(bucket, label)


def _copy_secret_fields(
    src: dict,
    dest: dict,
    *,
    need_ssh: bool = True,
    need_snmp: bool,
    need_new_password: bool,
    skip: Optional[set] = None,
) -> None:
    """A global answer fills gaps only. A row that already has the field keeps its own value."""
    skip = skip or set()
    for key in _secret_keys(
        need_ssh=need_ssh, need_snmp=need_snmp, need_new_password=need_new_password
    ):
        if key in skip:
            continue
        if (dest.get(key) or "").strip():
            continue
        dest[key] = src.get(key) or ""


def _clear_secret_fields(
    col: dict, *, need_ssh: bool = True, need_snmp: bool, need_new_password: bool
) -> None:
    """Blank one row's secrets when the operator chose to re-enter them for that collective, so the prompt that follows asks again instead of reusing the global values."""
    for key in _secret_keys(
        need_ssh=need_ssh, need_snmp=need_snmp, need_new_password=need_new_password
    ):
        col[key] = ""


def promote_shared_fields(creds: dict, keys: tuple) -> None:
    """If top-level is empty and every collective has the key, copy the first."""
    raw = creds.get("collectives")
    rows = [x for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []
    if not rows:
        return
    for key in keys:
        if str(creds.get(key) or "").strip():
            continue
        vals = [_optional_str(r, key) for r in rows]
        if vals and all(vals):
            creds[key] = vals[0]


def prepare_collectives(
    creds: dict,
    collectives: List[Dict[str, Any]],
    *,
    need_ssh: bool = True,
    need_snmp: bool = False,
    need_new_password: bool = False,
) -> List[Dict[str, Any]]:
    """Fill each collective's secrets, then check SNMP settings before any login.

    Values already in the file are not prompted for, so the prompt never checks
    them. The SNMP check runs here on every row instead, and stops the tool with
    E21 before step 1 rather than failing on the box later.
    """
    out = _prepare_collectives(
        creds,
        collectives,
        need_ssh=need_ssh,
        need_snmp=need_snmp,
        need_new_password=need_new_password,
    )
    if need_snmp:
        require_snmp_settings(out)
    return out


def snmp_secret_ok(value: str) -> bool:
    """A passphrase goes into the walk's snmp.conf as one token. A space cuts it short; CR or LF adds a directive."""
    return bool(value) and not any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value)


def snmp_setting_errors(col: Dict[str, Any]) -> List[str]:
    """Problems with one collective's SNMP user and passphrases. Names fields only, never the values."""
    label = f"collective {col.get('index', '?')} ({col.get('fqdn') or 'no FQDN'})"
    errors = []
    user = str(col.get("snmp_user") or "")
    if user and not re.fullmatch(SNMP_NAME_RE, user):
        errors.append(
            f"{label}: snmp_user must be 1-32 letters, digits, underscore, dot, or hyphen (USM limit)."
        )
    for key in ("snmp_auth", "snmp_priv"):
        value = str(col.get(key) or "")
        if value and not snmp_secret_ok(value):
            errors.append(f"{label}: {key} contains a space or a control character.")
    return errors


def require_snmp_settings(collectives: List[Dict[str, Any]]) -> None:
    """Stop before login when any collective's SNMP settings would fail on the box or in the walk."""
    errors = [msg for col in collectives for msg in snmp_setting_errors(col)]
    # print(f"DEBUG snmp settings: errors={len(errors)}")
    if errors:
        halt("E21", "SNMP settings in credentials.json cannot be used", *errors)


def _prepare_collectives(
    creds: dict,
    collectives: List[Dict[str, Any]],
    *,
    need_ssh: bool = True,
    need_snmp: bool = False,
    need_new_password: bool = False,
) -> List[Dict[str, Any]]:
    """SSH/SNMP/new-password: skip prompts when every collective already has the field.

    A global fill is skipped for a field only when every row already has it.
    A typed global value is copied only into rows that do not already have that field.
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

    flags = {
        "need_ssh": need_ssh,
        "need_snmp": need_snmp,
        "need_new_password": need_new_password,
    }
    if all(_col_secrets_ready(c, **flags) for c in collectives):
        # print(f"DEBUG prepare: skip prompts n={len(collectives)} ssh={need_ssh} snmp={need_snmp}")
        if DEBUG:
            print(
                f"      DEBUG prepare: every collective already has required secrets "
                f"(n={len(collectives)} ssh={need_ssh} snmp={need_snmp})",
                file=sys.stderr,
            )
        return collectives

    if len(collectives) < 2:
        _fill_secret_fields(
            collectives[0], f"Collective {collectives[0].get('index', '1')}", **flags
        )
        return collectives

    scope = _prompt_cred_scope(len(collectives))
    # print(f"DEBUG prepare: scope={scope}")

    if scope == "per":
        for col in collectives:
            _fill_secret_fields(col, f"Collective {col.get('index', '?')}", **flags)
        return collectives

    skip = _global_skip_keys(collectives, **flags)
    _fill_secret_fields(creds, "Global", skip=skip, **flags)
    for col in collectives:
        _copy_secret_fields(creds, col, skip=skip, **flags)

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
