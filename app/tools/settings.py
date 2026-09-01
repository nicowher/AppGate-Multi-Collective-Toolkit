"""Menu C: edit common knobs in config.py (DEBUG, LAB_MODE, SSH timeouts)."""
import os
import re
import sys

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

import config
from config import YES_ANSWERS

CONFIG_PATH = os.path.join(_APP_DIR, "config.py")

# name, type, short help — LAB_MODE derived TLS/SSH/Kul/minlen stay computed in config.py
EDITABLE = (
    ("DEBUG", bool, "step traces and JSON dump on console"),
    ("LAB_MODE", bool, "lab TLS/SSH/STIG posture (TLS_VERIFY follows this)"),
    ("DRY_RUN", bool, "force preview; skip pin/push/purge/walk"),
    ("WRITE_RUN_REPORT", bool, "write reports/*.json"),
    ("SSH_TIMEOUT", int, "SSH command timeout (seconds)"),
    ("SSH_AUTH_TIMEOUT", int, "SSH connect/auth timeout (seconds)"),
    ("SSH_CONCURRENCY", int, "parallel SSH sessions"),
    ("SSH_PORT", int, "SSH port"),
    ("WALK_CONCURRENCY", int, "parallel SNMP walks"),
    ("WALK_IP_ATTEMPTS", int, "walk tries per IP"),
    ("WALK_FQDN_ATTEMPTS", int, "walk tries per FQDN"),
    ("SNMPWALK_PROBE_TIMEOUT", int, "pysnmp probe timeout (seconds)"),
    ("SNMPWALK_RETRIES", int, "pysnmp retries per probe"),
    ("VALIDATION_RETRY_DELAY", int, "delay between walk retries (seconds)"),
    ("SNMP_RELOAD_DELAY", int, "wait after API push (seconds)"),
    ("API_TIMEOUT", int, "Controller HTTPS timeout (seconds)"),
    ("ACAS_SSH_TIMEOUT", int, "ACAS script timeout (seconds)"),
    ("CZ_PASSWORD_VERIFY_DELAY", int, "wait before cz password login-verify"),
    ("NTP_VERIFY_DELAY", int, "wait after cz-customization restart before chronyc"),
)


def _literal(value) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"
    return str(int(value))


def _write_assignment(text: str, name: str, value) -> str:
    lit = _literal(value)
    pat = re.compile(
        rf"^({re.escape(name)}\s*=\s*)(True|False|-?\d+)(\s*(#.*)?)?$",
        re.MULTILINE,
    )
    new, n = pat.subn(rf"\g<1>{lit}\3", text, count=1)
    if n != 1:
        raise ValueError(f"Could not update {name} in config.py")
    return new


def _parse_bool(raw: str, current: bool) -> bool:
    s = raw.strip().lower()
    if not s:
        return current
    if s in YES_ANSWERS or s in ("true", "1", "on"):
        return True
    if s in ("n", "no", "false", "0", "off"):
        return False
    raise ValueError("Enter y/n, true/false, or 1/0")


def _parse_int(raw: str, current: int) -> int:
    s = raw.strip()
    if not s:
        return current
    n = int(s, 10)
    if n < 0:
        raise ValueError("Must be >= 0")
    return n


def _apply_runtime(name: str, value) -> None:
    setattr(config, name, value)
    if name == "LAB_MODE":
        config.TLS_VERIFY = not value
        config.SSH_STRICT_HOST_KEY = not value
        config.PRINT_ESXI_KEYS = value
        config.SNMP_MIN_PASSPHRASE_LEN = 8 if value else 15


def main() -> None:
    print("Configure config.py (Enter keeps the current value).")
    print("TLS_VERIFY / SSH_STRICT_HOST_KEY follow LAB_MODE.")
    print()
    values = {name: getattr(config, name) for name, _t, _h in EDITABLE}
    while True:
        for i, (name, _t, help_txt) in enumerate(EDITABLE, 1):
            print(f"  {i:2d}) {name} = {values[name]!r}  ({help_txt})")
        print("   S) Save to config.py")
        print("   Q) Cancel")
        raw = input("Select number, S, or Q: ").strip().lower()
        if raw in ("q", "quit"):
            print("      No changes written.")
            return
        if raw in ("s", "save"):
            text = open(CONFIG_PATH, encoding="utf-8").read()
            for name, _t, _h in EDITABLE:
                text = _write_assignment(text, name, values[name])
            with open(CONFIG_PATH, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            for name, _t, _h in EDITABLE:
                _apply_runtime(name, values[name])
            print(f"      Saved {CONFIG_PATH}")
            print(
                "      If a tool already ran in this session, restart the launcher "
                "so every import sees the new values."
            )
            return
        try:
            idx = int(raw, 10)
        except ValueError:
            print("Invalid choice.")
            continue
        if idx < 1 or idx > len(EDITABLE):
            print("Invalid choice.")
            continue
        name, typ, help_txt = EDITABLE[idx - 1]
        current = values[name]
        entered = input(f"      {name} [{current!r}] ({help_txt}): ")
        try:
            if typ is bool:
                values[name] = _parse_bool(entered, current)
            else:
                values[name] = _parse_int(entered, current)
        except ValueError as exc:
            print(f"      {exc}")
