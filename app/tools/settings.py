"""Menu C: edit common knobs in config.py (DEBUG, LAB_MODE, SSH timeouts).

Why a dedicated editor: operators on air-gap hosts should not hand-edit
Python. LAB_MODE derived knobs (SSH host-key check and SNMP min passphrase)
are recomputed on save so they cannot drift. The Kul flag is still set, but
the summary does not print those keys.
"""
import os
import re
import sys
import tempfile

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

import config
from config import YES_ANSWERS
from core.utils import print_error

CONFIG_PATH = os.path.join(_APP_DIR, "config.py")

# name, type, short help — LAB_MODE derived TLS/SSH/Kul/minlen stay computed in config.py
EDITABLE = (
    ("DEBUG", bool, "step traces and JSON dump on console"),
    ("LAB_MODE", bool, "SSH host keys, passphrase floor, STIG cz password"),
    ("INSECURE_API", bool, "skip Controller CA file (API only, not SSH)"),
    ("CNSA_STRICT", bool, "SSH and Controller TLS use only CNSA-grade algorithms"),
    ("DRY_RUN", bool, "force preview; skip pin/push/purge/walk"),
    ("SKIP_CREDENTIAL_WALK", bool, "skip walk after SNMP credential push"),
    ("ALLOW_SOURCES_LOCKOUT_SSH", bool, "abort replace if this host fails new SSH rules"),
    ("ALLOW_SOURCES_LOCKOUT_HTTPS", bool, "abort replace if this host fails Admin/SPA HTTPS rules"),
    ("WRITE_RUN_REPORT", bool, "write reports/*.json"),
    ("SSH_TIMEOUT", int, "SSH command timeout (seconds)"),
    ("SSH_PRIME_TIMEOUT", int, "per-address host-key read and DNS wait (skip dead NICs)"),
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
    """Python text for one bool or int value written back to config.py."""
    if isinstance(value, bool):
        return "True" if value else "False"
    return str(int(value))


def _write_assignment(text: str, name: str, value) -> str:
    """Replace one assignment. A loose match would rewrite the wrong knob.

    A name assigned more than once is refused: only one line could be changed,
    and the later line would still win at import, so the save would have no effect.
    """
    # print(f"DEBUG settings: {name} assignments={len(re.findall(rf'^{re.escape(name)}\s*=', text, re.M))}")
    count = len(re.findall(rf"^{re.escape(name)}\s*=", text, re.MULTILINE))
    if count != 1:
        raise ValueError(
            f"{name} is assigned {count} times in config.py; leave exactly one line, then save again"
        )
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
    """Enter keeps the current value; anything not clearly yes or no is refused."""
    s = raw.strip().lower()
    if not s:
        return current
    if s in YES_ANSWERS or s in ("true", "1", "on"):
        return True
    if s in ("n", "no", "false", "0", "off"):
        return False
    raise ValueError("Enter y/n, true/false, or 1/0")


def _parse_int(raw: str, current: int, name: str = "") -> int:
    """Enter keeps the current value. Ranges stop a value that would hang or break a run, such as a 0 timeout or a huge concurrency."""
    s = raw.strip()
    if not s:
        return current
    n = int(s, 10)
    if n < 0:
        raise ValueError("Must be >= 0")
    if "CONCURRENCY" in name:
        if n < 1 or n > 8:
            raise ValueError("Concurrency must be 1-8")
    elif name == "SSH_PORT":
        if n < 1 or n > 65535:
            raise ValueError("Port must be 1-65535")
    elif "TIMEOUT" in name:
        if n < 1 or n > 600:
            raise ValueError("Timeout must be 1-600")
    elif "ATTEMPTS" in name or "RETRIES" in name:
        if n < 1 or n > 10:
            raise ValueError("Attempts must be 1-10")
    elif "DELAY" in name and n > 300:
        raise ValueError("Delay must be 0-300")
    return n


def _apply_runtime(name: str, value) -> None:
    """Apply the value in this process too, including LAB_MODE's linked settings, until the toolkit restarts."""
    setattr(config, name, value)
    if name == "LAB_MODE":
        config.SSH_STRICT_HOST_KEY = not value
        config.PRINT_ESXI_KEYS = value
        config.SNMP_MIN_PASSPHRASE_LEN = (
            config.SNMP_MIN_PASSPHRASE_LEN_LAB
            if value
            else config.SNMP_MIN_PASSPHRASE_LEN_STIG
        )


def main() -> bool:
    """Menu C: edit config.py values. INSECURE_API and LAB_MODE need an extra confirm before saving."""
    # print(f"DEBUG settings: path={CONFIG_PATH} DEBUG={config.DEBUG} LAB_MODE={config.LAB_MODE}")
    print("Configure config.py (Enter keeps the current value).")
    print("SSH_STRICT_HOST_KEY follows LAB_MODE. INSECURE_API does not.")
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
            return False
        if raw in ("s", "save"):
            if values.get("INSECURE_API") and not config.INSECURE_API:
                first = input(
                    "      INSECURE_API=True skips the Controller CA. Continue? [y/N]: "
                ).strip().lower()
                second = input("      Type YES to skip Controller certificate checks: ").strip()
                if first not in YES_ANSWERS or second != "YES":
                    print("      Save cancelled.")
                    continue
            if not values.get("CNSA_STRICT", True) and getattr(config, "CNSA_STRICT", True):
                # Same kind of downgrade as LAB_MODE and INSECURE_API, so it gets a yes too.
                confirm = input(
                    "      CNSA_STRICT=False relaxes TLS and SSH for every Controller and box "
                    "(SHA-256 MACs, P-256, AES-128 and TLS 1.3 become possible). Continue? [y/N]: "
                ).strip().lower()
                if confirm not in YES_ANSWERS:
                    print("      Save cancelled.")
                    continue
            if values.get("LAB_MODE") and not config.LAB_MODE:
                confirm = input(
                    "      LAB_MODE=True disables SSH host-key checks and STIG floors. "
                    "It does not skip the Controller CA. Continue? [y/N]: "
                ).strip().lower()
                if confirm not in YES_ANSWERS:
                    print("      Save cancelled.")
                    continue
            with open(CONFIG_PATH, encoding="utf-8") as fh:
                text = fh.read()
            try:
                for name, _t, _h in EDITABLE:
                    text = _write_assignment(text, name, values[name])
            except ValueError as exc:
                # Nothing has been written yet, so config.py is unchanged.
                print_error("E22", str(exc), "Save cancelled; config.py was not changed. Remove the duplicate line and save again.")
                continue
            try:
                mode = os.stat(CONFIG_PATH).st_mode & 0o777
            except OSError:
                mode = 0o644
            fd, tmp_path = tempfile.mkstemp(
                prefix="config.py.", suffix=".tmp", dir=os.path.dirname(CONFIG_PATH)
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
                os.chmod(tmp_path, mode)
                os.replace(tmp_path, CONFIG_PATH)
            except Exception:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                raise
            # print(f"DEBUG settings: wrote {CONFIG_PATH}")
            for name, _t, _h in EDITABLE:
                _apply_runtime(name, values[name])
            print(f"      Saved {CONFIG_PATH}")
            print("      Relaunch the launcher so the new values take effect.")
            return True
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
                values[name] = _parse_int(entered, current, name)
        except ValueError as exc:
            print(f"      {exc}")
