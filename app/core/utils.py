"""Shared helpers for credentials, host validation, pip, and reports.

Lives in ``core/`` so ``app/`` stays menu + config + folders. ``APP_DIR`` is
the parent of this package (``app/``), not ``app/core/``.


  is_valid_host / prompt_until_valid
      Step 0 prompts: IPv4/IPv6/FQDN and re-ask on bad input.

  load_credentials
      Read optional credentials.json next to the OS launcher (repo root).
      Missing or invalid files become {} so prompts still work.
      collectives[] is kept as a list of objects (not stringified).

  vendor_has_wheels / install_from_vendor / ensure_package / download_vendor_wheels
      Used when requests/paramiko/pysnmp are missing. Vendor wheels first
      (air-gapped); online pip only if the operator allows it.
"""
import importlib.util
import ipaddress
import json
import os
import re
import subprocess
import sys
from getpass import getpass
from typing import Any, Callable, Dict, Optional

from config import (
    DEBUG,
    PIP_INSTALL_TIMEOUT,
    REPORT_FILE_MODE,
    REPORTS_DIRNAME,
    VENDOR_DOWNLOAD_TIMEOUT,
    VENDOR_PACKAGES,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
)

# FQDN: labels of letters/digits/hyphen, at least one dot, TLD 2+ letters.
_FQDN_RE = re.compile(
    r"(?i)^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def is_valid_host(value: str) -> bool:
    """True if value is IPv4, IPv6 (optional brackets), or an FQDN."""
    text = (value or "").strip()
    if not text:
        return False
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return bool(_FQDN_RE.fullmatch(text))


# This file lives in app/core/; vendor/ and launchers stay under app/ and repo root.
CORE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.dirname(CORE_DIR)
REPO_ROOT = os.path.dirname(APP_DIR)
VENDOR_DIR = os.path.join(APP_DIR, "vendor")
VENDOR_WHEELS = os.path.join(VENDOR_DIR, "wheels")


def vendor_has_wheels() -> bool:
    return os.path.isdir(VENDOR_WHEELS) and any(
        name.endswith((".whl", ".tar.gz", ".zip"))
        for name in os.listdir(VENDOR_WHEELS)
    )


def install_from_vendor(package: str) -> bool:
    """Install a pip package from vendor/wheels with no network."""
    if not vendor_has_wheels():
        return False
    print(f"      Installing {package} from vendor/wheels ...", file=sys.stderr)
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--find-links",
                VENDOR_WHEELS,
                package,
            ],
            check=True,
            timeout=PIP_INSTALL_TIMEOUT,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"      vendor install of {package} failed: {exc}", file=sys.stderr)
        return False


def download_vendor_wheels() -> None:
    """Fetch wheels for VENDOR_PACKAGES into vendor/wheels (needs network)."""
    os.makedirs(VENDOR_WHEELS, exist_ok=True)
    print(f"Downloading {', '.join(VENDOR_PACKAGES)} into {VENDOR_WHEELS} ...", file=sys.stderr)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "-d",
            VENDOR_WHEELS,
            *VENDOR_PACKAGES,
        ],
        check=True,
        timeout=VENDOR_DOWNLOAD_TIMEOUT,
    )


def ensure_package(package: str, import_name: str) -> None:
    """Install a missing dependency from vendor/ first, then pip if allowed."""
    if importlib.util.find_spec(import_name) is not None:
        return
    print(f"Missing required package: {package}", file=sys.stderr)
    if install_from_vendor(package) and importlib.util.find_spec(import_name) is not None:
        return
    answer = input(f"Install {package} now via pip (needs network)? [Y/n]: ").strip().lower()
    if is_yes(answer, default_yes=True):
        subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            check=True,
            timeout=PIP_INSTALL_TIMEOUT,
        )
        return
    print(
        f"Please install {package} (or run launcher option 2 / python app/main.py 2) and rerun.",
        file=sys.stderr,
    )
    sys.exit(1)


def prompt_until_valid(
    creds: Dict[str, Any],
    field: str,
    prompt: str,
    *,
    sensitive: bool = False,
    required: bool = True,
    min_len: int = 0,
    pattern: Optional[str] = None,
    pattern_msg: str = "Invalid format. Try again.",
    validator: Optional[Callable[[str], bool]] = None,
    validator_msg: str = "Enter IPv4, IPv6, or an FQDN (e.g. host.example.com).",
) -> str:
    """Read a field from creds or stdin. Invalid values re-prompt; never exit."""
    value = str(creds.get(field) or "").strip()
    while True:
        if value:
            if min_len and len(value) < min_len:
                print(f"      Must be at least {min_len} characters. Try again.", file=sys.stderr)
            elif pattern and not re.fullmatch(pattern, value):
                print(f"      {pattern_msg}", file=sys.stderr)
            elif validator and not validator(value):
                print(f"      {validator_msg}", file=sys.stderr)
            else:
                return value
        elif not required:
            return ""
        if sensitive:
            value = getpass(f"{prompt}: ").strip()
        else:
            value = input(f"{prompt}: ").strip()
        if required and not value:
            print("      This field is required. Try again.", file=sys.stderr)


def load_credentials(path: str) -> Dict[str, Any]:
    """Load optional credentials.json. Missing or invalid files become {}."""
    if not os.path.isfile(path):
        # print(f"DEBUG creds: missing {path}")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        # print(f"DEBUG creds: loaded keys={list(data)} from {path}")
        if DEBUG:
            print(f"      DEBUG creds: loaded {path} keys={sorted(data)}", file=sys.stderr)
        out: Dict[str, Any] = {}
        for key, value in data.items():
            # Keep collectives[] as a list of objects (do not stringify it).
            if key == "collectives":
                out[key] = value
            else:
                out[key] = "" if value is None else str(value)
        return out
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"Warning: Could not load credentials from {path}: {exc}", file=sys.stderr)
        return {}


def is_yes(answer: str, *, default_yes: bool = False) -> bool:
    """True for y/yes. Empty input follows *default_yes* (install prompts default yes)."""
    text = (answer or "").strip().lower()
    if not text:
        return default_yes
    return text in YES_ANSWERS


def write_json_report(prefix: str, payload: Dict[str, Any]) -> None:
    """Write reports/<prefix>-<utc>.json (mode 600). Console dump only if DEBUG.

    Reports never include passwords, tokens, or full localized USM keys.
    """
    from datetime import datetime, timezone

    text = json.dumps(payload, indent=2)
    if DEBUG:
        print("\n----- BEGIN RUN REPORT -----")
        print(text)
        print("----- END RUN REPORT -----")
    if not WRITE_RUN_REPORT:
        return
    reports_dir = os.path.join(REPO_ROOT, REPORTS_DIRNAME)
    try:
        os.makedirs(reports_dir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(reports_dir, f"{prefix}-{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.write("\n")
        try:
            os.chmod(path, REPORT_FILE_MODE)
        except OSError:
            pass
        print(f"      Report written: {path}", file=sys.stderr)
    except OSError as exc:
        print(f"      Could not write report file: {exc}", file=sys.stderr)
