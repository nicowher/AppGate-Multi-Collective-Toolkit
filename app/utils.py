"""Shared helpers used before and during the 8-step workflow.

  vendor_has_wheels / install_from_vendor / ensure_package
      Launchers and API/SSH modules call these when a pip package is
      missing. Vendor wheels (air-gapped) are tried first; online pip
      only if the operator allows it.

  load_credentials
      Step 0: read optional credentials.json next to the launchers.
      Missing or invalid files become {} so the prompts still work.
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

from config import PIP_INSTALL_TIMEOUT, VENDOR_PACKAGES

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
        return bool(_FQDN_RE.fullmatch(value.strip()))


APP_DIR = os.path.dirname(os.path.abspath(__file__))
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
        timeout=PIP_INSTALL_TIMEOUT,
    )


def ensure_package(package: str, import_name: str) -> None:
    """Install a missing dependency from vendor/ first, then pip if allowed."""
    if importlib.util.find_spec(import_name) is not None:
        return
    print(f"Missing required package: {package}", file=sys.stderr)
    if install_from_vendor(package) and importlib.util.find_spec(import_name) is not None:
        return
    answer = input(f"Install {package} now via pip (needs network)? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes"):
        subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            check=True,
            timeout=PIP_INSTALL_TIMEOUT,
        )
        return
    print(
        f"Please install {package} (or run Download-Deps) and rerun.",
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
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
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
