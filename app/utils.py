import importlib.util
import json
import os
import subprocess
import sys
from typing import Any, Dict

from config import PIP_INSTALL_TIMEOUT, VENDOR_PACKAGES

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
VENDOR_DIR = os.path.join(PROJECT_ROOT, "vendor")
VENDOR_WHEELS = os.path.join(VENDOR_DIR, "wheels")
VENDOR_HASHGEN_ZIP = os.path.join(VENDOR_DIR, "SNMPv3-Hash-Generator.zip")


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
        f"Please install {package} (or run: python download_deps.py) and rerun.",
        file=sys.stderr,
    )
    sys.exit(1)


def load_credentials(path: str) -> Dict[str, Any]:
    """Load optional credentials.json. Missing or invalid files become {}."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        return {k: str(v) for k, v in data.items()}
    except Exception as exc:
        print(f"Warning: Could not load credentials from {path}: {exc}", file=sys.stderr)
        return {}
