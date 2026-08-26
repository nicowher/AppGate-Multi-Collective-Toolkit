"""Menu D: pip download into app/vendor/wheels (air-gap copy, no install).

Menu U: pip install --upgrade into the current interpreter (needs network,
does not refresh wheels). Same package list: VENDOR_PACKAGES.

Not part of the configure 8-step flow. Run D on a networked machine that
matches the target OS and Python, then copy the project (including
app/vendor/) to the air-gapped host. ensure_package() installs from
vendor/ before offering online pip.
"""
import os
import sys

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from config import DEBUG, VENDOR_PACKAGES
from core.utils import VENDOR_DIR, download_vendor_wheels, upgrade_vendor_packages


def main() -> None:
    # print(f"DEBUG deps: vendor={VENDOR_DIR} packages={VENDOR_PACKAGES}")
    if DEBUG:
        print(f"      DEBUG deps: writing wheels to {VENDOR_DIR}", file=sys.stderr)
    try:
        download_vendor_wheels()
    except Exception as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Vendor cache ready in {VENDOR_DIR}", file=sys.stderr)
    print("Copy this folder to the air-gapped machine, then run the Multi-Collective Toolkit launcher.")


def upgrade_main() -> None:
    if DEBUG:
        print(f"      DEBUG deps: pip install --upgrade {VENDOR_PACKAGES}", file=sys.stderr)
    try:
        upgrade_vendor_packages()
    except Exception as exc:
        print(f"Upgrade failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print("Packages upgraded.", file=sys.stderr)


if __name__ == "__main__":
    main()
