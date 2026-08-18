"""Download Python wheels into app/vendor/wheels for air-gapped installs.

Run this on a networked machine that matches the target OS/Python, then copy
the whole project (including app/vendor/) to the air-gapped host.
"""
import sys

from utils import VENDOR_DIR, download_vendor_wheels


def main() -> None:
    try:
        download_vendor_wheels()
    except Exception as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Vendor cache ready in {VENDOR_DIR}", file=sys.stderr)
    print("Copy this folder to the air-gapped machine, then run Passwordinator-<OS>.")


if __name__ == "__main__":
    main()
