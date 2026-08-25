"""Menu option 2: prefetch Python wheels into app/vendor/wheels.

Not part of the configure 8-step flow. Run on a networked machine that
matches the target OS and Python, then copy the project (including
app/vendor/) to the air-gapped host. ensure_package() installs from
vendor/ before offering online pip.
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
    print("Copy this folder to the air-gapped machine, then run the Multi-Collective Toolkit launcher.")


if __name__ == "__main__":
    main()
