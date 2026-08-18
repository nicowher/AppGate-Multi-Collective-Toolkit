"""Download Python wheels and snmpv3-hashgen into vendor/ for air-gapped installs.

Run this on a networked machine that matches the target OS/Python, then copy
the whole project (including vendor/) to the air-gapped host.
"""
import os
import sys
import urllib.request

from config import HASHGEN_ZIP_URL
from utils import VENDOR_DIR, VENDOR_HASHGEN_ZIP, download_vendor_wheels


def download_hashgen_zip() -> None:
    os.makedirs(VENDOR_DIR, exist_ok=True)
    print(f"Downloading SNMPv3-Hash-Generator to {VENDOR_HASHGEN_ZIP} ...", file=sys.stderr)
    urllib.request.urlretrieve(HASHGEN_ZIP_URL, VENDOR_HASHGEN_ZIP)


def main() -> None:
    try:
        download_vendor_wheels()
        download_hashgen_zip()
    except Exception as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Vendor cache ready in {VENDOR_DIR}", file=sys.stderr)
    print("Copy this folder to the air-gapped machine, then run: python main.py")


if __name__ == "__main__":
    main()
