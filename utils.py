import importlib.util
import json
import os
import subprocess
import sys
from typing import Any, Dict


def ensure_package(package: str, import_name: str) -> None:
    if importlib.util.find_spec(import_name) is not None:
        return
    print(f"Missing required package: {package}", file=sys.stderr)
    answer = input(f"Install {package} now via pip? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes"):
        subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            check=True,
            timeout=120,
        )
        return
    print(f"Please install {package} manually and rerun.", file=sys.stderr)
    sys.exit(1)


def load_credentials(path: str) -> Dict[str, Any]:
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
