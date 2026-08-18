import importlib.util
import subprocess
import sys


def ensure_package(package: str, import_name: str) -> None:
    module = importlib.util.find_spec(import_name)
    spec = module.find_spec(import_name)
    if spec is not None:
        return
    print(f"Missing required package: {package}", file=sys.stderr)
    answer = input(f"Install {package} now via pip? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes"):
        subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)
        return
    print(f"Please install {package} manually and rerun.", file=sys.stderr)
    sys.exit(1)
