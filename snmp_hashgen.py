import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from config import (
    HASHGEN_DETECT_TIMEOUT,
    HASHGEN_REPO,
    HASHGEN_TIMEOUT,
    HASHGEN_ZIP_URL,
    PIP_INSTALL_TIMEOUT,
    SNMP_HASH_ALGO,
)
from utils import VENDOR_HASHGEN_ZIP

HASH_HEX_LEN = {
    "md5": 32,
    "sha1": 40,
    "sha224": 56,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
}

class SNMPHashGenerator:
    def generate_hashes(
        self,
        user: str,
        auth: str,
        priv: str,
        engine_id: str,
        hash_algo: str = SNMP_HASH_ALGO,
    ) -> Dict[str, Any]:
        """Run snmpv3-hashgen and return its JSON (localized auth/priv keys)."""
        cmd, env = self._resolve_hashgen_command()
        cmd.extend([
            "--user", user,
            "--auth", auth,
            "--priv", priv,
            "--engine", engine_id,
            "--hash", hash_algo,
            "--mode", "priv",
            "--json",
        ])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=HASHGEN_TIMEOUT,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"snmpv3-hashgen timed out after {HASHGEN_TIMEOUT}s") from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"snmpv3-hashgen failed (rc={exc.returncode}). "
                f"stderr: {(exc.stderr or '').strip()[:500]}"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"snmpv3-hashgen executable not found: {cmd[0]}. "
                "Ensure it is installed and in PATH."
            ) from exc

        data = json.loads(result.stdout)

        expected_len = HASH_HEX_LEN.get(hash_algo)
        if expected_len:
            for key in ("auth", "priv"):
                value = data.get("hashes", {}).get(key)
                if value and len(value) != expected_len:
                    raise RuntimeError(
                        f"snmpv3-hashgen returned {key} hash length {len(value)} "
                        f"for {hash_algo} (expected {expected_len})."
                    )
        return data

    def _resolve_hashgen_command(self) -> Tuple[List[str], Optional[Dict[str, str]]]:
        found = self._find_hashgen()
        if found:
            return found

        print("      snmpv3-hashgen not found.", file=sys.stderr)
        answer = input("      Install SNMPv3-Hash-Generator now? [Y/n]: ").strip().lower()
        if answer not in ("", "y", "yes"):
            raise FileNotFoundError(
                "snmpv3-hashgen is required. Install from "
                "https://github.com/TheMysteriousX/SNMPv3-Hash-Generator and rerun."
            )

        if not self._install_hashgen():
            raise FileNotFoundError("Could not install snmpv3-hashgen automatically.")

        found = self._find_hashgen()
        if not found:
            raise FileNotFoundError("snmpv3-hashgen install finished but the tool is still missing.")
        print("      snmpv3-hashgen installed.", file=sys.stderr)
        return found

    def _find_hashgen(self) -> Optional[Tuple[List[str], Optional[Dict[str, str]]]]:
        project_root = os.path.dirname(os.path.abspath(__file__))
        bundled = os.path.join(
            project_root, "SNMPv3-Hash-Generator", "scripts", "snmpv3_hashgen.py"
        )
        env = self._bundled_env(project_root)
        if os.path.isfile(bundled) and self._probe([sys.executable, bundled], env):
            return [sys.executable, bundled], env

        if os.path.isfile(VENDOR_HASHGEN_ZIP):
            dest = os.path.join(project_root, "SNMPv3-Hash-Generator")
            print("      Extracting snmpv3-hashgen from vendor/ ...", file=sys.stderr)
            if self._extract_hashgen_zip(VENDOR_HASHGEN_ZIP, dest):
                if os.path.isfile(bundled) and self._probe([sys.executable, bundled], env):
                    return [sys.executable, bundled], env

        for cmd in self._path_candidates():
            if self._probe(cmd, None):
                return cmd, None
        return None

    @staticmethod
    def _bundled_env(project_root: str) -> Dict[str, str]:
        package_root = os.path.join(project_root, "SNMPv3-Hash-Generator")
        env = os.environ.copy()
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = package_root + (os.pathsep + existing if existing else "")
        return env

    @staticmethod
    def _path_candidates() -> List[List[str]]:
        names = ["snmpv3-hashgen", "snmpv3_hashgen"]
        if os.name == "nt":
            names.extend(["snmpv3-hashgen.exe", "snmpv3_hashgen.exe"])
        scripts = os.path.join(os.path.dirname(sys.executable), "Scripts")
        cmds = [[name] for name in names]
        cmds.extend([os.path.join(scripts, name)] for name in names)
        return cmds

    def _install_hashgen(self) -> bool:
        dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SNMPv3-Hash-Generator")
        print("      Installing SNMPv3-Hash-Generator...", file=sys.stderr)
        if os.path.isfile(VENDOR_HASHGEN_ZIP) and self._extract_hashgen_zip(VENDOR_HASHGEN_ZIP, dest):
            return True
        if self._clone_hashgen(dest):
            return True
        if self._download_hashgen(dest):
            return True
        return self._pip_install_hashgen()

    def _clone_hashgen(self, dest: str) -> bool:
        if shutil.which("git") is None:
            return False
        try:
            if os.path.isdir(dest) and not os.listdir(dest):
                os.rmdir(dest)
            if os.path.exists(dest):
                return os.path.isfile(os.path.join(dest, "scripts", "snmpv3_hashgen.py"))
            print(f"      Cloning {HASHGEN_REPO} ...", file=sys.stderr)
            subprocess.run(
                ["git", "clone", "--depth", "1", HASHGEN_REPO, dest],
                check=True,
                timeout=PIP_INSTALL_TIMEOUT,
            )
            return os.path.isfile(os.path.join(dest, "scripts", "snmpv3_hashgen.py"))
        except Exception as exc:
            print(f"      git clone failed: {exc}", file=sys.stderr)
            return False

    def _download_hashgen(self, dest: str) -> bool:
        print("      Downloading SNMPv3-Hash-Generator zip...", file=sys.stderr)
        try:
            os.makedirs(os.path.dirname(VENDOR_HASHGEN_ZIP), exist_ok=True)
            urllib.request.urlretrieve(HASHGEN_ZIP_URL, VENDOR_HASHGEN_ZIP)
            return self._extract_hashgen_zip(VENDOR_HASHGEN_ZIP, dest)
        except Exception as exc:
            print(f"      download failed: {exc}", file=sys.stderr)
            return False

    @staticmethod
    def _extract_hashgen_zip(zip_path: str, dest: str) -> bool:
        try:
            with tempfile.TemporaryDirectory() as tmp:
                with zipfile.ZipFile(zip_path) as zf:
                    zf.extractall(tmp)
                extracted = None
                for root, _dirs, files in os.walk(tmp):
                    if "snmpv3_hashgen.py" in files and os.path.basename(root) == "scripts":
                        extracted = os.path.dirname(root)
                        break
                if extracted is None:
                    print("      Zip did not contain snmpv3_hashgen.py.", file=sys.stderr)
                    return False
                if os.path.exists(dest):
                    shutil.rmtree(dest)
                shutil.copytree(extracted, dest)
            return os.path.isfile(os.path.join(dest, "scripts", "snmpv3_hashgen.py"))
        except Exception as exc:
            print(f"      extract failed: {exc}", file=sys.stderr)
            return False

    def _pip_install_hashgen(self) -> bool:
        print("      Falling back to pip install from GitHub...", file=sys.stderr)
        try:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    f"git+{HASHGEN_REPO}",
                ],
                check=True,
                timeout=PIP_INSTALL_TIMEOUT,
            )
            return True
        except Exception as exc:
            print(f"      pip install failed: {exc}", file=sys.stderr)
            return False

    @staticmethod
    def _probe(cmd: List[str], env: Optional[Dict[str, str]]) -> bool:
        if cmd and os.path.isabs(cmd[0]) and not os.path.isfile(cmd[0]):
            return False
        try:
            subprocess.run(
                cmd + ["--help"],
                capture_output=True,
                check=True,
                timeout=HASHGEN_DETECT_TIMEOUT,
                env=env,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False
