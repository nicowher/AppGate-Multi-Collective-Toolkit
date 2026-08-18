import hashlib
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

# RFC 3414 password-to-key expansion length.
_KDF_LEN = 1048576


class SNMPHashGenerator:
    def generate_hashes(
        self,
        user: str,
        auth: str,
        priv: str,
        engine_id: str,
        hash_algo: str = SNMP_HASH_ALGO,
    ) -> Dict[str, Any]:
        """Return localized SNMPv3 auth/priv keys.

        Hashes in-process (no PATH). Optionally installs the upstream
        generator so a later CLI fallback can work.
        """
        data = self._hash_inprocess(user, auth, priv, engine_id, hash_algo)
        if data:
            return self._check_lengths(data, hash_algo)

        print("      In-process hash unavailable. Trying snmpv3-hashgen CLI...", file=sys.stderr)
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
                f"snmpv3-hashgen executable not found: {cmd[0]}."
            ) from exc
        return self._check_lengths(json.loads(result.stdout), hash_algo)

    def _hash_inprocess(
        self,
        user: str,
        auth: str,
        priv: str,
        engine_id: str,
        hash_algo: str,
    ) -> Optional[Dict[str, Any]]:
        """RFC 3414 localize using hashlib. Does not need snmpv3-hashgen on PATH."""
        if hash_algo not in HASH_HEX_LEN:
            return None
        try:
            auth_hash = self._localize(auth, engine_id, hash_algo)
            priv_hash = self._localize(priv, engine_id, hash_algo)
        except ValueError as exc:
            print(f"      In-process hash failed: {exc}", file=sys.stderr)
            return None
        print("      Hashed passwords in-process (no external tool).", file=sys.stderr)
        return {
            "user": user,
            "engine": engine_id,
            "hashes": {"auth": auth_hash, "priv": priv_hash},
        }

    @staticmethod
    def _localize(passphrase: str, engine_id: str, hash_algo: str) -> str:
        digest = getattr(hashlib, hash_algo)
        expanded = (passphrase * ((_KDF_LEN // len(passphrase)) + 1))[:_KDF_LEN].encode("utf-8")
        ku = digest(expanded).digest()
        engine = bytes.fromhex(engine_id[2:] if engine_id.lower().startswith("0x") else engine_id)
        return digest(ku + engine + ku).hexdigest()

    @staticmethod
    def _check_lengths(data: Dict[str, Any], hash_algo: str) -> Dict[str, Any]:
        expected_len = HASH_HEX_LEN.get(hash_algo)
        if expected_len:
            for key in ("auth", "priv"):
                value = data.get("hashes", {}).get(key)
                if value and len(value) != expected_len:
                    raise RuntimeError(
                        f"hash returned {key} length {len(value)} "
                        f"for {hash_algo} (expected {expected_len})."
                    )
        return data

    def _resolve_hashgen_command(self) -> Tuple[List[str], Optional[Dict[str, str]]]:
        found = self._find_hashgen()
        if found:
            return found

        print("      snmpv3-hashgen CLI not found.", file=sys.stderr)
        answer = input("      Install SNMPv3-Hash-Generator now? [Y/n]: ").strip().lower()
        if answer not in ("", "y", "yes"):
            raise FileNotFoundError(
                "snmpv3-hashgen is required. Run python download_deps.py on a networked box."
            )

        if not self._install_hashgen():
            raise FileNotFoundError("Could not install snmpv3-hashgen automatically.")

        found = self._find_hashgen()
        if not found:
            raise FileNotFoundError(
                "snmpv3-hashgen files installed but the CLI is still not runnable. "
                "In-process hashing should have been used instead."
            )
        print("      snmpv3-hashgen installed.", file=sys.stderr)
        return found

    def _find_hashgen(self) -> Optional[Tuple[List[str], Optional[Dict[str, str]]]]:
        project_root = os.path.dirname(os.path.abspath(__file__))
        dest = os.path.join(project_root, "SNMPv3-Hash-Generator")
        bundled = os.path.join(dest, "scripts", "snmpv3_hashgen.py")
        env = self._bundled_env(project_root)

        if os.path.isfile(VENDOR_HASHGEN_ZIP) and not os.path.isfile(bundled):
            print("      Extracting snmpv3-hashgen from vendor/ ...", file=sys.stderr)
            self._extract_hashgen_zip(VENDOR_HASHGEN_ZIP, dest)

        if os.path.isfile(bundled):
            if self._probe([sys.executable, bundled], env):
                return [sys.executable, bundled], env
            print(
                f"      Found {bundled} but --help failed (import/PATH). "
                "Will hash in-process if possible.",
                file=sys.stderr,
            )

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
        roots = [
            os.path.join(os.path.dirname(sys.executable), "Scripts"),
            os.path.join(sys.prefix, "Scripts"),
            os.path.join(
                os.environ.get("APPDATA", ""),
                "Python",
                f"Python{sys.version_info.major}{sys.version_info.minor}",
                "Scripts",
            ),
        ]
        cmds = [[name] for name in names]
        for root in roots:
            if not root:
                continue
            cmds.extend([os.path.join(root, name)] for name in names)
        return cmds

    def _install_hashgen(self) -> bool:
        dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SNMPv3-Hash-Generator")
        script = os.path.join(dest, "scripts", "snmpv3_hashgen.py")
        print("      Installing SNMPv3-Hash-Generator into the project folder...", file=sys.stderr)
        if os.path.isfile(VENDOR_HASHGEN_ZIP) and self._extract_hashgen_zip(VENDOR_HASHGEN_ZIP, dest):
            return os.path.isfile(script)
        if self._clone_hashgen(dest):
            return os.path.isfile(script)
        if self._download_hashgen(dest):
            return os.path.isfile(script)
        if self._pip_install_hashgen():
            return self._find_hashgen() is not None
        return False

    def _clone_hashgen(self, dest: str) -> bool:
        if shutil.which("git") is None:
            print("      git not on PATH; skipping clone.", file=sys.stderr)
            return False
        try:
            if os.path.isdir(dest) and not os.listdir(dest):
                os.rmdir(dest)
            if os.path.isfile(os.path.join(dest, "scripts", "snmpv3_hashgen.py")):
                return True
            if os.path.exists(dest):
                print(f"      {dest} already exists and is incomplete; trying zip instead.", file=sys.stderr)
                return False
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
            ok = os.path.isfile(os.path.join(dest, "scripts", "snmpv3_hashgen.py"))
            if ok:
                print(f"      Extracted hashgen to {dest}", file=sys.stderr)
            return ok
        except Exception as exc:
            print(f"      extract failed: {exc}", file=sys.stderr)
            return False

    def _pip_install_hashgen(self) -> bool:
        print("      Falling back to pip install from GitHub...", file=sys.stderr)
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", f"git+{HASHGEN_REPO}"],
                check=True,
                timeout=PIP_INSTALL_TIMEOUT,
            )
            return True
        except Exception as exc:
            print(f"      pip install failed: {exc}", file=sys.stderr)
            return False

    @staticmethod
    def _probe(cmd: List[str], env: Optional[Dict[str, str]]) -> bool:
        if cmd and (os.path.isabs(cmd[0]) or os.path.dirname(cmd[0])) and not os.path.isfile(cmd[0]):
            return False
        try:
            result = subprocess.run(
                cmd + ["--help"],
                capture_output=True,
                text=True,
                timeout=HASHGEN_DETECT_TIMEOUT,
                env=env,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
