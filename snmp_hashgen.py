import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

from config import HASHGEN_DETECT_TIMEOUT, HASHGEN_TIMEOUT, SNMP_HASH_ALGO

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

        # Catch generators that silently fall back to a weaker algorithm.
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

    def _resolve_hashgen_command(self) -> tuple:
        """Prefer the bundled script, then a PATH install."""
        project_root = os.path.dirname(os.path.abspath(__file__))
        bundled = os.path.join(
            project_root, "SNMPv3-Hash-Generator", "scripts", "snmpv3_hashgen.py"
        )
        package_root = os.path.join(project_root, "SNMPv3-Hash-Generator")

        env = os.environ.copy()
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = package_root + (os.pathsep + existing if existing else "")

        if os.path.isfile(bundled) and self._probe([sys.executable, bundled], env):
            return [sys.executable, bundled], env

        for name in ("snmpv3-hashgen", "snmpv3_hashgen"):
            if self._probe([name], None):
                return [name], None

        raise FileNotFoundError(
            "snmpv3-hashgen not found. Expected bundled copy at "
            f"{bundled} or a PATH install."
        )

    @staticmethod
    def _probe(cmd: List[str], env: Optional[Dict[str, str]]) -> bool:
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
