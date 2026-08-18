import json
import os
import subprocess
import sys
from typing import Any, Dict


class SNMPHashGenerator:
    # ========================================================================
    # FIPS 140-3 / CNSA 2.0 Approved Hash Algorithms
    # ========================================================================
    # SNMPv3-usuable hash algorithms for USM key derivation:
    #   md5    -> 32 hex chars  (deprecated, not CNSA 2.0)
    #   sha1   -> 40 hex chars  (deprecated, not CNSA 2.0)
    #   sha224 -> 56 hex chars  (CNSA 2.0)
    #   sha256 -> 64 hex chars  (CNSA 2.0, preferred)
    #   sha384 -> 96 hex chars  (CNSA 2.0)
    #   sha512 -> 128 hex chars (CNSA 2.0)
    #
    # Default is sha256 (lowest CNSA 2.0-approved algorithm with widest
    # appliance support). The hash algorithm MUST match the createUser line
    # in appgate.py and the SNMP walk validation protocols.
    # ========================================================================
    FIPS_HASH_ALGOS = ("sha224", "sha256", "sha384", "sha512")

    def generate_hashes(self, user: str, auth: str, priv: str, engine_id: str, hash_algo: str = "sha256") -> Dict[str, Any]:
        """Execute snmpv3-hashgen and return the parsed JSON output.

        Args:
            user: SNMPv3 username
            auth: Authentication passphrase (plaintext)
            priv: Privacy passphrase (plaintext)
            engine_id: Hex engine ID string (with or without 0x prefix)
            hash_algo: Hash algorithm — must match SNMP_HASH_ALGO in config.py
        """
        script_path = self._resolve_hashgen_script()

        # If the resolved tool is a Python script, invoke it with the current
        # interpreter so the correct venv is used.
        if script_path.endswith(".py"):
            cmd = [sys.executable, script_path]
        else:
            cmd = [script_path]

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
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=15)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"snmpv3-hashgen failed (rc={exc.returncode}). "
                f"stderr: {exc.stderr.strip()[:500]}"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"snmpv3-hashgen executable not found: {cmd[0]}. "
                "Ensure it is installed and in PATH."
            ) from exc

        data = json.loads(result.stdout)

        # ====================================================================
        # Sanity check: verify hash length matches the requested algorithm.
        # This catches installed hash generators that silently fall back to
        # a different algorithm (e.g., sha1 instead of sha256).
        # ====================================================================
        expected_len = {"md5": 32, "sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128}.get(hash_algo)
        if expected_len:
            for key in ("auth", "priv"):
                if data.get("hashes", {}).get(key) and len(data["hashes"][key]) != expected_len:
                    raise RuntimeError(
                        f"snmpv3-hashgen returned {key} hash with unexpected length "
                        f"{len(data['hashes'][key])} for {hash_algo} (expected {expected_len}). "
                        f"The installed hash generator may not support {hash_algo}."
                    )
        return data

    @staticmethod
    def _resolve_hashgen_script() -> str:
        """Locate the snmpv3-hashgen CLI script."""
        workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates = [
            "snmpv3-hashgen",
            "snmpv3_hashgen",
            os.path.join(workspace_root, "SNMPv3-Hash-Generator", "scripts", "snmpv3_hashgen.py"),
        ]

        for candidate in candidates:
            try:
                if candidate.endswith(".py"):
                    subprocess.run(
                        [sys.executable, candidate, "--help"],
                        capture_output=True,
                        check=True,
                        timeout=3,
                    )
                    return candidate
                subprocess.run(
                    [candidate, "--help"],
                    capture_output=True,
                    check=True,
                    timeout=5,
                )
                return candidate
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue

        raise FileNotFoundError(
            f"snmpv3-hashgen tool not found. Checked: {candidates}. "
            "Ensure it is installed and in PATH."
        )
