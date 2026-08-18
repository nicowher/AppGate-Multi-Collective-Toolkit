import hashlib
import sys
from typing import Any, Dict

from config import SNMP_HASH_ALGO

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
        """Return localized SNMPv3 auth/priv keys (RFC 3414, in-process)."""
        if hash_algo not in HASH_HEX_LEN:
            raise ValueError(f"Unsupported hash algorithm: {hash_algo}")
        auth_hash = self._localize(auth, engine_id, hash_algo)
        priv_hash = self._localize(priv, engine_id, hash_algo)
        print("      Hashed passwords in-process (no external tool).", file=sys.stderr)
        data = {
            "user": user,
            "engine": engine_id,
            "hashes": {"auth": auth_hash, "priv": priv_hash},
        }
        return self._check_lengths(data, hash_algo)

    @staticmethod
    def _localize(passphrase: str, engine_id: str, hash_algo: str) -> str:
        if not passphrase:
            raise ValueError("SNMP passphrase must be non-empty")
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
