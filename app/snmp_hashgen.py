"""Step 4: RFC 3414 USM key localization. No external hashgen binary.

For each passphrase (auth, then priv):

  1. Reject passphrases shorter than SNMP_MIN_PASSPHRASE_LEN
  2. Repeat the passphrase until it fills 1 MiB (RFC3414_KDF_LEN)
  3. Ku  = H(that 1 MiB buffer)
  4. Kul = H(Ku || engineID || Ku)   ← this hex string is the USM key

H is SHA-256 by default (CNSA 2.0). MD5 / SHA-1 are rejected.
createUser on the appliance stores Kul; walks use the original
passphrases, not these hashes.
"""
import hashlib
import sys
from typing import Any, Dict

from config import ALLOWED_HASH_ALGOS, RFC3414_KDF_LEN, SNMP_HASH_ALGO, SNMP_MIN_PASSPHRASE_LEN

HASH_HEX_LEN = {
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
        """Step 4: localize *auth* and *priv* against *engine_id*."""
        algo = hash_algo.lower()
        if algo not in ALLOWED_HASH_ALGOS or algo not in HASH_HEX_LEN:
            raise ValueError(
                f"Hash algorithm {hash_algo!r} is not allowed. "
                f"CNSA 2.0 / DISA require one of: {', '.join(ALLOWED_HASH_ALGOS)}"
            )
        auth_hash = self._localize(auth, engine_id, algo)
        priv_hash = self._localize(priv, engine_id, algo)
        print("      Hashed passwords in-process (RFC 3414).", file=sys.stderr)
        data = {
            "user": user,
            "engine": engine_id,
            "hashes": {"auth": auth_hash, "priv": priv_hash},
        }
        return self._check_lengths(data, algo)

    @staticmethod
    def _localize(passphrase: str, engine_id: str, hash_algo: str) -> str:
        if len(passphrase) < SNMP_MIN_PASSPHRASE_LEN:
            raise ValueError(
                f"SNMP passphrase must be at least {SNMP_MIN_PASSPHRASE_LEN} characters"
            )
        digest = getattr(hashlib, hash_algo)
        # Repeat passphrase to exactly 1 MiB, then hash → Ku.
        expanded = (passphrase * ((RFC3414_KDF_LEN // len(passphrase)) + 1))[:RFC3414_KDF_LEN]
        ku = digest(expanded.encode("utf-8")).digest()
        hex_id = engine_id[2:] if engine_id.lower().startswith("0x") else engine_id
        engine = bytes.fromhex(hex_id)
        # Localized key Kul = H(Ku || engineID || Ku).
        return digest(ku + engine + ku).hexdigest()

    @staticmethod
    def _check_lengths(data: Dict[str, Any], hash_algo: str) -> Dict[str, Any]:
        expected_len = HASH_HEX_LEN[hash_algo]
        for key in ("auth", "priv"):
            value = data.get("hashes", {}).get(key)
            if value and len(value) != expected_len:
                raise RuntimeError(
                    f"hash returned {key} length {len(value)} "
                    f"for {hash_algo} (expected {expected_len})."
                )
        return data
