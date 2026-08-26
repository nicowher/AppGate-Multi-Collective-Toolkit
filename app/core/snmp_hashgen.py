"""Step 5: RFC 3414 USM key localization (in-process, no external binary).

Lives in ``core/`` — used by ``tools/snmp_credentials.py``, not by the API.


Why localize at all: net-snmp createUser with -l expects Kul (localized key),
not the human passphrase. Kul is bound to that appliance's engine ID, so the
same password yields different hex on every box — required for multi-appliance.

For each passphrase (auth, then priv):

  1. Reject short passphrases (DISA/CNSA floor via SNMP_MIN_PASSPHRASE_LEN)
  2. Expand passphrase to 1 MiB (RFC 3414)
  3. Ku  = H(expanded)
  4. Kul = H(Ku || engineID || Ku)  ← hex stored in createUser

H defaults to SHA-256 (CNSA 2.0). MD5/SHA-1 rejected. Walks still use the
original passphrases; only the agent stores Kul.
"""
import hashlib
import sys
from typing import Any, Dict

from config import (
    ALLOWED_HASH_ALGOS,
    DEBUG,
    ENGINE_ID_MAX_OCTETS,
    ENGINE_ID_MIN_OCTETS,
    RFC3414_KDF_LEN,
    SNMP_HASH_ALGO,
    SNMP_MIN_PASSPHRASE_LEN,
)

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
        """Step 5: localize *auth* and *priv* against *engine_id*."""
        algo = hash_algo.lower()
        if algo not in ALLOWED_HASH_ALGOS or algo not in HASH_HEX_LEN:
            raise ValueError(
                f"Hash algorithm {hash_algo!r} is not allowed. "
                f"CNSA 2.0 / DISA require one of: {', '.join(ALLOWED_HASH_ALGOS)}"
            )
        # print(f"DEBUG step5: user={user!r} algo={algo} engine_len={len(engine_id or '')}")
        if DEBUG:
            print(
                f"      DEBUG step5: localizing {user!r} with {algo} "
                f"(engine_id {len(engine_id or '')} hex chars)",
                file=sys.stderr,
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
        if not passphrase or len(passphrase) < SNMP_MIN_PASSPHRASE_LEN:
            raise ValueError(
                f"SNMP passphrase must be at least {SNMP_MIN_PASSPHRASE_LEN} characters"
            )
        digest = getattr(hashlib, hash_algo)
        # Repeat passphrase to exactly 1 MiB, then hash → Ku.
        expanded = (passphrase * ((RFC3414_KDF_LEN // len(passphrase)) + 1))[:RFC3414_KDF_LEN]
        ku = digest(expanded.encode("utf-8")).digest()
        engine = _engine_id_bytes(engine_id)
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


def _engine_id_bytes(engine_id: str) -> bytes:
    """Parse an SNMP engine ID. Reject empty / odd / non-hex / out-of-range (RFC 3411)."""
    hex_id = (engine_id or "").strip()
    if hex_id.lower().startswith("0x"):
        hex_id = hex_id[2:]
    if not hex_id or len(hex_id) % 2:
        raise ValueError(f"Invalid SNMP engine ID (empty or odd-length hex): {engine_id!r}")
    try:
        raw = bytes.fromhex(hex_id)
    except ValueError as exc:
        raise ValueError(f"Invalid SNMP engine ID hex: {engine_id!r}") from exc
    if not (ENGINE_ID_MIN_OCTETS <= len(raw) <= ENGINE_ID_MAX_OCTETS):
        raise ValueError(
            f"SNMP engine ID length {len(raw)} octets is outside RFC 3411 "
            f"range {ENGINE_ID_MIN_OCTETS}-{ENGINE_ID_MAX_OCTETS}"
        )
    return raw
