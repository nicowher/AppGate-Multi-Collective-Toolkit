"""Unit tests for app/core/snmp_hashgen.py (RFC 3414 / CNSA SHA-256 vectors)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from core.snmp_hashgen import SNMPHashGenerator  # noqa: E402


class HashgenTests(unittest.TestCase):
    """RFC 3414 localization must match known vectors and refuse weak input, because a wrong key fails silently on the box."""
    def setUp(self) -> None:
        """A fresh generator per test, so no state carries between vectors."""
        self.gen = SNMPHashGenerator()

    def test_sha256_known_vectors(self) -> None:
        """Fixed SHA-256 localization outputs (RFC 3414 method; maplesyrup is the RFC 7860 vector). A change here means keys pushed by older runs would no longer match."""
        self.assertEqual(
            self.gen._localize("authpass", "8000000001020304", "sha256"),
            "16253b02ee093dec5ed435737ab098dff3f1d5aa8f4654d635f7eed51b9fc18c",
        )
        self.assertEqual(
            self.gen._localize("privpass", "8000000001020304", "sha256"),
            "aaec915c835af193f6b248e481420807a80dccd3d07a39abea056e062217dfd2",
        )
        self.assertEqual(
            self.gen._localize("maplesyrup", "8000000000000000", "sha256"),
            "ef8bc5ecc34c1de5f63c8bcf07027ca73c60771b44bee8e37320c0a0913317f2",
        )

    def test_generate_hashes_lengths(self) -> None:
        """Auth key is full digest length and the AES-256 priv key is 32 bytes, as snmpd expects."""
        data = self.gen.generate_hashes(
            "user", "authpassphrase15", "privpassphrase15", "8000000001020304"
        )
        self.assertEqual(len(data["hashes"]["auth"]), 128)
        # AES-256 privacy uses the first 32 bytes of the localized key (64 hex).
        self.assertEqual(len(data["hashes"]["priv"]), 64)
        self.assertNotEqual(data["hashes"]["auth"], data["hashes"]["priv"])

    def test_rejects_md5_and_sha1(self) -> None:
        """Weak hash algorithms are refused (DISA/CNSA)."""
        with self.assertRaises(ValueError):
            self.gen.generate_hashes("user", "authpass", "privpass", "00", hash_algo="md5")
        with self.assertRaises(ValueError):
            self.gen.generate_hashes("user", "authpass", "privpass", "00", hash_algo="sha1")

    def test_rejects_short_passphrase(self) -> None:
        """Short passphrases are refused before any key is made."""
        with self.assertRaises(ValueError):
            self.gen._localize("short", "8000000001020304", "sha256")
        with self.assertRaises(ValueError):
            self.gen.generate_hashes("user", "short", "short", "8000000001020304")

    def test_0x_prefix_same_as_bare(self) -> None:
        """An engine ID with or without 0x must give the same key."""
        a = self.gen._localize("authpass", "8000000001020304", "sha256")
        b = self.gen._localize("authpass", "0x8000000001020304", "sha256")
        self.assertEqual(a, b)

    def test_rejects_empty_and_non_hex_engine(self) -> None:
        """A bad engine ID must fail, not produce a key for the wrong box."""
        with self.assertRaises(ValueError):
            self.gen._localize("authpass", "", "sha256")
        with self.assertRaises(ValueError):
            self.gen._localize("authpass", "zz", "sha256")
        with self.assertRaises(ValueError):
            self.gen._localize("authpass", "00", "sha256")


if __name__ == "__main__":
    unittest.main()
