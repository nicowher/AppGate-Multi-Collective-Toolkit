"""Unit tests for app/snmp_hashgen.py (RFC 3414 / CNSA SHA-256 vectors)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from snmp_hashgen import SNMPHashGenerator  # noqa: E402


class HashgenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gen = SNMPHashGenerator()

    def test_sha256_known_vectors(self) -> None:
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
        data = self.gen.generate_hashes(
            "user", "authpass", "privpass", "8000000001020304"
        )
        self.assertEqual(len(data["hashes"]["auth"]), 64)
        self.assertEqual(len(data["hashes"]["priv"]), 64)
        self.assertNotEqual(data["hashes"]["auth"], data["hashes"]["priv"])

    def test_rejects_md5_and_sha1(self) -> None:
        with self.assertRaises(ValueError):
            self.gen.generate_hashes("user", "authpass", "privpass", "00", hash_algo="md5")
        with self.assertRaises(ValueError):
            self.gen.generate_hashes("user", "authpass", "privpass", "00", hash_algo="sha1")

    def test_rejects_short_passphrase(self) -> None:
        with self.assertRaises(ValueError):
            self.gen._localize("short", "8000000001020304", "sha256")

    def test_0x_prefix_same_as_bare(self) -> None:
        a = self.gen._localize("authpass", "8000000001020304", "sha256")
        b = self.gen._localize("authpass", "0x8000000001020304", "sha256")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
