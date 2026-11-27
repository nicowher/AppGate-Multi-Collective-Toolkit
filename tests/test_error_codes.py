"""Error codes: the code, the registry and the README table must list the same set.

Codes used to drift: the README documented codes nothing printed, and a comment
named a code nothing defined. These tests read the source as text, so they need
no Controller, SSH host or credentials.
"""
import glob
import os
import re
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
APP = os.path.join(ROOT, "app")
sys.path.insert(0, APP)

from core.errors import CODES  # noqa: E402

# A code passed as a value: "E07" as a whole string literal.
_CODE_LITERAL = re.compile(r"""["'](E\d{2})["']""")
_README_ROW = re.compile(r"^\| \*\*(E\d{2})\*\* \|", re.M)


def _used_codes() -> set:
    """Codes the toolkit passes to halt, print_error, record_failure or target.code."""
    used = set()
    for path in glob.glob(os.path.join(APP, "**", "*.py"), recursive=True):
        norm = path.replace("\\", "/")
        if "/vendor/" in norm or norm.endswith("core/errors.py"):
            continue
        with open(path, encoding="utf-8") as fh:
            used |= set(_CODE_LITERAL.findall(fh.read()))
    return used


def _readme_codes() -> set:
    """Codes that have a row in the README error table."""
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        return set(_README_ROW.findall(fh.read()))


class ErrorCodeTests(unittest.TestCase):
    """Every code is registered, documented and used, so the operator's lookup always works."""

    def test_used_codes_are_registered(self) -> None:
        """A code printed to the operator must have a title and a default hint."""
        self.assertEqual(sorted(_used_codes() - set(CODES)), [])

    def test_registered_codes_are_used(self) -> None:
        """A registered code nothing prints is a table row an operator will never see."""
        self.assertEqual(sorted(set(CODES) - _used_codes()), [])

    def test_readme_matches_registry(self) -> None:
        """The README table and the registry list the same codes."""
        self.assertEqual(sorted(_readme_codes() ^ set(CODES)), [])

    def test_every_code_has_title_and_hint(self) -> None:
        """An empty title or hint would print a bare code with nothing to do."""
        for code, (title, hint) in CODES.items():
            self.assertTrue(title and hint, code)


if __name__ == "__main__":
    unittest.main()
