"""ANSI color for Windows (VT) and Unix TTYs. Honors NO_COLOR."""
from __future__ import annotations

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[37m"

_vt_done = False


def _enable_windows_vt() -> None:
    """Turn on virtual terminal processing for stdout and stderr (Win10+)."""
    global _vt_done
    if _vt_done or os.name != "nt":
        return
    _vt_done = True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        for handle_id in (-11, -12):
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def enabled(stream=None) -> bool:
    """True when color is safe on this stream."""
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream or sys.stdout
    if not getattr(stream, "isatty", lambda: False)():
        return False
    _enable_windows_vt()
    return True


def paint(text: str, *codes: str, stream=None) -> str:
    """Wrap text in ANSI codes when enabled; otherwise return text."""
    if not codes or not enabled(stream):
        return text
    return "".join(codes) + text + RESET


def ok(text: str = "OK", stream=None) -> str:
    """Color only the status word so a log scrape can still match it."""
    return paint(text, BOLD, GREEN, stream=stream)


def fail(text: str = "Failed", stream=None) -> str:
    """Red bold status word only, so a log scrape still matches the plain text."""
    return paint(text, BOLD, RED, stream=stream)


def warn(text: str, stream=None) -> str:
    """Yellow for warnings, so they stand out from progress lines without hiding the text."""
    return paint(text, BOLD, YELLOW, stream=stream)


def heading(text: str, stream=None) -> str:
    """Bold title and [n/N] step banners, so an operator can find where a long run is or stopped."""
    return paint(text, BOLD, CYAN, stream=stream)


def step(text: str, stream=None) -> str:
    """Menu choice keys (1), 2), ...) in color so the key to press stands out from its label."""
    return paint(text, CYAN, stream=stream)


def dim(text: str, stream=None) -> str:
    """Dim menu descriptions, so the choice name reads first and the hint second."""
    return paint(text, DIM, stream=stream)
