"""Console layout: step banners and the end-of-run summary.

Why one module: every menu used to word its banners and closing lines its own way,
so a long run was hard to scan. Result lines per box stay in core.run.print_result
(one line per box per step); this file holds the parts around them.
"""
import builtins
import sys
import time
from typing import Iterable

from config import SUMMARY_WIDTH
from core.color import dim, fail, heading
from core.inventory import STATUS_FAILED, STATUS_OK, STATUS_PREVIEW, STATUS_UNCHANGED


# DEBUG step timing: (step label, start time, prompt wait so far) of the step now running.
_step_started = None
# Seconds spent waiting at input() in this process; the step clock leaves it out.
_prompt_wait = 0.0
_builtin_input = builtins.input


def input(prompt: object = "") -> str:  # noqa: A001 - named input so main's Ctrl+C check sees a prompt frame
    """input() that counts how long it waited, so DEBUG step times show the toolkit's own work.

    Installed as builtins.input when this module loads. The name stays "input"
    because main._in_stdin_wait looks for that frame name to tell a Ctrl+C at a
    prompt from one during work.
    """
    global _prompt_wait
    started = time.monotonic()
    try:
        return _builtin_input(prompt)
    finally:
        _prompt_wait += time.monotonic() - started


builtins.input = input


def _debug_step_done() -> None:
    """DEBUG: how long the step that just ended took (slow Controller, SSHBRUTE, near-timeouts)."""
    global _step_started
    import config as _config

    if _step_started and getattr(_config, "DEBUG", False):
        label, t0, waited0 = _step_started
        waited = _prompt_wait - waited0
        work = time.monotonic() - t0 - waited
        tail = f" (plus {waited:.1f} s at prompts)" if waited >= 0.05 else ""
        # print(f"DEBUG ui: step {label} raw={time.monotonic() - t0:.2f}s prompts={waited:.2f}s")
        print(f"      DEBUG {label} took {work:.1f} s{tail}", file=sys.stderr)
    _step_started = None


def step_banner(step: str, title: str, detail: str = "") -> None:
    """A thin rule, then "[n/N] Title  detail", so each step starts where the eye expects it.

    detail is the scope (box count, parallelism) in dim text. ASCII only, because
    some Windows consoles still use a code page without box-drawing characters.
    With DEBUG, the previous step's duration is printed first; a [1/N] banner
    starts a new run, so no stale time from an earlier menu run is shown.
    """
    global _step_started
    if step.startswith("[1/"):
        _step_started = None
    _debug_step_done()
    _step_started = (step, time.monotonic(), _prompt_wait)
    print()
    print(dim("-" * SUMMARY_WIDTH))
    tail = f"  {dim(detail)}" if detail else ""
    print(f"{heading(step)} {title}{tail}")


def boxes(n: int) -> str:
    """'1 box' or '3 boxes', for banners and prompts."""
    return f"{n} box" if n == 1 else f"{n} boxes"


def run_summary(targets: Iterable, *, preview: bool, list_failed: bool = True) -> None:
    """End of a menu run: one counts line, then one line per failed box with its code.

    Before, the operator scrolled back through every step to find what failed.
    The reasons are the same plain text the Failed lines showed; the code can be
    looked up in the README error table.
    """
    _debug_step_done()
    items = list(targets)
    count = {}
    for t in items:
        count[t.status] = count.get(t.status, 0) + 1
    if preview:
        parts = [
            f"{count.get(STATUS_PREVIEW, 0)} would change",
            f"{count.get(STATUS_UNCHANGED, 0)} already set",
            f"{count.get(STATUS_FAILED, 0)} failed",
        ]
        head = "Preview"
    else:
        parts = [
            f"{count.get(STATUS_OK, 0)} OK",
            f"{count.get(STATUS_FAILED, 0)} failed",
            f"{count.get(STATUS_UNCHANGED, 0)} already set",
        ]
        other = sum(v for k, v in count.items() if k not in ("ok", "failed", "unchanged"))
        if other:
            # pending/preview left after a stop: these boxes were not reached.
            parts.append(f"{other} not reached")
        head = "Done"
    # Drop zero counts except the first, so the line stays short.
    shown = [parts[0]] + [p for p in parts[1:] if not p.startswith("0 ")]
    print()
    print(dim("-" * SUMMARY_WIDTH))
    print(f"{heading(head + ':')} " + ", ".join(shown))
    if not list_failed:
        return
    for t in items:
        if t.status != STATUS_FAILED:
            continue
        code = f"{t.code} " if getattr(t, "code", "") else ""
        print(f"      {fail('Failed', stream=sys.stdout)}  {t.label():<28} {code}{t.error}")
