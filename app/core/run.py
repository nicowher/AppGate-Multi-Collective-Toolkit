"""Shared login, inventory, add/replace prompt, and result lines.

Tools pass step banners ([1/4], [2/8], …). One AppGateClient per collective.
"""
from __future__ import annotations

import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from api.appgate import AppGateClient
from config import SSH_LOG_PREVIEW
from core.color import fail as color_fail
from core.color import ok as color_ok
from core.inventory import STATUS_FAILED, STATUS_PENDING, STATUS_PREVIEW, Target, mark_label_collisions, prompt_exclusions
from core.utils import debug_log, halt, print_error
from core.ui import step_banner

ClientMap = Dict[int, AppGateClient]


def ssh_failure(message: str) -> Tuple[str, str]:
    """(code, plain message) for an SSH failure text, or ("", "") when it is not one.

    One list for both, so the code and the wording cannot disagree (they used to
    be two functions with their own keyword lists). It reads the kind tags
    _with_ssh_endpoints puts in its message ("(auth)", "(network)") and the
    words ssh.client.ssh_failure_kind uses, so an unrelated word such as
    snmp_auth cannot match. Order matters: the most specific case first.
    """
    from ssh.client import SSH_FAILURE_WORDS

    low = (message or "").lower()
    word = next((w for w in SSH_FAILURE_WORDS if w.lower() in low), "")
    # print(f"DEBUG failure: {low[:80]!r} word={word!r}")
    if "(cnsa)" in low or "no cnsa-grade" in low or "below the cnsa minimum" in low or "cnsa_strict is on" in low:
        return "E18", "This box offers no CNSA-grade SSH algorithm or host key, and CNSA_STRICT is on."
    if "no ssh address answered" in low:
        tail = f" ({word})" if word else ""
        return "E07", f"No SSH address for this box answered{tail}. Check port 22 and SSHBRUTE on the box."
    if "getaddrinfo" in low or "(no dns)" in low:
        return "", "Hostname does not resolve. Use the SSH IP or fix DNS."
    if "(auth)" in low or "auth failed" in low:
        return "", "SSH login failed. Check username and password."
    if "(hostkey)" in low or "host key" in low:
        return "E07", "SSH host key did not match or was not accepted."
    if "(network)" in low or "timed out" in low or "timeouterror" in low:
        return "", f"Could not reach the box over SSH ({word or 'timed out or no route'}). SSHBRUTE may be rate-limiting this computer."
    return "", ""


def ssh_failure_reason(message: str) -> str:
    """Plain-language reason for an SSH failure, or empty when the message is not one (see ssh_failure)."""
    return ssh_failure(message)[1]


def ssh_failure_code(message: str) -> str:
    """E18, E07 or "" for an SSH failure text (see ssh_failure); a tool's own code applies when empty."""
    return ssh_failure(message)[0]


def _hide_addresses(target: Target, text: str) -> str:
    """Replace this box's SSH addresses in report text with their position (address 1, 2, ...).

    The failure text names every address tried ("No SSH address answered: <host>
    (timed out), <ip> ..."), which would put site hostnames and IPs into a report
    that otherwise leaves them out. The console keeps the full text. Longest
    first, whole tokens only, so 192.0.2.1 never eats part of 192.0.2.10.
    """
    if not text:
        return text
    addrs = [a for a in target.ssh_endpoints() if a]
    pos = {a: i for i, a in enumerate(addrs, 1)}
    for addr in sorted(pos, key=len, reverse=True):
        text = re.sub(
            r"(?<![\w.:-])" + re.escape(addr) + r"(?![\w-]|\.\w|:[0-9a-fA-F]{1,4}:[0-9a-fA-F:])",
            f"address {pos[addr]}",
            text,
        )
    # print(f"DEBUG report: hid {len(pos)} address(es) for {target.label()}")
    return text


def report_target_fields(target: Target, *, label: bool = True, hide_addresses: bool = True) -> Dict[str, Any]:
    """Per-box fields every tool's report shares: label, status, error, detail.

    One place, so a new common field is one edit instead of one per tool. A tool
    adds its own fields to the returned dict. hide_addresses=False is for a
    report that already lists the box's addresses in their own fields (menus 2
    and 4), where hiding them in the error text would hide nothing.
    """
    out: Dict[str, Any] = {}
    if label:
        out["label"] = target.label()
    error, detail = target.error, target.detail
    if hide_addresses:
        error, detail = _hide_addresses(target, error), _hide_addresses(target, detail)
    out.update(status=target.status, code=target.code if target.status == STATUS_FAILED else "", error=error, detail=detail)
    return out


def fail_box(target: Target, human: str, message: str, code: str = "") -> None:
    """Mark a box failed and show it: record, one Failed line, and with DEBUG the technical detail.

    Every tool's _fail used to repeat these three steps; only the wording each
    tool picks for human is its own. The detail never holds a password
    (callers pass exception text).
    """
    import config as _config

    record_failure(target, human, message, code)
    print_result(target, human, ok=False)
    if getattr(_config, "DEBUG", False):
        print(f"      Details: {target.code} {message}".rstrip(), file=sys.stderr)


def record_failure(target: Target, human: str, message: str, code: str = "") -> None:
    """Mark one box failed. error is for the operator; detail keeps the technical reason for the report.

    detail is the SSH or API error text (error kind, step names, box label),
    capped at SSH_LOG_PREVIEW. It holds no password: callers pass exception text,
    which never includes the secrets sent to the box. code (core.errors) is
    shown on the Failed line and kept in the report, so a box failure can be
    looked up in the error table without DEBUG.
    """
    target.status = STATUS_FAILED
    target.error = human
    target.detail = (message or "")[:SSH_LOG_PREVIEW]
    target.code = code or target.code


def rollback_prior(done: list) -> None:
    """A later PUT failed. Restore earlier boxes from the in-memory pre-PUT copy, then stop."""
    for target, client in reversed(done):
        try:
            client.restore_noted(target.appliance_id)
            target.status = STATUS_FAILED
            target.error = "rolled back after a later appliance failed"
            print(f"      {target.label()}: rolled back", file=sys.stderr)
        except Exception as exc:
            target.status = STATUS_FAILED
            target.error = f"rollback failed; this box stayed changed: {exc}"
            print(
                f"      {target.label()}: rollback failed; left changed ({exc})",
                file=sys.stderr,
            )


def login_collectives(collectives: list, *, step: str = "[1/N]") -> ClientMap:
    """POST /admin/login per collective. Fail-soft; halt if none succeed."""
    step_banner(step, "Log in to each Controller API", f"{len(collectives)} Controller{'s' if len(collectives) != 1 else ''}")
    clients: ClientMap = {}
    for col in collectives:
        idx = int(col["index"])
        user = col.get("api_username") or col.get("admin_username") or ""
        password = col.get("api_password") or col.get("admin_password") or ""
        host = col.get("fqdn") or col.get("agip") or ""
        debug_log(f"login: idx={idx} host={host!r} user={user!r}")
        if not user or not password:
            print_error(
                "E02",
                f"[{idx}] LOGIN FAILED: missing api_username/api_password",
                "Set api_username and api_password (global or per collective).",
            )
            continue
        print(f"      [{idx}] {host} as {user}...")
        client = AppGateClient(col.get("fqdn") or "", fallback_ip=col.get("agip") or "")
        try:
            client.login(user, password)
            clients[idx] = client
            print(f"      [{idx}] {color_ok('Authenticated')}")
        except Exception as exc:
            text = str(exc)
            if "No CA file" in text or "not a CA" in text or "Could not verify permissions" in text:
                hints = (
                    "Copy the AppGate .cer to the path in the E06 line. No password was sent.",
                    "INSECURE_API=True skips the file. LAB_MODE does not.",
                )
            else:
                hints = (
                    "Check api_username/api_password and MFA exemption.",
                    "Port 8443 /admin. A bad CA file is E06, not a password error.",
                )
            print_error("E02", f"[{idx}] LOGIN FAILED: {exc}", *hints)
    if not clients:
        halt(
            "E02",
            "No Controller accepted login",
            "If E06 printed a certs\\ path, copy the AppGate .cer there. Otherwise check API creds and port 8443.",
        )
    return clients


def select_appliances(
    clients: ClientMap, *, step: str = "[2/N]", inventory_out: Optional[List[Target]] = None
) -> List[Target]:
    """GET /appliances + status, exclude prompt. Halt if none left.

    inventory_out, when given, receives every selectable appliance, including the
    ones the operator excluded, so a caller can tell a whole collective from part of one.
    """
    step_banner(step, "Read appliances from every Controller")
    inventory: List[Target] = []
    for idx, client in sorted(clients.items()):
        try:
            inventory.extend(
                client.list_targets(
                    collective=idx,
                    fallback_ip=client.fallback_ip,
                    collective_fqdn=client.fqdn,
                )
            )
        except Exception as exc:
            print(f"      [{idx}] list failed: {exc}", file=sys.stderr)
    if not inventory:
        halt(
            "E03",
            "No selectable appliances",
            "Activated boxes with hostname/IP; Appliance View.",
        )
    # Labels must be unique before the table, exclude and backups use them.
    mark_label_collisions(inventory)
    print(f"      Found {len(inventory)} selectable appliance(s)")
    debug_log(f"inventory: n={len(inventory)} collectives={list(clients)}")
    if inventory_out is not None:
        inventory_out.extend(inventory)
    selected = prompt_exclusions(inventory)
    if not selected:
        halt("E04", "Nothing left after exclusions", "Press Enter to keep all.")
    print(f"      Selected {len(selected)} appliance(s)")
    return selected


def preview_then_apply(
    selected: List[Target],
    *,
    preview: Callable[[], None],
    apply: Callable[[List[Target]], None],
    report: Callable[[bool, str], None],
    prompt: str,
    confirm: Optional[Callable[[List[Target]], bool]] = None,
    before_apply: Optional[Callable[[], None]] = None,
    summary: bool = True,
    dry_run_note: bool = True,
) -> bool:
    """The run flow every changing menu shares: preview, confirm, then the live run.

    1. preview(), the preview counts, report(dry_run=True, started_at).
    2. Stop if DRY_RUN is set or nothing would change.
    3. Ask: prompt with {boxes} filled in ("3 boxes"), [y/N], or the tool's own
       confirm(boxes) when it needs more (menu 6 lockout and replace checks).
    4. before_apply(), then every preview box becomes pending, and apply(confirmed)
       runs with exactly those boxes: a tool never decides on its own which
       boxes the live run touches (that is how one menu once wrote boxes the
       confirm had not counted).
    5. The closing counts, and report(dry_run=False, started_at) in a finally,
       so a Ctrl+C mid-run still writes the report.
    Five tools used to repeat this, and the copies drifted (one had no preview
    counts). Returns True when the live run started. summary=False is for a
    tool that prints its own counts (menu 1's table does).
    """
    import config as _config
    from datetime import datetime, timezone

    from core.ui import boxes, run_summary

    started_at = datetime.now(timezone.utc).isoformat()
    preview()
    if summary:
        run_summary(selected, preview=True)
    report(True, started_at)
    if getattr(_config, "DRY_RUN", False):
        if dry_run_note:
            print("      DRY_RUN is set — preview only.", file=sys.stderr)
        return False
    waiting = [t for t in selected if t.status == STATUS_PREVIEW]
    if not waiting:
        return False
    if confirm is not None:
        go = confirm(waiting)
    else:
        answer = input(f"\n      {prompt.format(boxes=boxes(len(waiting)))} [y/N]: ").strip().lower()
        go = answer in _config.YES_ANSWERS
    # print(f"DEBUG flow: confirm={go} n={len(waiting)}")
    if not go:
        return False
    if before_apply is not None:
        before_apply()
    confirmed = []
    for target in selected:
        if target.status == STATUS_PREVIEW:
            target.status = STATUS_PENDING
            target.error = ""
            confirmed.append(target)
    live_started = datetime.now(timezone.utc).isoformat()
    try:
        apply(confirmed)
        if summary:
            run_summary(selected, preview=False)
    finally:
        report(False, live_started)
    return True


def prompt_add_or_replace(
    current_line: str,
    *,
    add_line: str,
    replace_line: str,
    extra: str = "",
) -> bool:
    """True = replace. Q cancels (SystemExit 0)."""
    if current_line:
        print(f"      {current_line}")
    print(f"  1) {add_line}")
    print(f"  2) {replace_line}")
    if extra:
        print(f"      {extra}")
    choice = ""
    while choice not in ("1", "2", "q"):
        choice = input("Select 1, 2, or Q: ").strip().lower()
    if choice == "q":
        print("      Cancelled.")
        raise SystemExit(0)
    return choice == "2"


def print_result(target: Target, extra: str = "", *, ok: bool = True, word: str = "") -> None:
    """One aligned result line per box per step: status word, label, host, then the detail.

    The word is OK or Failed (from ok), or Plan / Skip when word is given. A
    Failed line starts its detail with the box's error code, so it can be looked
    up in the README table without DEBUG. Color only on a terminal.
    """
    # Pad before color so ANSI codes do not shift the host column.
    # word: "Plan" for a preview line, "Skip" for a box left out on purpose. Every
    # per-box line uses this one layout, so a step reads as one aligned table.
    if word:
        from core.color import step as color_step, warn as color_warn

        label = f"{word:<6}"
        status = color_warn(label) if word == "Skip" else color_step(label)
    else:
        label = "OK    " if ok else "Failed"
        status = color_ok(label) if ok else color_fail(label)
    host = target.ssh_fqdn or target.ssh_ip
    if not ok and not word and target.code and not (extra or "").startswith(target.code):
        # The code first, so the line can be looked up in the error table.
        extra = f"{target.code} {extra}".rstrip()
    tail = f"  {extra}" if extra else ""
    print(f"      {status}  {target.label():<32} {host:<22}{tail}".rstrip())
