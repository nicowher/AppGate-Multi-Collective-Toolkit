"""Shared login, inventory, add/replace prompt, and result lines.

Tools pass step banners ([1/4], [2/8], …). One AppGateClient per collective.
"""
from __future__ import annotations

import sys
from typing import Dict, List, Optional

from api.appgate import AppGateClient
from core.color import fail as color_fail
from core.color import heading
from core.color import ok as color_ok
from core.inventory import Target, prompt_exclusions
from core.utils import debug_log, halt, print_error

ClientMap = Dict[int, AppGateClient]


def rollback_prior(done: list) -> None:
    """A later PUT failed. Restore earlier boxes from the in-memory pre-PUT copy, then stop."""
    for target, client in reversed(done):
        try:
            client.restore_noted(target.appliance_id)
            target.status = "failed"
            target.error = "rolled back after a later appliance failed"
            print(f"      {target.label()}: rolled back", file=sys.stderr)
        except Exception as exc:
            target.status = "failed"
            target.error = f"rollback failed; this box stayed changed: {exc}"
            print(
                f"      {target.label()}: rollback failed; left changed ({exc})",
                file=sys.stderr,
            )


def login_collectives(collectives: list, *, step: str = "[1/N]") -> ClientMap:
    """POST /admin/login per collective. Fail-soft; halt if none succeed."""
    print(f"\n{heading(step)} Authenticating to Controller API(s)...")
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
    print(f"\n{heading(step)} Pulling appliances from every Controller...")
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
    print(f"      Found {len(inventory)} selectable appliance(s)")
    debug_log(f"inventory: n={len(inventory)} collectives={list(clients)}")
    if inventory_out is not None:
        inventory_out.extend(inventory)
    selected = prompt_exclusions(inventory)
    if not selected:
        halt("E04", "Nothing left after exclusions", "Press Enter to keep all.")
    print(f"      Selected {len(selected)} appliance(s)")
    return selected


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


def print_result(target: Target, extra: str = "", *, ok: bool = True) -> None:
    """One result line: OK/Failed (color on TTY), label, host, optional extra."""
    # Pad before color so ANSI codes do not shift the host column.
    word = "OK    " if ok else "Failed"
    status = color_ok(word) if ok else color_fail(word)
    host = target.ssh_fqdn or target.ssh_ip
    tail = f"  {extra}" if extra else ""
    print(f"      {status}  {target.label():<32} {host:<22}{tail}".rstrip())
