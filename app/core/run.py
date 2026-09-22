"""Shared login, inventory, add/replace prompt, and result lines.

Tools pass step banners ([1/4], [2/8], …). One AppGateClient per collective.
"""
from __future__ import annotations

import sys
from typing import Dict, List

from api.appgate import AppGateClient
from core.inventory import Target, prompt_exclusions
from core.utils import debug_log, halt, print_error

ClientMap = Dict[int, AppGateClient]


def login_collectives(collectives: list, *, step: str = "[1/N]") -> ClientMap:
    """POST /admin/login per collective. Fail-soft; halt if none succeed."""
    print(f"\n{step} Authenticating to Controller API(s)...")
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
            print(f"      [{idx}] Authenticated")
        except Exception as exc:
            print_error(
                "E02",
                f"[{idx}] LOGIN FAILED: {exc}",
                "Check api_username/api_password and MFA exemption.",
                "Self-signed: answer y on Proceed anyway, or LAB_MODE=True.",
            )
    if not clients:
        halt(
            "E02",
            "No Controller accepted login",
            "Fix API creds, TLS, or agip. https://<fqdn>:8443/admin.",
        )
    return clients


def select_appliances(clients: ClientMap, *, step: str = "[2/N]") -> List[Target]:
    """GET /appliances + status, exclude prompt. Halt if none left."""
    print(f"\n{step} Pulling appliances from every Controller...")
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
    state = "PASSED" if ok else "FAILED"
    host = target.ssh_fqdn or target.ssh_ip
    tail = f" {extra}" if extra else ""
    print(f"      [{state:<7}] {target.label():<32} {host:<22}{tail}".rstrip())
