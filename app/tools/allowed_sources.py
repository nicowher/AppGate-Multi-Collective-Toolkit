"""Allowed sources tool (menu 6).

  1/4  API login
  2/4  inventory / exclude
  3/4  add vs replace
  4/4  GET/PUT existing allowSources arrays (no SSH)

JSON is per appliance function; multi-function boxes inherit both lists
(deduped). Host routes /32 and /128 matching this box's own IPs are dropped.
"""
import ipaddress
import os
import sys

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from api.appgate import AppGateClient, AppliancePutError
from config import (
    DEBUG,
    DRY_RUN,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
    warn_insecure_transport,
)
from core.inventory import Target, prompt_exclusions
from core.prompts import (
    CREDENTIALS_PATH,
    _parse_collectives,
    collective_for_target,
    prepare_collectives,
    resolve_allowed_sources,
)
from core.utils import (
    HaltError,
    begin_replaced_run,
    halt,
    load_credentials,
    print_error,
    write_json_report,
)

ClientMap = Dict[int, AppGateClient]


def _fail(target: Target, message: str) -> None:
    target.status = "failed"
    target.error = message
    print_error(
        "E08",
        f"{target.label()}: {message}",
        "This box is skipped; others continue.",
        "PUT only allowSources on existing interfaces. Check Client Profile View on portals.",
    )


def _login(collectives: list) -> ClientMap:
    print("\n[1/4] Authenticating to Controller API(s)...")
    clients: ClientMap = {}
    for col in collectives:
        idx = int(col["index"])
        user = col.get("api_username") or col.get("admin_username") or ""
        password = col.get("api_password") or col.get("admin_password") or ""
        print(f"      [{idx}] {col.get('fqdn') or col.get('agip')} as {user}...")
        client = AppGateClient(col.get("fqdn") or "", fallback_ip=col.get("agip") or "")
        try:
            client.login(user, password)
            clients[idx] = client
            print(f"      [{idx}] Authenticated")
        except Exception as exc:
            print_error(
                "E02",
                f"[{idx}] LOGIN FAILED: {exc}",
                "API user/password, MFA exemption, port 8443 /admin.",
            )
    if not clients:
        halt("E02", "No Controller logins succeeded", "Fix API credentials and retry.")
    return clients


def _inventory(clients: ClientMap) -> List[Target]:
    print("\n[2/4] Pulling appliances from every Controller...")
    inventory: List[Target] = []
    for idx, client in sorted(clients.items()):
        inventory.extend(client.list_targets(collective=idx))
    if not inventory:
        halt("E03", "No selectable appliances", "Activated boxes with hostname; Appliance View.")
    print(f"      Found {len(inventory)} selectable appliance(s)")
    selected = prompt_exclusions(inventory)
    if not selected:
        halt("E04", "Nothing left after exclusions", "Press Enter to keep all.")
    print(f"      Selected {len(selected)} appliance(s)")
    return selected


def _normalize_source(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    address = str(entry.get("address") or "").strip()
    nic = str(entry.get("nic") or "").strip()
    try:
        netmask = int(entry.get("netmask"))
    except (TypeError, ValueError):
        return {}
    if not address:
        return {}
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
        vmax = 32 if isinstance(ip, ipaddress.IPv4Address) else 128
    except ValueError:
        return {}
    if netmask < 0 or netmask > vmax:
        return {}
    return {"address": str(ip), "netmask": netmask, "nic": nic}


def _source_key(entry: Dict[str, Any]) -> Tuple[str, int, str]:
    return (entry.get("address") or "", int(entry.get("netmask") or -1), entry.get("nic") or "")


def _is_host_route(address: str, netmask: int) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return netmask in (32, 128)
    if isinstance(ip, ipaddress.IPv4Address) and netmask == 32:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and netmask == 128:
        return True
    return False


def _ip_canon(addr: str) -> str:
    try:
        return str(ipaddress.ip_address((addr or "").split("%")[0]))
    except ValueError:
        return (addr or "").strip()


def _drop_self(
    entries: List[Dict[str, Any]], self_ips: List[str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    own = {_ip_canon(ip) for ip in self_ips}
    kept: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []
    for item in entries:
        addr = item.get("address") or ""
        mask = int(item.get("netmask") or -1)
        if _is_host_route(addr, mask) and _ip_canon(addr) in own:
            dropped.append(item)
            continue
        kept.append(item)
    return kept, dropped


def _desired_for_target(target: Target, col: dict) -> List[Dict[str, Any]]:
    src = col.get("allowed_sources") or {}
    if not isinstance(src, dict):
        return []
    lower = {str(k).replace(" ", "").lower(): v for k, v in src.items()}
    seen = set()
    out: List[Dict[str, Any]] = []
    for fn in target.functions:
        rows = src.get(fn) or lower.get(fn.lower()) or []
        if not isinstance(rows, list):
            continue
        for raw in rows:
            item = _normalize_source(raw)
            if not item:
                continue
            key = _source_key(item)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out


def _fmt(entries: List[Dict[str, Any]]) -> str:
    if not entries:
        return "(none)"
    return ", ".join(
        f"{e.get('address')}/{e.get('netmask')}"
        + (f"@{e.get('nic')}" if e.get("nic") else "")
        for e in entries
    )


def _prompt_merge_mode(clients: ClientMap, selected: List[Target]) -> bool:
    sample = selected[0]
    client = clients.get(int(sample.collective))
    current: List[Dict[str, Any]] = []
    if client is not None:
        try:
            current = client.peek_allow_sources(sample.appliance_id)
        except Exception as exc:
            print(f"      Could not read current allowSources: {exc}", file=sys.stderr)
    print(f"      Current allowSources on {sample.label()}: {_fmt(current)}")
    print("  1) Add (append per interface, skip duplicates)")
    print("  2) Replace (same list on every existing allowSources array)")
    print("      Replace does not create new interface objects. Backup goes to reports/replaced/.")
    choice = ""
    while choice not in ("1", "2", "q"):
        choice = input("Select 1, 2, or Q: ").strip().lower()
    if choice == "q":
        print("      Cancelled.")
        raise SystemExit(0)
    return choice == "2"


def _apply(
    selected: List[Target],
    clients: ClientMap,
    collectives: list,
    *,
    overwrite: bool,
    dry_run: bool,
) -> None:
    print("\n[4/4] Updating allowSources via Controller API...")
    if overwrite and not dry_run:
        begin_replaced_run()
    for target in selected:
        if target.status == "failed":
            continue
        col = collective_for_target(target, collectives)
        desired = _desired_for_target(target, col)
        desired, dropped = _drop_self(desired, target.self_ips)
        if dropped:
            print(
                f"      {target.label()}: excluded self /32|/128 {_fmt(dropped)}",
                file=sys.stderr,
            )
        if not target.functions:
            _fail(target, "no appliance functions; nothing to inherit")
            continue
        if not desired:
            _fail(target, "no allowed_sources left after function merge / exclude-self")
            continue
        if dry_run:
            mode = "replace" if overwrite else "add"
            # print(f"DEBUG allow: {target.label()} {mode} desired={desired!r} dropped={dropped!r}")
            print(f"      {target.label()}: would {mode} {_fmt(desired)}")
            target.status = "preview"
            continue
        client = clients.get(int(target.collective))
        if client is None:
            _fail(target, "no API client for this collective")
            continue
        try:
            merged = client.update_allow_sources(
                target.appliance_id,
                desired,
                overwrite=overwrite,
                snapshot_label=target.label(),
            )
            target.status = "ok"
            host = target.ssh_fqdn or target.ssh_ip
            print(
                f"      [{'PASSED':<7}] {target.label():<32} {host:<22} "
                f"allowSources {len(merged)}"
            )
            # print(f"DEBUG allow: {target.label()} merged={merged!r}")
        except AppliancePutError as exc:
            _fail(target, str(exc))
        except Exception as exc:
            _fail(target, str(exc))


def _emit_report(
    collectives: list,
    selected: List[Target],
    *,
    overwrite: bool,
    dry_run: bool,
    started_at: str,
) -> None:
    if not (WRITE_RUN_REPORT or DEBUG):
        return
    report = {
        "script": "allowed-sources",
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "overwrite": overwrite,
        "ok_count": sum(1 for t in selected if t.status == "ok"),
        "preview_count": sum(1 for t in selected if t.status == "preview"),
        "failed_count": sum(1 for t in selected if t.status == "failed"),
        "collectives": [
            {"index": int(c["index"]), "fqdn": c.get("fqdn", ""), "agip": c.get("agip", "")}
            for c in collectives
        ],
        "targets": [
            {
                "label": t.label(),
                "functions": t.functions,
                "self_ips": t.self_ips,
                "status": t.status,
                "error": t.error,
            }
            for t in selected
        ],
    }
    write_json_report("allowed-sources", report)


def main() -> None:
    warn_insecure_transport()
    creds = load_credentials(CREDENTIALS_PATH)
    collectives = _parse_collectives(creds)
    if not collectives:
        halt(
            "E01",
            "No collectives defined (collectives[] or agip)",
            "Add collectives[].fqdn to credentials.json or enter when prompted.",
        )
    prepare_collectives(creds, collectives, need_ssh=False)
    any_src = False
    for col in collectives:
        col["allowed_sources"] = resolve_allowed_sources(col, creds)
        if col.get("allowed_sources"):
            any_src = True
    if not any_src:
        halt(
            "E19",
            "No allowed_sources in credentials.json",
            "Add allowed_sources.<function>[] with address, netmask, nic.",
        )
    clients = _login(collectives)
    selected = _inventory(clients)
    overwrite = _prompt_merge_mode(clients, selected)
    dry_run = DRY_RUN
    if not dry_run:
        answer = input("\n      Dry-run only (preview, no PUT)? [y/N]: ").strip().lower()
        dry_run = answer in YES_ANSWERS
    started_at = datetime.now(timezone.utc).isoformat()
    _apply(selected, clients, collectives, overwrite=overwrite, dry_run=dry_run)
    _emit_report(
        collectives, selected, overwrite=overwrite, dry_run=dry_run, started_at=started_at
    )
    if dry_run and any(t.status == "preview" for t in selected):
        apply = input("\n      Apply allowSources now? [y/N]: ").strip().lower()
        if apply in YES_ANSWERS:
            for target in selected:
                if target.status == "preview":
                    target.status = "pending"
                    target.error = ""
            live_started = datetime.now(timezone.utc).isoformat()
            _apply(selected, clients, collectives, overwrite=overwrite, dry_run=False)
            _emit_report(
                collectives,
                selected,
                overwrite=overwrite,
                dry_run=False,
                started_at=live_started,
            )
    if any(t.status == "failed" for t in selected):
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        raise
    except HaltError:
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
