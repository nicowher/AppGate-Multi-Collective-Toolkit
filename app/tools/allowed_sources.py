"""Allowed sources tool (menu 6).

  1/4  API login
  2/4  inventory / exclude
  3/4  add vs replace
  4/4  GET/PUT existing allowSources arrays (no SSH)

JSON is per appliance type, then slot (ssh, spa, admin, https, ping, snmp).
Each slot is address/netmask/nic. Multi-function boxes merge per slot.
Host routes /32 and /128 matching this box's own IPs are dropped.
Replace: E20 if this workstation would miss new SSH/Admin/SPA HTTPS CIDRs
(any prefix length); then two-step confirm (y, then YES) — confirm is not optional.
"""
import ipaddress
import os
import socket
import sys

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from api.appgate import AppliancePutError
from config import (
    ALLOW_SOURCES_LOCKOUT_HTTPS,
    ALLOW_SOURCES_LOCKOUT_SSH,
    ALLOW_SOURCES_PARENT_LABEL,
    ALLOW_SOURCES_SLOT_PARENT,
    DEBUG,
    DRY_RUN,
    SSH_PRIME_TIMEOUT,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
    warn_insecure_transport,
)
from core.inventory import Target
from core.prompts import (
    CREDENTIALS_PATH,
    _parse_collectives,
    collective_for_target,
    prepare_collectives,
    resolve_allowed_sources,
)
from core.run import (
    ClientMap,
    login_collectives,
    print_result,
    prompt_add_or_replace,
    select_appliances,
)
from core.utils import (
    HaltError,
    begin_replaced_run,
    halt,
    load_credentials,
    print_error,
    write_json_report,
)


def _human_allow_error(exc: Exception) -> str:
    """Map Controller/PUT errors to one sentence for the operator."""
    text = str(exc)
    low = text.lower()
    if "nic" in low and "empty" in low:
        return "NIC cannot be blank. Leave NIC out for Any, or set eth0."
    if "portal.profiles" in low:
        return "This API user cannot see the portal profile (need Client Profile View)."
    if "http 422" in low:
        return "The Controller rejected this change. Check the report or turn on DEBUG."
    if "http 403" in low or "http 401" in low:
        return "This API user is not allowed to edit that appliance."
    if "empty allowSources" in text:
        return "Replace would wipe all allowed sources; that was blocked."
    return "Could not update who can reach this appliance. Check the report."


def _fail(target: Target, message: str) -> None:
    """Fail-soft one box. Console is human; DEBUG prints the raw message."""
    target.status = "failed"
    low = message.lower()
    if "http " in low or "422" in message or "allowsources" in low:
        human = _human_allow_error(Exception(message))
    else:
        human = message
    target.error = human
    print_result(target, human, ok=False)
    if DEBUG:
        print(f"      Details: {message}", file=sys.stderr)


def _normalize_source(entry: Any) -> Dict[str, Any]:
    """Validate address/netmask; omit nic when blank (GUI Any)."""
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
    out: Dict[str, Any] = {"address": str(ip), "netmask": netmask}
    if nic:
        out["nic"] = nic
    return out


def _source_key(entry: Dict[str, Any]) -> Tuple[str, int, str]:
    """Dedupe key: address, prefix length, nic (empty = Any)."""
    return (entry.get("address") or "", int(entry.get("netmask") or -1), entry.get("nic") or "")


def _is_host_route(address: str, netmask: int) -> bool:
    """True for /32 IPv4 or /128 IPv6 (exclude-self only applies to these)."""
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
    """Canonical IP string so fe80::1 and FE80:0:0:0:0:0:0:1 compare equal."""
    try:
        return str(ipaddress.ip_address((addr or "").split("%")[0]))
    except ValueError:
        return (addr or "").strip()


def _drop_self(
    entries: List[Dict[str, Any]], self_ips: List[str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Drop /32|/128 rows that match this appliance's own addresses."""
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


def _merge_entries(dst: List[Dict[str, Any]], rows: Any) -> None:
    """Append normalized rows onto dst, skipping duplicates."""
    if not isinstance(rows, list):
        return
    seen = {_source_key(x) for x in dst}
    for raw in rows:
        item = _normalize_source(raw)
        if not item:
            continue
        key = _source_key(item)
        if key in seen:
            continue
        seen.add(key)
        dst.append(item)


def _desired_slots(target: Target, col: dict) -> Dict[str, List[Dict[str, Any]]]:
    """Merge allowed_sources.all then allowed_sources.<function> per slot (deduped)."""
    src = col.get("allowed_sources") or {}
    if not isinstance(src, dict):
        return {}
    lower = {str(k).replace(" ", "").lower(): v for k, v in src.items()}
    by_slot: Dict[str, List[Dict[str, Any]]] = {}
    for fn in ("all", *target.functions):
        block = src.get(fn) or lower.get(str(fn).lower()) or {}
        if not isinstance(block, dict):
            continue
        for slot, rows in block.items():
            name = str(slot).strip().lower()
            if name not in ALLOW_SOURCES_SLOT_PARENT:
                continue
            _merge_entries(by_slot.setdefault(name, []), rows)
    return by_slot


def _slots_to_parents(
    by_slot: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, List[Dict[str, Any]]]:
    """spa + https both map to clientInterface — union those lists."""
    by_parent: Dict[str, List[Dict[str, Any]]] = {}
    for slot, rows in by_slot.items():
        parent = ALLOW_SOURCES_SLOT_PARENT.get(slot)
        if not parent or not rows:
            continue
        _merge_entries(by_parent.setdefault(parent, []), rows)
    return by_parent


def _fmt(entries: List[Dict[str, Any]]) -> str:
    """One-line list: 10.0.0.0/8 on eth0."""
    if not entries:
        return "(none)"
    parts = []
    for e in entries:
        item = f"{e.get('address')}/{e.get('netmask')}"
        if e.get("nic"):
            item += f" on {e['nic']}"
        parts.append(item)
    return ", ".join(parts)


def _parent_label(parent: str) -> str:
    """API parent name → GUI label (SSH, SPA/HTTPS, …)."""
    return ALLOW_SOURCES_PARENT_LABEL.get(parent, parent)


def _outbound_ip(peer: str) -> str:
    """Local address this host would use to reach peer (UDP connect, no packets)."""
    peer = (peer or "").split("%")[0].strip()
    if not peer:
        return ""
    family = socket.AF_INET6 if ":" in peer else socket.AF_INET
    for port in (22, 443, 8443):
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(SSH_PRIME_TIMEOUT)
            sock.connect((peer, port))
            ip = sock.getsockname()[0]
            sock.close()
            return ip
        except OSError:
            continue
    return ""


def _rule_allows(local_ip: str, rows: List[Dict[str, Any]]) -> bool:
    """True if local_ip is inside any row's CIDR (any prefix length)."""
    if not local_ip or not rows:
        return False
    try:
        addr = ipaddress.ip_address(local_ip.split("%")[0])
    except ValueError:
        return False
    for row in rows:
        try:
            net = ipaddress.ip_network(
                f"{row.get('address')}/{int(row.get('netmask'))}",
                strict=False,
            )
        except (TypeError, ValueError):
            continue
        if addr in net:
            # print(f"DEBUG lockout: {local_ip} in {net}")
            return True
    return False


def _print_plan(label: str, mode: str, desired: Dict[str, List[Dict[str, Any]]]) -> None:
    """Dry-run: GUI slot names. DEBUG dumps the raw parent dict separately."""
    print(f"      {label}: would {mode}")
    width = max(len(_parent_label(p)) for p in desired) if desired else 3
    for parent, rows in desired.items():
        print(f"            {_parent_label(parent):<{width}}  {_fmt(rows)}")


def _counts_line(counts: Dict[str, int]) -> str:
    """OK-line extra: 'SSH 3, SPA/HTTPS 2'."""
    return ", ".join(f"{_parent_label(p)} {n}" for p, n in counts.items())


def _prompt_merge_mode(clients: ClientMap, selected: List[Target]) -> bool:
    """Ask add vs replace. True = replace. Q cancels."""
    sample = selected[0]
    client = clients.get(int(sample.collective))
    current: List[Dict[str, Any]] = []
    if client is not None:
        try:
            current = client.peek_allow_sources(sample.appliance_id)
        except Exception as exc:
            print(f"      Could not read current allowSources: {exc}", file=sys.stderr)
    return prompt_add_or_replace(
        f"Current allowSources on {sample.label()}: {_fmt(current)}",
        add_line="Add (append onto each matching slot, skip duplicates)",
        replace_line="Replace (overwrite each matching slot that already exists)",
        extra="SSH/SPA/ping/SNMP per type; admin=Controller/LogServer; https=Portal.",
    )


def _plan_one(
    target: Target, collectives: list
) -> Dict[str, List[Dict[str, Any]]]:
    """Build parent→rows for one box (all + functions, exclude-self)."""
    col = collective_for_target(target, collectives)
    by_slot = _desired_slots(target, col)
    dropped_all: List[Dict[str, Any]] = []
    for slot, rows in list(by_slot.items()):
        kept, dropped = _drop_self(rows, target.self_ips)
        by_slot[slot] = kept
        dropped_all.extend(dropped)
    if dropped_all:
        print(
            f"      {target.label()}: excluded self /32|/128 {_fmt(dropped_all)}",
            file=sys.stderr,
        )
    return _slots_to_parents(by_slot)


def _ssh_peer(target: Target) -> str:
    """Address used to guess this PC's outbound IP toward the appliance."""
    return target.ssh_ip or target.ssh_fqdn or (target.self_ips[0] if target.self_ips else "")


def _check_lockout(
    selected: List[Target],
    plans: Dict[str, Dict[str, List[Dict[str, Any]]]],
) -> None:
    """Halt E20 if replace SSH/Admin/SPA HTTPS rules would not match this host."""
    checks = []
    if ALLOW_SOURCES_LOCKOUT_SSH:
        checks.append(("sshServer", "SSH"))
    if ALLOW_SOURCES_LOCKOUT_HTTPS:
        checks.append(("adminInterface", "Admin/API"))
        checks.append(("clientInterface", "SPA/HTTPS"))
    if not checks:
        return
    blocked = []
    for target in selected:
        if target.status == "failed":
            continue
        desired = plans.get(target.label()) or {}
        peer = _ssh_peer(target)
        local_ip = _outbound_ip(peer)
        if DEBUG:
            print(
                f"      DEBUG lockout: {target.label()} local={local_ip!r} peer={peer!r}",
                file=sys.stderr,
            )
        for parent, label in checks:
            rows = desired.get(parent) or []
            if not rows:
                continue
            host = target.hostname or target.ssh_fqdn or target.label()
            verb = {
                "SSH": "SSH to",
                "Admin/API": "reach Admin/API on",
                "SPA/HTTPS": "reach SPA/HTTPS on",
            }.get(label, f"use {label} on")
            if not local_ip:
                blocked.append(
                    f"Could not tell this computer's address toward {host} ({label})."
                )
                continue
            if not _rule_allows(local_ip, rows):
                blocked.append(
                    f"This computer ({local_ip}) would no longer be allowed to {verb} {host}."
                )
    if blocked:
        halt(
            "E20",
            "Replace would lock this computer out",
            *blocked,
            "Add this computer's IP, use Add instead of Replace, or turn off lockout in Configure.",
        )


def _confirm_replace(plans: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> None:
    """Always-on two-step confirm: y, then type YES. Not configurable."""
    print("\n      Replace plan (all changes):")
    for label, desired in plans.items():
        _print_plan(label, "replace", desired)
    first = input("\n      Proceed with replace? [y/N]: ").strip().lower()
    if first not in YES_ANSWERS:
        print("      Cancelled.")
        raise SystemExit(0)
    second = input("      Type YES to confirm replace: ").strip()
    if second != "YES":
        print("      Cancelled.")
        raise SystemExit(0)


def _apply(
    selected: List[Target],
    clients: ClientMap,
    collectives: list,
    *,
    overwrite: bool,
    dry_run: bool,
    skip_guards: bool = False,
) -> None:
    """Preview (dry_run) or PUT. skip_guards=True after main() already confirmed."""
    print("\n[4/4] Updating allowSources via Controller API...")
    plans: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for target in selected:
        if target.status == "failed":
            continue
        desired = _plan_one(target, collectives)
        if not desired:
            _fail(target, "no allowed_sources left after slot merge / exclude-self")
            continue
        plans[target.label()] = desired
        if dry_run:
            mode = "replace" if overwrite else "add"
            target.status = "preview"
            client = clients.get(int(target.collective))
            if client is not None and not overwrite:
                try:
                    have = {
                        (e.get("address"), int(e.get("netmask") or -1), e.get("nic") or "")
                        for e in client.peek_allow_sources(target.appliance_id)
                    }
                    want = set()
                    for rows in desired.values():
                        for e in rows:
                            want.add(
                                (e.get("address"), int(e.get("netmask") or -1), e.get("nic") or "")
                            )
                    if want and want <= have:
                        target.status = "unchanged"
                        print_result(target, "already set")
                        continue
                except Exception:
                    pass
            _print_plan(target.label(), mode, desired)
            if DEBUG:
                print(
                    f"      DEBUG allow: {target.label()} {mode} {desired!r}",
                    file=sys.stderr,
                )
    if dry_run:
        return
    if overwrite and plans and not skip_guards:
        _check_lockout(selected, plans)
        _confirm_replace(plans)
    if overwrite and plans and not dry_run:
        begin_replaced_run()
    for target in selected:
        if target.status == "failed":
            continue
        desired = plans.get(target.label())
        if not desired:
            continue
        client = clients.get(int(target.collective))
        if client is None:
            _fail(target, "no API client for this collective")
            continue
        try:
            counts = client.update_allow_sources(
                target.appliance_id,
                desired,
                overwrite=overwrite,
                snapshot_label=target.label(),
            )
            target.status = "ok"
            print_result(target, _counts_line(counts))
            if DEBUG:
                print(
                    f"      DEBUG allow: {target.label()} counts={counts!r} desired={desired!r}",
                    file=sys.stderr,
                )
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
    """Write reports/allowed-sources-*.json (no secrets)."""
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
    """Menu 6: preview allowed sources, then apply (replace uses y + YES)."""
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
    missing = []
    for col in collectives:
        src = resolve_allowed_sources(col, creds)
        col["allowed_sources"] = src
        if not src:
            missing.append(col.get("fqdn") or col.get("agip") or str(col.get("index")))
    if missing:
        print("Allowed sources for this Controller are missing:", file=sys.stderr)
        for name in missing:
            print(f"      {name}", file=sys.stderr)
        print(
            "      Add allowed_sources (all or per Controller) in credentials.json.",
            file=sys.stderr,
        )
        raise HaltError("allowed sources missing")
    clients = login_collectives(collectives, step="[1/4]")
    selected = select_appliances(clients, step="[2/4]")
    overwrite = _prompt_merge_mode(clients, selected)
    started_at = datetime.now(timezone.utc).isoformat()
    _apply(selected, clients, collectives, overwrite=overwrite, dry_run=True)
    _emit_report(
        collectives, selected, overwrite=overwrite, dry_run=True, started_at=started_at
    )
    if DRY_RUN:
        print("      DRY_RUN is set — preview only.", file=sys.stderr)
    elif any(t.status == "preview" for t in selected):
        go = False
        if overwrite:
            plans = {
                t.label(): _plan_one(t, collectives)
                for t in selected
                if t.status == "preview"
            }
            _check_lockout(selected, plans)
            _confirm_replace(plans)
            go = True
        else:
            apply = input("\n      Apply these changes now? [y/N]: ").strip().lower()
            go = apply in YES_ANSWERS
        if go:
            for target in selected:
                if target.status == "preview":
                    target.status = "pending"
                    target.error = ""
            live_started = datetime.now(timezone.utc).isoformat()
            _apply(
                selected,
                clients,
                collectives,
                overwrite=overwrite,
                dry_run=False,
                skip_guards=True,
            )
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
