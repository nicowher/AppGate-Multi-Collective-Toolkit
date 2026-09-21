"""NTP tool (menu 5).

  1/4  API login
  2/4  inventory / exclude
  3/4  PUT appliance.ntp.servers (GUI/cz-configd; survives reboot)
  4/4  SSH restart cz-customization.service (no REST for that), then chronyc ntpdata

SHA256 keys get HEX: if missing. Reports never store the NTP key.
"""
import os
import sys
import time

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from datetime import datetime, timezone
from typing import Dict, List

from api.appgate import AppGateClient, AppliancePutError
from config import (
    DEBUG,
    DRY_RUN,
    NTP_CUSTOMIZATION_UNIT,
    SSH_LOG_PREVIEW,
    NTP_VERIFY_DELAY,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
    warn_insecure_transport,
)
from core.inventory import Target, prompt_exclusions
from core.prompts import (
    CREDENTIALS_PATH,
    _parse_collectives,
    collective_for_target,
    ensure_ntp_servers,
    prepare_collectives,
)
from core.utils import HaltError, halt, load_credentials, print_error, write_json_report
from ssh.client import prime_target_host_keys, ssh_password_for
from ssh.ntp import NtpSsh

ClientMap = Dict[int, AppGateClient]


def _fail(target: Target, message: str, code: str = "E11") -> None:
    target.status = "failed"
    target.error = message
    print_error(
        code,
        f"{target.label()}: {message}",
        "This box is skipped; others continue.",
        "E11 422: PUT ntp.servers objects (hostname, keyType, keyNo, key).",
        "E17: wait NTP_VERIFY_DELAY, then chronyc ntpdata must show the hostname.",
    )


def _login(collectives: list) -> ClientMap:
    print("\n[1/4] Authenticating to Controller API(s)...")
    clients: ClientMap = {}
    for col in collectives:
        idx = int(col["index"])
        print(f"      [{idx}] {col['fqdn']} as {col['api_username']}...")
        client = AppGateClient(col["fqdn"], fallback_ip=col.get("agip") or "")
        try:
            client.login(col["api_username"], col["api_password"])
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


def _inventory(clients: ClientMap) -> List[Target]:
    print("\n[2/4] Pulling appliances from every Controller...")
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
            "No activated appliances with an SSH address were found",
            "Need activated appliances with SSH FQDN/IP.",
        )
    print(f"      Found {len(inventory)} selectable appliance(s)")
    selected = prompt_exclusions(inventory)
    if not selected:
        halt(
            "E04",
            "Nothing left after exclusions",
            "Press Enter to keep all, or exclude fewer.",
        )
    print(f"      Selected {len(selected)} appliance(s)")
    return selected


def _prompt_merge_mode(clients: ClientMap, selected: List[Target]) -> bool:
    """True = replace entire ntp list. False = add/update by hostname."""
    sample = selected[0]
    client = clients.get(int(sample.collective))
    current: List[str] = []
    if client is not None:
        try:
            current = client.peek_ntp(sample.appliance_id)
        except Exception as exc:
            print(f"      Could not read current NTP: {exc}", file=sys.stderr)
    print(
        f"      Current NTP on {sample.label()}: "
        + (", ".join(current) if current else "(none / not in GET)")
    )
    # print(f"DEBUG ntp: peek hosts={current!r} sample={sample.label()}")
    print("  1) Add (update key if hostname matches, else append)")
    print("  2) Overwrite (replace the whole NTP list with credentials.json)")
    choice = ""
    while choice not in ("1", "2", "q"):
        choice = input("Select 1, 2, or Q: ").strip().lower()
    if choice == "q":
        print("      Cancelled.")
        raise SystemExit(0)
    return choice == "2"


def _host_list(servers: list) -> str:
    return ", ".join(s.get("hostname") or "?" for s in servers) or "(none)"


def _ntpdata_ok(output: str, servers: list) -> bool:
    """PASS only if chronyc shows a configured hostname (not generic leap text)."""
    text = (output or "").lower()
    if not text.strip() or "cannot talk" in text or "not authorised" in text:
        return False
    names = [(s.get("hostname") or "").lower() for s in servers if s.get("hostname")]
    # print(f"DEBUG ntpdata: names={names!r} hit={[n for n in names if n and n in text]}")
    return any(n and n in text for n in names)


def _apply(
    selected: List[Target],
    clients: ClientMap,
    collectives: list,
    *,
    overwrite: bool,
    dry_run: bool,
) -> None:
    mode = "overwrite" if overwrite else "add/update"
    print(f"\n[3/4] Push NTP via API ({mode})...")
    for target in selected:
        col = collective_for_target(target, collectives)
        servers = col.get("ntp_servers") or []
        if dry_run:
            print(
                f"      {target.label()}: would {mode} {_host_list(servers)}"
            )
            target.status = "preview"
            continue
        client = clients.get(int(target.collective))
        if client is None:
            _fail(target, "no API client for this collective")
            continue
        try:
            merged = client.update_ntp_servers(
                target.appliance_id, servers, overwrite=overwrite
            )
            target.status = "ok"
            print(
                f"      {target.label()}: NTP {mode} "
                f"({len(merged)} server(s))"
            )
        except AppliancePutError as exc:
            # print(f"DEBUG ntp: E11 put {target.label()!r} {exc!r}")
            _fail(target, str(exc), code="E11")
        except Exception as exc:
            _fail(target, str(exc), code="E11")

    print(f"\n[4/4] Restart {NTP_CUSTOMIZATION_UNIT} + chronyc ntpdata...")
    live = [t for t in selected if t.status == "ok"]
    if dry_run:
        for target in selected:
            if target.status == "preview":
                print(
                    f"      {target.label()}: would restart "
                    f"{NTP_CUSTOMIZATION_UNIT} then chronyc ntpdata"
                )
        return
    if not live:
        return
    prime_target_host_keys(live, collectives)
    for target in live:
        col = collective_for_target(target, collectives)
        try:
            NtpSsh(col["ssh_username"], ssh_password_for(target, col)).restart_customization(
                target
            )
            print(f"      {target.label()}: {NTP_CUSTOMIZATION_UNIT} restarted")
        except Exception as exc:
            _fail(target, f"customization restart: {exc}", code="E17")
    time.sleep(NTP_VERIFY_DELAY)
    for target in selected:
        if target.status != "ok":
            continue
        col = collective_for_target(target, collectives)
        servers = col.get("ntp_servers") or []
        try:
            out = NtpSsh(col["ssh_username"], ssh_password_for(target, col)).ntpdata(
                target
            )
            if DEBUG:
                print(
                    f"      DEBUG ntpdata {target.label()}: {out[:SSH_LOG_PREVIEW]!r}",
                    file=sys.stderr,
                )
            if _ntpdata_ok(out, servers):
                print(f"      {target.label()}: chronyc ntpdata PASS")
            else:
                _fail(target, "chronyc ntpdata did not show configured server", code="E17")
        except Exception as exc:
            _fail(target, f"chronyc ntpdata: {exc}", code="E17")


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
        "script": "ntp",
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "overwrite": overwrite,
        "collectives": [
            {
                "index": int(c["index"]),
                "fqdn": c.get("fqdn", ""),
                "agip": c.get("agip", ""),
                "api_username": c["api_username"],
                "ntp_hosts": [s.get("hostname") for s in (c.get("ntp_servers") or [])],
            }
            for c in collectives
        ],
        "ok_count": sum(1 for t in selected if t.status == "ok"),
        "preview_count": sum(1 for t in selected if t.status == "preview"),
        "failed_count": sum(1 for t in selected if t.status == "failed"),
        "targets": [
            {
                "label": t.label(),
                "status": t.status,
                "error": t.error,
            }
            for t in selected
        ],
    }
    write_json_report("ntp", report)


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
    prepare_collectives(creds, collectives)
    for col in collectives:
        ensure_ntp_servers(col, creds)
        if not col.get("ntp_servers"):
            halt(
                "E12",
                f"Collective {col.get('index')} has no NTP servers",
                "Add ntp_servers[].hostname (and keyType/keyNo/key) in credentials.json.",
                "Or enter hostname at the NTP prompt. Global ntp_servers apply if the collective list is empty.",
            )
    # print(f"DEBUG ntp: overwrite prompt next, hosts={[c.get('ntp_servers') for c in collectives]}")
    if DEBUG:
        print(f"      DEBUG ntp: collectives={len(collectives)}", file=sys.stderr)

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
        apply = input("\n      Apply NTP to these appliances now? [y/N]: ").strip().lower()
        if apply in YES_ANSWERS:
            for target in selected:
                if target.status == "preview":
                    target.status = "pending"
                    target.error = ""
            live_started = datetime.now(timezone.utc).isoformat()
            _apply(
                selected, clients, collectives, overwrite=overwrite, dry_run=False
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
        sys.exit(1)
    except HaltError:
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
