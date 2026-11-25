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

from api.appgate import AppliancePutError
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
from core.inventory import Target
from core.prompts import (
    CREDENTIALS_PATH,
    _parse_collectives,
    collective_for_target,
    ensure_ntp_servers,
    prepare_collectives,
)
from core.utils import (
    HaltError,
    begin_replaced_run,
    halt,
    load_credentials,
    print_error,
    write_json_report,
)
from core.run import (
    ClientMap,
    login_collectives,
    rollback_prior,
    print_result,
    prompt_add_or_replace,
    select_appliances,
)
from ssh.client import prime_target_host_keys, ssh_password_for
from ssh.ntp import NtpSsh


def _fail(target: Target, message: str, code: str = "E11") -> None:
    """Fail-soft NTP box. Human line; DEBUG prints E11/E17 detail."""
    target.status = "failed"
    low = message.lower()
    if "http " in low or "422" in message:
        human = "The Controller rejected the NTP change. Check the report."
    elif "chronyc" in low:
        human = "NTP is set, but this box is not using the new server yet. Wait and retry, or check chrony on the appliance."
    else:
        human = message
    target.error = human
    print_result(target, human, ok=False)
    if DEBUG:
        print(f"      Details: {code} {message}", file=sys.stderr)


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
    return prompt_add_or_replace(
        f"Current NTP on {sample.label()}: "
        + (", ".join(current) if current else "(none / not in GET)"),
        add_line="Add (update key if hostname matches, else append)",
        replace_line="Overwrite (replace the whole NTP list with credentials.json)",
    )


def _host_list(servers: list) -> str:
    return ", ".join(s.get("hostname") or "?" for s in servers) or "(none)"


def _ntpdata_ok(output: str, servers: list) -> bool:
    """A hostname echo is not sync. Require a normal leap and a real stratum."""
    text = output or ""
    low = text.lower()
    if not low.strip() or "cannot talk" in low or "not authorised" in low:
        return False
    if "leap status" not in low or "normal" not in low:
        return False
    stratum = None
    for line in text.splitlines():
        if "stratum" not in line.lower():
            continue
        digits = "".join(ch if ch.isdigit() else " " for ch in line).split()
        if digits:
            stratum = int(digits[0])
            break
    if stratum is None or not 1 <= stratum <= 15:
        return False
    names = []
    for s in servers:
        host = str((s or {}).get("hostname") or "").strip()
        if host:
            names.append(host.lower())
    if names and not any(n in low for n in names):
        return False
    return True


def _apply(
    selected: List[Target],
    clients: ClientMap,
    collectives: list,
    *,
    overwrite: bool,
    dry_run: bool,
) -> None:
    mode = "overwrite" if overwrite else "add/update"
    changing = set()
    print(f"\n[3/4] Push NTP via API ({mode})...")
    if overwrite and not dry_run:
        begin_replaced_run()
    done = []
    for target in selected:
        col = collective_for_target(target, collectives)
        servers = col.get("ntp_servers") or []
        if dry_run:
            client = clients.get(int(target.collective))
            current_rows = []
            if client is not None:
                try:
                    current_rows = client.peek_ntp_state(target.appliance_id)
                except Exception:
                    current_rows = []
            by_host = {r["hostname"]: r for r in current_rows}
            desired_rows = []
            for s in servers:
                host = str(s.get("hostname") or "").strip().lower()
                if not host:
                    continue
                key_no = s.get("keyNo")
                desired_rows.append(
                    {
                        "hostname": host,
                        "keyType": str(s.get("keyType") or ""),
                        "keyNo": "" if key_no in ("", None) else str(key_no),
                        "has_key": bool(s.get("key")),
                    }
                )
            unchanged = (
                not overwrite
                and bool(desired_rows)
                and all(by_host.get(r["hostname"]) == r for r in desired_rows)
            )
            if unchanged:
                target.status = "unchanged"
                print_result(target, "already set")
                continue
            target.status = "preview"
            changing.add(target.label())
            print(f"      {target.label()}: would {mode} {_host_list(servers)}")
            continue
        client = clients.get(int(target.collective))
        if client is None:
            _fail(target, "no API client for this collective")
            continue
        try:
            merged = client.update_ntp_servers(
                target.appliance_id,
                servers,
                overwrite=overwrite,
                snapshot_label=target.label(),
            )
            target.status = "ok"
            done.append((target, client))
            print_result(target, f"NTP {mode} ({len(merged)} server(s))")
            if DEBUG:
                print(f"      DEBUG ntp hosts={[s.get('hostname') for s in merged if isinstance(s, dict)]}", file=sys.stderr)
        except AppliancePutError as exc:
            # print(f"DEBUG ntp: E11 put {target.label()!r} {exc!r}")
            _fail(target, str(exc), code="E11")
            rollback_prior(done)
            break
        except Exception as exc:
            _fail(target, str(exc), code="E11")
            rollback_prior(done)
            break

    if dry_run and not changing:
        print("\n      No NTP changes to apply.")
        return
    print(f"\n[4/4] Restart {NTP_CUSTOMIZATION_UNIT} + chronyc ntpdata...")
    live = [t for t in selected if t.status == "ok"]
    if dry_run:
        for target in selected:
            if target.status == "preview" and target.label() in changing:
                print(f"      {target.label()}: would restart NTP apply service then verify")
                if DEBUG:
                    print(f"      DEBUG would restart {NTP_CUSTOMIZATION_UNIT}", file=sys.stderr)
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
            print(f"      {target.label()}: NTP apply service restarted")
            if DEBUG:
                print(f"      DEBUG restarted {NTP_CUSTOMIZATION_UNIT}", file=sys.stderr)
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
                target, servers
            )
            if DEBUG:
                print(
                    f"      DEBUG ntpdata {target.label()}: {out[:SSH_LOG_PREVIEW]!r}",
                    file=sys.stderr,
                )
            if _ntpdata_ok(out, servers):
                print_result(target, "NTP verify")
                try:
                    client = clients.get(int(target.collective))
                    if client is not None:
                        client.strip_ntp_keys(target.appliance_id)
                        print(f"      {target.label()}: NTP key removed from the appliance document")
                except Exception as exc:
                    _fail(target, f"NTP verified but the key is still on the appliance: {exc}", code="E11")
            else:
                preview = " | ".join(
                    ln.strip() for ln in (out or "").splitlines() if ln.strip()
                )[:SSH_LOG_PREVIEW]
                print(
                    f"      {target.label()}: chronyc: {preview or '(empty)'}",
                    file=sys.stderr,
                )
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
        apply = input("\n      Apply NTP to these appliances now? [y/N]: ").strip().lower()
        if apply in YES_ANSWERS:
            for target in selected:
                if target.status == "preview":
                    target.status = "pending"
                    target.error = ""
            live_started = datetime.now(timezone.utc).isoformat()
            try:
                _apply(
                    selected, clients, collectives, overwrite=overwrite, dry_run=False
                )
            finally:
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
