"""NTP tool (menu 5).

  1/4  API login
  2/4  inventory / exclude
  3/4  find each box's SSH address (no password), then PUT appliance.ntp.servers
       (GUI/cz-configd; survives reboot). A box with no SSH address is not changed.
  4/4  SSH restart cz-customization.service (no REST for that), then chronyc ntpdata

SHA256 keys get HEX: if missing. Reports never store the NTP key.
"""
import os
import re
import sys
import time

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from datetime import datetime, timezone
from typing import List

from config import (
    DEBUG,
    NTP_CUSTOMIZATION_UNIT,
    NTP_KEY_TYPE_MAP,
    SSH_LOG_PREVIEW,
    NTP_VERIFY_DELAY,
    WRITE_RUN_REPORT,
    warn_insecure_transport,
)
from core.inventory import STATUS_FAILED, STATUS_OK, STATUS_PENDING, STATUS_PREVIEW, STATUS_UNCHANGED, Target
from core.ui import boxes, step_banner
from core.prompts import (
    require_collectives,
    CREDENTIALS_PATH,
    _parse_collectives,
    collective_for_target,
    ensure_ntp_servers,
    prepare_collectives,
)
from core.utils import (
    run_tool,
    begin_replaced_run,
    halt,
    is_ip,
    load_credentials,
    write_json_report,
)
from core.run import (
    preview_then_apply,
    ClientMap,
    login_collectives,
    fail_box,
    report_target_fields,
    rollback_prior,
    print_result,
    prompt_add_or_replace,
    ssh_failure_code,
    ssh_failure_reason,
    select_appliances,
)
from ssh.client import prime_target_host_keys, ssh_password_for
from ssh.ntp import NtpSsh


def _fail(target: Target, message: str, code: str = "E11") -> None:
    """Fail-soft NTP box. Human line; the report keeps the detail, DEBUG prints the code."""
    low = message.lower()
    human = ssh_failure_reason(message)
    if human:
        pass
    elif "http " in low or "422" in message:
        human = "The Controller rejected the NTP change. The report has the reason."
    elif "chronyc" in low:
        human = "NTP is set, but this box is not using the new server yet. Wait and retry, or check chrony on the appliance."
    else:
        human = message
    fail_box(target, human, message, ssh_failure_code(message) or code)


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
    """Hostnames only for messages. Keys are never printed."""
    return ", ".join(s.get("hostname") or "?" for s in servers) or "(none)"


def _ntpdata_debug(label: str, output: str, servers: list) -> None:
    """DEBUG only: show what the NTP verify sees, field by field, so an FQDN server that never verifies can be explained.

    Prints the chronyc lines that carry the server address, leap status,
    stratum and reference ID, then each configured hostname with whether it
    appears in the output and the result of each check. chronyc output holds no
    keys or passwords; NTP keys are never part of it.
    """
    text = output or ""
    fields = [
        ln.strip() for ln in text.splitlines()
        if re.match(r"(?i)^\s*(remote address|reference id|leap status|stratum)\s*:", ln)
    ]
    print(f"      DEBUG ntpdata {label}: {len(text.splitlines())} line(s) of chronyc output", file=sys.stderr)
    for ln in fields[:24]:
        print(f"      DEBUG ntpdata {label}:   {ln[:120]}", file=sys.stderr)
    low = text.lower()
    leap_ok = any(
        m.group(1).lower() == "normal"
        for m in re.finditer(r"(?im)^\s*leap status\s*:\s*(.+?)\s*$", text)
    )
    strata = [int(m.group(1)) for m in re.finditer(r"(?im)^\s*stratum\s*:\s*(\d{1,3})\s*$", text)]
    for s in servers:
        host = str((s or {}).get("hostname") or "").strip()
        if host:
            print(
                f"      DEBUG ntpdata {label}: server {host!r} named in output={host.lower() in low} "
                f"| is an IP={is_ip(host)} | leap normal={leap_ok} | strata={strata[:6]}",
                file=sys.stderr,
            )
    print(f"      DEBUG ntpdata {label}: verify result={_ntpdata_ok(output, servers)}", file=sys.stderr)


def _ntpdata_ok(output: str, servers: list) -> bool:
    """A hostname echo is not sync. Require a normal leap and a real stratum.

    chronyc ntpdata prints one field per line ("Leap status     : Normal",
    "Stratum         : 2"). Each is matched as a whole line, so "Not synchronised
    (normal soon)" or the word normal elsewhere in the output does not count.
    """
    text = output or ""
    low = text.lower()
    if not low.strip() or "cannot talk" in low or "not authorised" in low:
        return False
    leap_lines = [m.group(1) for m in re.finditer(r"(?im)^\s*leap status\s*:\s*(.+?)\s*$", text)]
    # print(f"DEBUG ntpdata: leap={leap_lines!r}")
    if not leap_lines or not any(v.lower() == "normal" for v in leap_lines):
        return False
    stratum = None
    for m in re.finditer(r"(?im)^\s*stratum\s*:\s*(\d{1,3})\s*$", text):
        stratum = int(m.group(1))
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


def _canonical_key_type(raw) -> str:
    """The spelling the Controller stores (SHA512) for any accepted spelling (sha-512, SHA2 -> SHA256)."""
    text = str(raw or "").strip()
    return NTP_KEY_TYPE_MAP.get(text.replace("-", "").upper(), text)


def _already_set(client, target: Target, servers: list, overwrite: bool) -> bool:
    """True when Add would change nothing on this box (same hostnames, key type, key number, key present).

    Overwrite always counts as a change: the peek shows hostnames and key
    metadata only, so a new key value with the same metadata would be missed.
    A failed peek counts as a change, so the box is previewed rather than skipped.
    keyType is compared in its canonical spelling (SHA512, as the Controller
    stores it), so "sha-512" or "SHA2" in credentials.json still matches.
    """
    # print(f"DEBUG ntp: already-set compare for {target.label()} overwrite={overwrite}")
    if overwrite or client is None:
        return False
    try:
        current_rows = client.peek_ntp_state(target.appliance_id)
    except Exception:
        return False
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
                "keyType": _canonical_key_type(s.get("keyType")),
                "keyNo": "" if key_no in ("", None) else str(key_no),
                "has_key": bool(s.get("key")),
            }
        )
    return bool(desired_rows) and all(by_host.get(r["hostname"]) == r for r in desired_rows)


def _preview(selected: List[Target], clients: ClientMap, collectives: list, *, overwrite: bool) -> None:
    """Steps 3 and 4 as a preview: mark each box unchanged or preview, change nothing.

    Kept apart from the live run on purpose: one loop with dry-run branches once
    let the live run push boxes the preview had marked already set.
    """
    mode = "overwrite" if overwrite else "add/update"
    step_banner("[3/4]", f"Set NTP servers via the Controller API ({mode})", boxes(len(selected)))
    changing = []
    for target in selected:
        servers = collective_for_target(target, collectives).get("ntp_servers") or []
        if _already_set(clients.get(int(target.collective)), target, servers, overwrite):
            target.status = STATUS_UNCHANGED
            print_result(target, "already set")
            continue
        target.status = STATUS_PREVIEW
        changing.append(target)
        print_result(target, f"{mode} {_host_list(servers)}", word="Plan")
    if not changing:
        print("\n      No NTP changes to apply.")
        return
    step_banner("[4/4]", "Apply and verify NTP on each box over SSH", boxes(len(changing)))
    print(f"      Each Plan box above: restart {NTP_CUSTOMIZATION_UNIT}, then check chrony is using the server.")


def _push_live(selected: List[Target], clients: ClientMap, collectives: list, *, overwrite: bool) -> List[Target]:
    """Step 3 live: find SSH addresses, then PUT NTP on each reachable box the preview would change.

    Returns the boxes whose PUT succeeded. Only boxes marked "pending" (the
    preview said they change) are touched; an "already set" box gets no PUT,
    restart or verify. The address check comes first because the PUT alone
    changes nothing on the box: without the step 4 restart the Controller would
    hold a config (and key) the box never applies. A PUT failure rolls back the
    earlier boxes and stops; a box with no SSH address fails alone.
    """
    mode = "overwrite" if overwrite else "add/update"
    step_banner("[3/4]", f"Set NTP servers via the Controller API ({mode})", boxes(len([t for t in selected if t.status == STATUS_PENDING])))
    if overwrite:
        begin_replaced_run()
    to_push = [t for t in selected if t.status == STATUS_PENDING]
    # print(f"DEBUG ntp: push={[t.label() for t in to_push]} skip_unchanged={[t.label() for t in selected if t.status == STATUS_UNCHANGED]}")
    prime_target_host_keys(to_push, collectives)
    done = []
    for target in to_push:
        if target.status == STATUS_FAILED:
            # print(f"DEBUG ntp: skip PUT {target.label()!r}, no SSH address: {target.detail!r}")
            reason = target.error or "no SSH address"
            target.error = f"NTP not changed: SSH not reachable before the change ({reason})"
            print_result(target, target.error, ok=False)
            continue
        servers = collective_for_target(target, collectives).get("ntp_servers") or []
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
        except Exception as exc:
            # A guard or Controller refusal (AppliancePutError) and any other error stop the same way.
            # print(f"DEBUG ntp: E11 put {target.label()!r} {type(exc).__name__}")
            _fail(target, str(exc), code="E11")
            rollback_prior(done)
            break
        target.status = STATUS_OK
        done.append((target, client))
        print_result(target, f"NTP servers set ({len(merged)}, {mode})")
        if DEBUG:
            print(f"      DEBUG ntp hosts={[s.get('hostname') for s in merged if isinstance(s, dict)]}", file=sys.stderr)
    return [t for t in to_push if t.status == STATUS_OK]


def _restart_and_verify(live: List[Target], clients: ClientMap, collectives: list) -> None:
    """Step 4 live: restart the NTP apply service, wait, then verify chrony and strip the key.

    The restart reuses the address pinned before step 3. A restart failure keeps
    the PUT (it is not rolled back) and says so, so the operator reruns menu 5.
    """
    step_banner("[4/4]", "Apply and verify NTP on each box over SSH", boxes(len(live)))
    if not live:
        return
    for target in live:
        col = collective_for_target(target, collectives)
        try:
            NtpSsh(col["ssh_username"], ssh_password_for(target, col)).restart_customization(target)
            if DEBUG:
                print(f"      DEBUG {target.label()}: restarted {NTP_CUSTOMIZATION_UNIT}", file=sys.stderr)
        except Exception as exc:
            _fail(target, f"customization restart: {exc}", code="E17")
            target.error += " The NTP change is saved on the Controller but not applied; run menu 5 again on this box."
            print(f"      {target.label()}: NTP change kept on the Controller, not applied on the box.", file=sys.stderr)
    time.sleep(NTP_VERIFY_DELAY)
    for target in live:
        if target.status != STATUS_OK:
            continue
        col = collective_for_target(target, collectives)
        servers = col.get("ntp_servers") or []
        try:
            out = NtpSsh(col["ssh_username"], ssh_password_for(target, col)).ntpdata(target, servers)
            if DEBUG:
                print(f"      DEBUG ntpdata {target.label()}: {out[:SSH_LOG_PREVIEW]!r}", file=sys.stderr)
                _ntpdata_debug(target.label(), out, servers)
            if _ntpdata_ok(out, servers):
                try:
                    client = clients.get(int(target.collective))
                    if client is not None:
                        client.strip_ntp_keys(target.appliance_id)
                except Exception as exc:
                    _fail(target, f"NTP verified but the key is still on the appliance: {exc}", code="E11")
                else:
                    # One line for the box: applied, verified, and the key taken off the API copy.
                    print_result(target, "NTP applied and verified; key removed from the appliance document")
            else:
                preview = " | ".join(ln.strip() for ln in (out or "").splitlines() if ln.strip())[:SSH_LOG_PREVIEW]
                print(f"      {target.label()}: chronyc: {preview or '(empty)'}", file=sys.stderr)
                _fail(target, "chronyc ntpdata did not show configured server", code="E17")
        except Exception as exc:
            _fail(target, f"chronyc ntpdata: {exc}", code="E17")


def _apply(
    selected: List[Target],
    clients: ClientMap,
    collectives: list,
    *,
    overwrite: bool,
    dry_run: bool,
) -> None:
    """Steps 3 and 4: the preview, or the live push then restart and verify."""
    if dry_run:
        _preview(selected, clients, collectives, overwrite=overwrite)
        return
    live = _push_live(selected, clients, collectives, overwrite=overwrite)
    _restart_and_verify(live, clients, collectives)


def _emit_report(
    collectives: list,
    selected: List[Target],
    *,
    overwrite: bool,
    dry_run: bool,
    started_at: str,
) -> None:
    """Run report with hostnames only, no keys."""
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
        "ok_count": sum(1 for t in selected if t.status == STATUS_OK),
        "preview_count": sum(1 for t in selected if t.status == STATUS_PREVIEW),
        "failed_count": sum(1 for t in selected if t.status == STATUS_FAILED),
        "targets": [
            report_target_fields(t)
            for t in selected
        ],
    }
    write_json_report("ntp", report)


def main() -> None:
    """Menu 5: login, inventory, add or overwrite, preview, confirm, apply, verify and report."""
    warn_insecure_transport()
    creds = load_credentials(CREDENTIALS_PATH)
    collectives = _parse_collectives(creds)
    require_collectives(collectives)
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
    preview_then_apply(
        selected,
        preview=lambda: _apply(selected, clients, collectives, overwrite=overwrite, dry_run=True),
        apply=lambda go: _apply(go, clients, collectives, overwrite=overwrite, dry_run=False),
        report=lambda dry, at: _emit_report(collectives, selected, overwrite=overwrite, dry_run=dry, started_at=at),
        prompt="Apply NTP to {boxes} now?",
    )

    if any(t.status == STATUS_FAILED for t in selected):
        sys.exit(1)


if __name__ == "__main__":
    run_tool(main)
