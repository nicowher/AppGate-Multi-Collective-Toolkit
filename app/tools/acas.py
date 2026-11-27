"""ACAS scan prep — temporary unharden / restore via cz-configd.

Reached via ``python app/main.py 2`` or launcher menu option 2
(``python app/main.py unharden`` / ``harden``).

Steps:
  1/3  API login (inventory only — do not PUT appliance JSON)
  2/3  Same exclude table as SNMP credentials / walk
  3/3  SSH overlay on the session address. Unharden: SSHBRUTE, cz-config nopasswd,
       drop-in, ssh_confirm.sh TTY guard. Harden: restore backups, nopasswd
       false, nohup restart cz-configd (SSH drop otherwise).

Why SSH not API: persisting those changes via PUT would make unharden the
source of truth and fail STIG after the scan window.
"""
import os
import sys

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from datetime import datetime, timezone
from typing import List

from core.run import (
    preview_then_apply,
    login_collectives,
    print_result,
    fail_box,
    report_target_fields,
    select_appliances,
    ssh_failure_code,
    ssh_failure_reason,
)
from config import (
    ACAS_CZCONFIGD_UNIT,
    DEBUG,
    SSH_CONCURRENCY,
    WRITE_RUN_REPORT,
    warn_insecure_transport,
)
from core.inventory import STATUS_FAILED, STATUS_OK, STATUS_PREVIEW, Target
from core.ui import boxes, step_banner
from core.prompts import (
    require_collectives,
    CREDENTIALS_PATH,
    _parse_collectives,
    collective_for_target,
    prepare_collectives,
)
from core.utils import load_credentials, run_tool, write_json_report
from ssh.acas import AcasPrep
from ssh.client import iter_primed_targets, run_ssh_batch, ssh_password_for


def _fail(target: Target, message: str) -> None:
    """Fail-soft. Console is human; the report keeps the detail so the reason survives without DEBUG.

    The detail is the SSH or script error: step names, error kind, and the box
    label. It holds no password and is capped at SSH_LOG_PREVIEW characters.
    """
    low = message.lower()
    human = ssh_failure_reason(message)
    if human:
        pass
    elif "acas script failed" in low:
        human = "The ACAS script stopped at a step. The report lists the steps that ran."
    elif "cz-configd is not active" in low:
        human = "cz-configd did not come back after harden. Check the service on the box."
    else:
        human = "ACAS prep failed on this appliance. The report has the reason."
    fail_box(target, human, message, ssh_failure_code(message) or "E14")


def _mode_from_argv() -> str:
    """Command-line mode (1/unharden, 2/harden) so the menu can be skipped."""
    if len(sys.argv) < 2:
        return ""
    raw = sys.argv[1].strip().lower()
    if raw in ("1", "unharden", "deharden"):
        return "unharden"
    if raw in ("2", "harden", "reharden"):
        return "harden"
    return ""


def _prompt_mode() -> str:
    """Unharden or harden. The command line wins; otherwise ask."""
    mode = _mode_from_argv()
    if mode:
        return mode
    print("ACAS scan prep:")
    print("  1) Unharden  (iptables SSHBRUTE, sudo NOPASSWD, banner TTY skip)")
    print(f"  2) Harden    (remove overlay, restart {ACAS_CZCONFIGD_UNIT})")
    choice = ""
    while choice not in ("1", "2", "q"):
        choice = input("Select 1, 2, or Q: ").strip().lower()
    if choice == "q":
        print("      Cancelled.")
        raise SystemExit(0)
    return "unharden" if choice == "1" else "harden"


def _summarize_output(text: str) -> str:
    """Short step list for the result line, so the operator sees what ran without the whole script output."""
    hits = []
    for token in (
        "STEP_IPTABLES_OK",
        "STEP_IPTABLES_SKIP",
        # Unharden found rules saved by an earlier run and did not overwrite them.
        "STEP_IPTABLES_SAVED_KEPT",
        "STEP_SUDOERS_OK",
        "STEP_SUDOERS_DROPIN_OK",
        "STEP_SUDOERS_ALREADY",
        "STEP_CZCONFIG_NOPASSWD_TRUE",
        "STEP_BANNER_OK",
        "STEP_BANNER_ALREADY",
        "STEP_SCAP_DIR_OK",
        "STEP_BANNER_SKIP",
        "STEP_HARDEN_DONE",
        "STEP_UNHARDEN_DONE",
    ):
        if token in text:
            hits.append(token.replace("STEP_", "").lower())
    return ",".join(hits) if hits else (text.strip().splitlines()[-1] if text.strip() else "ok")


def _emit_report(
    mode: str,
    collectives: list,
    selected: List[Target],
    *,
    dry_run: bool,
    started_at: str,
) -> None:
    """Run report without passwords. Written even after a partial run, so the operator can see which boxes changed."""
    if not (WRITE_RUN_REPORT or DEBUG):
        return
    report = {
        "script": "acas",
        "mode": mode,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "collectives": [
            {
                "index": int(c["index"]),
                "fqdn": c.get("fqdn", ""),
                "agip": c.get("agip", ""),
                "api_username": c["api_username"],
            }
            for c in collectives
        ],
        "ok_count": sum(1 for t in selected if t.status == STATUS_OK),
        "preview_count": sum(1 for t in selected if t.status == STATUS_PREVIEW),
        "failed_count": sum(1 for t in selected if t.status == STATUS_FAILED),
        "targets": [
            {
                **report_target_fields(t, hide_addresses=False),
                "ssh_fqdn": t.ssh_fqdn,
                "ssh_ip": t.ssh_ip,
                "ssh_endpoints": t.ssh_endpoints(),
            }
            for t in selected
        ],
    }
    write_json_report("acas-" + mode, report)


def _preview(selected: List[Target], mode: str) -> None:
    """Step 3 preview: one Plan line per box, nothing sent."""
    verb = "Unharden" if mode == "unharden" else "Harden"
    step_banner("[3/3]", f"{verb} each box over SSH", f"{boxes(len(selected))}, up to {SSH_CONCURRENCY} at a time")
    if mode == "unharden":
        plan = "cz-config nopasswd, sudo drop-in, banner TTY skip, open SSHBRUTE"
    else:
        plan = f"nopasswd off, restore backups, remove drop-in, restart {ACAS_CZCONFIGD_UNIT}"
    for target in selected:
        if target.status == STATUS_FAILED:
            continue
        print_result(target, plan, word="Plan")
        target.status = STATUS_PREVIEW


def _apply_live(confirmed: List[Target], collectives: list, mode: str) -> None:
    """Step 3 live: run the script on each confirmed box, each starting as soon as its SSH address is settled.

    Kept apart from the preview on purpose: one function with dry-run branches is
    the shape that let other menus act on boxes the confirm had not covered.
    """
    verb = "Unharden" if mode == "unharden" else "Harden"
    step_banner("[3/3]", f"{verb} each box over SSH", f"{boxes(len(confirmed))}, up to {SSH_CONCURRENCY} at a time")

    def _one(target: Target) -> None:
        """One box in a worker thread: unharden or harden, and record a plain failure reason instead of raising, so other boxes continue."""
        col = collective_for_target(target, collectives)
        session = AcasPrep(col["ssh_username"], ssh_password_for(target, col))
        if mode == "unharden":
            out = session.unharden(target)
        else:
            out = session.harden(target)
        target.status = STATUS_OK
        print_result(target, "unhardened for the ACAS scan" if mode == "unharden" else "hardened again")
        if DEBUG:
            print(f"      {target.label()}: {_summarize_output(out)}")
            for ln in out.splitlines():
                if ln.startswith("STEP_"):
                    print(f"        {ln}")

    # Boxes are handed over as their address is settled; a box with no answering
    # address or a refused host key is never yielded, so it gets no SSH.
    run_ssh_batch(iter_primed_targets(confirmed, collectives), _one, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))


def main() -> None:
    """Menu 2: login, inventory and exclude, preview, confirm, then apply and report."""
    warn_insecure_transport()
    creds = load_credentials(CREDENTIALS_PATH)
    collectives = _parse_collectives(creds)
    require_collectives(collectives)
    prepare_collectives(creds, collectives)

    mode = _prompt_mode()
    # print(f"DEBUG acas: mode={mode} argv={sys.argv!r}")
    if DEBUG:
        print(f"      DEBUG acas: mode={mode} collectives={len(collectives)}", file=sys.stderr)

    clients = login_collectives(collectives, step="[1/3]")
    selected = select_appliances(clients, step="[2/3]")
    if mode in ("unharden", "deharden"):
        print("This weakens STIG until you harden again.", file=sys.stderr)
    def _stig_note() -> None:
        """Unharden weakens STIG until harden runs again; say it right before the change."""
        if mode in ("unharden", "deharden"):
            print("This weakens STIG until you harden again.", file=sys.stderr)

    preview_then_apply(
        selected,
        preview=lambda: _preview(selected, mode),
        apply=lambda go: _apply_live(go, collectives, mode),
        report=lambda dry, at: _emit_report(mode, collectives, selected, dry_run=dry, started_at=at),
        prompt=f"{mode.capitalize()} {{boxes}} now?",
        before_apply=_stig_note,
    )

    if any(t.status == STATUS_FAILED for t in selected):
        sys.exit(1)


if __name__ == "__main__":
    run_tool(main)
