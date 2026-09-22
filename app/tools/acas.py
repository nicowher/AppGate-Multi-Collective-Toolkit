"""ACAS scan prep — temporary unharden / restore via cz-configd.

Reached via ``python app/main.py 2`` or launcher menu option 2
(``python app/main.py unharden`` / ``harden``).

Steps:
  1/3  API login (inventory only — do not PUT appliance JSON)
  2/3  Same exclude table as SNMP credentials / walk
  3/3  SSH overlay (FQDN first). Unharden: SSHBRUTE, cz-config nopasswd,
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
from typing import Dict, List

from core.run import login_collectives, print_result, select_appliances
from config import (
    ACAS_CZCONFIGD_UNIT,
    DEBUG,
    DRY_RUN,
    SSH_CONCURRENCY,
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
)
from core.utils import HaltError, halt, load_credentials, print_error, write_json_report
from ssh.acas import AcasPrep
from ssh.client import prime_target_host_keys, run_ssh_batch, ssh_password_for




def _fail(target: Target, message: str) -> None:
    target.status = "failed"
    target.error = message
    host = target.ssh_fqdn or target.ssh_ip
    print(f"      [{'FAILED':<7}] {target.label():<32} {host:<22}")
    print_error(
        "E14",
        f"{target.label()}: {message}",
        "This box is skipped; others continue.",
        "If getaddrinfo failed: FQDN does not resolve — use SSH IP or fix DNS.",
        "Password prompt only after a real auth failure, not DNS/timeout.",
        "Unharden: confirm you are on the selected hostname, not another appliance.",
    )


def _mode_from_argv() -> str:
    if len(sys.argv) < 2:
        return ""
    raw = sys.argv[1].strip().lower()
    if raw in ("1", "unharden", "deharden"):
        return "unharden"
    if raw in ("2", "harden", "reharden"):
        return "harden"
    return ""


def _prompt_mode() -> str:
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
    hits = []
    for token in (
        "STEP_IPTABLES_OK",
        "STEP_IPTABLES_SKIP",
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
        "ok_count": sum(1 for t in selected if t.status == "ok"),
        "preview_count": sum(1 for t in selected if t.status == "preview"),
        "failed_count": sum(1 for t in selected if t.status == "failed"),
        "targets": [
            {
                "label": t.label(),
                "ssh_fqdn": t.ssh_fqdn,
                "ssh_ip": t.ssh_ip,
                "ssh_endpoints": t.ssh_endpoints(),
                "status": t.status,
                "error": t.error,
            }
            for t in selected
        ],
    }
    write_json_report("acas-" + mode, report)


def _apply(
    selected: List[Target],
    collectives: list,
    mode: str,
    dry_run: bool,
) -> None:
    verb = "Unharden" if mode == "unharden" else "Harden"
    print(f"\n[3/3] {verb} via SSH (up to {SSH_CONCURRENCY} at a time)...")
    if dry_run:
        for target in selected:
            if mode == "unharden":
                print(
                    f"      {target.label()}: would cz-config nopasswd, drop-in, "
                    "banner TTY, then iptables -F SSHBRUTE -A ACCEPT"
                )
            else:
                print(
                    f"      {target.label()}: would cz-config nopasswd false, "
                    f"restore backups, rm drop-in, restart {ACAS_CZCONFIGD_UNIT}"
                )
            target.status = "preview"
        return

    prime_target_host_keys(selected, collectives)

    def _one(target: Target) -> None:
        col = collective_for_target(target, collectives)
        session = AcasPrep(col["ssh_username"], ssh_password_for(target, col))
        if mode == "unharden":
            out = session.unharden(target)
        else:
            out = session.harden(target)
        target.status = "ok"
        print_result(target, mode)
        if DEBUG:
            print(f"      {target.label()}: {_summarize_output(out)}")
            for ln in out.splitlines():
                if ln.startswith("STEP_"):
                    print(f"        {ln}")

    run_ssh_batch(selected, _one, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))


def main() -> None:
    warn_insecure_transport()
    creds = load_credentials(CREDENTIALS_PATH)
    collectives = _parse_collectives(creds)
    if not collectives:
        halt(
            "E01",
            "No collectives defined (collectives[] or agip)",
            "Add collectives[].fqdn (and agip) to credentials.json, or enter them when prompted.",
        )
    prepare_collectives(creds, collectives)

    mode = _prompt_mode()
    # print(f"DEBUG acas: mode={mode} argv={sys.argv!r}")
    if DEBUG:
        print(f"      DEBUG acas: mode={mode} collectives={len(collectives)}", file=sys.stderr)

    clients = login_collectives(collectives, step="[1/3]")
    selected = select_appliances(clients, step="[2/3]")
    dry_run = DRY_RUN
    if not dry_run:
        answer = input("\n      Dry-run only (preview, no SSH changes)? [y/N]: ").strip().lower()
        dry_run = answer in YES_ANSWERS

    if not dry_run and mode in ("unharden", "deharden"):
        print(
            "WARNING: unharden is STIG-hostile (NOPASSWD + open SSHBRUTE). "
            "Re-harden as soon as the scan finishes.",
            file=sys.stderr,
        )
    started_at = datetime.now(timezone.utc).isoformat()
    _apply(selected, collectives, mode, dry_run)
    _emit_report(mode, collectives, selected, dry_run=dry_run, started_at=started_at)

    if dry_run and any(t.status == "preview" for t in selected):
        apply = input("\n      Apply to these appliances now? [y/N]: ").strip().lower()
        if apply in YES_ANSWERS:
            if mode in ("unharden", "deharden"):
                print(
                    "WARNING: unharden is STIG-hostile (NOPASSWD + open SSHBRUTE). "
                    "Re-harden as soon as the scan finishes.",
                    file=sys.stderr,
                )
            for target in selected:
                if target.status == "preview":
                    target.status = "pending"
                    target.error = ""
            live_started = datetime.now(timezone.utc).isoformat()
            _apply(selected, collectives, mode, dry_run=False)
            _emit_report(
                mode, collectives, selected, dry_run=False, started_at=live_started
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
