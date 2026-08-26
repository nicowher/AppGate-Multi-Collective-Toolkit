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

from api.appgate import AppGateClient
from config import (
    ACAS_CZCONFIGD_UNIT,
    DEBUG,
    DRY_RUN,
    SSH_CONCURRENCY,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
    warn_insecure_transport,
)
from core.inventory import Target, prompt_exclusions
from core.prompts import CREDENTIALS_PATH, _parse_collectives, _require
from core.utils import load_credentials, write_json_report
from ssh.acas import AcasPrep
from ssh.client import run_ssh_batch

ClientMap = Dict[int, AppGateClient]


def _fail(target: Target, message: str) -> None:
    target.status = "failed"
    target.error = message
    print(f"      FAIL {target.label()}: {message}", file=sys.stderr)


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
    while choice not in ("1", "2"):
        choice = input("Select 1 or 2: ").strip()
    return "unharden" if choice == "1" else "harden"


def _login(collectives: list) -> ClientMap:
    print("\n[1/3] Authenticating to Controller API(s)...")
    clients: ClientMap = {}
    for col in collectives:
        idx = int(col["index"])
        print(f"      [{idx}] {col['fqdn']} as {col['admin_username']}...")
        client = AppGateClient(col["fqdn"], fallback_ip=col.get("agip") or "")
        try:
            client.login(col["admin_username"], col["admin_password"])
            clients[idx] = client
            print(f"      [{idx}] Authenticated")
        except Exception as exc:
            print(f"      [{idx}] LOGIN FAILED: {exc}", file=sys.stderr)
    if not clients:
        raise ValueError("No Controller accepted login")
    return clients


def _inventory(clients: ClientMap) -> List[Target]:
    print("\n[2/3] Pulling appliances from every Controller...")
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
        raise ValueError("No activated appliances with an SSH address were found")
    print(f"      Found {len(inventory)} selectable appliance(s)")
    selected = prompt_exclusions(inventory)
    if not selected:
        raise ValueError("Nothing left after exclusions")
    print(f"      Selected {len(selected)} appliance(s)")
    return selected


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
                "admin_username": c["admin_username"],
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
    prep: AcasPrep,
    mode: str,
    dry_run: bool,
) -> None:
    verb = "Unharden" if mode == "unharden" else "Harden"
    print(f"\n[3/3] {verb} via SSH (up to {SSH_CONCURRENCY} at a time)...")
    if dry_run:
        for target in selected:
            if mode == "unharden":
                print(
                    f"      {target.label()}: would iptables -F SSHBRUTE, "
                    "append NOPASSWD to /etc/sudoers, wrap banner read -p"
                )
            else:
                print(
                    f"      {target.label()}: would restore /etc/sudoers "
                    f"and restart {ACAS_CZCONFIGD_UNIT}"
                )
            target.status = "preview"
        return

    def _one(target: Target) -> None:
        if mode == "unharden":
            out = prep.unharden(target.ssh_endpoints())
        else:
            out = prep.harden(target.ssh_endpoints())
        target.status = "ok"
        print(f"      {target.label()}: {_summarize_output(out)}")
        for ln in out.splitlines():
            if ln.startswith("STEP_"):
                print(f"        {ln}")

    run_ssh_batch(selected, _one, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))


def main() -> None:
    warn_insecure_transport()
    creds = load_credentials(CREDENTIALS_PATH)
    ssh_user = _require(creds, "ssh_username", "SSH Username")
    ssh_pass = _require(creds, "ssh_password", "SSH Password", sensitive=True)
    collectives = _parse_collectives(creds)
    if not collectives:
        raise ValueError("No collectives defined (collectives[] or agip)")

    mode = _prompt_mode()
    # print(f"DEBUG acas: mode={mode} argv={sys.argv!r}")
    if DEBUG:
        print(f"      DEBUG acas: mode={mode} collectives={len(collectives)}", file=sys.stderr)

    clients = _login(collectives)
    selected = _inventory(clients)
    dry_run = DRY_RUN
    if not dry_run:
        answer = input("\n      Dry-run only (preview, no SSH changes)? [y/N]: ").strip().lower()
        dry_run = answer in YES_ANSWERS

    prep = AcasPrep(ssh_user, ssh_pass)
    started_at = datetime.now(timezone.utc).isoformat()
    _apply(selected, prep, mode, dry_run)
    _emit_report(mode, collectives, selected, dry_run=dry_run, started_at=started_at)

    if dry_run and any(t.status == "preview" for t in selected):
        apply = input("\n      Apply to these appliances now? [y/N]: ").strip().lower()
        if apply in YES_ANSWERS:
            for target in selected:
                if target.status == "preview":
                    target.status = "pending"
                    target.error = ""
            live_started = datetime.now(timezone.utc).isoformat()
            _apply(selected, prep, mode, dry_run=False)
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
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
