"""Update appliance cz SSH password via cz-config.

Reached via ``python app/main.py 4`` or launcher menu option 4.

Uses current ssh_password to log in. Sets users/0/encrypted-password
(openssl passwd -6) and users/0/nopasswd false, then SSH-verifies the
new password. Does not rewrite credentials.json.
"""
import os
import sys
import time

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from datetime import datetime, timezone
from typing import Dict, List

from api.appgate import AppGateClient
from config import (
    CZ_PASSWORD_VERIFY_DELAY,
    DEBUG,
    DRY_RUN,
    SSH_CONCURRENCY,
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
)
from core.utils import HaltError, halt, load_credentials, print_error, write_json_report
from ssh.client import prime_target_host_keys, run_ssh_batch, ssh_password_for
from ssh.password import CzPassword

ClientMap = Dict[int, AppGateClient]


def _fail(target: Target, message: str) -> None:
    target.status = "failed"
    target.error = message
    print(f"      FAIL {target.label()}: {message}", file=sys.stderr)


def _login(collectives: list) -> ClientMap:
    print("\n[1/3] Authenticating to Controller API(s)...")
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
                "Self-signed cert: answer y on Proceed anyway, or set LAB_MODE=True.",
            )
    if not clients:
        halt(
            "E02",
            "No Controller accepted login",
            "Fix API creds, TLS prompt, or agip. Port 8443 /admin.",
        )
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
        halt(
            "E03",
            "No activated appliances with an SSH address were found",
            "Need activated appliances with SSH FQDN/IP and Appliance View.",
        )
    print(f"      Found {len(inventory)} selectable appliance(s)")
    selected = prompt_exclusions(inventory)
    if not selected:
        halt(
            "E04",
            "Nothing left after exclusions",
            "Press Enter to keep all appliances, or exclude fewer.",
        )
    print(f"      Selected {len(selected)} appliance(s)")
    return selected


def _apply(
    selected: List[Target],
    collectives: list,
    *,
    dry_run: bool,
) -> None:
    print(f"\n[3/3] Set cz password via SSH (up to {SSH_CONCURRENCY} at a time)...")
    if dry_run:
        for target in selected:
            print(
                f"      {target.label()}: would set password then SSH login-verify"
            )
            target.status = "preview"
        return

    prime_target_host_keys(selected, collectives)

    def _one(target: Target) -> None:
        col = collective_for_target(target, collectives)
        # print(f"DEBUG czpw: {target.label()} user={col.get('ssh_username')}")
        hosts = target.ssh_endpoints()
        out = CzPassword(col["ssh_username"], ssh_password_for(target, col)).set_password(
            hosts, col["ssh_password_new"]
        )
        time.sleep(CZ_PASSWORD_VERIFY_DELAY)
        # print(f"DEBUG czpw: verify user={col.get('ssh_username')}")
        ok = CzPassword(col["ssh_username"], col["ssh_password_new"]).verify_login(hosts)
        if DEBUG:
            for ln in out.splitlines():
                if ln.startswith("STEP_"):
                    print(f"        {ln}", file=sys.stderr)
        if not ok:
            print_error(
                "E13",
                f"{target.label()}: login verify FAILED",
                "cz-config set may have applied; SSH with the new password failed.",
                "Wait and retry menu 4, or SSH manually with ssh_password_new.",
            )
            raise RuntimeError("login verify FAILED")
        target.status = "ok"
        print(f"      {target.label()}: password updated, login PASS")

    run_ssh_batch(selected, _one, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))


def _emit_report(
    collectives: list,
    selected: List[Target],
    *,
    dry_run: bool,
    started_at: str,
) -> None:
    if not (WRITE_RUN_REPORT or DEBUG):
        return
    report = {
        "script": "cz_password",
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
                "status": t.status,
                "error": t.error,
                "login_ok": t.status == "ok",
            }
            for t in selected
        ],
    }
    write_json_report("cz-password", report)


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
    prepare_collectives(creds, collectives, need_new_password=True)
    if DEBUG:
        print(
            f"      DEBUG czpw: collectives={len(collectives)}",
            file=sys.stderr,
        )

    clients = _login(collectives)
    selected = _inventory(clients)
    dry_run = DRY_RUN
    if not dry_run:
        answer = input("\n      Dry-run only (preview, no SSH changes)? [y/N]: ").strip().lower()
        dry_run = answer in YES_ANSWERS

    started_at = datetime.now(timezone.utc).isoformat()
    _apply(selected, collectives, dry_run=dry_run)
    _emit_report(collectives, selected, dry_run=dry_run, started_at=started_at)

    if dry_run and any(t.status == "preview" for t in selected):
        apply = input("\n      Apply to these appliances now? [y/N]: ").strip().lower()
        if apply in YES_ANSWERS:
            for target in selected:
                if target.status == "preview":
                    target.status = "pending"
                    target.error = ""
            live_started = datetime.now(timezone.utc).isoformat()
            _apply(selected, collectives, dry_run=False)
            _emit_report(
                collectives, selected, dry_run=False, started_at=live_started
            )

    print(
        "      Note: credentials.json was not updated. "
        "Set ssh_password to the new value before other tools.",
        file=sys.stderr,
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
