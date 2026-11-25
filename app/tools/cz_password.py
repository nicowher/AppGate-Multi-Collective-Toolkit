"""Update appliance cz SSH password via cz-config.

Reached via ``python app/main.py 4`` or launcher menu option 4.

Uses current ssh_password to log in. Turns off passwordless sudo, then sets
the new hash. credentials.json is updated only when every selected box accepts it.
"""
import json
import os
import sys
import tempfile
import time

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.run import ClientMap, login_collectives, print_result, select_appliances
from config import (
    CZ_PASSWORD_VERIFY_DELAY,
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
from core.utils import HaltError, halt, load_credentials, print_error, read_credentials_text, write_json_report
from ssh.client import prime_target_host_keys, run_ssh_batch, ssh_password_for
from ssh.password import CzPassword

def _fail(target: Target, message: str) -> None:
    """Mark one box failed with a plain-language reason. DEBUG adds the detail."""
    target.status = "failed"
    low = message.lower()
    if "auth" in low:
        human = "SSH login failed. Check username and password."
    elif "verify" in low:
        human = "Password may be set, but login with the new password failed. Wait and retry."
    else:
        human = "Could not change the appliance SSH password. Check the report."
    target.error = human
    print_result(target, human, ok=False)
    if DEBUG:
        print(f"      Details: {message}", file=sys.stderr)


def _apply(
    selected: List[Target],
    collectives: list,
    *,
    dry_run: bool,
) -> None:
    """Step 3: preview, or set and verify the new password per box. A box with no working address is skipped."""
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
        if (col.get("ssh_password_new") or "") == ssh_password_for(target, col):
            _fail(target, "new SSH password matches the current one")
            return
        out = CzPassword(col["ssh_username"], ssh_password_for(target, col)).set_password(
            target, col["ssh_password_new"]
        )
        time.sleep(CZ_PASSWORD_VERIFY_DELAY)
        # print(f"DEBUG czpw: verify user={col.get('ssh_username')}")
        ok = CzPassword(col["ssh_username"], col["ssh_password_new"]).verify_login(target)
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
        print_result(target, "password updated")

    # A box with no answering address or a refused host key already failed above. Do not SSH to it.
    ready = [t for t in selected if t.status != "failed"]
    run_ssh_batch(ready, _one, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))


def _emit_report(
    collectives: list,
    selected: List[Target],
    *,
    dry_run: bool,
    started_at: str,
) -> None:
    """Run report without passwords, so the operator can see which boxes now use the new password."""
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


def _save_passwords(
    creds: dict,
    collectives: list,
    selected: List[Target],
    inventory: Optional[List[Target]] = None,
) -> None:
    """Record the new password only for collectives where every box now uses it.

    A credentials row holds one SSH password for a whole collective, so a row is
    updated only when every appliance of that collective in the inventory took
    the new password. Boxes excluded at the appliance prompt still have the old
    one, so their collective is left unchanged and reported. The row gets its
    own ssh_password, and the top-level ssh_password is never rewritten when the
    file has collectives[]: an excluded or untouched collective that inherits it
    keeps the old value its boxes still use. Rows are matched by FQDN. Boxes the
    Controller listed as unhealthy or not activated are not in the inventory, so
    they are not counted here.
    """
    # print(f"DEBUG czpw save: applied={[t.label() for t in selected if t.status == 'ok']}")
    applied = [t for t in selected if t.status == "ok"]
    if not applied or any(t.status == "failed" for t in selected):
        print(
            "      credentials.json left unchanged. Not every box took the new password.",
            file=sys.stderr,
        )
        return
    try:
        # Same decoding as the load, or a BOM file loads fine and then fails to save.
        data = json.loads(read_credentials_text(CREDENTIALS_PATH))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(f"      Could not update credentials.json: {exc}", file=sys.stderr)
        return
    if not isinstance(data, dict):
        return
    done_ids = {t.appliance_id for t in applied}
    pool = list(inventory) if inventory else list(selected)
    full = set()  # collective FQDNs where every listed box changed
    partial = []  # (collective, changed, total) where only some did
    for col in collectives:
        try:
            idx = int(col["index"])
        except (KeyError, TypeError, ValueError):
            continue
        boxes = [t for t in pool if int(t.collective) == idx]
        changed_here = [t for t in boxes if t.appliance_id in done_ids]
        fqdn = str(col.get("fqdn") or "").strip().lower()
        if not boxes or not changed_here or not fqdn:
            continue
        if len(changed_here) == len(boxes):
            full.add(fqdn)
        else:
            partial.append((col, len(changed_here), len(boxes)))
    # print(f"DEBUG czpw save: full={sorted(full)} partial={[(c.get('index'), a, b) for c, a, b in partial]}")
    for col, n_done, n_all in partial:
        print(
            f"      Collective {col.get('index')} ({col.get('fqdn')}): {n_done} of {n_all} boxes now use "
            "the NEW SSH password; the others still use the old one. credentials.json was not "
            "changed for this collective. Run menu 4 on the remaining boxes, or update it by hand.",
            file=sys.stderr,
        )
    by_fqdn = {
        str(c.get("fqdn") or "").strip().lower(): c
        for c in collectives
        if str(c.get("fqdn") or "").strip()
    }
    changed = False
    rows = data.get("collectives")
    if isinstance(rows, list) and rows:
        for row in rows:
            if not isinstance(row, dict):
                continue
            fqdn = str(row.get("fqdn") or "").strip().lower()
            col = by_fqdn.get(fqdn)
            if not fqdn or col is None or fqdn not in full:
                continue
            row["ssh_password"] = col.get("ssh_password_new") or ""
            row["ssh_password_new"] = ""
            changed = True
            print(
                f"      credentials.json: collective {col.get('index')} ({col.get('fqdn')}) "
                "now records the new password.",
                file=sys.stderr,
            )
        all_rows = [
            str(r.get("fqdn") or "").strip().lower()
            for r in rows
            if isinstance(r, dict) and str(r.get("fqdn") or "").strip()
        ]
        if changed and (data.get("ssh_password_new") or ""):
            if all_rows and all(f in full for f in all_rows):
                data["ssh_password_new"] = ""
            else:
                print(
                    "      The top-level ssh_password_new is kept for collectives not changed yet.",
                    file=sys.stderr,
                )
    elif len(collectives) == 1:
        # Single-Controller file: the top-level keys are that collective's row.
        only = collectives[0]
        if str(only.get("fqdn") or "").strip().lower() in full:
            data["ssh_password"] = only.get("ssh_password_new") or ""
            data["ssh_password_new"] = ""
            changed = True
    if not changed:
        print(
            "      credentials.json left unchanged. No collective had every box change, "
            "or no row matched by FQDN.",
            file=sys.stderr,
        )
        return
    text = json.dumps(data, indent=2) + "\n"
    try:
        mode = os.stat(CREDENTIALS_PATH).st_mode & 0o777
    except OSError:
        mode = 0o600
    tmp = ""
    try:
        fd, tmp = tempfile.mkstemp(prefix="credentials.", suffix=".tmp", dir=os.path.dirname(CREDENTIALS_PATH))
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, CREDENTIALS_PATH)
    except Exception as exc:
        if tmp:
            try:
                os.remove(tmp)
            except OSError:
                pass
        # The boxes already run the new password. Say so, or the operator retries with the old one.
        # Only the error type and OS reason are shown; the file text holds passwords.
        reason = getattr(exc, "strerror", None) or type(exc).__name__
        print(
            f"      Could not update credentials.json ({type(exc).__name__}: {reason}).",
            file=sys.stderr,
        )
        print(
            "      The appliances already use the NEW SSH password. Update ssh_password in "
            "credentials.json by hand before the next run.",
            file=sys.stderr,
        )
        return
    print("      credentials.json updated with the new SSH password.", file=sys.stderr)


def main() -> None:
    """Menu 4: login, inventory, preview, confirm, apply, then update credentials.json only if every box took the new password."""
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

    clients = login_collectives(collectives, step="[1/3]")
    # The full list is needed to tell whether every box of a collective changed.
    inventory: List[Target] = []
    selected = select_appliances(clients, step="[2/3]", inventory_out=inventory)
    started_at = datetime.now(timezone.utc).isoformat()
    _apply(selected, collectives, dry_run=True)
    _emit_report(collectives, selected, dry_run=True, started_at=started_at)
    if DRY_RUN:
        print("      DRY_RUN is set — preview only.", file=sys.stderr)
    elif any(t.status == "preview" for t in selected):
        apply = input("\n      Apply to these appliances now? [y/N]: ").strip().lower()
        if apply in YES_ANSWERS:
            for target in selected:
                if target.status == "preview":
                    target.status = "pending"
                    target.error = ""
            live_started = datetime.now(timezone.utc).isoformat()
            try:
                _apply(selected, collectives, dry_run=False)
            finally:
                _emit_report(
                    collectives, selected, dry_run=False, started_at=live_started
                )

    if any(t.status == "ok" for t in selected):
        _save_passwords(creds, collectives, selected, inventory)
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
