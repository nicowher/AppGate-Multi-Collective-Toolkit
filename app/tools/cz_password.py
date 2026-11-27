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
from typing import List, Optional

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
    CZ_PASSWORD_VERIFY_DELAY,
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
from core.utils import load_credentials, print_error, read_credentials_text, run_tool, write_json_report
from ssh.client import iter_primed_targets, run_ssh_batch, ssh_password_for
from ssh.password import CzPassword

def _fail(target: Target, message: str) -> None:
    """Mark one box failed with a plain-language reason. The report keeps the detail."""
    low = message.lower()
    human = ssh_failure_reason(message)
    if human:
        pass
    elif "verify" in low:
        human = "Password may be set, but login with the new password failed. Wait and retry."
    else:
        human = "Could not change the appliance SSH password. The report has the reason."
    fail_box(target, human, message, ssh_failure_code(message) or "E13")


def _preview(selected: List[Target]) -> None:
    """Step 3 preview: one Plan line per box, nothing sent."""
    step_banner("[3/3]", "Set the cz SSH password", f"{boxes(len(selected))}, up to {SSH_CONCURRENCY} at a time")
    for target in selected:
        if target.status == STATUS_FAILED:
            continue
        print_result(target, "set the password, then log in with it to verify", word="Plan")
        target.status = STATUS_PREVIEW


def _apply_live(confirmed: List[Target], collectives: list) -> None:
    """Step 3 live: set and verify the new password on each confirmed box, each starting as soon as its SSH address is settled."""
    step_banner("[3/3]", "Set the cz SSH password", f"{boxes(len(confirmed))}, up to {SSH_CONCURRENCY} at a time")

    def _one(target: Target) -> None:
        """One box in a worker thread: refuse a new password equal to the old, set it, and record a plain failure instead of raising."""
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
        target.status = STATUS_OK
        print_result(target, "password changed; login with it verified")

    # Boxes are handed over as their address is settled; a box with no answering
    # address or a refused host key is never yielded, so it gets no SSH.
    run_ssh_batch(iter_primed_targets(confirmed, collectives), _one, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))


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
        "ok_count": sum(1 for t in selected if t.status == STATUS_OK),
        "preview_count": sum(1 for t in selected if t.status == STATUS_PREVIEW),
        "failed_count": sum(1 for t in selected if t.status == STATUS_FAILED),
        "targets": [
            {
                **report_target_fields(t, hide_addresses=False),
                "ssh_fqdn": t.ssh_fqdn,
                "ssh_ip": t.ssh_ip,
                "login_ok": t.status == STATUS_OK,
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
    # print(f"DEBUG czpw save: applied={[t.label() for t in selected if t.status == STATUS_OK]}")
    applied = [t for t in selected if t.status == STATUS_OK]
    if not applied or any(t.status == STATUS_FAILED for t in selected):
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
    require_collectives(collectives)
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
    try:
        preview_then_apply(
            selected,
            preview=lambda: _preview(selected),
            apply=lambda go: _apply_live(go, collectives),
            report=lambda dry, at: _emit_report(collectives, selected, dry_run=dry, started_at=at),
            prompt="Change the SSH password on {boxes} now?",
        )
    finally:
        # Also after Ctrl+C or an error: boxes that finished already use the new
        # password, and the next run must log in with it. The whole-collective
        # rule in _save_passwords still applies.
        # print(f"DEBUG czpw: save step, ok={[t.label() for t in selected if t.status == STATUS_OK]}")
        if any(t.status == STATUS_OK for t in selected):
            _save_passwords(creds, collectives, selected, inventory)
    if any(t.status == STATUS_FAILED for t in selected):
        sys.exit(1)


if __name__ == "__main__":
    run_tool(main)
