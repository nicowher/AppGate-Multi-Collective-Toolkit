"""Walk-only check (no SSH, no config push).

Reached via ``python app/main.py 3`` or launcher menu option 3.

  1) Single IP / FQDN — SNMP walk only (snmp_*). Never asks for SSH.
  2) Controller list — API login + inventory/exclude, then walk
      (the address an earlier menu found this session, else admin hostname,
      admin IP, then the other NIC IPs). No SSH secrets.

If snmp_* / agip live only under collectives[], they are promoted so the
global prompt is skipped when every collective already has the field.
"""
import os
import sys

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from datetime import datetime, timezone

from core.ui import boxes, run_summary, step_banner
from core.inventory import STATUS_FAILED, STATUS_OK
from core.run import fail_box, login_collectives, print_result, select_appliances
from config import (
    DEBUG,
    SNMP_AUTH_PROTOCOL,
    SNMP_MIN_PASSPHRASE_LEN,
    SNMP_NAME_RE,
    SNMP_PRIV_PROTOCOL,
    WALK_CONCURRENCY,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
    warn_insecure_transport,
)

from core.prompts import (
    require_collectives,
    CREDENTIALS_PATH,
    _parse_collectives,
    _require,
    collective_for_target,
    prepare_collectives,
    promote_shared_fields,
    snmp_secret_ok,
)
from core.snmp_validate import SNMPValidator
from core.utils import (
    run_tool,
    is_valid_host,
    load_credentials,
    print_error,
    run_target_batch,
    write_json_report,
)


def _single_walk_hosts(creds: dict, typed: str) -> list:
    """If the typed FQDN matches a collective, also try that Controller's agip."""
    hosts = [typed]
    raw = creds.get("collectives")
    items = raw if isinstance(raw, list) else []
    if not items and (creds.get("fqdn") or creds.get("agip")):
        items = [{"fqdn": creds.get("fqdn"), "agip": creds.get("agip")}]
    typed_l = typed.strip().lower()
    for item in items:
        if not isinstance(item, dict):
            continue
        fqdn = str(item.get("fqdn") or item.get("hostname") or "").strip()
        agip = str(item.get("agip") or "").strip()
        if fqdn.lower() == typed_l and agip and agip not in hosts:
            hosts.append(agip)
    return hosts


def _snmp_creds(creds: dict):
    """SNMP user and passphrases only. Menu 3 never asks for SSH secrets."""
    promote_shared_fields(
        creds, ("snmp_user", "snmp_auth", "snmp_priv")
    )
    user = _require(
        creds,
        "snmp_user",
        "SNMP User",
        pattern=SNMP_NAME_RE,
        pattern_msg="Use 1-32 letters, digits, underscore, dot, or hyphen.",
    )
    auth = _require(
        creds, "snmp_auth", "SNMP Auth", sensitive=True, min_len=SNMP_MIN_PASSPHRASE_LEN,
        validator=snmp_secret_ok, validator_msg="No spaces or control characters in an SNMP passphrase.",
    )
    priv = _require(
        creds, "snmp_priv", "SNMP Priv", sensitive=True, min_len=SNMP_MIN_PASSPHRASE_LEN,
        validator=snmp_secret_ok, validator_msg="No spaces or control characters in an SNMP passphrase.",
    )
    return user, auth, priv


def _walk_single(creds: dict, user: str, auth: str, priv: str) -> int:
    """Walk addresses the operator types. Never defaults to the Controller agip, which would walk the Controller instead of the box."""
    validator = SNMPValidator()
    any_fail = False
    while True:
        # Always prompt. Do not default to Controller agip (that walks the Controller).
        source = {}
        ip = _require(
            source,
            "agip",
            "Appliance FQDN or IP to walk",
            validator=is_valid_host,
        )
        hosts = _single_walk_hosts(creds, ip)
        # print(f"DEBUG walk-single: hosts={hosts}")
        if DEBUG:
            print(f"      DEBUG walk-single: hosts={hosts}", file=sys.stderr)
        print(f"\n      SNMP walk {hosts}...")
        ok = validator.validate_snmp_walk(hosts, user, auth, priv, label=ip)
        state = "PASSED" if ok else "FAILED"
        print(f"      [{state:<7}] {ip}")
        if DEBUG:
            print(f"      DEBUG walk-single: ok={ok} hosts={hosts!r}", file=sys.stderr)
        if not ok:
            any_fail = True
        again = input("      Walk another IP? [y/N]: ").strip().lower()
        if again not in YES_ANSWERS:
            break
    return 1 if any_fail else 0


def _walk_inventory(creds: dict) -> int:
    """Walk every selected appliance from the Controller inventory, in parallel, on the address SSH found this session if there is one."""
    collectives = _parse_collectives(creds)
    require_collectives(collectives)
    prepare_collectives(creds, collectives, need_ssh=False, need_snmp=True)

    clients = login_collectives(collectives, step="[1/3]")
    selected = select_appliances(clients, step="[2/3]")

    # print("DEBUG walk-inventory:", [t.label() for t in selected])
    if DEBUG:
        print(f"      DEBUG walk-inventory: selected={[t.label() for t in selected]}", file=sys.stderr)
    step_banner("[3/3]", "Check each box answers an SNMPv3 walk", f"{boxes(len(selected))}, up to {WALK_CONCURRENCY} at a time")
    # print(f"DEBUG walk-inventory: parallel={WALK_CONCURRENCY}")

    def _walk_one(target) -> None:
        """Walk one box, trying its addresses in order, so one dead NIC does not fail a box that answers elsewhere."""
        col = collective_for_target(target, collectives)
        ok = SNMPValidator().validate_snmp_walk(
            target.walk_endpoints(),
            col.get("snmp_user") or "",
            col.get("snmp_auth") or "",
            col.get("snmp_priv") or "",
            engine_id=target.engine_id or None,
            label=target.label(),
        )
        target.walk_ok = ok
        if ok:
            target.status = STATUS_OK
            print_result(target, "SNMPv3 walk answered")
        if DEBUG:
            print(
                f"      DEBUG walk: {target.label()} endpoints={target.walk_endpoints()!r}",
                file=sys.stderr,
            )
        if not ok:
            raise RuntimeError("SNMP walk failed")

    def _walk_fail(target, exc) -> None:
        """A worker exception marks only this box failed (E10), so the other walks continue."""
        target.walk_ok = False
        fail_box(target, "No answer to the SNMPv3 walk on any address.", str(exc), "E10")

    run_target_batch(selected, _walk_one, WALK_CONCURRENCY, _walk_fail)
    failed = sum(1 for t in selected if not t.walk_ok)
    # Same closing lines as the other menus: counts, then each failed box with its code.
    run_summary(selected, preview=False)
    if failed:
        # The hints once for the run, instead of a block per failed box.
        print_error(
            "E10",
            f"{failed} box(es) did not answer the SNMPv3 walk",
            "Each address in turn (session address, admin name, admin IP, other IPs): check UDP/161, SNMP user/auth/priv, and leftover usmUser.",
            "Lab: pysnmp CFB warning is harmless. Air-gap: install vendor wheels (menu D).",
        )

    if WRITE_RUN_REPORT or DEBUG:
        report = {
            "script": "snmp_walk",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "auth_protocol": SNMP_AUTH_PROTOCOL,
            "priv_protocol": SNMP_PRIV_PROTOCOL,
            "collectives": [
                {
                    "index": int(c["index"]),
                    "fqdn": c.get("fqdn", ""),
                    "agip": c.get("agip", ""),
                    "api_username": c["api_username"],
                }
                for c in collectives
            ],
            "selected": [
                {
                    "label": t.label(),
                    "ssh_fqdn": t.ssh_fqdn,
                    "ssh_ip": t.ssh_ip,
                    "walk_endpoints": t.walk_endpoints(),
                    "walk_ok": t.walk_ok,
                    "code": t.code if t.status == STATUS_FAILED else "",
                }
                for t in selected
            ],
            "failed_count": failed,
        }
        write_json_report("walk", report)

    return 1 if failed else 0


def main() -> None:
    """Menu 3: single address or Controller inventory. Validation only; nothing is changed."""
    warn_insecure_transport()
    creds = load_credentials(CREDENTIALS_PATH)
    print("Walk mode:")
    print("  1) Single IP / FQDN")
    print("  2) Pull appliance list from Controller(s)")
    choice = ""
    while choice not in ("1", "2", "q"):
        choice = input("Select 1, 2, or Q: ").strip().lower()
    if choice == "q":
        return
    if choice == "1":
        user, auth, priv = _snmp_creds(creds)
        sys.exit(_walk_single(creds, user, auth, priv))
    sys.exit(_walk_inventory(creds))


if __name__ == "__main__":
    run_tool(main)
