"""Walk-only check (no SSH, no config push).

Reached via ``python app/main.py 3`` or launcher menu option 3.

  1) Single IP / FQDN — walk, then ask to walk another
  2) Controller list — same login / exclude as configure steps 1–2, then walk
      (FQDN first, then IP; gateway never uses Controller agip)
"""
import os
import sys

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from datetime import datetime, timezone

from api.appgate import AppGateClient
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
from core.inventory import prompt_exclusions
from core.prompts import (
    CREDENTIALS_PATH,
    _parse_collectives,
    _require,
    collective_for_target,
    prepare_collectives,
)
from core.snmp_validate import SNMPValidator
from core.utils import (
    HaltError,
    halt,
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
    user = _require(
        creds,
        "snmp_user",
        "SNMP User",
        pattern=SNMP_NAME_RE,
        pattern_msg="Use letters, digits, underscore, dot, or hyphen.",
    )
    auth = _require(
        creds, "snmp_auth", "SNMP Auth", sensitive=True, min_len=SNMP_MIN_PASSPHRASE_LEN
    )
    priv = _require(
        creds, "snmp_priv", "SNMP Priv", sensitive=True, min_len=SNMP_MIN_PASSPHRASE_LEN
    )
    return user, auth, priv


def _walk_single(creds: dict, user: str, auth: str, priv: str) -> int:
    validator = SNMPValidator()
    any_fail = False
    first = True
    while True:
        # First pass may use agip from the file; later passes always prompt.
        source = creds if first else {}
        first = False
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
        ok = validator.validate_snmp_walk(hosts, user, auth, priv)
        print(f"      {ip}: walk {'PASSED' if ok else 'FAILED'}")
        if not ok:
            any_fail = True
        again = input("      Walk another IP? [y/N]: ").strip().lower()
        if again not in YES_ANSWERS:
            break
    return 1 if any_fail else 0


def _walk_inventory(creds: dict, user: str, auth: str, priv: str) -> int:
    collectives = _parse_collectives(creds)
    if not collectives:
        halt(
            "E01",
            "No collectives defined (collectives[] or agip)",
            "Add collectives[].fqdn to credentials.json or enter when prompted.",
        )
    prepare_collectives(creds, collectives, need_snmp=True)

    print("\n[1/3] Authenticating to Controller API(s)...")
    clients = {}
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
            "Fix API creds, TLS, or agip.",
        )

    # list_targets uses GET /appliances plus GET /appliances/status (not /stats/appliances).
    print("\n[2/3] Pulling appliances from every Controller...")
    inventory = []
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
            "Need activated appliances with an SSH FQDN/IP.",
        )
    print(f"      Found {len(inventory)} selectable appliance(s)")
    selected = prompt_exclusions(inventory)
    if not selected:
        halt(
            "E04",
            "Nothing left to walk after exclusions",
            "Press Enter to keep all, or exclude fewer.",
        )
    print(f"      Selected {len(selected)} appliance(s)")

    # print("DEBUG walk-inventory:", [t.label() for t in selected])
    if DEBUG:
        print(f"      DEBUG walk-inventory: selected={[t.label() for t in selected]}", file=sys.stderr)
    print(f"\n[3/3] SNMP walk (up to {WALK_CONCURRENCY} at a time)...")
    # print(f"DEBUG walk-inventory: parallel={WALK_CONCURRENCY}")

    def _walk_one(target) -> None:
        col = collective_for_target(target, collectives)
        ok = SNMPValidator().validate_snmp_walk(
            target.walk_endpoints(),
            col.get("snmp_user") or user,
            col.get("snmp_auth") or auth,
            col.get("snmp_priv") or priv,
            engine_id=target.engine_id or None,
        )
        target.walk_ok = ok
        print(f"      {target.label()}: walk {'PASSED' if ok else 'FAILED'}")
        if not ok:
            raise RuntimeError("SNMP walk failed")

    def _walk_fail(target, _exc) -> None:
        target.walk_ok = False
        print_error(
            "E10",
            f"{target.label()}: walk FAILED",
            "This host is skipped; others continue.",
            "FQDN then IP: check UDP/161, SNMP user/auth/priv, and leftover usmUser.",
            "Lab: pysnmp CFB warning is harmless. Air-gap: install vendor wheels (menu D).",
        )

    run_target_batch(selected, _walk_one, WALK_CONCURRENCY, _walk_fail)
    failed = sum(1 for t in selected if not t.walk_ok)

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
                }
                for t in selected
            ],
            "failed_count": failed,
        }
        write_json_report("walk", report)

    return 1 if failed else 0


def main() -> None:
    warn_insecure_transport()
    creds = load_credentials(CREDENTIALS_PATH)
    print("Walk mode:")
    print("  1) Single IP / FQDN")
    print("  2) Pull appliance list from Controller(s)")
    choice = ""
    while choice not in ("1", "2"):
        choice = input("Select 1 or 2: ").strip()
    if choice == "1":
        user, auth, priv = _snmp_creds(creds)
        _require(creds, "ssh_username", "SSH Username")
        _require(creds, "ssh_password", "SSH Password", sensitive=True)
        sys.exit(_walk_single(creds, user, auth, priv))
    sys.exit(_walk_inventory(creds, user, auth, priv))


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
