"""Walk-only check (no SSH, no config push).

Reached via ``python app/main.py 3`` or launcher menu option 3.

  1) Single IP / FQDN — walk, then ask to walk another
  2) Controller list — same login / exclude as configure steps 1–2, then walk
     (IP first for NAT; gateway never uses Controller agip)
"""
import json
import os
import sys

from appgate import AppGateClient
from config import (
    CREDENTIALS_FILENAME,
    DEBUG,
    SNMP_AUTH_PROTOCOL,
    SNMP_MIN_PASSPHRASE_LEN,
    SNMP_NAME_RE,
    SNMP_PRIV_PROTOCOL,
    REPORTS_DIRNAME,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
    warn_insecure_transport,
)
from inventory import prompt_exclusions
from main import _parse_collectives, _require
from snmp_validate import SNMPValidator
from utils import REPO_ROOT, is_valid_host, load_credentials
from datetime import datetime, timezone

CREDENTIALS_PATH = os.path.join(REPO_ROOT, CREDENTIALS_FILENAME)


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
            hosts.insert(0, agip)
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
        raise ValueError("No collectives defined (collectives[] or agip)")

    print("\n[1/3] Authenticating to Controller API(s)...")
    clients = {}
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
        raise ValueError("No activated appliances with an SSH address were found")
    print(f"      Found {len(inventory)} selectable appliance(s)")
    selected = prompt_exclusions(inventory)
    if not selected:
        raise ValueError("Nothing left to walk after exclusions")
    print(f"      Selected {len(selected)} appliance(s)")

    # print("DEBUG walk-inventory:", [t.label() for t in selected])
    print("\n[3/3] SNMP walk...")
    validator = SNMPValidator()
    failed = 0
    for target in selected:
        ok = validator.validate_snmp_walk(
            # Controllers: FQDN then credentials agip. Gateways: FQDN only.
            # IP first (NAT), then FQDN. Gateway never uses Controller agip.
            target.walk_endpoints(), user, auth, priv, engine_id=target.engine_id or None
        )
        target.walk_ok = ok
        print(f"      {target.label()}: walk {'PASSED' if ok else 'FAILED'}")
        if not ok:
            failed += 1

    if WRITE_RUN_REPORT or DEBUG:
        report = {
            "script": "snmp_walk_test",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "auth_protocol": SNMP_AUTH_PROTOCOL,
            "priv_protocol": SNMP_PRIV_PROTOCOL,
            "collectives": [
                {
                    "index": int(c["index"]),
                    "fqdn": c.get("fqdn", ""),
                    "agip": c.get("agip", ""),
                    "admin_username": c["admin_username"],
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
        text = json.dumps(report, indent=2)
        if DEBUG:
            print("\n----- BEGIN RUN REPORT -----")
            print(text)
            print("----- END RUN REPORT -----")
        if WRITE_RUN_REPORT:
            reports_dir = os.path.join(REPO_ROOT, REPORTS_DIRNAME)
            try:
                os.makedirs(reports_dir, exist_ok=True)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                path = os.path.join(reports_dir, f"walk-{stamp}.json")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text + "\n")
                print(f"      Report written: {path}", file=sys.stderr)
            except OSError as exc:
                print(f"      Could not write report file: {exc}", file=sys.stderr)

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
    user, auth, priv = _snmp_creds(creds)
    if choice == "1":
        sys.exit(_walk_single(creds, user, auth, priv))
    sys.exit(_walk_inventory(creds, user, auth, priv))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
