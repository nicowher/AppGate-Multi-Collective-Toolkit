"""Multi-appliance SNMPv3 configure-and-validate via the Controller.

  1. Login to the Controller (agip)
  2. Pull appliances, keep activated/healthy, prompt to exclude
  3. API: engineIDType 3 on selected boxes, wait
  4. SSH (batches): restart snmpd, read oldEngineID, check MAC
  5. Localize hashes
  6. API: deleteUser then createUser per success (one PUT stream at a time)
  7. SSH (batches): purge persistent usmUser, restart
  8. Walk every pushed device
"""
import json
import os
import platform
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from getpass import getpass
from typing import Any, Callable, Dict, List

from appgate import AppGateClient
from config import (
    APPGATE_API_VERSION,
    CREDENTIALS_FILENAME,
    DEBUG,
    ENGINE_ID_TYPE,
    ETH_IFACE,
    SNMP_AUTH_PROTOCOL,
    SNMP_HASH_ALGO,
    SNMP_MIN_PASSPHRASE_LEN,
    SNMP_NAME_RE,
    SNMP_PRIV_PROTOCOL,
    SNMP_RELOAD_DELAY,
    SSH_CONCURRENCY,
    TLS_VERIFY,
)
from inventory import Target, prompt_exclusions
from snmp_engine import SNMPEngineFetcher
from snmp_hashgen import SNMPHashGenerator
from snmp_validate import SNMPValidator
from utils import REPO_ROOT, load_credentials

CREDENTIALS_PATH = os.path.join(REPO_ROOT, CREDENTIALS_FILENAME)


def _require(creds: dict, field: str, prompt: str, sensitive: bool = False) -> str:
    value = creds.get(field, "")
    if not value:
        if sensitive:
            value = getpass(f"{prompt}: ").strip()
        else:
            value = input(f"{prompt}: ").strip()
    return value


def _ok(targets: List[Target]) -> List[Target]:
    return [t for t in targets if t.status != "failed"]


def _fail(target: Target, message: str) -> None:
    target.status = "failed"
    target.error = message
    print(f"      FAIL {target.label()}: {message}", file=sys.stderr)


def _run_ssh_batch(
    targets: List[Target],
    worker: Callable[[Target], None],
    concurrency: int,
) -> None:
    if not targets:
        return
    workers = max(1, min(concurrency, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(worker, t): t for t in targets}
        for future in as_completed(futures):
            target = futures[future]
            try:
                future.result()
            except Exception as exc:
                _fail(target, str(exc))


def main() -> None:
    try:
        creds = load_credentials(CREDENTIALS_PATH)
        inputs = {
            "snmp_user": _require(creds, "snmp_user", "SNMP User"),
            "snmp_auth": _require(creds, "snmp_auth", "SNMP Auth", sensitive=True),
            "snmp_priv": _require(creds, "snmp_priv", "SNMP Priv", sensitive=True),
            "agip": _require(creds, "agip", "AppGate Controller IP"),
            "rouser": _require(creds, "rouser", "SNMP Read-Only Username (rouser)"),
        }
        if not all(inputs[k] for k in ("snmp_user", "snmp_auth", "snmp_priv", "agip")):
            raise ValueError("snmp_user, snmp_auth, snmp_priv, and agip (Controller) are required")

        admin_user = _require(creds, "admin_username", "AppGate Admin Username")
        admin_pass = _require(creds, "admin_password", "AppGate Admin Password", sensitive=True)
        ssh_user = _require(creds, "ssh_username", "SSH Username")
        ssh_pass = _require(creds, "ssh_password", "SSH Password", sensitive=True)
        if not all((admin_user, admin_pass, ssh_user, ssh_pass)):
            raise ValueError("admin and SSH credentials are required")
        if not re.fullmatch(SNMP_NAME_RE, inputs["snmp_user"]):
            raise ValueError("snmp_user must be letters, digits, underscore, dot, or hyphen")
        if inputs.get("rouser") and not re.fullmatch(SNMP_NAME_RE, inputs["rouser"]):
            raise ValueError("rouser must be letters, digits, underscore, dot, or hyphen")
        for label, secret in (("snmp_auth", inputs["snmp_auth"]), ("snmp_priv", inputs["snmp_priv"])):
            if len(secret) < SNMP_MIN_PASSPHRASE_LEN:
                raise ValueError(
                    f"{label} must be at least {SNMP_MIN_PASSPHRASE_LEN} characters"
                )

        client = AppGateClient(inputs["agip"])
        engine_fetcher = SNMPEngineFetcher(ssh_user, ssh_pass)
        hashgen = SNMPHashGenerator()
        validator = SNMPValidator()
        user = inputs["snmp_user"]
        rouser_line = f"rouser {inputs['rouser']} priv" if inputs.get("rouser") else ""

        print("\n[1/8] Authenticating to Controller API...")
        client.login(admin_user, admin_pass)
        print("      Authenticated")
        # print(f"DEBUG step1: controller={inputs['agip']} api=v{APPGATE_API_VERSION}")

        print("\n[2/8] Pulling appliances from Controller...")
        inventory = client.list_targets()
        if not inventory:
            raise ValueError("No activated/healthy appliances with an SSH address were found")
        print(f"      Found {len(inventory)} selectable appliance(s)")
        selected = prompt_exclusions(inventory)
        if not selected:
            raise ValueError("Nothing left to configure after exclusions")
        print(f"      Selected {len(selected)} appliance(s)")
        # print("DEBUG step2:", [(t.hostname, t.ssh_ip, t.functions) for t in selected])

        print("\n[3/8] Pinning engineIDType via API...")
        for target in selected:
            try:
                client.ensure_engine_id_type3(target.appliance_id)
                print(f"      {target.label()}: engineIDType set")
            except Exception as exc:
                _fail(target, f"API engineIDType: {exc}")
        time.sleep(SNMP_RELOAD_DELAY)

        print(f"\n[4/8] SSH engine ID (up to {SSH_CONCURRENCY} at a time)...")

        def _ssh_engine(target: Target) -> None:
            if target.status == "failed":
                return
            engine_id = engine_fetcher.get_engine_id(target.ssh_ip)
            if engine_id.lower().startswith("0x"):
                engine_id = engine_id[2:]
            target.engine_id = engine_id
            print(f"      {target.label()}: engine {engine_id}")
            # print(f"DEBUG step4: {target.label()} engine_len={len(engine_id)}")

        _run_ssh_batch(_ok(selected), _ssh_engine, SSH_CONCURRENCY)
        if not _ok(selected):
            print("      No appliances left after SSH engine-ID pass.", file=sys.stderr)

        print("\n[5/8] Localizing SNMPv3 keys...")
        for target in _ok(selected):
            try:
                data = hashgen.generate_hashes(
                    user, inputs["snmp_auth"], inputs["snmp_priv"], target.engine_id
                )
                target.auth_hash = data["hashes"]["auth"]
                target.priv_hash = data["hashes"]["priv"]
                print(f"      {target.label()}: hashed")
                # print(f"DEBUG step5: {target.label()} auth_len={len(target.auth_hash)}")
            except Exception as exc:
                _fail(target, f"hash: {exc}")

        print("\n[6/8] Pushing SNMPv3 config via Controller...")
        for target in _ok(selected):
            try:
                client.delete_snmp_user(user, appliance_id=target.appliance_id)
                time.sleep(SNMP_RELOAD_DELAY)
                client.update_snmp_config(
                    user,
                    target.auth_hash,
                    target.priv_hash,
                    rouser_line,
                    appliance_id=target.appliance_id,
                )
                target.status = "ok"
                print(f"      {target.label()}: config pushed")
            except Exception as exc:
                _fail(target, f"API push: {exc}")

        print(f"\n[7/8] SSH purge leftover usmUser (up to {SSH_CONCURRENCY} at a time)...")

        def _ssh_purge(target: Target) -> None:
            engine_fetcher.purge_persistent_user(
                target.ssh_ip, user, keep_hash=target.auth_hash
            )
            print(f"      {target.label()}: persistent USM purged")

        _run_ssh_batch(_ok(selected), _ssh_purge, SSH_CONCURRENCY)

        print("\n[8/8] Validating SNMP walks...")
        time.sleep(SNMP_RELOAD_DELAY)
        for target in _ok(selected):
            ok = validator.validate_snmp_walk(
                target.ssh_ip,
                user,
                inputs["snmp_auth"],
                inputs["snmp_priv"],
                engine_id=target.engine_id,
            )
            target.walk_ok = ok
            print(f"      {target.label()}: walk {'PASSED' if ok else 'FAILED'}")
            # print(f"DEBUG step8: {target.label()} walk_ok={ok}")
            if not ok:
                _fail(target, "SNMP walk failed")

        print("\n" + "=" * 60)
        print("Configuration Summary")
        print("=" * 60)
        print(f"User:     {user}")
        if rouser_line:
            print(f"Read-Only:{rouser_line}")
        for target in selected:
            state = target.status.upper()
            extra = target.engine_id or target.error
            print(f"  [{state:<7}] {target.label():<28} {target.ssh_ip:<18} {extra}")
            if target.status == "ok" and target.auth_hash:
                print(
                    f"           ESXi: {user}/{target.auth_hash}/{target.priv_hash}/priv"
                )
        print("=" * 60)
        if DEBUG:
            _print_debug_report(inputs["agip"], inventory, selected)
        if any(t.status == "failed" for t in selected):
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)


def _print_debug_report(
    controller: str, inventory: List[Target], selected: List[Target]
) -> None:
    """JSON dump with no passwords, tokens, or full localized keys."""
    report: Dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "controller": controller,
        "api_version": APPGATE_API_VERSION,
        "tls_verify": TLS_VERIFY,
        "config": {
            "hash": SNMP_HASH_ALGO,
            "auth": SNMP_AUTH_PROTOCOL,
            "priv": SNMP_PRIV_PROTOCOL,
            "engine_id_type": ENGINE_ID_TYPE,
            "eth_iface": ETH_IFACE,
            "ssh_concurrency": SSH_CONCURRENCY,
            "reload_delay": SNMP_RELOAD_DELAY,
        },
        "inventory_count": len(inventory),
        "selected_count": len(selected),
        "ok_count": sum(1 for t in selected if t.status == "ok"),
        "failed_count": sum(1 for t in selected if t.status == "failed"),
        "targets": [],
    }
    for t in selected:
        report["targets"].append(
            {
                "appliance_id": t.appliance_id,
                "hostname": t.hostname,
                "ssh_ip": t.ssh_ip,
                "functions": t.functions,
                "health": t.health,
                "engine_id": t.engine_id,
                "engine_id_len": len(t.engine_id),
                "auth_hash_len": len(t.auth_hash),
                "priv_hash_len": len(t.priv_hash),
                "auth_priv_hash_same": bool(t.auth_hash) and t.auth_hash == t.priv_hash,
                "status": t.status,
                "error": t.error,
                "walk_ok": t.walk_ok,
            }
        )
    print("\n----- BEGIN DEBUG REPORT -----")
    print(json.dumps(report, indent=2))
    print("----- END DEBUG REPORT -----")


if __name__ == "__main__":
    main()
