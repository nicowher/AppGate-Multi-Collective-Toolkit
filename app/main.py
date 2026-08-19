"""Multi-collective SNMPv3 configure-and-validate.

Phase-aligned across collectives (array order = 1, 2, 3, ...):

  1. Login every Controller (own API account / token)
  2. Pull appliances from every successful login; one exclude prompt
  3. API engineIDType 3 (serialized per Controller)
  4. SSH engine IDs (shared pool)
  5. Localize hashes
  6. API deleteUser + createUser (owning client only, serialized per Controller)
  7. SSH purge usmUser
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
from typing import Any, Callable, Dict, List, Optional

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
    warn_insecure_transport,
)
from inventory import Target, prompt_exclusions
from snmp_engine import SNMPEngineFetcher
from snmp_hashgen import SNMPHashGenerator
from snmp_validate import SNMPValidator
from utils import REPO_ROOT, load_credentials

# credentials.json lives next to the launchers, not inside app/.
CREDENTIALS_PATH = os.path.join(REPO_ROOT, CREDENTIALS_FILENAME)

# After step 1: collective number (1, 2, …) → that Controller's logged-in API client.
ClientMap = Dict[int, AppGateClient]


def _require(creds: dict, field: str, prompt: str, sensitive: bool = False) -> str:
    """Use credentials.json if the field is set; otherwise prompt (getpass for secrets)."""
    value = creds.get(field, "")
    if not value:
        if sensitive:
            value = getpass(f"{prompt}: ").strip()
        else:
            value = input(f"{prompt}: ").strip()
    return value


def _ok(targets: List[Target]) -> List[Target]:
    """Appliances that have not failed a previous phase (still in the run)."""
    return [t for t in targets if t.status != "failed"]


def _fail(target: Target, message: str) -> None:
    """Mark one appliance failed and keep going (fail-soft)."""
    target.status = "failed"
    target.error = message
    print(f"      FAIL {target.label()}: {message}", file=sys.stderr)


def _run_ssh_batch(
    targets: List[Target],
    worker: Callable[[Target], None],
    concurrency: int,
) -> None:
    """Steps 4 and 7: run SSH work in a pool (default 5). One box crashing does not stop the rest."""
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


def _parse_collectives(creds: dict) -> List[Dict[str, str]]:
    """Step 0: turn credentials into a numbered list of Controllers.

    Prefer collectives[]. If that key is missing, treat top-level agip/admin_*
    as collective 1 (old single-controller files). Array order is the name:
    first object = 1, second = 2. Duplicate agip warns; we still run both.
    """
    raw = creds.get("collectives")
    rows: List[Dict[str, str]] = []
    if isinstance(raw, list) and raw:
        for item in raw:
            if not isinstance(item, dict):
                continue
            rows.append({
                "agip": str(item.get("agip") or "").strip(),
                "admin_username": str(item.get("admin_username") or "").strip(),
                "admin_password": str(item.get("admin_password") or ""),
            })
    else:
        rows.append({
            "agip": str(creds.get("agip") or "").strip(),
            "admin_username": str(creds.get("admin_username") or "").strip(),
            "admin_password": str(creds.get("admin_password") or ""),
        })

    seen: Dict[str, int] = {}
    out: List[Dict[str, str]] = []
    for i, row in enumerate(rows, 1):
        agip = row["agip"] or _require({}, "agip", f"Collective {i} Controller IP")
        user = row["admin_username"] or _require(
            {}, "admin_username", f"Collective {i} Admin Username"
        )
        password = row["admin_password"] or getpass(
            f"Collective {i} ({agip}) Admin Password: "
        ).strip()
        if agip in seen:
            print(
                f"WARNING: collectives {seen[agip]} and {i} share agip {agip}. "
                "The same collective will be configured twice.",
                file=sys.stderr,
            )
        else:
            seen[agip] = i
        out.append({
            "index": str(i),
            "agip": agip,
            "admin_username": user,
            "admin_password": password,
        })
    return out


def _api_by_collective(
    targets: List[Target],
    clients: ClientMap,
    worker: Callable[[Target, AppGateClient], None],
) -> None:
    """Steps 3 and 6: call the API using the client that owns that appliance.

    PUTs to the same Controller stay sequential. Never send collective 2's
    token to collective 1's appliance id.
    """
    by_col: Dict[int, List[Target]] = {}
    for t in targets:
        by_col.setdefault(t.collective, []).append(t)
    for col in sorted(by_col):
        client = clients.get(col)
        if client is None:
            for t in by_col[col]:
                _fail(t, f"no API client for collective {col}")
            continue
        for target in by_col[col]:
            try:
                worker(target, client)
            except Exception as exc:
                _fail(target, str(exc))


def main() -> None:
    try:
        # --- Step 0: load file, prompt gaps, validate names/passphrase length ---
        creds = load_credentials(CREDENTIALS_PATH)
        inputs = {
            "snmp_user": _require(creds, "snmp_user", "SNMP User"),
            "snmp_auth": _require(creds, "snmp_auth", "SNMP Auth", sensitive=True),
            "snmp_priv": _require(creds, "snmp_priv", "SNMP Priv", sensitive=True),
            "rouser": _require(creds, "rouser", "SNMP Read-Only Username (rouser)"),
        }
        if not all(inputs[k] for k in ("snmp_user", "snmp_auth", "snmp_priv")):
            raise ValueError("snmp_user, snmp_auth, and snmp_priv are required")

        ssh_user = _require(creds, "ssh_username", "SSH Username")
        ssh_pass = _require(creds, "ssh_password", "SSH Password", sensitive=True)
        if not all((ssh_user, ssh_pass)):
            raise ValueError("SSH credentials are required")
        if not re.fullmatch(SNMP_NAME_RE, inputs["snmp_user"]):
            raise ValueError("snmp_user must be letters, digits, underscore, dot, or hyphen")
        if inputs.get("rouser") and not re.fullmatch(SNMP_NAME_RE, inputs["rouser"]):
            raise ValueError("rouser must be letters, digits, underscore, dot, or hyphen")
        for label, secret in (("snmp_auth", inputs["snmp_auth"]), ("snmp_priv", inputs["snmp_priv"])):
            if len(secret) < SNMP_MIN_PASSPHRASE_LEN:
                raise ValueError(
                    f"{label} must be at least {SNMP_MIN_PASSPHRASE_LEN} characters"
                )

        collectives = _parse_collectives(creds)
        if not collectives:
            raise ValueError("No collectives defined (collectives[] or agip)")

        # Lab TLS/SSH defaults print a DISA warning; flip TLS_VERIFY at bottom of config.py.
        warn_insecure_transport()
        engine_fetcher = SNMPEngineFetcher(ssh_user, ssh_pass)
        hashgen = SNMPHashGenerator()
        validator = SNMPValidator()
        user = inputs["snmp_user"]
        rouser_line = f"rouser {inputs['rouser']} priv" if inputs.get("rouser") else ""

        # --- Step 1: one POST /login per Controller; skip a site if login fails ---
        print("\n[1/8] Authenticating to Controller API(s)...")
        clients: ClientMap = {}
        for col in collectives:
            idx = int(col["index"])
            print(f"      [{idx}] {col['agip']} as {col['admin_username']}...")
            client = AppGateClient(col["agip"])
            try:
                client.login(col["admin_username"], col["admin_password"])
                clients[idx] = client
                print(f"      [{idx}] Authenticated")
            except Exception as exc:
                print(f"      [{idx}] LOGIN FAILED: {exc}", file=sys.stderr)
        if not clients:
            raise ValueError("No Controller accepted login")
        # print("DEBUG step1: logged in", list(clients))

        # --- Step 2: GET /appliances on each token; one exclude table (1.hostname) ---
        print("\n[2/8] Pulling appliances from every Controller...")
        inventory: List[Target] = []
        for idx, client in sorted(clients.items()):
            try:
                inventory.extend(client.list_targets(collective=idx))
            except Exception as exc:
                print(f"      [{idx}] list failed: {exc}", file=sys.stderr)
        if not inventory:
            raise ValueError("No activated appliances with an SSH address were found")
        print(f"      Found {len(inventory)} selectable appliance(s)")
        selected = prompt_exclusions(inventory)
        if not selected:
            raise ValueError("Nothing left to configure after exclusions")
        print(f"      Selected {len(selected)} appliance(s)")
        # print("DEBUG step2:", [t.label() for t in selected])

        # --- Step 3: PUT engineIDType 3 so SSH later reads a MAC-based engine ID ---
        print("\n[3/8] Pinning engineIDType via API...")

        def _pin(target: Target, client: AppGateClient) -> None:
            client.ensure_engine_id_type3(target.appliance_id)
            print(f"      {target.label()}: engineIDType set")

        _api_by_collective(_ok(selected), clients, _pin)
        # print("DEBUG step3: pinned", [t.label() for t in _ok(selected)])
        time.sleep(SNMP_RELOAD_DELAY)

        # --- Step 4: restart snmpd, read oldEngineID, check RFC 3411 type 3 vs eth0 MAC ---
        print(f"\n[4/8] SSH engine ID (up to {SSH_CONCURRENCY} at a time)...")

        def _ssh_engine(target: Target) -> None:
            if target.status == "failed":
                return
            engine_id = engine_fetcher.get_engine_id(target.ssh_ip)
            if engine_id.lower().startswith("0x"):
                engine_id = engine_id[2:]
            target.engine_id = engine_id
            print(f"      {target.label()}: engine {engine_id}")

        _run_ssh_batch(_ok(selected), _ssh_engine, SSH_CONCURRENCY)
        if not _ok(selected):
            print("      No appliances left after SSH engine-ID pass.", file=sys.stderr)

        # --- Step 5: RFC 3414 localize auth/priv against that box's engine ID ---
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

        # --- Step 6: deleteUser then createUser/rouser via the owning Controller ---
        print("\n[6/8] Pushing SNMPv3 config via each Controller...")

        def _push(target: Target, client: AppGateClient) -> None:
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

        _api_by_collective(_ok(selected), clients, _push)

        # --- Step 7: drop stale usmUser rows; keep the row that already has the new hash ---
        print(f"\n[7/8] SSH purge leftover usmUser (up to {SSH_CONCURRENCY} at a time)...")

        def _ssh_purge(target: Target) -> None:
            engine_fetcher.purge_persistent_user(
                target.ssh_ip, user, keep_hash=target.auth_hash
            )
            print(f"      {target.label()}: persistent USM purged")

        _run_ssh_batch(_ok(selected), _ssh_purge, SSH_CONCURRENCY)

        # --- Step 8: authPriv walk; cz-configd may need SNMP_RELOAD_DELAY first ---
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

        # Localized hashes are for ESXi USM, not the original passphrases.
        print("\n" + "=" * 60)
        print("Configuration Summary")
        print("=" * 60)
        print(f"User:     {user}")
        if rouser_line:
            print(f"Read-Only:{rouser_line}")
        current_col: Optional[int] = None
        for target in selected:
            if target.collective != current_col:
                current_col = target.collective
                print(f"  --- collective {current_col} ---")
            state = target.status.upper()
            extra = target.engine_id or target.error
            print(f"  [{state:<7}] {target.label():<32} {target.ssh_ip:<18} {extra}")
            if target.status == "ok" and target.auth_hash:
                print(
                    f"           ESXi: {user}/{target.auth_hash}/{target.priv_hash}/priv"
                )
        print("=" * 60)
        if DEBUG:
            _print_debug_report(collectives, inventory, selected)
        if any(t.status == "failed" for t in selected):
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)


def _print_debug_report(
    collectives: List[Dict[str, str]], inventory: List[Target], selected: List[Target]
) -> None:
    report: Dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "collectives": [
            {"index": int(c["index"]), "agip": c["agip"], "admin_username": c["admin_username"]}
            for c in collectives
        ],
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
                "collective": t.collective,
                "label": t.label(),
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
