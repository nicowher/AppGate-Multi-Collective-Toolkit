"""Multi-collective SNMPv3 configure-and-validate.

Phase-aligned across collectives (array order = 1, 2, 3, ...):

  1. Login every Controller (own API account / token)
  2. Pull appliances from every successful login; one exclude prompt
  3. API engineIDType 3 (serialized per Controller)  [skipped if DRY_RUN]
  4. SSH engine IDs (shared pool)                     [read-only; runs in dry-run]
  5. Localize hashes                                 [runs in dry-run]
  6. API deleteUser + createUser                     [skipped if DRY_RUN]
  7. SSH purge usmUser                               [skipped if DRY_RUN]
  8. Walk every pushed device                        [skipped if DRY_RUN]
"""
import json
import os
import platform
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from appgate import AppGateClient
from config import (
    APPGATE_API_VERSION,
    CREDENTIALS_FILENAME,
    DEBUG,
    DRY_RUN,
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
    WRITE_RUN_REPORT,
    YES_ANSWERS,
    warn_insecure_transport,
)
from inventory import Target, prompt_exclusions
from snmp_engine import SNMPEngineFetcher
from snmp_hashgen import SNMPHashGenerator
from snmp_validate import SNMPValidator
from utils import REPO_ROOT, is_valid_host, load_credentials, prompt_until_valid

# credentials.json lives next to the launchers, not inside app/.
CREDENTIALS_PATH = os.path.join(REPO_ROOT, CREDENTIALS_FILENAME)

# After step 1: collective number (1, 2, …) → that Controller's logged-in API client.
ClientMap = Dict[int, AppGateClient]


def _require(
    creds: dict,
    field: str,
    prompt: str,
    sensitive: bool = False,
    required: bool = True,
    min_len: int = 0,
    pattern: Optional[str] = None,
    pattern_msg: str = "Invalid format. Try again.",
    validator=None,
    validator_msg: str = "Enter IPv4, IPv6, or an FQDN (e.g. host.example.com).",
) -> str:
    """Use credentials.json if valid; otherwise keep asking (never exit)."""
    return prompt_until_valid(
        creds,
        field,
        prompt,
        sensitive=sensitive,
        required=required,
        min_len=min_len,
        pattern=pattern,
        pattern_msg=pattern_msg,
        validator=validator,
        validator_msg=validator_msg,
    )


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

    Prefer collectives[]. Each needs fqdn (API/SSH/walk primary) and optional
    agip (connect fallback). Array order is the name: 1, 2, …. Duplicate
    FQDNs warn; we still run both. Old files with only agip still prompt for FQDN.
    """
    raw = creds.get("collectives")
    rows: List[Dict[str, str]] = []
    if isinstance(raw, list) and raw:
        for item in raw:
            if not isinstance(item, dict):
                continue
            rows.append({
                "fqdn": str(item.get("fqdn") or item.get("hostname") or "").strip(),
                "agip": str(item.get("agip") or "").strip(),
                "admin_username": str(item.get("admin_username") or "").strip(),
                "admin_password": str(item.get("admin_password") or ""),
            })
    else:
        rows.append({
            "fqdn": str(creds.get("fqdn") or creds.get("hostname") or "").strip(),
            "agip": str(creds.get("agip") or "").strip(),
            "admin_username": str(creds.get("admin_username") or "").strip(),
            "admin_password": str(creds.get("admin_password") or ""),
        })

    seen: Dict[str, int] = {}
    out: List[Dict[str, str]] = []

    def _add(i: int, row: Dict[str, str]) -> None:
        fqdn = _require(
            row,
            "fqdn",
            f"Collective {i} Controller FQDN",
            validator=is_valid_host,
            validator_msg="Enter the Controller admin FQDN (e.g. hit-agr-001.hit.local).",
        )
        agip = _require(
            row,
            "agip",
            f"Collective {i} Controller IP (fallback)",
            required=False,
            validator=is_valid_host,
        )
        user = _require(row, "admin_username", f"Collective {i} Admin Username")
        label = f"{fqdn} - {agip}" if agip else fqdn
        password = _require(
            row, "admin_password", f"Collective {i} ({label}) Admin Password",
            sensitive=True,
        )
        key = fqdn.lower()
        if key in seen:
            print(
                f"WARNING: collectives {seen[key]} and {i} share FQDN {fqdn}. "
                "The same collective will be configured twice.",
                file=sys.stderr,
            )
        else:
            seen[key] = i
        out.append({
            "index": str(i),
            "fqdn": fqdn,
            "agip": agip,
            "admin_username": user,
            "admin_password": password,
        })

    from_file = os.path.isfile(CREDENTIALS_PATH) and any(
        (r.get("fqdn") or r.get("agip") or r.get("admin_username")) for r in rows
    )
    for i, row in enumerate(rows, 1):
        _add(i, row)

    first_ask = True
    while True:
        if first_ask and from_file:
            print(f"\n      Found {CREDENTIALS_FILENAME} with {len(out)} Controller(s):")
            for col in out:
                extra = f" - {col['agip']}" if col.get("agip") else ""
                print(f"        {col['index']}) {col['fqdn']}{extra}")
            more = input(
                "      Add another Controller besides those in the file? [y/N]: "
            ).strip().lower()
            first_ask = False
        else:
            more = input("      Add another Controller? [y/N]: ").strip().lower()
        if more not in YES_ANSWERS:
            break
        _add(
            len(out) + 1,
            {"fqdn": "", "agip": "", "admin_username": "", "admin_password": ""},
        )
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
            "snmp_user": _require(
                creds,
                "snmp_user",
                "SNMP User",
                pattern=SNMP_NAME_RE,
                pattern_msg="Use letters, digits, underscore, dot, or hyphen.",
            ),
            "snmp_auth": _require(
                creds, "snmp_auth", "SNMP Auth", sensitive=True, min_len=SNMP_MIN_PASSPHRASE_LEN
            ),
            "snmp_priv": _require(
                creds, "snmp_priv", "SNMP Priv", sensitive=True, min_len=SNMP_MIN_PASSPHRASE_LEN
            ),
            "rouser": _require(
                creds,
                "rouser",
                "SNMP Read-Only Username (rouser)",
                required=False,
                pattern=SNMP_NAME_RE,
                pattern_msg="Use letters, digits, underscore, dot, or hyphen.",
            ),
        }
        ssh_user = _require(creds, "ssh_username", "SSH Username")
        ssh_pass = _require(creds, "ssh_password", "SSH Password", sensitive=True)

        collectives = _parse_collectives(creds)
        if not collectives:
            raise ValueError("No collectives defined (collectives[] or agip)")

        # Lab TLS/SSH defaults print a DISA warning; flip TLS_VERIFY at bottom of config.py.
        warn_insecure_transport()
        if DRY_RUN:
            print(
                "\n*** DRY_RUN is ON — no API pin/push, no USM purge, no walk. "
                "Login, inventory, engine-ID read, and hash preview still run. ***\n",
                file=sys.stderr,
            )
        engine_fetcher = SNMPEngineFetcher(ssh_user, ssh_pass)
        hashgen = SNMPHashGenerator()
        validator = SNMPValidator()
        user = inputs["snmp_user"]
        rouser_line = f"rouser {inputs['rouser']} priv" if inputs.get("rouser") else ""
        started_at = datetime.now(timezone.utc).isoformat()

        # --- Step 1: one POST /login per Controller; skip a site if login fails ---
        print("\n[1/8] Authenticating to Controller API(s)...")
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
        # print("DEBUG step1: logged in", list(clients))

        # --- Step 2: GET /appliances on each token; one exclude table (1.hostname) ---
        print("\n[2/8] Pulling appliances from every Controller...")
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
            raise ValueError("Nothing left to configure after exclusions")
        print(f"      Selected {len(selected)} appliance(s)")
        # print("DEBUG step2:", [t.label() for t in selected])

        # --- Step 3: PUT engineIDType 3 so SSH later reads a MAC-based engine ID ---
        print("\n[3/8] Pinning engineIDType via API...")
        if DRY_RUN:
            for target in _ok(selected):
                print(f"      {target.label()}: would set engineIDType {ENGINE_ID_TYPE}")
        else:
            def _pin(target: Target, client: AppGateClient) -> None:
                client.ensure_engine_id_type3(target.appliance_id)
                print(f"      {target.label()}: engineIDType set")

            _api_by_collective(_ok(selected), clients, _pin)
            time.sleep(SNMP_RELOAD_DELAY)

        # --- Step 4: restart snmpd, read oldEngineID, check RFC 3411 type 3 vs eth0 MAC ---
        # Read-only enough for dry-run preview (engine ID + hash). Restarts snmpd briefly.
        print(f"\n[4/8] SSH engine ID (up to {SSH_CONCURRENCY} at a time)...")

        def _ssh_engine(target: Target) -> None:
            if target.status == "failed":
                return
            engine_id = engine_fetcher.get_engine_id(target.ssh_endpoints())
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
            except Exception as exc:
                _fail(target, f"hash: {exc}")

        # --- Step 6: deleteUser then createUser/rouser via the owning Controller ---
        print("\n[6/8] Pushing SNMPv3 config via each Controller...")
        if DRY_RUN:
            for target in _ok(selected):
                print(
                    f"      {target.label()}: would deleteUser {user} then createUser "
                    f"(engine {target.engine_id or '?'})"
                )
                target.status = "ok"
        else:
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

        # --- Step 7: delete persistent usmUser so snmpd applies createUser on restart ---
        print(f"\n[7/8] SSH purge leftover usmUser (up to {SSH_CONCURRENCY} at a time)...")
        if DRY_RUN:
            for target in _ok(selected):
                print(f"      {target.label()}: would purge persistent usmUser {user}")
        else:
            def _ssh_purge(target: Target) -> None:
                engine_fetcher.purge_persistent_user(
                    target.ssh_endpoints(), user, keep_hash=target.auth_hash
                )
                print(f"      {target.label()}: persistent USM purged")

            _run_ssh_batch(_ok(selected), _ssh_purge, SSH_CONCURRENCY)

        # --- Step 8: authPriv walk; cz-configd may need SNMP_RELOAD_DELAY first ---
        print("\n[8/8] Validating SNMP walks...")
        if DRY_RUN:
            for target in _ok(selected):
                print(f"      {target.label()}: would walk {target.walk_endpoints()}")
                target.walk_ok = None
        else:
            time.sleep(SNMP_RELOAD_DELAY)
            for target in _ok(selected):
                ok = validator.validate_snmp_walk(
                    target.walk_endpoints(),
                    user,
                    inputs["snmp_auth"],
                    inputs["snmp_priv"],
                    engine_id=target.engine_id,
                )
                target.walk_ok = ok
                print(f"      {target.label()}: walk {'PASSED' if ok else 'FAILED'}")
                if not ok:
                    _fail(target, "SNMP walk failed")

        # Localized hashes are for ESXi USM, not the original passphrases.
        print("\n" + "=" * 60)
        print("DRY-RUN Preview" if DRY_RUN else "Configuration Summary")
        print("=" * 60)
        print(f"User:     {user}")
        if DRY_RUN:
            print("Mode:     DRY_RUN (no changes applied)")
        if rouser_line:
            print(f"Read-Only:{rouser_line}")
        current_col: Optional[int] = None
        for target in selected:
            if target.collective != current_col:
                current_col = target.collective
                print(f"  --- collective {current_col} ---")
            state = target.status.upper()
            extra = target.engine_id or target.error
            host = target.ssh_fqdn or target.ssh_ip
            print(f"  [{state:<7}] {target.label():<32} {host:<22} {extra}")
            if target.status == "ok" and target.auth_hash:
                print(
                    f"           ESXi: {user}/{target.auth_hash}/{target.priv_hash}/priv"
                )
        print("=" * 60)
        report = _build_run_report(
            collectives, inventory, selected, user=user, dry_run=DRY_RUN, started_at=started_at
        )
        if WRITE_RUN_REPORT or DEBUG:
            _emit_run_report(report)
        if any(t.status == "failed" for t in selected):
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)


def _build_run_report(
    collectives: List[Dict[str, str]],
    inventory: List[Target],
    selected: List[Target],
    *,
    user: str,
    dry_run: bool,
    started_at: str,
) -> Dict[str, Any]:
    """Structured end-of-run report. No passwords, tokens, or full localized keys."""
    finished_at = datetime.now(timezone.utc).isoformat()
    report: Dict[str, Any] = {
        "script": "main",
        "started_at": started_at,
        "finished_at": finished_at,
        "dry_run": dry_run,
        "snmp_user": user,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "collectives": [
            {
                "index": int(c["index"]),
                "fqdn": c.get("fqdn", ""),
                "agip": c.get("agip", ""),
                "admin_username": c["admin_username"],
            }
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
            "dry_run": dry_run,
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
                "ssh_fqdn": t.ssh_fqdn,
                "ssh_ip": t.ssh_ip,
                "walk_endpoints": t.walk_endpoints(),
                "ssh_endpoints": t.ssh_endpoints(),
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
                "planned_actions": [
                    f"engineIDType {ENGINE_ID_TYPE}",
                    f"deleteUser {user}",
                    f"createUser {user} {SNMP_AUTH_PROTOCOL}/AES (localized)",
                    f"purge persistent usmUser {user}",
                    f"walk {t.walk_endpoints()}",
                ],
            }
        )
    return report


def _emit_run_report(report: Dict[str, Any]) -> None:
    """Print JSON report and optionally write reports/run-*.json."""
    text = json.dumps(report, indent=2)
    print("\n----- BEGIN RUN REPORT -----")
    print(text)
    print("----- END RUN REPORT -----")
    if not WRITE_RUN_REPORT:
        return
    reports_dir = os.path.join(REPO_ROOT, "reports")
    try:
        os.makedirs(reports_dir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        mode = "dryrun" if report.get("dry_run") else "run"
        path = os.path.join(reports_dir, f"{mode}-{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.write("\n")
        print(f"      Report written: {path}", file=sys.stderr)
    except OSError as exc:
        print(f"      Could not write report file: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
