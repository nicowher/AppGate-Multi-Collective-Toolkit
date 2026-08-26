"""SNMP Credential Tool — configure SNMPv3 USM across collectives.

Reached via ``python app/main.py 1`` or launcher menu option 1.

Configure flow is phase-aligned across collectives (finish a phase on every
selected box before the next phase) so logs stay readable and one slow site
does not interleave with another mid-step.

  0. Credentials + dry-run choice — fail early on bad input; preview before mutate
  1. Login each Controller — separate tokens; never reuse bearer across sites
  2. Inventory + exclude — API list (api/) + Target/exclude (core/inventory)
  3. engineIDType 3 via API — type-3 MAC engine IDs are stable and ESXi-friendly;
     must be API (cz-configd owns /etc/snmp/snmpd.conf)
  4. SSH engine ID — localization needs the real engine ID; dry-run skips snmpd
     restart so preview does not bounce production daemons
  5. Localize hashes — createUser stores Kul, not plaintext; each engine ID differs
  6. deleteUser then createUser — two PUTs so final conf has no deleteUser line
  7. Purge persistent usmUser — see ssh.engine (net-snmp ignores createUser if
     the user already exists under /var/lib/snmp)
  8. Walk — proves authPriv with the new passphrases (not the hashes)
  After dry-run: optional live apply on the same selection (no re-login)
"""
import os
import sys

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

import platform
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from api.appgate import AppGateClient
from config import (
    APPGATE_API_VERSION,
    DEBUG,
    DRY_RUN,
    PRINT_ESXI_KEYS,
    ENGINE_ID_TYPE,
    ETH_IFACE,
    SNMP_AUTH_PROTOCOL,
    SNMP_HASH_ALGO,
    SNMP_MIN_PASSPHRASE_LEN,
    SNMP_NAME_RE,
    SNMP_PRIV_PROTOCOL,
    SNMP_RELOAD_DELAY,
    SSH_CONCURRENCY,
    SUMMARY_WIDTH,
    TLS_VERIFY,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
    warn_insecure_transport,
)
from core.inventory import Target, prompt_exclusions
from core.prompts import CREDENTIALS_PATH, _parse_collectives, _require
from core.snmp_hashgen import SNMPHashGenerator
from core.snmp_validate import SNMPValidator
from core.utils import load_credentials, write_json_report
from ssh.client import run_ssh_batch
from ssh.engine import SNMPEngineFetcher

ClientMap = Dict[int, AppGateClient]


def _ok(targets: List[Target]) -> List[Target]:
    """Appliances that have not failed a previous phase (still in the run)."""
    return [t for t in targets if t.status != "failed"]


def _fail(target: Target, message: str) -> None:
    """Mark one appliance failed and keep going (fail-soft)."""
    target.status = "failed"
    target.error = message
    print(f"      FAIL {target.label()}: {message}", file=sys.stderr)


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
        if inputs["snmp_auth"] == inputs["snmp_priv"]:
            print(
                "WARNING: snmp_auth and snmp_priv are identical. "
                "DISA SNMPv3 wants distinct auth and priv secrets.",
                file=sys.stderr,
            )

        collectives = _parse_collectives(creds)
        if not collectives:
            raise ValueError("No collectives defined (collectives[] or agip)")

        warn_insecure_transport()
        dry_run = DRY_RUN
        # print(f"DEBUG step0: DRY_RUN={DRY_RUN} WRITE_RUN_REPORT={WRITE_RUN_REPORT} DEBUG={DEBUG}")
        if DEBUG:
            print(
                f"      DEBUG step0: dry_run={dry_run} collectives={len(collectives)}",
                file=sys.stderr,
            )
        engine_fetcher = SNMPEngineFetcher(ssh_user, ssh_pass)
        hashgen = SNMPHashGenerator()
        validator = SNMPValidator()
        user = inputs["snmp_user"]
        rouser_line = f"rouser {inputs['rouser']} priv" if inputs.get("rouser") else ""
        started_at = datetime.now(timezone.utc).isoformat()

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
        if DEBUG:
            print(f"      DEBUG step1: logged in collectives={list(clients)}", file=sys.stderr)

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

        if dry_run:
            print(
                "\n      DRY_RUN is set in config.py — no pin/push/purge/walk will run.",
                file=sys.stderr,
            )
        else:
            answer = input(
                "\n      Dry-run only (preview engine IDs/hashes, no changes)? [y/N]: "
            ).strip().lower()
            if answer in YES_ANSWERS:
                dry_run = True
        if dry_run:
            print(
                "\n*** DRY_RUN is ON — no API pin/push, no USM purge, no walk, "
                "no snmpd restart. Login, inventory, engine-ID read, and hash preview still run. ***\n",
                file=sys.stderr,
            )

        selected = prompt_exclusions(inventory)
        if not selected:
            raise ValueError("Nothing left to configure after exclusions")
        print(f"      Selected {len(selected)} appliance(s)")
        # print("DEBUG step2:", [t.label() for t in selected])
        if DEBUG:
            print(f"      DEBUG step2: selected={[t.label() for t in selected]}", file=sys.stderr)

        _run_phases_3_to_8(
            selected=selected,
            clients=clients,
            engine_fetcher=engine_fetcher,
            hashgen=hashgen,
            validator=validator,
            user=user,
            snmp_auth=inputs["snmp_auth"],
            snmp_priv=inputs["snmp_priv"],
            rouser_line=rouser_line,
            dry_run=dry_run,
        )

        _print_summary(selected, user=user, rouser_line=rouser_line, dry_run=dry_run)
        report = _build_run_report(
            collectives, inventory, selected, user=user, dry_run=dry_run, started_at=started_at
        )
        if WRITE_RUN_REPORT or DEBUG:
            _emit_run_report(report)

        if dry_run and any(t.status == "preview" for t in selected):
            # print(f"DEBUG: preview_count={sum(1 for t in selected if t.status == 'preview')}")
            apply = input(
                "\n      Push config to these appliances now? [y/N]: "
            ).strip().lower()
            if apply in YES_ANSWERS:
                print(
                    "\n*** Applying config (live run) — pin, push, purge, walk. ***\n",
                    file=sys.stderr,
                )
                for target in selected:
                    if target.status == "preview":
                        target.status = "pending"
                        target.error = ""
                        target.walk_ok = None
                live_started = datetime.now(timezone.utc).isoformat()
                _run_phases_3_to_8(
                    selected=selected,
                    clients=clients,
                    engine_fetcher=engine_fetcher,
                    hashgen=hashgen,
                    validator=validator,
                    user=user,
                    snmp_auth=inputs["snmp_auth"],
                    snmp_priv=inputs["snmp_priv"],
                    rouser_line=rouser_line,
                    dry_run=False,
                )
                _print_summary(selected, user=user, rouser_line=rouser_line, dry_run=False)
                live_report = _build_run_report(
                    collectives,
                    inventory,
                    selected,
                    user=user,
                    dry_run=False,
                    started_at=live_started,
                )
                if WRITE_RUN_REPORT or DEBUG:
                    _emit_run_report(live_report)

        if any(t.status == "failed" for t in selected):
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)


def _run_phases_3_to_8(
    *,
    selected: List[Target],
    clients: ClientMap,
    engine_fetcher: SNMPEngineFetcher,
    hashgen: SNMPHashGenerator,
    validator: SNMPValidator,
    user: str,
    snmp_auth: str,
    snmp_priv: str,
    rouser_line: str,
    dry_run: bool,
) -> None:
    """Steps 3–8 (shared by dry-run preview and live apply).

    dry_run=True:  print planned actions; step 4 greps engine ID without snmpd bounce.
    dry_run=False: mutate via API + SSH, then prove with a walk.
    """
    print("\n[3/8] Pinning engineIDType via API...")
    if dry_run:
        for target in _ok(selected):
            print(f"      {target.label()}: would set engineIDType {ENGINE_ID_TYPE}")
    else:
        def _pin(target: Target, client: AppGateClient) -> None:
            client.ensure_engine_id_type3(target.appliance_id)
            print(f"      {target.label()}: engineIDType set")

        _api_by_collective(_ok(selected), clients, _pin)
        time.sleep(SNMP_RELOAD_DELAY)

    print(f"\n[4/8] SSH engine ID (up to {SSH_CONCURRENCY} at a time)...")

    def _ssh_engine(target: Target) -> None:
        if target.status == "failed":
            return
        engine_id = engine_fetcher.get_engine_id(
            target.ssh_endpoints(), restart_snmpd=not dry_run
        )
        if engine_id.lower().startswith("0x"):
            engine_id = engine_id[2:]
        target.engine_id = engine_id
        print(f"      {target.label()}: engine {engine_id}")

    run_ssh_batch(_ok(selected), _ssh_engine, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))
    if not _ok(selected):
        print("      No appliances left after SSH engine-ID pass.", file=sys.stderr)

    print("\n[5/8] Localizing SNMPv3 keys...")
    for target in _ok(selected):
        try:
            data = hashgen.generate_hashes(user, snmp_auth, snmp_priv, target.engine_id)
            target.auth_hash = data["hashes"]["auth"]
            target.priv_hash = data["hashes"]["priv"]
            print(f"      {target.label()}: hashed")
        except Exception as exc:
            _fail(target, f"hash: {exc}")

    print("\n[6/8] Pushing SNMPv3 config via each Controller...")
    if dry_run:
        for target in _ok(selected):
            print(
                f"      {target.label()}: would deleteUser {user} then createUser "
                f"(engine {target.engine_id or '?'})"
            )
            target.status = "preview"
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

    print(f"\n[7/8] SSH purge leftover usmUser (up to {SSH_CONCURRENCY} at a time)...")
    if dry_run:
        for target in _ok(selected):
            print(f"      {target.label()}: would purge persistent usmUser {user}")
    else:
        def _ssh_purge(target: Target) -> None:
            engine_fetcher.purge_persistent_user(
                target.ssh_endpoints(), user, keep_hash=target.auth_hash
            )
            print(f"      {target.label()}: persistent USM purged")

        run_ssh_batch(_ok(selected), _ssh_purge, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))

    print("\n[8/8] Validating SNMP walks...")
    if dry_run:
        for target in _ok(selected):
            print(f"      {target.label()}: would walk {target.walk_endpoints()}")
            target.walk_ok = None
    else:
        time.sleep(SNMP_RELOAD_DELAY)
        for target in _ok(selected):
            ok = validator.validate_snmp_walk(
                target.walk_endpoints(),
                user,
                snmp_auth,
                snmp_priv,
                engine_id=target.engine_id,
            )
            target.walk_ok = ok
            print(f"      {target.label()}: walk {'PASSED' if ok else 'FAILED'}")
            if not ok:
                _fail(target, "SNMP walk failed")


def _print_summary(
    selected: List[Target], *, user: str, rouser_line: str, dry_run: bool
) -> None:
    print("\n" + "=" * SUMMARY_WIDTH)
    print("DRY-RUN Preview" if dry_run else "Configuration Summary")
    print("=" * SUMMARY_WIDTH)
    print(f"User:     {user}")
    if dry_run:
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
        if PRINT_ESXI_KEYS and target.auth_hash and target.status in ("ok", "preview"):
            print(f"           ESXi: {user}/{target.auth_hash}/{target.priv_hash}/priv")
    print("=" * SUMMARY_WIDTH)


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
        "script": "snmp_credentials",
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
        "preview_count": sum(1 for t in selected if t.status == "preview"),
        "failed_count": sum(1 for t in selected if t.status == "failed"),
        "targets": [],
    }
    for t in selected:
        entry: Dict[str, Any] = {
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
        }
        if dry_run:
            entry["planned_actions"] = [
                f"engineIDType {ENGINE_ID_TYPE}",
                f"deleteUser {user}",
                f"createUser {user} {SNMP_AUTH_PROTOCOL}/AES (localized)",
                f"purge persistent usmUser {user}",
                f"walk {t.walk_endpoints()}",
            ]
        report["targets"].append(entry)
    return report


def _emit_run_report(report: Dict[str, Any]) -> None:
    """Write reports/run-*.json or dryrun-*.json. Console dump only if DEBUG."""
    prefix = "dryrun" if report.get("dry_run") else "run"
    write_json_report(prefix, report)


if __name__ == "__main__":
    main()
