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
    WALK_CONCURRENCY,
    SUMMARY_WIDTH,
    TLS_VERIFY,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
    warn_insecure_transport,
)
from core.inventory import Target, prompt_exclusions
from core.prompts import (
    CREDENTIALS_PATH,
    _parse_collectives,
    _require,
    collective_for_target,
    prepare_collectives,
)
from core.snmp_hashgen import SNMPHashGenerator
from core.snmp_validate import SNMPValidator
from core.utils import HaltError, halt, load_credentials, print_error, run_target_batch, write_json_report
from ssh.client import prime_target_host_keys, run_ssh_batch, ssh_password_for
from ssh.engine import SNMPEngineFetcher

ClientMap = Dict[int, AppGateClient]


def _ok(targets: List[Target]) -> List[Target]:
    """Appliances that have not failed a previous phase (still in the run)."""
    return [t for t in targets if t.status != "failed"]


def _fail(target: Target, message: str) -> None:
    """Mark one appliance failed and keep going (fail-soft)."""
    target.status = "failed"
    target.error = message
    print_error(
        "E09",
        f"{target.label()}: {message}",
        "This box is skipped; others continue.",
        "SSH: after FQDN+IP fail, Try a new password, or check ssh_username/password.",
        "Engine ID: need engineIDType 3, eth0 MAC, sudo on the appliance.",
        "Walk/digest fail: leftover usmUser — re-run live so step 7 can purge.",
    )


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
        warn_insecure_transport()
        creds = load_credentials(CREDENTIALS_PATH)
        collectives = _parse_collectives(creds)
        if not collectives:
            halt(
                "E01",
                "No collectives defined (collectives[] or agip)",
                "Add collectives[].fqdn to credentials.json or enter when prompted.",
            )
        prepare_collectives(creds, collectives, need_snmp=True)
        inputs = {
            "snmp_user": collectives[0].get("snmp_user") or "",
            "snmp_auth": collectives[0].get("snmp_auth") or "",
            "snmp_priv": collectives[0].get("snmp_priv") or "",
            "rouser": _require(
                creds,
                "rouser",
                "SNMP Read-Only Username (rouser)",
                required=False,
                pattern=SNMP_NAME_RE,
                pattern_msg="Use letters, digits, underscore, dot, or hyphen.",
            ),
        }
        if inputs["snmp_auth"] and inputs["snmp_auth"] == inputs["snmp_priv"]:
            print(
                "WARNING: snmp_auth and snmp_priv are identical. "
                "DISA SNMPv3 wants distinct auth and priv secrets.",
                file=sys.stderr,
            )

        dry_run = DRY_RUN
        # print(f"DEBUG step0: DRY_RUN={DRY_RUN} WRITE_RUN_REPORT={WRITE_RUN_REPORT} DEBUG={DEBUG}")
        if DEBUG:
            print(
                f"      DEBUG step0: dry_run={dry_run} collectives={len(collectives)}",
                file=sys.stderr,
            )
        hashgen = SNMPHashGenerator()
        user = inputs["snmp_user"]
        rouser_line = f"rouser {inputs['rouser']} priv" if inputs.get("rouser") else ""
        started_at = datetime.now(timezone.utc).isoformat()

        print("\n[1/8] Authenticating to Controller API(s)...")
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
                    "Self-signed: answer y on Proceed anyway, or LAB_MODE=True.",
                )
        if not clients:
            halt(
                "E02",
                "No Controller accepted login",
                "Fix API creds, TLS, or agip.",
            )
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
            halt(
                "E03",
                "No activated appliances with an SSH address were found",
                "Need activated appliances with SSH FQDN/IP and Appliance View.",
            )
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
            halt(
                "E04",
                "Nothing left to configure after exclusions",
                "Press Enter to keep all, or exclude fewer.",
            )
        print(f"      Selected {len(selected)} appliance(s)")
        # print("DEBUG step2:", [t.label() for t in selected])
        if DEBUG:
            print(f"      DEBUG step2: selected={[t.label() for t in selected]}", file=sys.stderr)

        _run_phases_3_to_8(
            selected=selected,
            clients=clients,
            collectives=collectives,
            hashgen=hashgen,
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
                    collectives=collectives,
                    hashgen=hashgen,
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
    except HaltError:
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)


def _run_phases_3_to_8(
    *,
    selected: List[Target],
    clients: ClientMap,
    collectives: list,
    hashgen: SNMPHashGenerator,
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
    prime_target_host_keys(_ok(selected), collectives)

    def _ssh_engine(target: Target) -> None:
        if target.status == "failed":
            return
        col = collective_for_target(target, collectives)
        engine_id = SNMPEngineFetcher(
            col["ssh_username"], ssh_password_for(target, col)
        ).get_engine_id(target.ssh_endpoints(), restart_snmpd=not dry_run)
        if engine_id.lower().startswith("0x"):
            engine_id = engine_id[2:]
        target.engine_id = engine_id
        print(f"      {target.label()}: engine {engine_id}")

    run_ssh_batch(_ok(selected), _ssh_engine, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))
    if not _ok(selected):
        print_error(
            "E09",
            "No appliances left after SSH engine-ID pass",
            "Every selected box failed SSH or engine-ID read.",
            "After FQDN+IP fail: Try a new password. Check sudo, eth0, engineIDType 3.",
        )

    print("\n[5/8] Localizing SNMPv3 keys...")
    for target in _ok(selected):
        try:
            col = collective_for_target(target, collectives)
            data = hashgen.generate_hashes(
                col.get("snmp_user") or user,
                col.get("snmp_auth") or snmp_auth,
                col.get("snmp_priv") or snmp_priv,
                target.engine_id,
            )
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
            col = collective_for_target(target, collectives)
            snmp_user = col.get("snmp_user") or user
            client.delete_snmp_user(snmp_user, appliance_id=target.appliance_id)
            time.sleep(SNMP_RELOAD_DELAY)
            client.update_snmp_config(
                snmp_user,
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
            col = collective_for_target(target, collectives)
            SNMPEngineFetcher(
                col["ssh_username"], ssh_password_for(target, col)
            ).purge_persistent_user(
                target.ssh_endpoints(),
                col.get("snmp_user") or user,
                keep_hash=target.auth_hash,
            )
            print(f"      {target.label()}: persistent USM purged")

        run_ssh_batch(_ok(selected), _ssh_purge, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))

    print(f"\n[8/8] Validating SNMP walks (up to {WALK_CONCURRENCY} at a time)...")
    if dry_run:
        for target in _ok(selected):
            print(f"      {target.label()}: would walk {target.walk_endpoints()}")
            target.walk_ok = None
    else:
        time.sleep(SNMP_RELOAD_DELAY)

        def _walk_one(target: Target) -> None:
            col = collective_for_target(target, collectives)
            ok = SNMPValidator().validate_snmp_walk(
                target.walk_endpoints(),
                col.get("snmp_user") or user,
                col.get("snmp_auth") or snmp_auth,
                col.get("snmp_priv") or snmp_priv,
                engine_id=target.engine_id,
            )
            target.walk_ok = ok
            print(f"      {target.label()}: walk {'PASSED' if ok else 'FAILED'}")
            if not ok:
                raise RuntimeError("SNMP walk failed")

        run_target_batch(
            _ok(selected),
            _walk_one,
            WALK_CONCURRENCY,
            lambda t, e: _fail(t, "SNMP walk failed"),
        )


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
                "api_username": c["api_username"],
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
