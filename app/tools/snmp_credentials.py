"""SNMP Credential Tool — configure SNMPv3 USM across collectives.

Reached via ``python app/main.py 1`` or launcher menu option 1.

Configure flow is phase-aligned across collectives (finish a phase on every
selected box before the next phase) so logs stay readable and one slow site
does not interleave with another mid-step.

  0. Credentials — fail early on bad input. Preview always runs; Apply is a later prompt
  1. Login each Controller — separate tokens; never reuse bearer across sites
  2. Inventory + exclude — API list (api/) + Target/exclude (core/inventory)
  3. engineIDType 3 via API — type-3 MAC engine IDs are stable and ESXi-friendly;
     must be API (cz-configd owns /etc/snmp/snmpd.conf)
  4. SSH engine ID — localization needs the real engine ID; dry-run skips snmpd
     restart so preview does not bounce production daemons
  5. Localize hashes — createUser stores Kul, not plaintext; each engine ID differs
  6. Add keeps other USM users. Replace drops other createUser/rouser lines, then createUser
  7. Purge persistent usmUser — see ssh.engine (net-snmp ignores createUser if
     the user already exists under /var/lib/snmp)
  8. Walk — proves authPriv with the new passphrases (not the hashes)
  After preview: optional live apply on the same selection unless DRY_RUN (no re-login)
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

from api.appgate import AppGateClient, AppliancePutError
from core.run import (
    preview_then_apply,
    ClientMap,
    login_collectives,
    fail_box,
    report_target_fields,
    rollback_prior,
    print_result,
    prompt_add_or_replace,
    select_appliances,
    ssh_failure_code,
    ssh_failure_reason,
)
from config import (
    APPGATE_API_VERSION,
    DEBUG,
    DRY_RUN,
    SKIP_CREDENTIAL_WALK,
    ENGINE_ID_TYPE,
    ETH_IFACE,
    SNMP_AUTH_PROTOCOL,
    SNMP_HASH_ALGO,
    SNMP_NAME_RE,
    SNMP_PRIV_PROTOCOL,
    SNMP_RELOAD_DELAY,
    SSH_CONCURRENCY,
    WALK_CONCURRENCY,
    SUMMARY_WIDTH,
    insecure_api_enabled,
    WRITE_RUN_REPORT,
    warn_insecure_transport,
)
from core.inventory import STATUS_FAILED, STATUS_OK, STATUS_PREVIEW, Target
from core.ui import boxes, run_summary, step_banner
from core.prompts import (
    require_collectives,
    CREDENTIALS_PATH,
    _parse_collectives,
    _require,
    collective_for_target,
    prepare_collectives,
    promote_shared_fields,
)
from core.snmp_hashgen import SNMPHashGenerator
from core.snmp_validate import SNMPValidator
from core.utils import (
    print_unexpected_error,
    run_tool,
    HaltError,
    begin_replaced_run,
    load_credentials,
    print_error,
    run_target_batch,
    write_json_report,
)
from ssh.client import iter_primed_targets, run_ssh_batch, ssh_password_for
from ssh.engine import SNMPEngineFetcher

def _ok(targets: List[Target]) -> List[Target]:
    """Appliances that have not failed a previous phase (still in the run)."""
    return [t for t in targets if t.status != STATUS_FAILED]


def _fail(target: Target, message: str, code: str = "E09") -> None:
    """Mark one appliance failed and keep going (fail-soft). The report keeps the detail."""
    low = message.lower()
    # The old bare "auth" check also matched SNMP text such as "auth hash".
    human = ssh_failure_reason(message)
    if human:
        pass
    elif "walk" in low:
        human = "SNMP walk failed. Check UDP 161, the SNMP user, and leftover users on the box."
    elif "engine" in low:
        human = "Could not read the SNMP engine ID. Check sudo and the management interface."
    elif "http " in low:
        human = "The Controller rejected the SNMP change. Check the report."
    else:
        human = message
    fail_box(target, human, message, ssh_failure_code(message) or code)


def _prompt_snmp_mode() -> bool:
    """True = replace all USM users in snmpd.conf with this one."""
    return prompt_add_or_replace(
        "",
        add_line="Add (keep other USM users; add/update this username)",
        replace_line="Replace (drop other createUser/rouser lines; this user only)",
    )


def _api_by_collective(
    targets: List[Target],
    clients: ClientMap,
    worker: Callable[[Target, AppGateClient], None],
) -> None:
    """Steps 3 and 6: call the API using the client that owns that appliance.

    PUTs to the same Controller stay sequential. Never send collective 2's
    token to collective 1's appliance id.

    The first failure stops the step for every collective. Earlier boxes are
    rolled back, and every box not reached yet is marked failed. A box left in
    its old status would go on to the SSH steps, and step 7 would purge its SNMP
    user even though it never got the new createUser line.
    """
    by_col: Dict[int, List[Target]] = {}
    applied = []
    for t in targets:
        by_col.setdefault(t.collective, []).append(t)
    order = [t for col in sorted(by_col) for t in by_col[col]]

    def _stop_after(failed: Target) -> None:
        """First API failure in a step: roll back boxes already changed and mark the rest not changed, so a half-applied collective is not left behind."""
        rollback_prior(applied)
        done = {id(t) for t, _c in applied} | {id(failed)}
        left = [t for t in order if id(t) not in done and t.status != STATUS_FAILED]
        # print(f"DEBUG api_by_collective: stop at {failed.label()} left={[t.label() for t in left]}")
        for t in left:
            # Same code as the API step that stopped (not E09, which is the engine-ID read).
            _fail(t, f"not changed; this step stopped after {failed.label()} failed", code="E08")

    for col in sorted(by_col):
        client = clients.get(col)
        if client is None:
            for t in by_col[col]:
                _fail(t, f"no API client for collective {col}")
            continue
        for target in by_col[col]:
            try:
                worker(target, client)
                applied.append((target, client))
            except AppliancePutError as exc:
                _fail(target, str(exc), code="E08")
                _stop_after(target)
                return
            except Exception as exc:
                _fail(target, str(exc))
                _stop_after(target)
                return


def main() -> None:
    """Menu 1: login, inventory, preview all 8 steps, then apply only after confirm. Each step skips boxes that failed an earlier step."""
    try:
        warn_insecure_transport()
        creds = load_credentials(CREDENTIALS_PATH)
        collectives = _parse_collectives(creds)
        require_collectives(collectives)
        prepare_collectives(creds, collectives, need_snmp=True)
        promote_shared_fields(creds, ("rouser",))
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
                pattern_msg="Use 1-32 letters, digits, underscore, dot, or hyphen.",
            ),
        }
        if inputs["snmp_auth"] and inputs["snmp_auth"] == inputs["snmp_priv"]:
            print(
                "WARNING: snmp_auth and snmp_priv are identical. "
                "DISA SNMPv3 wants distinct auth and priv secrets.",
                file=sys.stderr,
            )

        if DEBUG:
            print(
                f"      DEBUG step0: preview first DRY_RUN={DRY_RUN} collectives={len(collectives)}",
                file=sys.stderr,
            )
        hashgen = SNMPHashGenerator()
        user = inputs["snmp_user"]
        rouser_line = f"rouser {inputs['rouser']} priv" if inputs.get("rouser") else ""

        clients = login_collectives(collectives, step="[1/8]")
        # print("DEBUG step1: logged in", list(clients))
        if DEBUG:
            print(f"      DEBUG step1: logged in collectives={list(clients)}", file=sys.stderr)

        print(
            "\n*** Preview — no API pin/push, no USM purge, no walk, "
            "no snmpd restart. Engine-ID read and hash preview still run. ***\n",
            file=sys.stderr,
        )
        if DRY_RUN:
            print(
                "      DRY_RUN is set in config.py — apply will not be offered.",
                file=sys.stderr,
            )

        selected = select_appliances(clients, step="[2/8]")
        inventory = selected
        # print("DEBUG step2:", [t.label() for t in selected])
        if DEBUG:
            print(f"      DEBUG step2: selected={[t.label() for t in selected]}", file=sys.stderr)
        replace = _prompt_snmp_mode()

        phase_args = dict(
            selected=selected, clients=clients, collectives=collectives, hashgen=hashgen, user=user,
            snmp_auth=inputs["snmp_auth"], snmp_priv=inputs["snmp_priv"], rouser_line=rouser_line, replace=replace,
        )

        def _phases(dry: bool, targets: Optional[List[Target]] = None) -> None:
            """Steps 3-8 on targets (the live run gets only the confirmed boxes), then menu 1's table for every box."""
            _run_phases_3_to_8(dry_run=dry, **dict(phase_args, selected=targets if targets is not None else selected))
            _print_summary(selected, user=user, rouser_line=rouser_line, dry_run=dry)

        def _report(dry: bool, at: str) -> None:
            """Menu 1's own report shape (engine ID lengths, hash lengths, planned actions)."""
            built = _build_run_report(
                collectives, inventory, selected, user=user, dry_run=dry, started_at=at, clients=clients,
            )
            if WRITE_RUN_REPORT or DEBUG:
                _emit_run_report(built)

        def _live_banner() -> None:
            """Say the live run starts, and clear the preview's walk results."""
            print("\n*** Applying config (live run) — pin, push, purge, walk. ***\n", file=sys.stderr)
            for target in selected:
                if target.status == STATUS_PREVIEW:
                    target.walk_ok = None

        preview_then_apply(
            selected,
            preview=lambda: _phases(True),
            apply=lambda go: _phases(False, go),
            report=_report,
            prompt="Push SNMP config to {boxes} now?",
            before_apply=_live_banner,
            summary=False,
            dry_run_note=False,
        )

        if any(t.status == STATUS_FAILED for t in selected):
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        raise
    except HaltError:
        sys.exit(1)
    except Exception as exc:
        print_unexpected_error(exc)
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
    replace: bool = False,
) -> None:
    """Steps 3-8: the preview (no change anywhere) or the live run.

    Two separate paths on purpose: one loop with dry_run branches in every step
    is the shape that once let a live run act on boxes the preview had not
    cleared. Steps 4 and 5 (engine read, key localization) are shared helpers.
    """
    keys = dict(selected=selected, collectives=collectives, hashgen=hashgen, user=user,
                snmp_auth=snmp_auth, snmp_priv=snmp_priv)
    if dry_run:
        _preview_phases(replace=replace, **keys)
    else:
        _live_phases(clients=clients, rouser_line=rouser_line, replace=replace, **keys)


def _step4_engine(selected: List[Target], collectives: list, *, restart: bool) -> None:
    """Step 4: read each box's engine ID over SSH (live: restart snmpd first so engineIDType 3 applies).

    Each box starts as soon as its SSH address is settled. Two boxes with the
    same engine ID both fail, because keys localized to one ID would be valid
    on both.
    """
    step_banner(
        "[4/8]",
        "Read each SNMP engine ID over SSH",
        f"{boxes(len(_ok(selected)))}, up to {SSH_CONCURRENCY} at a time" + ("; snmpd restarts first" if restart else ""),
    )
    # print(f"DEBUG step4: restart_snmpd={restart}")

    def _ssh_engine(target: Target) -> None:
        """Read one box's engine ID over SSH, because the localized keys depend on it."""
        if target.status == STATUS_FAILED:
            return
        col = collective_for_target(target, collectives)
        engine_id = SNMPEngineFetcher(
            col["ssh_username"], ssh_password_for(target, col)
        ).get_engine_id(target, restart_snmpd=restart)
        if engine_id.lower().startswith("0x"):
            engine_id = engine_id[2:]
        target.engine_id = engine_id
        # The engine ID itself only with DEBUG (it stays off the console in production).
        print_result(target, f"engine ID {engine_id}" if DEBUG else "engine ID read")

    run_ssh_batch(iter_primed_targets(_ok(selected), collectives), _ssh_engine, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))
    seen_engine: Dict[str, Target] = {}
    for target in list(_ok(selected)):
        eid = (target.engine_id or "").lower()
        if not eid:
            continue
        prior = seen_engine.get(eid)
        if prior is not None:
            _fail(target, f"engine ID matches {prior.label()}")
            _fail(prior, f"engine ID matches {target.label()}")
        else:
            seen_engine[eid] = target
    if not _ok(selected):
        print_error(
            "E09",
            "No appliances left after SSH engine-ID pass",
            "Every selected box failed SSH or engine-ID read.",
            "After FQDN+IP fail: Try a new password. Check sudo, eth0, engineIDType 3.",
        )


def _step5_localize(
    selected: List[Target], collectives: list, hashgen: SNMPHashGenerator, user: str, snmp_auth: str, snmp_priv: str
) -> None:
    """Step 5: localize auth and priv keys to each engine ID in memory (RFC 3414); nothing is sent."""
    step_banner("[5/8]", "Localize the SNMPv3 keys to each engine ID", "in memory, RFC 3414")
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
            print_result(target, f"keys localized ({SNMP_AUTH_PROTOCOL} / {SNMP_PRIV_PROTOCOL})")
        except Exception as exc:
            _fail(target, f"hash: {exc}")


def _preview_phases(
    *, selected: List[Target], collectives: list, hashgen: SNMPHashGenerator, user: str,
    snmp_auth: str, snmp_priv: str, replace: bool,
) -> None:
    """Preview of steps 3-8: plan lines only, plus the read-only engine read and key localization.

    Nothing is changed: no API pin or push, no snmpd restart, no USM purge, no
    walk. Boxes that would change end with status "preview".
    """
    n = len(_ok(selected))
    step_banner("[3/8]", f"Pin engineIDType {ENGINE_ID_TYPE} via the Controller API", boxes(n))
    for target in _ok(selected):
        print_result(target, f"set engineIDType {ENGINE_ID_TYPE}", word="Plan")
    _step4_engine(selected, collectives, restart=False)
    _step5_localize(selected, collectives, hashgen, user, snmp_auth, snmp_priv)
    mode = "replace" if replace else "add"
    step_banner("[6/8]", "Push the SNMPv3 user through each Controller", boxes(len(_ok(selected))))
    for target in _ok(selected):
        print_result(target, f"{mode} SNMPv3 user {user}", word="Plan")
        if DEBUG:
            print(f"      DEBUG {target.label()}: engine={target.engine_id or '?'}", file=sys.stderr)
        target.status = STATUS_PREVIEW
    step_banner("[7/8]", "Clear the old SNMP key rows over SSH", f"{boxes(len(_ok(selected)))}, up to {SSH_CONCURRENCY} at a time")
    for target in _ok(selected):
        print_result(target, f"clear old usmUser rows for {user}", word="Plan")
    step_banner("[8/8]", "Check each box answers an SNMPv3 walk", f"{boxes(len(_ok(selected)))}, up to {WALK_CONCURRENCY} at a time")
    for target in _ok(selected):
        if SKIP_CREDENTIAL_WALK:
            print_result(target, "walk skipped (SKIP_CREDENTIAL_WALK)", word="Skip")
        else:
            host = (target.walk_endpoints() or ["?"])[0]
            print_result(target, f"walk {host}", word="Plan")
            if DEBUG:
                print(f"      DEBUG walk endpoints={target.walk_endpoints()!r}", file=sys.stderr)
        target.walk_ok = None


def _live_phases(
    *, selected: List[Target], clients: ClientMap, collectives: list, hashgen: SNMPHashGenerator, user: str,
    snmp_auth: str, snmp_priv: str, rouser_line: str, replace: bool,
) -> None:
    """Live steps 3-8: pin, read the engine ID after an snmpd restart, localize, push, purge, walk.

    Each step acts only on boxes not failed so far; a box whose push failed or
    was rolled back is not purged.
    """
    step_banner("[3/8]", f"Pin engineIDType {ENGINE_ID_TYPE} via the Controller API", boxes(len(_ok(selected))))

    def _pin(target: Target, client: AppGateClient) -> None:
        """Step 3: pin engineIDType 3 so step 4 reads the MAC-based engine ID the keys are localized to."""
        client.ensure_engine_id_type3(target.appliance_id)
        print_result(target, f"engineIDType {ENGINE_ID_TYPE} set")

    _api_by_collective(_ok(selected), clients, _pin)
    time.sleep(SNMP_RELOAD_DELAY)
    _step4_engine(selected, collectives, restart=True)
    _step5_localize(selected, collectives, hashgen, user, snmp_auth, snmp_priv)

    step_banner("[6/8]", "Push the SNMPv3 user through each Controller", boxes(len(_ok(selected))))
    # Appliance ids whose createUser PUT succeeded. Step 7 purges only these, so a box
    # that was never pushed keeps its existing SNMP user.
    pushed: set = set()
    mode = "replace" if replace else "add"
    if replace:
        begin_replaced_run()

    def _push(target: Target, client: AppGateClient) -> None:
        """Step 6: write createUser through the Controller. Only boxes recorded here are purged in step 7."""
        col = collective_for_target(target, collectives)
        snmp_user = col.get("snmp_user") or user
        client.update_snmp_config(
            snmp_user,
            target.auth_hash,
            target.priv_hash,
            rouser_line,
            appliance_id=target.appliance_id,
            replace=replace,
            snapshot_label=target.label(),
        )
        target.status = STATUS_OK
        pushed.add(target.appliance_id)
        print_result(target, f"SNMPv3 user {user} ({mode})")

    _api_by_collective(_ok(selected), clients, _push)

    step_banner("[7/8]", "Clear the old SNMP key rows over SSH", f"{boxes(len(_ok(selected)))}, up to {SSH_CONCURRENCY} at a time")

    def _ssh_purge(target: Target) -> None:
        """Step 7: clear the old persistent USM rows so snmpd recreates the user with the new key, then drop the localized key from the API copy."""
        col = collective_for_target(target, collectives)
        SNMPEngineFetcher(
            col["ssh_username"], ssh_password_for(target, col)
        ).purge_persistent_user(
            target,
            col.get("snmp_user") or user,
            keep_hash=target.auth_hash,
            # Replace keeps only this user, so the other users' saved key rows go too.
            drop_others=replace,
        )
        client = clients.get(int(target.collective))
        if client is not None:
            client.strip_localized_key(
                col.get("snmp_user") or user,
                appliance_id=target.appliance_id,
            )
        # One line once both parts are done: rows cleared on the box, key off the API copy.
        print_result(target, "old key rows cleared; new key active")

    # A rolled-back box is failed, so _ok drops it even though its id is in pushed.
    purge_set = [t for t in _ok(selected) if t.appliance_id in pushed]
    # print(f"DEBUG step7: purge={[t.label() for t in purge_set]}")
    run_ssh_batch(purge_set, _ssh_purge, SSH_CONCURRENCY, lambda t, e: _fail(t, str(e)))

    step_banner("[8/8]", "Check each box answers an SNMPv3 walk", f"{boxes(len(_ok(selected)))}, up to {WALK_CONCURRENCY} at a time")
    # print(f"DEBUG step8: skip={SKIP_CREDENTIAL_WALK}")
    if SKIP_CREDENTIAL_WALK:
        for target in _ok(selected):
            print_result(target, "walk skipped (SKIP_CREDENTIAL_WALK)", word="Skip")
            target.walk_ok = None
        return
    time.sleep(SNMP_RELOAD_DELAY)

    def _walk_one(target: Target) -> None:
        """Step 8: walk with the passphrases. This is the real test that the new user works."""
        col = collective_for_target(target, collectives)
        ok = SNMPValidator().validate_snmp_walk(
            target.walk_endpoints(),
            col.get("snmp_user") or user,
            col.get("snmp_auth") or snmp_auth,
            col.get("snmp_priv") or snmp_priv,
            engine_id=target.engine_id,
            label=target.label(),
        )
        target.walk_ok = ok
        if not ok:
            # The batch's failure handler prints the one Failed line (E10).
            raise RuntimeError("SNMP walk failed")
        print_result(target, "SNMPv3 walk answered")

    run_target_batch(
        _ok(selected),
        _walk_one,
        WALK_CONCURRENCY,
        lambda t, e: _fail(t, "SNMP walk failed", code="E10"),
    )


def _print_summary(
    selected: List[Target], *, user: str, rouser_line: str, dry_run: bool
) -> None:
    """End-of-run table per collective: preview, ok or failed, with the engine ID."""
    print("\n" + "=" * SUMMARY_WIDTH)
    print("DRY-RUN Preview" if dry_run else "Configuration Summary")
    print("=" * SUMMARY_WIDTH)
    print(f"User:     {user}")
    if dry_run:
        print("Mode:     DRY_RUN (no changes applied)")
    if rouser_line:
        print(f"Read-Only: {rouser_line}")
    current_col: Optional[int] = None
    for target in selected:
        if target.collective != current_col:
            current_col = target.collective
            print(f"  --- collective {current_col} ---")
        state = target.status.upper()
        extra = target.error
        if DEBUG:
            extra = target.engine_id or target.error
        host = target.ssh_fqdn or target.ssh_ip
        tail = f" {extra}" if extra else ""
        print(f"  [{state:<7}] {target.label():<32} {host:<22}{tail}")
    print("=" * SUMMARY_WIDTH)
    # The table above lists every box, so only the counts are added here.
    run_summary(selected, preview=dry_run, list_failed=False)


def _build_run_report(
    collectives: List[Dict[str, str]],
    inventory: List[Target],
    selected: List[Target],
    *,
    user: str,
    dry_run: bool,
    started_at: str,
    clients: Optional[ClientMap] = None,
) -> Dict[str, Any]:
    """Structured end-of-run report. No passwords, tokens, or full localized keys.

    The API version is the one each Controller negotiated at login. Collectives
    can run different releases, so the config default is only the fallback.
    """
    finished_at = datetime.now(timezone.utc).isoformat()
    versions: Dict[int, str] = {}
    for c in collectives:
        idx = int(c["index"])
        client = (clients or {}).get(idx)
        versions[idx] = str(getattr(client, "api_version", "") or APPGATE_API_VERSION)
    distinct = sorted(set(versions.values()))
    # print(f"DEBUG report: api_versions={versions!r}")
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
                "api_username": c["api_username"],
                "api_version": versions[int(c["index"])],
            }
            for c in collectives
        ],
        "api_version": distinct[0] if len(distinct) == 1 else "mixed",
        "insecure_api": insecure_api_enabled(),
        "config": {
            "hash": SNMP_HASH_ALGO,
            "auth": SNMP_AUTH_PROTOCOL,
            "priv": SNMP_PRIV_PROTOCOL,
            "engine_id_type": ENGINE_ID_TYPE,
            "eth_iface": ETH_IFACE,
            "ssh_concurrency": SSH_CONCURRENCY,
            "reload_delay": SNMP_RELOAD_DELAY,
            "dry_run": dry_run,
            "skip_credential_walk": SKIP_CREDENTIAL_WALK,
        },
        "inventory_count": len(inventory),
        "selected_count": len(selected),
        "ok_count": sum(1 for t in selected if t.status == STATUS_OK),
        "preview_count": sum(1 for t in selected if t.status == STATUS_PREVIEW),
        "failed_count": sum(1 for t in selected if t.status == STATUS_FAILED),
        "targets": [],
    }
    for t in selected:
        entry: Dict[str, Any] = {
            "collective": t.collective,
            "appliance_id": t.appliance_id,
            "functions": t.functions,
            "health": t.health,
            "engine_id": t.engine_id if DEBUG else "",
            "engine_id_len": len(t.engine_id),
            "auth_hash_len": len(t.auth_hash),
            "priv_hash_len": len(t.priv_hash),
            "auth_priv_hash_same": bool(t.auth_hash) and t.auth_hash == t.priv_hash,
            # No label here: this report leaves hostnames out, and addresses in
            # the failure text are replaced by their position.
            **report_target_fields(t, label=False),
            "walk_ok": t.walk_ok,
        }
        if dry_run and t.status == STATUS_FAILED:
            # A box that failed in the preview (no SSH address, refused host key, ...)
            # is skipped by the live run, so the report must not list changes for it.
            # error is the same operator text already shown above; it holds no secret.
            # print(f"DEBUG report: {t.label()} planned_actions skipped ({t.error!r})")
            entry["planned_actions"] = [f"skipped: {entry['error'] or 'failed in preview'}"]
        elif dry_run:
            entry["planned_actions"] = [
                f"engineIDType {ENGINE_ID_TYPE}",
                f"deleteUser {user}",
                f"createUser {user} {SNMP_AUTH_PROTOCOL}/{SNMP_PRIV_PROTOCOL} (localized)",
                f"purge persistent usmUser {user}",
                # Positions, not names: this report leaves hostnames out (the console has them).
                f"walk {', '.join(f'address {i}' for i in range(1, len(t.walk_endpoints()) + 1)) or 'no address'}",
            ]
        report["targets"].append(entry)
    return report


def _emit_run_report(report: Dict[str, Any]) -> None:
    """Write reports/run-*.json or dryrun-*.json. Console dump only if DEBUG."""
    prefix = "dryrun" if report.get("dry_run") else "run"
    write_json_report(prefix, report)


if __name__ == "__main__":
    run_tool(main)
