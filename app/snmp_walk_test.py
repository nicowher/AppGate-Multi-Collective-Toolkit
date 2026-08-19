"""Standalone SNMPv3 authPriv walk. No Controller API and no SSH.

Launchers: SNMP-Walk-Windows.bat / SNMP-Walk-Linux.sh / SNMP-Walk-macOS.command

Uses the same credentials.json as Passwordinator, but `agip` here is the
**appliance to walk**, not the Controller. Prompts for anything missing.
Does not take an engine ID (discovery is left to pysnmp).
"""
import asyncio
import os
import re
import sys
from getpass import getpass

from config import (
    CREDENTIALS_FILENAME,
    DEBUG,
    DEFAULT_SNMP_PORT,
    SNMPWALK_PROBE_TIMEOUT,
    SNMPWALK_RETRIES,
    SNMP_AUTH_PROTOCOL,
    SNMP_MIN_PASSPHRASE_LEN,
    SNMP_NAME_RE,
    SNMP_PRIV_PROTOCOL,
    SNMP_WALK_OID,
    get_auth_protocol,
    get_priv_protocol,
    warn_insecure_transport,
)
from utils import REPO_ROOT, ensure_package, load_credentials

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        walk_cmd,
    )
except ImportError:
    ensure_package("pysnmp", "pysnmp")
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        walk_cmd,
    )

CREDENTIALS_PATH = os.path.join(REPO_ROOT, CREDENTIALS_FILENAME)


async def snmp_walk(ip: str, user: str, auth: str, priv: str) -> bool:
    """Walk SNMP_WALK_OID with SHA-256 / AES-256 authPriv. Print first varBind."""
    transport = await UdpTransportTarget.create(
        (ip, DEFAULT_SNMP_PORT),
        timeout=SNMPWALK_PROBE_TIMEOUT,
        retries=SNMPWALK_RETRIES,
    )
    engine = SnmpEngine()
    agen = walk_cmd(
        engine,
        UsmUserData(
            user,
            auth,
            priv,
            authProtocol=get_auth_protocol(),
            privProtocol=get_priv_protocol(),
        ),
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(SNMP_WALK_OID)),
    )
    try:
        async for (errorIndication, errorStatus, errorIndex, varBinds) in agen:
            if errorIndication:
                print(f"SNMP walk error: {errorIndication}", file=sys.stderr)
                return False
            if errorStatus:
                print(f"SNMP walk error: {errorStatus.prettyPrint()}", file=sys.stderr)
                return False
            for varBind in varBinds:
                print(varBind.prettyPrint())
            return True
        return False
    finally:
        try:
            await agen.aclose()
        except Exception:
            pass
        dispatcher = getattr(engine, "transport_dispatcher", None) or getattr(
            engine, "transportDispatcher", None
        )
        if dispatcher is not None:
            for name in ("close_dispatcher", "closeDispatcher"):
                closer = getattr(dispatcher, name, None)
                if closer:
                    try:
                        closer()
                    except Exception:
                        pass
                    break


def _require(creds: dict, field: str, prompt: str, sensitive: bool = False) -> str:
    value = creds.get(field, "")
    if value:
        return value
    if sensitive:
        return getpass(f"{prompt}: ").strip()
    return input(f"{prompt}: ").strip()


if __name__ == "__main__":
    try:
        warn_insecure_transport()
        creds = load_credentials(CREDENTIALS_PATH)
        # Do not use collectives[].agip — that is a Controller, not a walk target.
        ip = _require(creds, "agip", "Appliance IP / hostname to walk")
        # print(f"DEBUG walk-test: creds agip={creds.get('agip')!r} collectives={bool(creds.get('collectives'))}")
        user = _require(creds, "snmp_user", "SNMP User")
        auth = _require(creds, "snmp_auth", "SNMP Auth", sensitive=True)
        priv = _require(creds, "snmp_priv", "SNMP Priv", sensitive=True)

        if not all((ip, user, auth, priv)):
            print("Need walk target, snmp_user, snmp_auth, and snmp_priv", file=sys.stderr)
            sys.exit(1)
        if not re.fullmatch(SNMP_NAME_RE, user):
            print("snmp_user must be letters, digits, underscore, dot, or hyphen", file=sys.stderr)
            sys.exit(1)
        for label, secret in (("snmp_auth", auth), ("snmp_priv", priv)):
            if len(secret) < SNMP_MIN_PASSPHRASE_LEN:
                print(
                    f"{label} must be at least {SNMP_MIN_PASSPHRASE_LEN} characters",
                    file=sys.stderr,
                )
                sys.exit(1)

        # print(f"DEBUG walk-test: target={ip} user={user} oid={SNMP_WALK_OID}")
        loop = asyncio.new_event_loop()
        try:
            ok = loop.run_until_complete(snmp_walk(ip, user, auth, priv))
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()
        if DEBUG:
            import json
            print("\n----- BEGIN DEBUG REPORT -----")
            print(json.dumps({
                "script": "snmp_walk_test",
                "target": ip,
                "user": user,
                "auth_protocol": SNMP_AUTH_PROTOCOL,
                "priv_protocol": SNMP_PRIV_PROTOCOL,
                "oid": SNMP_WALK_OID,
                "walk_ok": ok,
            }, indent=2))
            print("----- END DEBUG REPORT -----")
        sys.exit(0 if ok else 1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
