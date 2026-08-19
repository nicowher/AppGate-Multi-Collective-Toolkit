"""Standalone SNMPv3 walk using credentials.json (no API or SSH).

This is step 6 only — the SNMP-Walk-<OS> launchers call this file.

  1. Load credentials.json; prompt for agip / user / auth / priv
  2. pysnmp authPriv walk of SNMP_WALK_OID (system MIB)
  3. Print the first varBind and exit 0, or exit 1 on failure
"""
import asyncio
import os
import sys
from getpass import getpass

from config import (
    CREDENTIALS_FILENAME,
    DEFAULT_SNMP_PORT,
    SNMPWALK_PROBE_TIMEOUT,
    SNMPWALK_RETRIES,
    SNMP_WALK_OID,
    get_auth_protocol,
    get_priv_protocol,
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
    transport = await UdpTransportTarget.create(
        (ip, DEFAULT_SNMP_PORT),
        timeout=SNMPWALK_PROBE_TIMEOUT,
        retries=SNMPWALK_RETRIES,
    )
    async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
        SnmpEngine(),
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
    ):
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


def _require(creds: dict, field: str, prompt: str, sensitive: bool = False) -> str:
    value = creds.get(field, "")
    if value:
        return value
    if sensitive:
        return getpass(f"{prompt}: ").strip()
    return input(f"{prompt}: ").strip()


if __name__ == "__main__":
    # Same credential file as Passwordinator; no admin/SSH fields needed.
    creds = load_credentials(CREDENTIALS_PATH)
    ip = _require(creds, "agip", "AppGate IP Address")
    user = _require(creds, "snmp_user", "SNMP User")
    auth = _require(creds, "snmp_auth", "SNMP Auth", sensitive=True)
    priv = _require(creds, "snmp_priv", "SNMP Priv", sensitive=True)

    if not all((ip, user, auth, priv)):
        print("Need agip, snmp_user, snmp_auth, and snmp_priv", file=sys.stderr)
        sys.exit(1)

    ok = asyncio.run(snmp_walk(ip, user, auth, priv))
    sys.exit(0 if ok else 1)
