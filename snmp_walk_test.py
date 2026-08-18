import asyncio
import json
import os
import sys

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    UsmUserData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    walk_cmd,
    usmHMAC192SHA256AuthProtocol,
    usmAesCfb256Protocol,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_PATH = os.path.join(SCRIPT_DIR, "credentials.json")


def load_credentials() -> dict:
    if not os.path.isfile(CREDENTIALS_PATH):
        return {}
    try:
        with open(CREDENTIALS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        return {k: str(v) for k, v in data.items()}
    except Exception as exc:
        print(f"Warning: Could not load credentials from {CREDENTIALS_PATH}: {exc}", file=sys.stderr)
        return {}


async def snmp_walk(ip: str, user: str, auth: str, priv: str) -> bool:
    transport = await UdpTransportTarget.create((ip, 161), timeout=5, retries=1)
    async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
        SnmpEngine(),
        UsmUserData(
            user,
            auth,
            priv,
                    authProtocol=usmHMAC192SHA256AuthProtocol,
                    privProtocol=usmAesCfb256Protocol,
        ),
        transport,
        ContextData(),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1")),
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


if __name__ == "__main__":
    creds = load_credentials()
    ip = creds.get("agip", "")
    user = creds.get("snmp_user", "")
    auth = creds.get("snmp_auth", "")
    priv = creds.get("snmp_priv", "")

    if not all((ip, user, auth, priv)):
        print("Missing credentials in credentials.json. Need: agip, snmp_user, snmp_auth, snmp_priv", file=sys.stderr)
        sys.exit(1)

    ok = asyncio.run(snmp_walk(ip, user, auth, priv))
    sys.exit(0 if ok else 1)
