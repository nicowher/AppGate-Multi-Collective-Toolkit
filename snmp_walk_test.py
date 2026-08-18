import asyncio
import os
import sys

from config import get_auth_protocol, get_priv_protocol
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    UsmUserData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    walk_cmd,
)
from utils import load_credentials

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_PATH = os.path.join(SCRIPT_DIR, "credentials.json")


async def snmp_walk(ip: str, user: str, auth: str, priv: str) -> bool:
    transport = await UdpTransportTarget.create((ip, 161), timeout=5, retries=1)
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
    creds = load_credentials(CREDENTIALS_PATH)
    ip = creds.get("agip", "")
    user = creds.get("snmp_user", "")
    auth = creds.get("snmp_auth", "")
    priv = creds.get("snmp_priv", "")

    if not all((ip, user, auth, priv)):
        print("Missing credentials in credentials.json. Need: agip, snmp_user, snmp_auth, snmp_priv", file=sys.stderr)
        sys.exit(1)

    ok = asyncio.run(snmp_walk(ip, user, auth, priv))
    sys.exit(0 if ok else 1)
