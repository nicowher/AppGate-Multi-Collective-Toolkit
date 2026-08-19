"""AppGate admin API: login, appliance lookup, snmpd.conf push.

Called from main.py in this order:

  login()                 → step 1  (bearer token)
  find_appliance_by_ip()  → step 2  (sets self.appliance_id)
  ensure_engine_id_type3()→ step 3  (API pin; SSH reads the ID)
  delete_snmp_user()      → step 5a (deleteUser + engineIDType 3)
  update_snmp_config()    → step 5b (createUser / rouser / type 3)

cz-configd owns /etc/snmp/snmpd.conf, so every snmpd change is a PUT
of the appliance object. Never push exactEngineID — cz-configd
truncates it and breaks RFC 3411 type-3 (11-byte) IDs.
"""
from utils import ensure_package

try:
    import requests
except ImportError:
    ensure_package("requests", "requests")
    import requests

from config import (
    API_TIMEOUT,
    APPGATE_ADMIN_PORT,
    APPGATE_ADMIN_PREFIX,
    APPGATE_API_VERSION,
    APPGATE_MACHINE_ID,
    APPGATE_PROVIDER,
    ENGINE_ID_TYPE,
    DEFAULT_SNMP_PORT,
    SNMP_AUTH_PROTOCOL,
    SNMP_PRIV_PROTOCOL,
    STRIP_V1V2_COMMUNITIES,
    TLS_VERIFY,
)
import re
import sys
from typing import Any, Dict, Optional

if not TLS_VERIFY:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class AppGateClient:
    def __init__(
        self,
        agip: str,
        api_version: Optional[str] = None,
        provider: str = APPGATE_PROVIDER,
    ) -> None:
        self.agip = agip
        self.api_version = api_version or APPGATE_API_VERSION
        self.provider = provider
        self.base_url = f"https://{agip}:{APPGATE_ADMIN_PORT}{APPGATE_ADMIN_PREFIX}"
        self.machine_id = APPGATE_MACHINE_ID
        self.headers: Dict[str, str] = {
            "Accept": f"application/vnd.appgate.peer-v{self.api_version}+json",
            "Content-Type": "application/json",
        }
        self.appliance_id: Optional[str] = None

    def login(self, username: str, password: str, provider: Optional[str] = None) -> str:
        """Step 1: POST /admin/login and keep the bearer token on self.headers."""
        provider_name = provider or self.provider
        payload = {
            "machineId": self.machine_id,
            "providerName": provider_name,
            "username": username,
            "password": password,
        }
        response = requests.post(
            f"{self.base_url}/login",
            headers=self.headers,
            json=payload,
            verify=TLS_VERIFY,
            timeout=API_TIMEOUT,
        )
        if response.status_code != 200:
            self._handle_login_error(response, username, provider_name)
        data = response.json()
        token = data.get("token")
        if not token:
            body_preview = (response.text or "")[:300]
            raise ValueError(
                f"Login response did not contain an API token. "
                f"HTTP {response.status_code}. Response body: {body_preview}"
            )
        self.headers["Authorization"] = f"Bearer {token}"
        return token

    def _handle_login_error(self, response: requests.Response, _username: str, provider: str) -> None:
        """Provide actionable guidance for common 401/403 responses."""
        try:
            body = response.json()
            msg = body.get("message", response.text)
            err_id = body.get("id", "")
            failure = body.get("failureType", "")
        except Exception:
            msg = response.text or f"HTTP {response.status_code}"
            err_id = ""
            failure = ""

        if response.status_code == 401:
            if "MFA" in msg or failure == "MfaRequired" or "twoFactor" in msg.lower():
                print(
                    "ERROR: Admin MFA is enabled. Either disable MFA for this API user in AppGate, "
                    "or use a SAML/OIDC provider that supports token-based login.",
                    file=sys.stderr,
                )
            elif "unauthorized" in err_id or "Invalid username or password" in msg:
                print(
                    "ERROR: Invalid username or password. Verify the credentials and try again.",
                    file=sys.stderr,
                )
            else:
                print(f"ERROR: Login failed (HTTP 401): {msg}", file=sys.stderr)
            print(
                "\nTroubleshooting tips:\n"
                "  - Confirm the account has API access and is exempt from Admin MFA\n"
                "  - Verify providerName is correct (common values: 'local', 'saml', 'oidc')\n"
                "  - Ensure the machineId is accepted by the Controller\n",
                file=sys.stderr,
            )
        elif response.status_code == 403:
            print(
                f"ERROR: Insufficient permissions (HTTP 403): {msg}\n"
                "Ensure the API user has the required admin role privileges.",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: Login failed (HTTP {response.status_code}): {msg}", file=sys.stderr)

        raise SystemExit(1)

    @staticmethod
    def _snmpd_lines_without_user(appliance: Dict[str, Any], user: str) -> list:
        """Return snmpd.conf lines with this user's entries and engine-ID pins removed."""
        existing_conf = appliance.get("snmpServer", {}).get("snmpd.conf", "")
        lines = existing_conf.splitlines() if existing_conf else []
        drop = (
            rf"^createUser\s+{re.escape(user)}\b",
            rf"^rouser\s+{re.escape(user)}\b",
            rf"^deleteUser\s+{re.escape(user)}\b",
            *AppGateClient._engine_pin_patterns(),
            *AppGateClient._community_patterns(),
        )
        return [line for line in lines if not any(re.match(pat, line) for pat in drop)]

    @staticmethod
    def _engine_pin_patterns() -> tuple:
        return (
            r"(?i)^exactEngineID\s+",
            r"(?i)^engineIDType\s+",
            r"(?i)^engineID\s+",
        )

    @staticmethod
    def _community_patterns() -> tuple:
        if not STRIP_V1V2_COMMUNITIES:
            return ()
        return (
            r"(?i)^rocommunity6?\b",
            r"(?i)^rwcommunity6?\b",
        )

    @staticmethod
    def _snmpd_lines_without_engine_pins(appliance: Dict[str, Any]) -> list:
        existing_conf = appliance.get("snmpServer", {}).get("snmpd.conf", "")
        lines = existing_conf.splitlines() if existing_conf else []
        drop = AppGateClient._engine_pin_patterns() + AppGateClient._community_patterns()
        return [line for line in lines if not any(re.match(pat, line) for pat in drop)]

    def ensure_engine_id_type3(self) -> None:
        """Step 3 (API half): drop old engine pins, then write engineIDType 3.

        SSH (snmp_engine.py) restarts snmpd afterwards and reads oldEngineID.
        """
        appliance = self._get_appliance()
        lines = self._snmpd_lines_without_engine_pins(appliance)
        lines.append(f"engineIDType {ENGINE_ID_TYPE}")
        self._put_snmpd_conf(appliance, "\n".join(lines), enabled=True)

    def get_appliances(self) -> list:
        """Return all appliances visible to the current API user."""
        response = requests.get(
            f"{self.base_url}/appliances",
            headers=self.headers,
            verify=TLS_VERIFY,
            timeout=API_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        if "data" not in data:
            raise ValueError(
                f"Unexpected appliances response format. "
                f"HTTP {response.status_code}. Body preview: {(response.text or '')[:300]}"
            )
        return data.get("data", [])

    def find_appliance_by_ip(self, ip: str) -> Dict[str, Any]:
        """Step 2: find the appliance whose hostname or NIC address is *ip*."""
        for appliance in self.get_appliances():
            if self._ip_matches_appliance(ip, appliance):
                self.appliance_id = appliance["id"]
                return appliance
        raise ValueError(f"Appliance with IP address {ip} not found in AppGate")

    @staticmethod
    def _ip_matches_appliance(ip: str, appliance: Dict[str, Any]) -> bool:
        for iface in (
            appliance.get("adminInterface", {}),
            appliance.get("clientInterface", {}),
        ):
            if iface.get("hostname") == ip:
                return True

        for nic in appliance.get("networking", {}).get("nics", []):
            for addr in nic.get("ipv4", {}).get("static", []):
                if addr.get("address") == ip:
                    return True
            for addr in nic.get("ipv6", {}).get("static", []):
                if addr.get("address") == ip:
                    return True
        return False

    def delete_snmp_user(self, user: str) -> bool:
        """Step 5a (API half): push deleteUser, then wait for cz-configd.

        Separate from createUser so the final snmpd.conf has no deleteUser
        line. Persistent /var/lib/snmp usmUser rows are purged over SSH
        first (see SNMPEngineFetcher.purge_persistent_user).
        """
        appliance = self._get_appliance()
        lines = self._snmpd_lines_without_user(appliance, user)
        lines.append(f"deleteUser {user}")
        # Do not pin exactEngineID — AppGate/cz-configd truncates it (16 hex)
        # and that breaks RFC 3411 type-3 (11-byte) IDs. Type 3 + oldEngineID is enough.
        lines.append(f"engineIDType {ENGINE_ID_TYPE}")
        self._put_snmpd_conf(appliance, "\n".join(lines), enabled=True)
        return True

    def update_snmp_config(
        self,
        user: str,
        auth_hash: str,
        priv_hash: str,
        rouser_line: str = "",
        enabled: bool = True,
    ) -> bool:
        """Step 5b: PUT createUser + optional rouser + engineIDType 3.

        Call after delete_snmp_user so the final blob has no deleteUser line.
        Auth/priv algorithms must match snmp_hashgen.py / config.py.
        """
        create_user_line = (
            f"createUser {user} {SNMP_AUTH_PROTOCOL} -l 0x{auth_hash} "
            f"{SNMP_PRIV_PROTOCOL} -l 0x{priv_hash}"
        )

        appliance = self._get_appliance()
        lines = self._snmpd_lines_without_user(appliance, user)
        if rouser_line:
            lines.append(rouser_line)
        lines.append(create_user_line)
        lines.append(f"engineIDType {ENGINE_ID_TYPE}")
        self._put_snmpd_conf(appliance, "\n".join(lines), enabled=enabled)
        return True

    def _get_appliance(self) -> Dict[str, Any]:
        if not self.appliance_id:
            raise RuntimeError("Appliance ID is not set. Run find_appliance_by_ip first.")
        response = requests.get(
            f"{self.base_url}/appliances/{self.appliance_id}",
            headers=self.headers,
            verify=TLS_VERIFY,
            timeout=API_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _put_snmpd_conf(self, appliance: Dict[str, Any], new_conf: str, enabled: bool) -> None:
        """PUT the whole appliance object with a replaced snmpd.conf blob."""
        existing = appliance.get("snmpServer")
        if not isinstance(existing, dict):
            existing = {}
        appliance["snmpServer"] = {
            **existing,
            "enabled": enabled,
            "snmpd.conf": new_conf,
            "tcpPort": existing.get("tcpPort", DEFAULT_SNMP_PORT),
            "udpPort": existing.get("udpPort", DEFAULT_SNMP_PORT),
        }
        put_response = requests.put(
            f"{self.base_url}/appliances/{self.appliance_id}",
            headers=self.headers,
            json=appliance,
            verify=TLS_VERIFY,
            timeout=API_TIMEOUT,
        )
        if put_response.status_code != 200:
            body_preview = (put_response.text or "")[:500]
            raise RuntimeError(
                f"Failed to update SNMP config (HTTP {put_response.status_code}): {body_preview}"
            )
