from utils import ensure_package

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    ensure_package("requests", "requests")
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import re
import sys
from typing import Any, Dict, Optional


class AppGateClient:
    DEFAULT_API_VERSION = "24"
    DEFAULT_PROVIDER = "local"
    DEFAULT_SNMP_PORT = 161
    MACHINE_ID = "f0031c00-0522-43b3-a642-ae23cfd1bc22"

    def __init__(self, agip: str, api_version: Optional[str] = None, provider: str = DEFAULT_PROVIDER) -> None:
        self.agip = agip
        self.api_version = api_version or self.DEFAULT_API_VERSION
        self.provider = provider
        self.base_url = f"https://{agip}:8443/admin"
        self.machine_id = self.MACHINE_ID
        self.headers: Dict[str, str] = {
            "Accept": f"application/vnd.appgate.peer-v{self.api_version}+json",
            "Content-Type": "application/json",
        }
        self.appliance_id: Optional[str] = None

    def login(self, username: str, password: str, provider: Optional[str] = None) -> str:
        """Authenticate to the AppGate API and store the bearer token."""
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
            verify=False,
            timeout=30,
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

    def _handle_login_error(self, response: requests.Response, username: str, provider: str) -> None:
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

    def get_appliances(self) -> list:
        """Return all appliances visible to the current API user."""
        response = requests.get(
            f"{self.base_url}/appliances",
            headers=self.headers,
            verify=False,
            timeout=30,
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
        """Locate the appliance object whose interface matches *ip*."""
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

    def update_snmp_config(
        self,
        user: str,
        auth_hash: str,
        priv_hash: str,
        rouser_line: str = "",
        enabled: bool = True,
        engine_id: Optional[str] = None,
    ) -> bool:
        """Push the updated snmpd.conf to the AppGate appliance."""
        if not self.appliance_id:
            raise RuntimeError("Appliance ID is not set. Run find_appliance_by_ip first.")

        response = requests.get(
            f"{self.base_url}/appliances/{self.appliance_id}",
            headers=self.headers,
            verify=False,
            timeout=30,
        )
        response.raise_for_status()
        appliance = response.json()

        create_user_line = f"createUser {user} SHA -l 0x{auth_hash} AES -l 0x{priv_hash}"

        existing_conf = appliance.get("snmpServer", {}).get("snmpd.conf", "")
        lines = existing_conf.splitlines() if existing_conf else []
        lines = [
            line for line in lines
            if not re.match(rf"^createUser\s+{re.escape(user)}\s", line)
        ]
        lines = [
            line for line in lines
            if not re.match(rf"^(rouser|deleteUser)\s+{re.escape(user)}\s", line)
        ]
        if rouser_line:
            lines.append(rouser_line)
        lines.append(f"deleteUser {user}")
        lines.append(create_user_line)
        if engine_id:
            lines.append(f"exactEngineID 0x{engine_id}")
        new_conf = "\n".join(lines)

        appliance["snmpServer"] = {
            "enabled": enabled,
            "snmpd.conf": new_conf,
            "tcpPort": self.DEFAULT_SNMP_PORT,
            "udpPort": self.DEFAULT_SNMP_PORT,
        }

        put_response = requests.put(
            f"{self.base_url}/appliances/{self.appliance_id}",
            headers=self.headers,
            json=appliance,
            verify=False,
            timeout=30,
        )
        if put_response.status_code != 200:
            body_preview = (put_response.text or "")[:500]
            raise RuntimeError(
                f"Failed to update SNMP config (HTTP {put_response.status_code}): {body_preview}"
            )
        return True
