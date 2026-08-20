"""AppGate admin API: login, appliance lookup, snmpd.conf push.

One AppGateClient per collective (own login token). main.py steps:

   1 login() each Controller
   2 list_targets(collective=N)
   3 ensure_engine_id_type3(id) via that client
   6 delete_snmp_user / update_snmp_config via that client only

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
    APPLIANCE_SKIP_STATUS,
    APPGATE_ADMIN_PORT,
    APPGATE_ADMIN_PREFIX,
    APPGATE_API_VERSION,
    APPGATE_MACHINE_ID,
    API_AUTH_FAIL_CODES,
    APPGATE_PROVIDER,
    APPLIANCE_LIST_MAX,
    APPLIANCE_LIST_PAGE,
    APPLIANCE_STATUS_PATH,
    ENGINE_ID_TYPE,
    DEFAULT_SNMP_PORT,
    SNMP_AUTH_PROTOCOL,
    SNMP_PRIV_PROTOCOL,
    STRIP_V1V2_COMMUNITIES,
    TLS_VERIFY,
)
import re
import sys
from typing import Any, Dict, List, Optional

from inventory import (
    Target,
    appliance_functions,
    appliance_health,
    appliance_hosts,
    is_selectable,
)

if not TLS_VERIFY:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class AppGateClient:
    def __init__(
        self,
        fqdn: str,
        fallback_ip: str = "",
        api_version: Optional[str] = None,
        provider: str = APPGATE_PROVIDER,
    ) -> None:
        # Prefer FQDN (Controller admin hostname). IP is only a connect fallback.
        self.fqdn = (fqdn or "").strip()
        self.fallback_ip = (fallback_ip or "").strip()
        self.endpoints = [h for h in (self.fqdn, self.fallback_ip) if h]
        if not self.endpoints:
            raise ValueError("Controller FQDN or IP is required")
        self.agip = self.endpoints[0]
        self.api_version = api_version or APPGATE_API_VERSION
        self.provider = provider
        self.machine_id = APPGATE_MACHINE_ID
        self.headers: Dict[str, str] = {
            "Accept": f"application/vnd.appgate.peer-v{self.api_version}+json",
            "Content-Type": "application/json",
        }
        self._set_endpoint(self.agip)

    def _set_endpoint(self, host: str) -> None:
        self.agip = host
        self.base_url = f"https://{host}:{APPGATE_ADMIN_PORT}{APPGATE_ADMIN_PREFIX}"

    def login(self, username: str, password: str, provider: Optional[str] = None) -> str:
        """Step 1: POST /admin/login. FQDN first; IP if connect/HTTP fails (not 401/403)."""
        provider_name = provider or self.provider
        payload = {
            "machineId": self.machine_id,
            "providerName": provider_name,
            "username": username,
            "password": password,
        }
        last_connect_error: Optional[Exception] = None
        for host in self.endpoints:
            self._set_endpoint(host)
            try:
                response = requests.post(
                    f"{self.base_url}/login",
                    headers=self.headers,
                    json=payload,
                    verify=TLS_VERIFY,
                    timeout=API_TIMEOUT,
                )
            except (requests.ConnectionError, requests.Timeout, OSError) as exc:
                last_connect_error = exc
                print(
                    f"      Cannot reach {host} ({type(exc).__name__}); trying fallback...",
                    file=sys.stderr,
                )
                continue
            if response.status_code != 200:
                if response.status_code in API_AUTH_FAIL_CODES:
                    self._handle_login_error(response, username, provider_name)
                print(
                    f"      {host} returned HTTP {response.status_code}; trying fallback...",
                    file=sys.stderr,
                )
                last_connect_error = RuntimeError(f"HTTP {response.status_code} from {host}")
                continue
            data = response.json()
            token = data.get("token")
            if not token:
                body_preview = (response.text or "")[:300]
                raise ValueError(
                    f"Login response did not contain an API token. "
                    f"HTTP {response.status_code}. Response body: {body_preview}"
                )
            self.headers["Authorization"] = f"Bearer {token}"
            if host != self.fqdn and self.fqdn:
                print(f"      Using IP fallback {host} (FQDN {self.fqdn} unreachable)", file=sys.stderr)
            return token
        raise RuntimeError(
            f"Could not reach Controller {self.fqdn or self.fallback_ip}: {last_connect_error}"
        )

    def _handle_login_error(self, response: requests.Response, _username: str, provider: str) -> None:
        """Provide actionable guidance for common 401/403 responses."""
        try:
            body = response.json()
            msg = body.get("message", response.text)
            err_id = body.get("id", "")
            failure = body.get("failureType", "")
        except (ValueError, TypeError, requests.JSONDecodeError):
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

        raise RuntimeError(f"Login failed (HTTP {response.status_code})")

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

    def ensure_engine_id_type3(self, appliance_id: Optional[str] = None) -> None:
        """Pin engineIDType via API before SSH reads oldEngineID."""
        appliance = self._get_appliance(appliance_id)
        lines = self._snmpd_lines_without_engine_pins(appliance)
        lines.append(f"engineIDType {ENGINE_ID_TYPE}")
        self._put_snmpd_conf(appliance, "\n".join(lines), enabled=True)

    def _paged_get(self, path: str) -> list:
        """GET a 6.7 collection. range is a query param; total is in JSON 'range' (0-49/123)."""
        items: list = []
        start = 0
        page = APPLIANCE_LIST_PAGE
        while True:
            end = start + page - 1
            response = requests.get(
                f"{self.base_url}{path}",
                headers=self.headers,
                params={"range": f"{start}-{end}"},
                verify=TLS_VERIFY,
                timeout=API_TIMEOUT,
            )
            if response.status_code not in (200, 206):
                response.raise_for_status()
            payload = response.json()
            body_range = ""
            if isinstance(payload, list):
                chunk = payload
            elif isinstance(payload, dict):
                chunk = payload.get("data", [])
                body_range = str(payload.get("range") or "")
            else:
                chunk = []
            items.extend(chunk)
            total = None
            if "/" in body_range:
                try:
                    total = int(body_range.rsplit("/", 1)[-1])
                except ValueError:
                    total = None
            if total is not None:
                if len(items) >= total or not chunk:
                    break
                start = len(items)
                continue
            if len(chunk) < page:
                break
            start += len(chunk)
            if start > APPLIANCE_LIST_MAX:
                break
        return items

    def get_appliances(self) -> list:
        """Every appliance this token can view. Paginate if JSON range says so."""
        response = requests.get(
            f"{self.base_url}/appliances",
            headers=self.headers,
            verify=TLS_VERIFY,
            timeout=API_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, list):
            return payload
        chunk = payload.get("data", [])
        body_range = str(payload.get("range") or "")
        if "/" in body_range:
            try:
                total = int(body_range.rsplit("/", 1)[-1])
            except ValueError:
                total = 0
            if total > len(chunk):
                return self._paged_get("/appliances")
        return chunk

    def get_appliance_status(self) -> Dict[str, Dict[str, Any]]:
        """6.3+ replacement for GET /stats/appliances → GET /appliances/status."""
        try:
            # print(f"DEBUG step2: GET {APPLIANCE_STATUS_PATH}")
            items = self._paged_get(APPLIANCE_STATUS_PATH)
        except (requests.RequestException, ValueError, OSError):
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for item in items:
            if isinstance(item, dict) and item.get("id"):
                out[item["id"]] = item
        return out

    def list_targets(
        self,
        collective: int = 1,
        fallback_ip: str = "",
        collective_fqdn: str = "",
    ) -> List[Target]:
        """Activated appliances this token can view, tagged with *collective* index."""
        raw = self.get_appliances()
        status_by_id = self.get_appliance_status()
        print(
            f"      [{collective}] {self.fqdn or self.agip}: {len(raw)} appliance(s)",
            file=sys.stderr,
        )
        targets: List[Target] = []
        for appliance in raw:
            name = str(appliance.get("name") or appliance.get("id") or "?")
            aid = appliance.get("id") or ""
            if not aid or appliance.get("activated") is False:
                continue
            health = appliance_health(appliance, status_by_id.get(aid, {}))
            if not is_selectable(health, APPLIANCE_SKIP_STATUS):
                continue
            ssh_fqdn, ssh_ip = appliance_hosts(appliance)
            if not ssh_fqdn and not ssh_ip:
                continue
            targets.append(
                Target(
                    appliance_id=aid,
                    hostname=name,
                    ssh_fqdn=ssh_fqdn,
                    ssh_ip=ssh_ip,
                    collective=collective,
                    collective_fqdn=collective_fqdn or self.fqdn,
                    collective_ip=fallback_ip or self.fallback_ip,
                    functions=appliance_functions(appliance),
                    health=health,
                )
            )
        return targets

    def delete_snmp_user(self, user: str, appliance_id: Optional[str] = None) -> bool:
        """Push deleteUser + engineIDType. createUser is a later PUT.

        Persistent usmUser rows are purged over SSH *after* createUser
        so snmpd re-reads the new keys on restart.
        """
        appliance = self._get_appliance(appliance_id)
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
        appliance_id: Optional[str] = None,
    ) -> bool:
        """Step 6: PUT createUser + optional rouser + engineIDType 3.

        Call after delete_snmp_user so the final blob has no deleteUser line.
        Auth/priv algorithms must match snmp_hashgen.py / config.py.
        """
        create_user_line = (
            f"createUser {user} {SNMP_AUTH_PROTOCOL} -l 0x{auth_hash} "
            f"{SNMP_PRIV_PROTOCOL} -l 0x{priv_hash}"
        )

        appliance = self._get_appliance(appliance_id)
        lines = self._snmpd_lines_without_user(appliance, user)
        if rouser_line:
            lines.append(rouser_line)
        lines.append(create_user_line)
        lines.append(f"engineIDType {ENGINE_ID_TYPE}")
        self._put_snmpd_conf(appliance, "\n".join(lines), enabled=enabled)
        return True

    def _get_appliance(self, appliance_id: Optional[str] = None) -> Dict[str, Any]:
        aid = appliance_id
        if not aid:
            raise RuntimeError("Appliance ID is not set.")
        response = requests.get(
            f"{self.base_url}/appliances/{aid}",
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
            f"{self.base_url}/appliances/{appliance.get('id')}",
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
