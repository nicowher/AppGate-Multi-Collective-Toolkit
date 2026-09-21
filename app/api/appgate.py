"""AppGate admin API: login, list appliances, snmpd.conf PUT.

Inventory *shape* (Target, health, exclude) lives in ``core/inventory.py``.
This file only talks HTTP.


One AppGateClient per collective (own bearer token) so a token from site A
is never sent to site B (403 / wrong collective).

   1  login() — FQDN first (Controller admin-hostname guidance); agip only when
      the name does not connect. Never fall back on 401/403 (that is auth, not DNS).
   2  list_targets() — Controller inventory is source of truth; status endpoint
      is 6.3+ /appliances/status (not removed /stats/appliances).
   3  ensure_engine_id_type3() — type-3 MAC engine IDs are stable for ESXi USM.
   6  delete_snmp_user / update_snmp_config — full appliance PUT because
      cz-configd owns /etc/snmp/snmpd.conf; SSH edits get overwritten.

Why no exactEngineID: cz-configd has truncated type-3 IDs and broken localization.
SNMP: GET full appliance, change only snmpd.conf, PUT the same document.
Site object → UUID (never stripped). tcpPort is never added. Unknown GET
top-level keys are preserved on PUT (DEBUG lists them). Portal PUT may 422
if the API user lacks Client Profile View (`portal.profiles[]`). Any other
field diff refuses the PUT and dumps GET/PUT when DEBUG.
"""
from core.utils import ensure_package

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
    API_ERROR_BODY_PREVIEW,
    APPGATE_PROVIDER,
    DEBUG,
    LOGIN_BODY_PREVIEW,
    APPLIANCE_LIST_MAX,
    APPLIANCE_LIST_PAGE,
    APPLIANCE_STATUS_PATH,
    ENGINE_ID_TYPE,
    LAB_MODE,
    NTP_KEY_HEX_PREFIX,
    NTP_KEY_TYPE_MAP,
    NTP_WEAK_KEY_TYPES,
    SNMP_AUTH_PROTOCOL,
    SNMP_PRIV_PROTOCOL,
    STRIP_V1V2_COMMUNITIES,
    TLS_VERIFY,
    confirm_skip_tls_verify,
)
import copy
import ipaddress
import json
import re
import sys
from typing import Any, Dict, List, Optional

from core.inventory import (
    Target,
    appliance_functions,
    appliance_health,
    appliance_hosts,
    is_selectable,
)
from core.utils import print_error


class AppliancePutError(RuntimeError):
    """GET/PUT guard or Controller rejected the appliance document (E08)."""

_tls_verify = TLS_VERIFY
if not _tls_verify:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def _disable_tls_verify() -> None:
    global _tls_verify
    _tls_verify = False
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


SNMP_PUT_ALLOWED = ("snmpServer.snmpd.conf", "snmpServer.enabled")
NTP_PUT_ALLOWED = ("ntp", "ntpServers", "ntpServer")
# Top-level keys we already know. Unknown GET keys are still PUT unchanged;
# DEBUG lists them so a new 6.x field is visible without aborting the run.
APPLIANCE_GET_KNOWN_TOP = frozenset(
    {
        "id",
        "name",
        "notes",
        "tags",
        "created",
        "updated",
        "version",
        "hostname",
        "site",
        "networking",
        "adminInterface",
        "peerInterface",
        "clientInterface",
        "controller",
        "gateway",
        "logServer",
        "logForwarder",
        "connector",
        "portal",
        "metricsAggregator",
        "connectionBroker",
        "snmpServer",
        "ntp",
        "ntpServer",
        "ntpServers",
        "sshServer",
        "ping",
        "rsyslogDestinations",
        "healthcheckServer",
        "prometheusExporter",
        "customization",
        "customizations",
        "activated",
        "extraHostnames",
        "dnsServers",
        "hosts",
    }
)


def _log_unknown_appliance_keys(appliance: Dict[str, Any], where: str) -> None:
    extra = sorted(str(k) for k in appliance if k not in APPLIANCE_GET_KNOWN_TOP)
    if extra:
        # print(f"DEBUG get-unknown: {where} extra={extra!r}")
        if DEBUG:
            print(
                f"      DEBUG {where}: unknown GET keys (preserved on PUT): {extra}",
                file=sys.stderr,
            )


def _redact_appliance_for_debug(obj: Any) -> Any:
    """Strip snmpd.conf hashes and NTP keys before DEBUG dumps."""
    data = copy.deepcopy(obj)
    if not isinstance(data, dict):
        return data
    snmp = data.get("snmpServer")
    if isinstance(snmp, dict) and snmp.get("snmpd.conf"):
        snmp["snmpd.conf"] = "<redacted snmpd.conf>"
    ntp = data.get("ntp")
    if isinstance(ntp, dict):
        for row in ntp.get("servers") or []:
            if isinstance(row, dict) and row.get("key"):
                row["key"] = "<redacted>"
    return data


def _site_uuid_reshape(before: Any, after: Any) -> bool:
    if not isinstance(before, dict):
        return False
    site_id = before.get("id") or before.get("siteId")
    return bool(site_id) and str(after) == str(site_id)


def _changed_paths(before: Any, after: Any, prefix: str = "") -> List[str]:
    """JSON-pointer-ish list of added/removed/changed paths. Lists compare as one node."""
    if before == after:
        return []
    diffs: List[str] = []
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after), key=str):
            path = f"{prefix}.{key}" if prefix else str(key)
            if key not in before:
                diffs.append(f"+{path}")
            elif key not in after:
                diffs.append(f"-{path}")
            else:
                diffs.extend(_changed_paths(before[key], after[key], path))
        return diffs
    if isinstance(before, list) and isinstance(after, list):
        if before != after:
            diffs.append(prefix or ".")
        return diffs
    diffs.append(prefix or ".")
    return diffs


def _path_allowed(item: str, allowed: tuple) -> bool:
    path = item.lstrip("+-")
    for rule in allowed:
        if path == rule or path.startswith(rule + "."):
            return True
    return False


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
        h = host
        try:
            ipaddress.IPv6Address(host)
            h = f"[{host}]"
        except ValueError:
            pass
        self.base_url = f"https://{h}:{APPGATE_ADMIN_PORT}{APPGATE_ADMIN_PREFIX}"

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
                    verify=_tls_verify,
                    timeout=API_TIMEOUT,
                )
            except requests.exceptions.SSLError as exc:
                last_connect_error = exc
                print(
                    f"      TLS verify failed for {host} (self-signed or untrusted CA).",
                    file=sys.stderr,
                )
                if confirm_skip_tls_verify():
                    _disable_tls_verify()
                    try:
                        response = requests.post(
                            f"{self.base_url}/login",
                            headers=self.headers,
                            json=payload,
                            verify=False,
                            timeout=API_TIMEOUT,
                        )
                    except (requests.ConnectionError, requests.Timeout, OSError) as retry_exc:
                        last_connect_error = retry_exc
                        continue
                else:
                    continue
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
            # print(f"DEBUG login: host={host!r} status={response.status_code}")
            try:
                data = response.json()
            except ValueError:
                raise RuntimeError(
                    f"Login returned non-JSON (HTTP {response.status_code}): "
                    f"{(response.text or '')[:LOGIN_BODY_PREVIEW]}"
                )
            if not isinstance(data, dict):
                raise RuntimeError("Login JSON was not an object")
            token = data.get("token")
            if not token:
                raise ValueError(
                    "Login response did not contain an API token. "
                    f"HTTP {response.status_code}."
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
                verify=_tls_verify,
                timeout=API_TIMEOUT,
            )
            if response.status_code not in (200, 206):
                response.raise_for_status()
            try:
                payload = response.json()
            except ValueError:
                break
            body_range = ""
            if isinstance(payload, list):
                chunk = payload
            elif isinstance(payload, dict):
                chunk = payload.get("data")
                body_range = str(payload.get("range") or "")
            else:
                chunk = []
            if not isinstance(chunk, list):
                chunk = []
            # print(f"DEBUG paged_get: path={path} start={start} n={len(chunk)}")
            if not chunk:
                break
            if items and chunk and items[0] == chunk[0]:
                break
            items.extend(chunk)
            if len(items) >= APPLIANCE_LIST_MAX:
                return items[:APPLIANCE_LIST_MAX]
            total = None
            if "/" in body_range:
                try:
                    total = int(body_range.rsplit("/", 1)[-1])
                except ValueError:
                    total = None
            if total is not None:
                if len(items) >= total:
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
            verify=_tls_verify,
            timeout=API_TIMEOUT,
        )
        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError:
            raise RuntimeError("GET /appliances returned non-JSON")
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            return []
        chunk = payload.get("data")
        if not isinstance(chunk, list):
            chunk = []
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
            # print(f"DEBUG step2: GET {APPLIANCE_STATUS_PATH} host={self.agip}")
            if DEBUG:
                print(f"      DEBUG step2: GET {APPLIANCE_STATUS_PATH} on {self.agip}", file=sys.stderr)
            items = self._paged_get(APPLIANCE_STATUS_PATH)
        except (requests.RequestException, ValueError, OSError):
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            # API may key by id, applianceId, or nest under appliance.
            aid = (
                item.get("id")
                or item.get("applianceId")
                or item.get("appliance_id")
            )
            if not aid and isinstance(item.get("appliance"), dict):
                aid = item["appliance"].get("id")
            if aid:
                out[str(aid)] = item
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
            if not aid:
                continue
            if appliance.get("activated") is False:
                print(
                    f"      skip {name}: not activated",
                    file=sys.stderr,
                )
                continue
            health = appliance_health(appliance, status_by_id.get(aid, {}))
            if not is_selectable(health, APPLIANCE_SKIP_STATUS):
                print(
                    f"      skip {name}: not healthy (status={health!r})",
                    file=sys.stderr,
                )
                continue
            ssh_fqdn, ssh_ips = appliance_hosts(appliance)
            ssh_ip = ssh_ips[0] if ssh_ips else ""
            if not ssh_fqdn and not ssh_ip:
                print(f"      skip {name}: no FQDN or IP for SSH", file=sys.stderr)
                continue
            targets.append(
                Target(
                    appliance_id=aid,
                    hostname=name,
                    ssh_fqdn=ssh_fqdn,
                    ssh_ip=ssh_ip,
                    ssh_ips=ssh_ips,
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
        """Step 6: PUT createUser + optional rouser + engineIDType 3 (live run only).

        Call after delete_snmp_user so the final blob has no deleteUser line.
        Auth/priv algorithms must match core/snmp_hashgen.py / config.py.
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
            verify=_tls_verify,
            timeout=API_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError(f"GET appliance {aid} returned non-object JSON")
        _log_unknown_appliance_keys(payload, f"GET /appliances/{aid}")
        return payload

    @staticmethod
    def _sanitize_appliance_for_put(appliance: Dict[str, Any]) -> Dict[str, Any]:
        """GET often expands site to an object; PUT wants the site UUID. Never drop site."""
        body = dict(appliance)
        site = body.get("site")
        if isinstance(site, dict):
            site_id = site.get("id") or site.get("siteId")
            if not site_id:
                raise RuntimeError(
                    "Appliance site object has no id; refusing PUT that would drop site"
                )
            body["site"] = str(site_id)
        return body

    def _put_snmpd_conf(self, appliance: Dict[str, Any], new_conf: str, enabled: bool) -> None:
        """GET body + snmpd.conf only. Keep site/NICs/tcpPort exactly as retrieved."""
        original = copy.deepcopy(appliance)
        existing = appliance.get("snmpServer")
        if not isinstance(existing, dict):
            existing = {}
        snmp = dict(existing)
        snmp["enabled"] = enabled
        snmp["snmpd.conf"] = new_conf
        appliance["snmpServer"] = snmp
        body = self._sanitize_appliance_for_put(appliance)
        self._assert_put_safe(
            original,
            body,
            allowed=SNMP_PUT_ALLOWED,
            what="SNMP config",
        )
        self._put_appliance_body(body, what="SNMP config")

    def _assert_put_safe(
        self,
        original: Dict[str, Any],
        body: Dict[str, Any],
        *,
        allowed: tuple,
        what: str,
    ) -> None:
        """Refuse PUT if anything outside *allowed* (plus site UUID reshape) changed."""
        diffs = _changed_paths(original, body)
        unexpected = []
        for item in diffs:
            path = item.lstrip("+-")
            if path == "site" and _site_uuid_reshape(original.get("site"), body.get("site")):
                continue
            if item == "+snmpServer":
                extra = set((body.get("snmpServer") or {})) - {"enabled", "snmpd.conf"}
                if extra:
                    unexpected.append(f"+snmpServer extra={sorted(extra)}")
                continue
            if _path_allowed(item, allowed):
                continue
            unexpected.append(item)
        if not unexpected:
            return
        # print(f"DEBUG put-safe: what={what!r} unexpected={unexpected!r}")
        if DEBUG:
            print(f"      DEBUG {what} PUT original:", file=sys.stderr)
            print(json.dumps(_redact_appliance_for_debug(original), indent=2, default=str), file=sys.stderr)
            print(f"      DEBUG {what} PUT body:", file=sys.stderr)
            print(json.dumps(_redact_appliance_for_debug(body), indent=2, default=str), file=sys.stderr)
        raise AppliancePutError(
            f"Refusing {what} PUT; unexpected field changes {unexpected}. "
            "Set DEBUG=True to dump GET/PUT bodies."
        )

    def _put_appliance_body(self, body: Dict[str, Any], *, what: str) -> None:
        aid = body.get("id")
        if not aid:
            raise AppliancePutError(f"Refusing {what} PUT; appliance id missing")
        url = f"{self.base_url}/appliances/{aid}"
        put_response = requests.put(
            url, headers=self.headers, json=body, verify=_tls_verify, timeout=API_TIMEOUT
        )
        if put_response.status_code != 200:
            if DEBUG:
                print(f"      DEBUG {what} PUT HTTP {put_response.status_code}", file=sys.stderr)
                print(json.dumps(_redact_appliance_for_debug(body), indent=2, default=str), file=sys.stderr)
                print((put_response.text or "")[:API_ERROR_BODY_PREVIEW], file=sys.stderr)
            body_preview = (put_response.text or "")[:API_ERROR_BODY_PREVIEW]
            hint = ""
            text_l = (put_response.text or "").lower()
            if put_response.status_code == 422 and "portal.profiles" in text_l:
                hint = (
                    " Hint: Admin Role needs View on Client Profile "
                    "(portal.profiles[] are client profile names)."
                )
            elif put_response.status_code == 422 and "site" in text_l:
                hint = (
                    " Hint: this API user can View the appliance but may lack "
                    "Appliance Edit and/or Site access. In Admin UI check "
                    "Admin Role → Appliances (Edit) and Sites for this box."
                )
            elif put_response.status_code in (401, 403):
                hint = (
                    " Hint: check Admin Role privileges (Appliance View + Edit, "
                    "Site View, Client Profile View on portals) "
                    "for this Controller login."
                )
            raise AppliancePutError(
                f"Failed to update {what} (HTTP {put_response.status_code}): "
                f"{body_preview}{hint}"
            )

    @staticmethod
    def _ntp_key_for_api(entry: Dict[str, Any]) -> Dict[str, Any]:
        """6.7 GET shape: ntp.servers[].hostname, optional keyType/keyNo/key (SHA256 → HEX:)."""
        host = str(entry.get("hostname") or "").strip()
        out: Dict[str, Any] = {"hostname": host}
        key_type = str(entry.get("keyType") or "").strip()
        key_no = entry.get("keyNo")
        key = str(entry.get("key") or "").strip()
        if key_type:
            compact = key_type.replace("-", "").upper()
            mapped = NTP_KEY_TYPE_MAP.get(compact, key_type)
            if str(mapped).upper() in NTP_WEAK_KEY_TYPES:
                msg = (
                    f"NTP keyType {mapped} is not CNSA 2.0 / DISA (use SHA256). "
                    f"hostname={host}"
                )
                if not LAB_MODE:
                    raise ValueError(msg)
                print(f"      WARNING: {msg}", file=sys.stderr)
            out["keyType"] = mapped
        if key_no not in ("", None):
            try:
                out["keyNo"] = int(key_no)
            except (TypeError, ValueError):
                out["keyNo"] = key_no
        if key:
            if not key_type and not LAB_MODE:
                raise ValueError(
                    f"NTP key set but keyType empty for {host}; DISA requires SHA256"
                )
            compact = (out.get("keyType") or key_type).replace("-", "").upper()
            prefix = NTP_KEY_HEX_PREFIX
            if compact == "SHA256" and not key.upper().startswith(prefix.upper()):
                key = prefix + key
            out["key"] = key
        return out

    @staticmethod
    def _ntp_hostname(entry: Any) -> str:
        if isinstance(entry, str):
            return entry.strip()
        if isinstance(entry, dict):
            return str(
                entry.get("hostname") or entry.get("src") or entry.get("server") or ""
            ).strip()
        return ""

    @staticmethod
    def _ntp_list_from_appliance(appliance: Dict[str, Any]) -> List[Any]:
        """6.7: appliance.ntp.servers is the list (ntp is an object)."""
        raw = appliance.get("ntp")
        if isinstance(raw, dict) and isinstance(raw.get("servers"), list):
            return raw["servers"]
        if isinstance(raw, list):
            return raw
        for key in ("ntpServers", "ntpServer"):
            legacy = appliance.get(key)
            if isinstance(legacy, list):
                return legacy
        return []

    def peek_ntp(self, appliance_id: str) -> List[str]:
        """Hostnames currently on the appliance (no keys)."""
        appliance = self._get_appliance(appliance_id)
        raw = appliance.get("ntp")
        servers = self._ntp_list_from_appliance(appliance)
        if DEBUG:
            print(
                f"      DEBUG ntp GET: type={type(raw).__name__} n={len(servers)}",
                file=sys.stderr,
            )
        return [h for h in (self._ntp_hostname(x) for x in servers) if h]

    def update_ntp_servers(
        self,
        appliance_id: str,
        servers: List[Dict[str, Any]],
        *,
        overwrite: bool,
    ) -> List[Dict[str, Any]]:
        """PUT appliance.ntp so cz-configd applies (survives reboot)."""
        appliance = self._get_appliance(appliance_id)
        original = copy.deepcopy(appliance)
        existing_list = self._ntp_list_from_appliance(appliance)
        desired = [self._ntp_key_for_api(s) for s in servers if self._ntp_hostname(s)]
        if overwrite:
            merged = desired
        else:
            by_host: Dict[str, Any] = {}
            for item in existing_list:
                host = self._ntp_hostname(item)
                if host:
                    by_host[host.lower()] = item if isinstance(item, dict) else {"hostname": host}
            for item in desired:
                host = item["hostname"].lower()
                if host in by_host and isinstance(by_host[host], dict):
                    by_host[host].update(item)
                else:
                    by_host[host] = item
            merged = list(by_host.values())
        appliance.pop("ntpServers", None)
        appliance.pop("ntpServer", None)
        ntp_obj = appliance.get("ntp")
        if not isinstance(ntp_obj, dict):
            ntp_obj = {}
        ntp_obj["servers"] = merged
        appliance["ntp"] = ntp_obj
        if DEBUG:
            safe = [
                {
                    "hostname": self._ntp_hostname(x),
                    "keyType": x.get("keyType") if isinstance(x, dict) else "",
                    "keyNo": x.get("keyNo") if isinstance(x, dict) else "",
                    "has_key": bool(isinstance(x, dict) and x.get("key")),
                }
                for x in merged
            ]
            print(
                f"      DEBUG ntp PUT ntp.servers={safe!r}",
                file=sys.stderr,
            )
        body = self._sanitize_appliance_for_put(appliance)
        self._assert_put_safe(
            original,
            body,
            allowed=NTP_PUT_ALLOWED,
            what="NTP servers",
        )
        self._put_appliance_body(body, what="NTP servers")
        return merged
