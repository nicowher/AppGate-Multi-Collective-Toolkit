"""AppGate admin API: login, list appliances, snmpd.conf PUT.

Inventory *shape* (Target, health, exclude) lives in ``core/inventory.py``.
This file only talks HTTP.


One AppGateClient per collective (own bearer token) so a token from site A
is never sent to site B (403 / wrong collective).

    1  login() — production pins the Controller CA before the password is sent.
        FQDN first; agip only when the name does not connect. Never fall back
        on 401/403 (that is auth, not DNS). Only INSECURE_API skips the pin.
        LAB_MODE does not.
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
    API_AUTH_FAIL_CODES,
    API_ERROR_BODY_PREVIEW,
    APPGATE_PROVIDER,
    DEBUG,
    LOGIN_BODY_PREVIEW,
    APPLIANCE_LIST_MAX,
    APPLIANCE_LIST_PAGE,
    APPLIANCE_STATUS_PATH,
    ENGINE_ID_TYPE,
    NTP_KEY_HEX_PREFIX,
    ALLOW_SOURCES_PUT_ALLOWED,
    ALLOW_SOURCES_SLOT_PARENT,
    NTP_KEY_TYPE_MAP,
    NTP_WEAK_KEY_TYPES,
    SNMP_AUTH_PROTOCOL,
    SNMP_PRIV_PROTOCOL,
    STRIP_V1V2_COMMUNITIES,
    insecure_api_enabled,
)
import copy
import ipaddress
import json
import re
import sys
from typing import Any, Dict, List, Optional

from core.ca_pin import CaPinError, require_ca_file
from core.inventory import (
    Target,
    appliance_functions,
    appliance_health,
    appliance_hosts,
    is_selectable,
    status_self_ips,
)
from core.utils import print_error, redact_preview, write_replaced_snapshot


from .allow_sources import AllowSourcesMixin
from .errors import AppliancePutError
from .ntp import NtpMixin
from .snmp import SnmpMixin

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]|\x1b\[[0-?]*[ -/]*[@-~]")


def _strip_controls(text: str) -> str:
    """A Controller error must not rewrite the operator terminal."""
    # print(f"DEBUG strip: n={len(text or '')}")
    return _CTRL.sub("", text or "")


def _disable_tls_verify() -> None:
    """INSECURE_API only. Hides urllib3 noise when verify is off."""
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


if insecure_api_enabled():
    _disable_tls_verify()


SNMP_PUT_ALLOWED = ("snmpServer.snmpd.conf", "snmpServer.enabled")
NTP_PUT_ALLOWED = ("ntp", "ntpServers", "ntpServer")
ALLOW_SOURCES_PARENTS = tuple(sorted(set(ALLOW_SOURCES_SLOT_PARENT.values())))


def _merge_self_ips(nic_ips: List[str], status: Dict[str, Any]) -> List[str]:
    """Status addresses are not always on the NIC list. Exclude-self misses them if they are dropped."""
    out: List[str] = []
    for ip in list(nic_ips) + status_self_ips(status):
        text = str(ip or "").strip()
        if text and text not in out:
            out.append(text)
    return out


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
    """Same secret list as replace backups. DEBUG dumps must not keep keys or tokens."""
    from core.utils import redact_for_backup

    return redact_for_backup(obj)


def _site_uuid_reshape(before: Any, after: Any) -> bool:
    """PUT must keep the same site UUID. Dropping the object is a different edit and is refused."""
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
    """A nested edit has to stay inside the allowed slice or a portal field can ride along."""
    path = item.lstrip("+-")
    for rule in allowed:
        if path == rule or path.startswith(rule + "."):
            return True
    return False


class AppGateClient(SnmpMixin, NtpMixin, AllowSourcesMixin):
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
        from core.utils import install_machine_id

        self.machine_id = install_machine_id()
        self._login_id_field = "machineId"
        self._version_learned = False
        self.headers: Dict[str, str] = {
            "Accept": f"application/vnd.appgate.peer-v{self.api_version}+json",
            "Content-Type": "application/json",
        }
        self._set_endpoint(self.agip)
        self._ca_bundle = ""

    def _verify(self):
        """INSECURE_API skips verify. Otherwise the hand-placed CA file. Never the system store."""
        if insecure_api_enabled():
            return False
        if self._ca_bundle:
            return self._ca_bundle
        raise CaPinError("Controller CA file was not loaded. Refusing to call the API.")

    def _set_endpoint(self, host: str) -> None:
        self.agip = host
        h = host
        try:
            ipaddress.IPv6Address(host)
            h = f"[{host}]"
        except ValueError:
            pass
        self.base_url = f"https://{h}:{APPGATE_ADMIN_PORT}{APPGATE_ADMIN_PREFIX}"

    def _peer_from_payload(self, payload: Any) -> str:
        """peerVersion is the Accept number. A 7.x product string is peer 25 if that field is missing."""
        if not isinstance(payload, dict):
            return ""
        for key in ("peerVersion", "peer_version"):
            raw = payload.get(key)
            if raw not in (None, ""):
                return str(raw).split(".", 1)[0]
        product = str(payload.get("version") or "")
        if product.startswith("7"):
            return "25"
        return ""

    def _set_peer_version(self, version: str) -> None:
        """7.0 rejects a v24 Accept as a fake 403, so the header must match the probe."""
        self.api_version = str(version).split(".", 1)[0]
        self.headers["Accept"] = f"application/vnd.appgate.peer-v{self.api_version}+json"
        self._version_learned = True
        print(f"      API version {self.api_version}", file=sys.stderr)

    def _version_in_text(self, text: str) -> str:
        """406/403 bodies name the Accept the Controller will speak. Do not guess one."""
        match = re.search(r"peer-v(\d+)", text or "")
        return match.group(1) if match else ""

    def _use_controller_api_version(self) -> None:
        """GET /admin/version has no auth. Try the header this client already speaks, then json."""
        accepts = (
            self.headers.get("Accept") or "application/json",
            "application/json",
            "*/*",
        )
        seen = []
        last = ""
        for accept in accepts:
            if accept in seen:
                continue
            seen.append(accept)
            try:
                response = requests.get(
                    f"{self.base_url}/version",
                    headers={"Accept": accept},
                    verify=self._verify(),
                    timeout=API_TIMEOUT,
                    allow_redirects=False,
                )
            except requests.exceptions.RequestException as exc:
                last = str(exc)
                if DEBUG:
                    print(f"      DEBUG version GET failed accept={accept!r} err={exc}", file=sys.stderr)
                continue
            body = (response.text or "")[:LOGIN_BODY_PREVIEW]
            if DEBUG:
                print(
                    f"      DEBUG version GET status={response.status_code} accept={accept!r}",
                    file=sys.stderr,
                )
            # print(f"DEBUG version probe: status={response.status_code} accept={accept}")
            named = self._version_in_text(body)
            if named:
                self._set_peer_version(named)
                return
            if response.status_code != 200:
                last = f"HTTP {response.status_code} body={body!r}"
                continue
            try:
                payload = response.json()
            except ValueError:
                last = "non-JSON"
                continue
            version = self._peer_from_payload(payload)
            if version:
                self._set_peer_version(version)
                return
            last = f"no peerVersion keys={sorted(payload) if isinstance(payload, dict) else type(payload).__name__}"
        print(f"      API version probe failed ({last}); login stays on v{self.api_version}", file=sys.stderr)

    def _peer_major(self) -> int:
        """peerVersion is '24' or '25'. A non-numeric value stays on the v24 login body."""
        raw = str(self.api_version).split(".", 1)[0]
        try:
            return int(raw)
        except ValueError:
            return 24

    def _identity_provider_names(self) -> list:
        """Provider display names are public. A mismatch is a 403, not a bad password."""
        try:
            response = requests.get(
                f"{self.base_url}/identity-providers/names",
                headers=self.headers,
                verify=self._verify(),
                timeout=API_TIMEOUT,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            if DEBUG:
                print(f"      DEBUG providers: {exc}", file=sys.stderr)
            return []
        if DEBUG:
            print(
                f"      DEBUG providers status={response.status_code}",
                file=sys.stderr,
            )
        # print(f"DEBUG providers: status={response.status_code}")
        if response.status_code != 200:
            return []
        try:
            payload = response.json()
        except ValueError:
            return []
        data = payload.get("data") if isinstance(payload, dict) else payload
        names = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str) and item.strip():
                    names.append(item.strip())
                elif isinstance(item, dict):
                    name = str(item.get("name") or item.get("displayName") or "").strip()
                    if name:
                        names.append(name)
        return names

    @staticmethod
    def _match_provider(wanted: str, names: list) -> str:
        """Use the Controller's spelling when it differs only by case."""
        if not names:
            return wanted
        for name in names:
            if name == wanted:
                return name
        for name in names:
            if name.lower() == (wanted or "").lower():
                return name
        return wanted

    def _login_payload(self, username: str, password: str, provider_name: str) -> Dict[str, str]:
        """6.7 accepts machineId. 7.0 (peer 25) requires deviceId. Same UUID either way."""
        field = "deviceId" if self._peer_major() >= 25 else "machineId"
        self._login_id_field = field
        # print(f"DEBUG login id field={field} peer={self.api_version}")
        return {
            field: self.machine_id,
            "providerName": provider_name,
            "username": username,
            "password": password,
        }

    def login(self, username: str, password: str, provider: Optional[str] = None) -> str:
        """Step 1: POST /admin/login. FQDN first; IP if connect/HTTP fails (not 401/403).

        One collective CA covers both names. If the FQDN file exists, the IP
        fallback reuses it instead of demanding a second .cer.
        """
        provider_name = provider or self.provider
        last_connect_error: Optional[Exception] = None
        pinned = ""
        for host in self.endpoints:
            self._set_endpoint(host)
            if not insecure_api_enabled():
                try:
                    self._ca_bundle = require_ca_file(host)
                    pinned = self._ca_bundle
                except CaPinError as exc:
                    if pinned and not exc.fatal:
                        self._ca_bundle = pinned
                    else:
                        print(f"ERROR E06: {exc}", file=sys.stderr)
                        last_connect_error = exc
                        if exc.fatal:
                            break
                        continue
            self._use_controller_api_version()
            names = self._identity_provider_names()
            provider_name = self._match_provider(provider or self.provider, names)
            if DEBUG and names and provider_name not in names:
                print(
                    f"      DEBUG provider {provider_name!r} not in {names!r}",
                    file=sys.stderr,
                )
            payload = self._login_payload(username, password, provider_name)
            self._login_retried = False
            try:
                response = requests.post(
                    f"{self.base_url}/login",
                    headers=self.headers,
                    json=payload,
                    verify=self._verify(),
                    timeout=API_TIMEOUT,
                    allow_redirects=False,
                )
                if DEBUG:
                    print(
                        f"      DEBUG login POST accept={self.headers.get('Accept')!r} "
                        f"id_field={self._login_id_field} status={response.status_code}",
                        file=sys.stderr,
                    )
            except requests.exceptions.SSLError as exc:
                last_connect_error = exc
                print(
                    f"      TLS verify failed for {host} (self-signed or untrusted CA).",
                    file=sys.stderr,
                )
                continue
            except (requests.ConnectionError, requests.Timeout, OSError) as exc:
                last_connect_error = exc
                print(
                    f"      Cannot reach {host} ({type(exc).__name__}); trying fallback...",
                    file=sys.stderr,
                )
                continue
            named = self._version_in_text(response.text or "")
            if (
                response.status_code == 403
                and named
                and named != str(self.api_version)
            ):
                # Only retry when the Controller names the Accept it wants. A blind v25 retry still 403s.
                print(f"      Accept rejected; retrying peer {named}", file=sys.stderr)
                self._set_peer_version(named)
                payload = self._login_payload(username, password, provider_name)
                response = requests.post(
                    f"{self.base_url}/login",
                    headers=self.headers,
                    json=payload,
                    verify=self._verify(),
                    timeout=API_TIMEOUT,
                    allow_redirects=False,
                )
                if DEBUG:
                    # print(f"DEBUG login retry status={response.status_code}")
                    print(
                        f"      DEBUG login retry status={response.status_code} "
                        f"accept={self.headers.get('Accept')!r} "
                        f"body={(response.text or '')[:LOGIN_BODY_PREVIEW]!r}",
                        file=sys.stderr,
                    )
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
                    f"{_strip_controls((response.text or '')[:LOGIN_BODY_PREVIEW])}"
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
            msg = _strip_controls(redact_preview(str(body.get("message", response.text)), LOGIN_BODY_PREVIEW))
            err_id = body.get("id", "")
            failure = body.get("failureType", "")
        except (ValueError, TypeError, requests.JSONDecodeError):
            msg = _strip_controls(redact_preview(response.text or f"HTTP {response.status_code}", LOGIN_BODY_PREVIEW))
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
                "  - Ensure machineId (peer 24) or deviceId (peer 25) is accepted\n",
                file=sys.stderr,
            )
        elif response.status_code == 403:
            print(
                f"ERROR: HTTP 403 from API v{self.api_version} as {_username} "
                f"({self._login_id_field}): {msg}\n"
                "Accept matched this Controller. This is not the v24 header rejection. "
                "The account authenticated far enough to be denied admin rights.",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: Login failed (HTTP {response.status_code}): {msg}", file=sys.stderr)

        raise RuntimeError(f"Login failed (HTTP {response.status_code})")

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
                verify=self._verify(),
                timeout=API_TIMEOUT,
                allow_redirects=False,
            )
            if response.status_code not in (200, 206):
                response.raise_for_status()
            try:
                payload = response.json()
            except ValueError as exc:
                raise RuntimeError(f"GET {path} returned non-JSON") from exc
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
            verify=self._verify(),
            timeout=API_TIMEOUT,
            allow_redirects=False,
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
        # A failed status read must not look like n/a and stay selectable.
        # print(f"DEBUG step2: GET {APPLIANCE_STATUS_PATH} host={self.agip}")
        if DEBUG:
            print(f"      DEBUG step2: GET {APPLIANCE_STATUS_PATH} on {self.agip}", file=sys.stderr)
        items = self._paged_get(APPLIANCE_STATUS_PATH)
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
                    self_ips=_merge_self_ips(ssh_ips, status_by_id.get(aid, {})),
                )
            )
        return targets

    def _get_appliance(self, appliance_id: Optional[str] = None) -> Dict[str, Any]:
        aid = appliance_id
        if not aid:
            raise RuntimeError("Appliance ID is not set.")
        response = requests.get(
            f"{self.base_url}/appliances/{aid}",
            headers=self.headers,
            verify=self._verify(),
            timeout=API_TIMEOUT,
            allow_redirects=False,
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
            url,
            headers=self.headers,
            json=body,
            verify=self._verify(),
            timeout=API_TIMEOUT,
            allow_redirects=False,
        )
        if put_response.status_code != 200:
            if DEBUG:
                print(f"      DEBUG {what} PUT HTTP {put_response.status_code}", file=sys.stderr)
                print(json.dumps(_redact_appliance_for_debug(body), indent=2, default=str), file=sys.stderr)
                print(_strip_controls((put_response.text or "")[:API_ERROR_BODY_PREVIEW]), file=sys.stderr)
            body_preview = _strip_controls(redact_preview(put_response.text or "", API_ERROR_BODY_PREVIEW))
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

