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
    APPLIANCE_PUT_REUSE_SEC,
    DEBUG_BODY_PREVIEW,
    APPGATE_PROVIDER,
    DEBUG,
    LOGIN_BODY_PREVIEW,
    APPLIANCE_LIST_MAX,
    APPLIANCE_LIST_PAGE,
    APPLIANCE_STATUS_PATH,
    ALLOW_SOURCES_SLOT_PARENT,
    insecure_api_enabled,
)
import copy
import ipaddress
import atexit
import json
import re
import socket
import ssl
import time
import sys
from typing import Any, Dict, List, Optional

from core.ca_pin import CaPinError, require_ca_file
from core.inventory import (
    Target,
    appliance_admin_ip,
    appliance_functions,
    appliance_health,
    appliance_hosts,
    appliance_ssh_host,
    is_selectable,
    status_self_ips,
)
from core.utils import clean_for_terminal, is_ip, print_error, redact_preview


from .allow_sources import AllowSourcesMixin
from .errors import AppliancePutError
from .ntp import NtpMixin
from .snmp import SnmpMixin

def _strip_controls(text: str) -> str:
    """A Controller error must not rewrite the operator terminal. Multi-line text keeps its line breaks."""
    return clean_for_terminal(text, keep_newlines=True)


# Peer version per Controller address, for this process only (see _use_controller_api_version).
_PEER_VERSION_SEEN: Dict[str, str] = {}
# Controllers (agip, lowercased) whose no-range status retry returned no live
# status this session; the retry is skipped for them on later menu runs.
_STATUS_RETRY_USELESS: set = set()
# Identity-provider names per Controller address, for this process only.
_PROVIDERS_SEEN: Dict[str, list] = {}

_CNSA_TLS_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
_cnsa_session = None


_cnsa_contexts: Dict[Any, ssl.SSLContext] = {}


def _cnsa_context_for(verify: Any) -> ssl.SSLContext:
    """One CNSA context per CA file, so each Controller trusts only its own CA.

    urllib3 loads the verify file into the context it is given. A single shared
    context would collect every Controller's CA, and collective 1's CA would then
    be trusted for collective 2. The pool key includes the context, so each CA
    also gets its own connection pool.
    """
    key = verify if isinstance(verify, str) else bool(verify)
    ctx = _cnsa_contexts.get(key)
    if ctx is None:
        ctx = _cnsa_context(verify_off=(key is False))
        if isinstance(verify, str):
            ctx.load_verify_locations(cafile=verify)
        _cnsa_contexts[key] = ctx
        # print(f"DEBUG cnsa: TLS context for {('CA file' if isinstance(verify, str) else verify)!r}")
    return ctx


def _cnsa_context(verify_off: bool = False) -> ssl.SSLContext:
    """TLS 1.2 with ECDHE AES-256-GCM-SHA384 on P-384 only.

    TLS 1.3 is turned off because Python cannot limit its cipher list, and
    OpenSSL would also offer AES-128-GCM and ChaCha20 there. PROTOCOL_TLS_CLIENT
    loads no system CAs: the hand-placed Controller CA is still the only trust.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    # SECLEVEL=3 makes OpenSSL refuse an RSA server key under 3072 bits. A P-256
    # server certificate still passes this check; the cipher and curve are P-384.
    ctx.set_ciphers(_CNSA_TLS_CIPHERS + ":@SECLEVEL=3")
    ctx.set_ecdh_curve("secp384r1")
    # Same certificate checks as the normal (urllib3) path, so strict is never laxer.
    ctx.verify_flags |= getattr(ssl, "VERIFY_X509_STRICT", 0) | getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    if verify_off:
        # Only reached with verify=False, which _verify() returns only for INSECURE_API.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _CnsaAdapter(requests.adapters.HTTPAdapter):
    """Every HTTPS connection in this session uses the CNSA context for its own CA file."""

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        """Give each request the context for its own CA file, so the pool key (and the trust) differ per Controller."""
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(request, verify, cert)
        pool_kwargs["ssl_context"] = _cnsa_context_for(verify)
        return host_params, pool_kwargs


def _cnsa_tls_refused(exc: BaseException) -> bool:
    """True when CNSA_STRICT is on and the failure is a handshake mismatch, not a trust problem."""
    import config as _config

    text = str(exc).lower()
    return bool(getattr(_config, "CNSA_STRICT", True)) and any(
        word in text for word in ("handshake failure", "no shared cipher", "unsupported protocol",
                                  "wrong version number", "no ciphers available", "sslv3 alert",
                                  "key too small", "ca md too weak")
    )


class _DebugHttp:
    """DEBUG wrapper: one line per Controller request (method, path, status, time).

    Only the URL path is printed: never the query values, body, headers or
    token. Used for every call so a failed step shows exactly which request it
    sent and what came back.
    """

    def __init__(self, inner) -> None:
        """inner is the requests module or the CNSA session."""
        self._inner = inner

    def _call(self, method: str, url: str, **kwargs):
        """Time one request and print its line, also when it raises."""
        from urllib.parse import urlsplit

        path = urlsplit(url).path
        started = time.monotonic()
        try:
            response = getattr(self._inner, method)(url, **kwargs)
        except Exception as exc:
            ms = (time.monotonic() - started) * 1000
            print(f"      DEBUG api {method.upper()} {path} -> {type(exc).__name__} ({ms:.0f} ms)", file=sys.stderr)
            raise
        ms = (time.monotonic() - started) * 1000
        print(f"      DEBUG api {method.upper()} {path} -> {response.status_code} ({ms:.0f} ms)", file=sys.stderr)
        return response

    def get(self, url, **kwargs):
        """GET through the wrapper."""
        return self._call("get", url, **kwargs)

    def post(self, url, **kwargs):
        """POST through the wrapper."""
        return self._call("post", url, **kwargs)

    def put(self, url, **kwargs):
        """PUT through the wrapper."""
        return self._call("put", url, **kwargs)

    def delete(self, url, **kwargs):
        """DELETE through the wrapper."""
        return self._call("delete", url, **kwargs)


def _http():
    """requests itself, or a CNSA-only session when CNSA_STRICT is on. Read per call so menu C applies at once.

    With DEBUG, the choice is wrapped so every request prints one line.
    """
    import config as _config

    inner = _http_inner()
    return _DebugHttp(inner) if getattr(_config, "DEBUG", False) else inner


def _http_inner():
    """The plain transport: requests, or the CNSA-only session."""
    global _cnsa_session
    import config as _config

    # A config.py from before this setting gets the strict default too.
    if not getattr(_config, "CNSA_STRICT", True):
        return requests
    if _cnsa_session is None:
        session = requests.Session()
        session.trust_env = False  # no proxy or CA bundle from the environment
        session.mount("https://", _CnsaAdapter())
        _cnsa_session = session
        # print("DEBUG cnsa: TLS session created")
    return _cnsa_session


def _strip_display(text: str) -> str:
    """A one-line name for the table, result lines and reports: no control, escape or format characters."""
    return clean_for_terminal(text).strip()


def _disable_tls_verify() -> None:
    """INSECURE_API only. Hides urllib3 noise when verify is off."""
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


if insecure_api_enabled():
    _disable_tls_verify()


SNMP_PUT_ALLOWED = ("snmpServer.snmpd.conf", "snmpServer.enabled")
NTP_PUT_ALLOWED = ("ntp", "ntpServers", "ntpServer")
ALLOW_SOURCES_PARENTS = tuple(sorted(set(ALLOW_SOURCES_SLOT_PARENT.values())))


def _copy_saved_path(src: Dict[str, Any], dest: Dict[str, Any], path: str) -> None:
    """Copy one saved slice onto the fresh GET. A missing saved field is removed."""
    parts = path.split(".")
    cur_s: Any = src
    cur_d: Any = dest
    for part in parts[:-1]:
        nxt = cur_s.get(part) if isinstance(cur_s, dict) else None
        if not isinstance(nxt, dict):
            return
        if not isinstance(cur_d.get(part), dict):
            cur_d[part] = {}
        cur_s = nxt
        cur_d = cur_d[part]
    leaf = parts[-1]
    if isinstance(cur_s, dict) and leaf in cur_s:
        cur_d[leaf] = copy.deepcopy(cur_s[leaf])
    elif isinstance(cur_d, dict):
        cur_d.pop(leaf, None)


def _status_lacks_details(items: Any) -> bool:
    """True when a status reply has rows but none carries a details object.

    A v25 Controller has returned status "n/a" with no stats for every box. That
    reply has no health, so one documented retry (no range parameter) is worth
    one call, and the operator is told if it stays that way. An empty list is not
    "lacking": there is nothing to improve.
    """
    rows = [i for i in (items or []) if isinstance(i, dict)]
    return bool(rows) and not any(isinstance(i.get("details"), dict) for i in rows)


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
        # Seen on 6.x/7.x Controllers. Still sent back unchanged on PUT; listing them
        # only stops DEBUG from reporting them as unknown on every GET.
        "collectiveReplication",
        "hostnameAliases",
        "pendingCertificateRenewal",
        "readOnly",
        "siteName",
        "telemetryAggregator",
    }
)


def _log_unknown_appliance_keys(appliance: Dict[str, Any], where: str) -> None:
    """A new Controller field must be visible without stopping the run. Unknown keys are still sent back unchanged on PUT; DEBUG only lists them."""
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
    """One Controller session. Each collective gets its own client so a bearer token is never sent to another collective's Controller."""
    def __init__(
        self,
        fqdn: str,
        fallback_ip: str = "",
        api_version: Optional[str] = None,
        provider: str = APPGATE_PROVIDER,
    ) -> None:
        """FQDN first, IP only as a connect fallback. The login id comes from certs/.machine-id so the Controller sees one stable device per install."""
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
        self._appliance_match: Dict[str, str] = {}
        self._rollback: Dict[str, tuple] = {}
        self._logout_registered = False
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
        """Point base_url at one Controller address. A bare IPv6 address needs brackets in the URL."""
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
                major = str(raw).strip().split(".", 1)[0]
                # Only a plain number can go into the Accept header.
                if major.isascii() and major.isdigit() and len(major) <= 4:
                    return major
        product = str(payload.get("version") or "")
        if product.startswith("7"):
            return "25"
        return ""

    def _set_peer_version(self, version: str, note: str = "") -> None:
        """7.0 rejects a v24 Accept as a fake 403, so the header must match the probe.

        A value that is not a plain number is ignored: it would build an Accept
        header such as peer-vabc that no Controller answers.
        """
        major = str(version).strip().split(".", 1)[0]
        if not (major.isascii() and major.isdigit() and len(major) <= 4):
            # print(f"DEBUG version: ignored non-numeric peer version {version!r}")
            return
        self.api_version = major
        self.headers["Accept"] = f"application/vnd.appgate.peer-v{self.api_version}+json"
        self._version_learned = True
        if self.agip:
            _PEER_VERSION_SEEN[self.agip.lower()] = self.api_version
        print(f"      API version {self.api_version}{note}", file=sys.stderr)

    def _version_in_text(self, text: str) -> str:
        """406/403 bodies name the Accept the Controller will speak. Do not guess one.

        A body can list several versions; the highest is the one the Controller
        speaks best, so it is used (the first one listed is often the oldest).
        Numbers beyond 4 digits are not a peer version and are ignored.
        """
        names = [int(n) for n in re.findall(r"peer-v(\d{1,4})(?!\d)", text or "")]
        # print(f"DEBUG version text: names={names!r}")
        return str(max(names)) if names else ""

    def _use_controller_api_version(self) -> None:
        """GET /admin/version has no auth. A version already learned this session is reused.

        AppGate documents application/json for this endpoint, so it is tried first,
        then the vendor header this client speaks. Some Controllers answer 406 and
        name the peer version in the body; the whole body is searched for it. The
        result is kept per Controller for this process only, so later menus make
        no version request at all.
        """
        cached = _PEER_VERSION_SEEN.get(self.agip.lower())
        if cached:
            # print(f"DEBUG version: reuse {cached} for {self.agip}")
            self._set_peer_version(cached, note=" (learned earlier this session)")
            return
        accepts = (
            "application/json",
            self.headers.get("Accept") or "application/json",
            "*/*",
        )
        seen = []
        last = ""
        for accept in accepts:
            if accept in seen:
                continue
            seen.append(accept)
            try:
                response = _http().get(
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
            full_body = response.text or ""
            body = full_body[:LOGIN_BODY_PREVIEW]
            if DEBUG:
                # The snippet shows why a 406 came back; it is redacted and has no secrets.
                snippet = _strip_controls(redact_preview(full_body, DEBUG_BODY_PREVIEW)) if response.status_code != 200 else ""
                print(
                    f"      DEBUG version GET status={response.status_code} accept={accept!r}"
                    + (f" body={snippet!r}" if snippet else ""),
                    file=sys.stderr,
                )
            # print(f"DEBUG version probe: status={response.status_code} accept={accept}")
            named = self._version_in_text(full_body)
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
        """Provider display names are public. A mismatch is a 403, not a bad password.

        Kept per Controller for the session, like the peer version, so later
        menus do not ask again.
        """
        cached = _PROVIDERS_SEEN.get(self.agip.lower())
        if cached:
            return list(cached)
        try:
            response = _http().get(
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
        if names:
            _PROVIDERS_SEEN[self.agip.lower()] = list(names)
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
                        print_error("E06", str(exc))
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
            import config as _config

            tls_info = None
            if getattr(_config, "CNSA_STRICT", True):
                # Before the password goes out: a certificate key below CNSA 2.0
                # stops this Controller. A probe that cannot connect is left to
                # the login itself, which reports the real network error.
                try:
                    tls_info = self._peer_tls(host)
                    problem = self._cert_key_problem(tls_info)
                except Exception as exc:  # noqa: BLE001
                    problem = ""
                    # print(f"DEBUG tls {host}: certificate probe failed ({type(exc).__name__})")
                if problem:
                    print_error(
                        "E18",
                        f"{host}: {problem}. CNSA_STRICT is on, so no password was sent.",
                    )
                    last_connect_error = RuntimeError(f"{host}: {problem}")
                    continue
            payload = self._login_payload(username, password, provider_name)
            self._login_retried = False
            try:
                response = _http().post(
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
                if _cnsa_tls_refused(exc):
                    print_error(
                        "E18",
                        f"{host} does not offer CNSA-grade TLS (TLS 1.2, ECDHE AES-256-GCM, P-384, "
                        "RSA keys of 3072 bits or more). CNSA_STRICT is on.",
                    )
                else:
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
                # Same handling as the first POST: a network error here tries the IP fallback, not a traceback.
                try:
                    response = _http().post(
                        f"{self.base_url}/login",
                        headers=self.headers,
                        json=payload,
                        verify=self._verify(),
                        timeout=API_TIMEOUT,
                        allow_redirects=False,
                    )
                except requests.exceptions.SSLError as exc:
                    last_connect_error = exc
                    print(f"      TLS verify failed for {host} on the retry.", file=sys.stderr)
                    continue
                except (requests.ConnectionError, requests.Timeout, OSError) as exc:
                    last_connect_error = exc
                    print(
                        f"      Cannot reach {host} on the retry ({type(exc).__name__}); trying fallback...",
                        file=sys.stderr,
                    )
                    continue
                if DEBUG:
                    # print(f"DEBUG login retry status={response.status_code}")
                    print(
                        f"      DEBUG login retry status={response.status_code} "
                        f"accept={self.headers.get('Accept')!r}",
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
            if not self._logout_registered:
                atexit.register(self.logout)
                self._logout_registered = True
            if host != self.fqdn and self.fqdn:
                print(f"      Using IP fallback {host} (FQDN {self.fqdn} unreachable)", file=sys.stderr)
            if DEBUG:
                self._debug_tls(host, tls_info)
            return token
        raise RuntimeError(
            f"Could not reach Controller {self.fqdn or self.fallback_ip}: {last_connect_error}"
        )

    def _peer_tls(self, host: str) -> Dict[str, Any]:
        """One extra TLS handshake to read what the Controller negotiates and its certificate key.

        requests hides its socket, so the strict check and the DEBUG line use
        this probe, with the same kind of context the session uses (CNSA when
        CNSA_STRICT is on). It sends no request, no password and no token; the
        certificate is public data. Raises on a connect or handshake error.
        """
        import config as _config

        if getattr(_config, "CNSA_STRICT", True):
            ctx = _cnsa_context_for(self._verify())
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, APPGATE_ADMIN_PORT), timeout=API_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                version, cipher = tls.version(), (tls.cipher() or ("?",))[0]
                der = tls.getpeercert(binary_form=True)
        info: Dict[str, Any] = {"version": version, "cipher": cipher, "kind": "?", "size": "", "sig": "?"}
        if der:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import ec, rsa

            cert = x509.load_der_x509_certificate(der)
            pub = cert.public_key()
            if isinstance(pub, ec.EllipticCurvePublicKey):
                info.update(kind="EC", size=pub.curve.name)
            elif isinstance(pub, rsa.RSAPublicKey):
                info.update(kind="RSA", size=pub.key_size)
            else:
                info.update(kind=type(pub).__name__)
            info["sig"] = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?"
        return info

    @staticmethod
    def _cert_key_problem(info: Dict[str, Any]) -> str:
        """Why a Controller certificate key is below CNSA 2.0 (P-384 / RSA-3072), or "".

        The strict TLS context already refuses an RSA key below 3072 bits
        (security level 3) and a P-256 key (no P-256 signature algorithm), at
        the handshake. This is a second check on the key itself, so a later
        change to the context cannot quietly accept a weak certificate. Level 4
        is not an option: it would also refuse RSA 4096.
        """
        kind, size = info.get("kind"), info.get("size")
        if kind == "EC":
            return "" if size in ("secp384r1", "secp521r1") else f"EC {size} certificate key (CNSA needs P-384 or P-521)"
        if kind == "RSA":
            return "" if isinstance(size, int) and size >= 3072 else f"RSA {size} certificate key (CNSA needs 3072 bits or more)"
        return f"{kind} certificate key (CNSA needs P-384, P-521 or RSA-3072+)"

    def _debug_tls(self, host: str, info: Optional[Dict[str, Any]] = None) -> None:
        """DEBUG: the TLS the Controller negotiates (version, cipher, certificate key), for strict-mode checks.

        info is the strict-mode certificate check's result when there was one,
        so no second handshake is made for this line.
        """
        try:
            if info is None:
                info = self._peer_tls(host)
            size = f" {info['size']}" if info.get("size") != "" else ""
            print(
                f"      DEBUG tls {host}: {info['version']} {info['cipher']}; "
                f"certificate key {info['kind']}{size}, signed {info['sig']}",
                file=sys.stderr,
            )
        except Exception as exc:  # noqa: BLE001 - a diagnostic must never fail the login
            print(f"      DEBUG tls {host}: probe failed ({type(exc).__name__})", file=sys.stderr)

    def logout(self) -> None:
        """Drop the bearer token on the Controller. A logout failure must not turn a finished job into a failure."""
        token = self.headers.pop("Authorization", "")
        if not token:
            return
        try:
            _http().delete(
                f"{self.base_url}/login",
                headers={**self.headers, "Authorization": token},
                verify=self._verify(),
                timeout=API_TIMEOUT,
                allow_redirects=False,
            )
        except Exception:
            return

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

    def _paged_get(
        self, path: str, start: int = 0, seed: Optional[list] = None, ranged: bool = True
    ) -> list:
        """GET a 6.7 collection. range is a query param; total is in JSON 'range' (0-49/123).

        Always the vendor Accept header: the spec allows no other on collections.
        ranged=False sends one GET with no range parameter (the spec default is all
        objects) and returns that one reply; used for the status retry.
        """
        # seed/start continue from a page the caller already has, so it is not fetched twice.
        items: list = list(seed or [])
        page = APPLIANCE_LIST_PAGE
        while True:
            end = start + page - 1
            response = _http().get(
                f"{self.base_url}{path}",
                headers=self.headers,
                params={"range": f"{start}-{end}"} if ranged else None,
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
            if not ranged:
                return (items + chunk)[:APPLIANCE_LIST_MAX]
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
        response = _http().get(
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
                # print(f"DEBUG appliances: first page n={len(chunk)} total={total}")
                return self._paged_get("/appliances", start=len(chunk), seed=chunk)
        return chunk

    def get_appliance_status(self) -> Dict[str, Dict[str, Any]]:
        """6.3+ replacement for GET /stats/appliances → GET /appliances/status."""
        # A failed status read must not look like n/a and stay selectable.
        # print(f"DEBUG step2: GET {APPLIANCE_STATUS_PATH} host={self.agip}")
        if DEBUG:
            print(f"      DEBUG step2: GET {APPLIANCE_STATUS_PATH} on {self.agip}", file=sys.stderr)
        # AppGate's spec allows only the vendor Accept here (application/json is for
        # /admin/version only, and these Controllers refuse it), so no other
        # Accept is tried.
        items = self._paged_get(APPLIANCE_STATUS_PATH)
        retried = False
        ctrl = (self.agip or "").lower()
        if _status_lacks_details(items) and ctrl not in _STATUS_RETRY_USELESS:
            # A v25 Controller has answered with status "n/a" and no live stats
            # (no cpu, no details) for every box. The spec says a plain GET makes
            # the Controller query each active appliance, so ask once more with
            # no range parameter, exactly as documented. If that is no better,
            # the first reply is kept and the operator is told below.
            # print(f"DEBUG step2: status rows lack details; one retry with no range on {self.agip}")
            retried = True
            try:
                retry = self._paged_get(APPLIANCE_STATUS_PATH, ranged=False)
            except (requests.exceptions.RequestException, RuntimeError) as exc:
                retry = None
                if DEBUG:
                    resp = getattr(exc, "response", None)
                    code = getattr(resp, "status_code", "-")
                    body = _strip_controls(redact_preview(getattr(resp, "text", "") or "", DEBUG_BODY_PREVIEW))
                    print(f"      DEBUG step2: status retry failed: {type(exc).__name__} HTTP {code} body={body!r}", file=sys.stderr)
            if retry and not _status_lacks_details(retry):
                items = retry
            else:
                # The status call queries every appliance and can be slow, so a
                # retry that gave nothing better is not repeated this session.
                _STATUS_RETRY_USELESS.add(ctrl)
        if DEBUG:
            # Field names and status words only, never other values.
            rows = [i for i in items if isinstance(i, dict)]
            first = rows[0] if rows else {}
            details = first.get("details") if isinstance(first.get("details"), dict) else {}
            print(
                f"      DEBUG step2: peer v{self.api_version} status items={len(items)} retried={retried} "
                f"has cpu={'cpu' in first} has details={bool(details)} "
                f"status values={sorted({str(r.get('status')) for r in rows})[:6]} "
                f"details keys={sorted(details)[:20]}",
                file=sys.stderr,
            )
        if _status_lacks_details(items):
            # Not a toolkit failure: the Controller itself returned no live status.
            # Say so once, because the health column and APPLIANCE_SKIP_STATUS
            # depend on it and an operator would otherwise trust the blank column.
            print(
                f"      Note: {self.agip} returned no live status for its appliances (status n/a, no stats). "
                "Health shows a dash and offline boxes cannot be skipped for this collective. "
                "Check the appliance status in this Controller's Admin UI.",
                file=sys.stderr,
            )
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
            if not isinstance(appliance, dict):
                print("      skip one appliance: the Controller returned a non-object entry", file=sys.stderr)
                continue
            try:
                target = self._appliance_target(
                    appliance, status_by_id, collective, collective_fqdn, fallback_ip
                )
            except (AttributeError, TypeError, ValueError, KeyError) as exc:
                # One odd appliance must not drop every box of this Controller.
                label = _strip_controls(str(appliance.get("name") or appliance.get("id") or "?"))
                # print(f"DEBUG list_targets: skip {label!r} {type(exc).__name__}: {exc}")
                print(
                    f"      skip {label}: unexpected appliance data from the Controller ({type(exc).__name__})",
                    file=sys.stderr,
                )
                continue
            if target is not None:
                targets.append(target)
        if DEBUG:
            # Per-collective summary for comparing a v24 and a v25 Controller in one run.
            print(
                f"      DEBUG collective {collective}: peer v{self.api_version} login id={self._login_id_field} "
                f"appliances={len(raw)} selectable={len(targets)} "
                f"health={sorted({t.health for t in targets})}",
                file=sys.stderr,
            )
        return targets

    def _appliance_target(
        self,
        appliance: Dict[str, Any],
        status_by_id: Dict[str, Dict[str, Any]],
        collective: int,
        collective_fqdn: str,
        fallback_ip: str,
    ) -> Optional[Target]:
        """One appliance row to a Target, or None when it is skipped (not activated, unhealthy, no address).

        A field of an unexpected type raises, and list_targets skips only this box.
        """
        # The name is printed in the table, every result line and the reports, so
        # control and bidi characters from the Controller are removed here once.
        name = _strip_display(str(appliance.get("name") or appliance.get("id") or "?")) or "?"
        aid = appliance.get("id") or ""
        if not aid:
            return None
        if appliance.get("activated") is False:
            print(
                f"      skip {name}: not activated",
                file=sys.stderr,
            )
            return None
        health = appliance_health(appliance, status_by_id.get(aid, {}))
        if DEBUG:
            item = status_by_id.get(aid, {})
            det = item.get("details") if isinstance(item.get("details"), dict) else {}
            where = [f"{k}" for k in ("status", "state") if isinstance(item.get(k), str) and item.get(k)]
            where += [f"details.{k}" for k in ("status", "state") if isinstance(det.get(k), str) and det.get(k)]
            # Which fields carried a health string for this box (the value is the health shown).
            print(
                f"      DEBUG health v{self.api_version} {name}: {health!r} from fields {where or ['none']}"
                f"{'' if item else ' (no status item for this id)'}",
                file=sys.stderr,
            )
        if not is_selectable(health, APPLIANCE_SKIP_STATUS):
            print(
                f"      skip {name}: not healthy (status={health!r})",
                file=sys.stderr,
            )
            return None
        ssh_fqdn, ssh_ips = appliance_hosts(appliance)
        # Admin hostname first, then admin IP. The other NIC IPs stay in ssh_ips as fallbacks.
        ssh_host = appliance_ssh_host(appliance)
        admin_ip = appliance_admin_ip(appliance)
        ssh_ip = admin_ip or (ssh_host if is_ip(ssh_host) else (ssh_ips[0] if ssh_ips else ""))
        if ssh_host and not is_ip(ssh_host):
            ssh_fqdn = ssh_host
        # print(f"DEBUG list_targets: {name} admin={ssh_fqdn!r} admin_ip={admin_ip!r} ips={ssh_ips!r}")
        if not ssh_fqdn and not ssh_ip:
            print(f"      skip {name}: no FQDN or IP for SSH", file=sys.stderr)
            return None
        return Target(
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

    def _get_appliance(self, appliance_id: Optional[str] = None, *, fresh: bool = False) -> Dict[str, Any]:
        """GET one appliance and remember its ETag or version. The later PUT sends it as If-Match so a parallel edit is not overwritten.

        The reply of this run's own PUT to the same appliance, if it is younger
        than APPLIANCE_PUT_REUSE_SEC, is used once instead of a new GET (the PUT
        reply is the full updated appliance). fresh=True always GETs: a rollback
        must start from what the Controller holds now.
        """
        aid = appliance_id
        if not aid:
            raise RuntimeError("Appliance ID is not set.")
        cached = None if fresh else self._take_put_reply(str(aid))
        if cached is not None:
            payload, token = cached
            self._appliance_match[str(aid)] = token
            # print(f"DEBUG appliance {aid}: reusing the PUT reply instead of a GET")
            if DEBUG:
                print(f"      DEBUG api GET /admin/appliances/{aid} skipped (reused this run's PUT reply)", file=sys.stderr)
            return payload
        response = _http().get(
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
        self._remember_match(aid, response, payload)
        _log_unknown_appliance_keys(payload, f"GET /appliances/{aid}")
        return payload

    def _take_put_reply(self, aid: str):
        """(appliance, If-Match token) from a recent PUT reply of this appliance, used once; or None."""
        replies = getattr(self, "_put_replies", None) or {}
        entry = replies.pop(aid, None)
        if not entry or APPLIANCE_PUT_REUSE_SEC <= 0:
            return None
        saved_at, payload, token = entry
        if time.monotonic() - saved_at > APPLIANCE_PUT_REUSE_SEC:
            return None
        return copy.deepcopy(payload), token

    def _keep_put_reply(self, aid: str, response: requests.Response) -> None:
        """Keep a successful PUT reply for the next step, only when it is this appliance with a version.

        Without an id match or a version/ETag the reply cannot stand in for a
        GET (the next PUT would have no If-Match), so a GET happens as before.
        """
        if not hasattr(self, "_put_replies"):
            self._put_replies = {}
        self._put_replies.pop(aid, None)
        if APPLIANCE_PUT_REUSE_SEC <= 0:
            return
        try:
            payload = response.json()
        except ValueError:
            return
        if not isinstance(payload, dict) or str(payload.get("id") or "") != aid:
            return
        token = (response.headers.get("ETag") or "").strip()
        if not token:
            for key in ("version", "updated"):
                val = payload.get(key)
                if val not in (None, ""):
                    token = str(val)
                    break
        if token:
            self._put_replies[aid] = (time.monotonic(), payload, token)

    def note_rollback(self, aid: str, original: Dict[str, Any], allowed: tuple, what: str) -> None:
        """Keep the pre-PUT document in memory. The on-disk snapshot is redacted and cannot be PUT back."""
        self._rollback[str(aid)] = (copy.deepcopy(original), tuple(allowed), what)

    def restore_noted(self, aid: str) -> None:
        """PUT the saved slice onto a fresh GET so If-Match is current."""
        saved = self._rollback.get(str(aid))
        if not saved:
            raise AppliancePutError(f"No pre-PUT copy for {aid}")
        original, allowed, what = saved
        fresh = self._get_appliance(aid, fresh=True)
        body_src = copy.deepcopy(fresh)
        for path in allowed:
            _copy_saved_path(original, body_src, path)
        body = self._sanitize_appliance_for_put(body_src)
        self._assert_put_safe(fresh, body, allowed=allowed, what=what)
        self._put_appliance_body(body, what=what)

    def _remember_match(self, aid: str, response: requests.Response, payload: Dict[str, Any]) -> None:
        """A later PUT must send the GET version. Without it a parallel edit is overwritten."""
        token = (response.headers.get("ETag") or "").strip()
        if not token:
            for key in ("version", "updated"):
                val = payload.get(key)
                if val not in (None, ""):
                    token = str(val)
                    break
        self._appliance_match[str(aid)] = token

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
        """PUT the whole appliance with If-Match. No version token means no PUT. Error bodies are redacted, and common HTTP codes get a hint the operator can act on."""
        aid = body.get("id")
        if not aid:
            raise AppliancePutError(f"Refusing {what} PUT; appliance id missing")
        token = self._appliance_match.get(str(aid), "")
        if not token:
            raise AppliancePutError(
                f"Refusing {what} PUT; appliance GET did not include a version or ETag"
            )
        headers = dict(self.headers)
        headers["If-Match"] = token if token.startswith('"') or token.startswith("W/") else f'"{token}"'
        url = f"{self.base_url}/appliances/{aid}"
        put_response = _http().put(
            url,
            headers=headers,
            json=body,
            verify=self._verify(),
            timeout=API_TIMEOUT,
            allow_redirects=False,
        )
        if put_response.status_code == 200:
            self._keep_put_reply(str(aid), put_response)
        else:
            # A refused PUT may mean the copy is stale: the next step GETs again.
            getattr(self, "_put_replies", {}).pop(str(aid), None)
        if DEBUG and put_response.status_code == 200:
            # One line per successful appliance PUT, so v24 and v25 Controllers can be compared.
            match_kind = "ETag" if token.startswith(('"', "W/")) else "version"
            print(
                f"      DEBUG PUT ok peer v{self.api_version} {what} appliance={aid} If-Match={match_kind}",
                file=sys.stderr,
            )
        if put_response.status_code != 200:
            if DEBUG:
                print(f"      DEBUG {what} PUT HTTP {put_response.status_code}", file=sys.stderr)
                print(json.dumps(_redact_appliance_for_debug(body), indent=2, default=str), file=sys.stderr)
                # A 4xx body can echo the PUT document, so the same redaction as the normal error line applies.
                print(
                    _strip_controls(redact_preview(put_response.text or "", API_ERROR_BODY_PREVIEW)),
                    file=sys.stderr,
                )
            body_preview = _strip_controls(redact_preview(put_response.text or "", API_ERROR_BODY_PREVIEW))
            hint = ""
            text_l = (put_response.text or "").lower()
            if put_response.status_code in (409, 412):
                hint = " Hint: the appliance changed after the GET. Run the tool again."
            elif put_response.status_code == 422 and "portal.profiles" in text_l:
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

