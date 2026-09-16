"""Appliance table model — not an API client.

HTTP lives in ``api/appgate.py`` (``list_targets``). This module holds the
``Target`` dataclass, health/function helpers, and the step-2 exclude prompt
shared by SNMP credentials and walk.


  Target.label()          → 1.hostname so two sites can share a hostname safely
  Target.ssh_endpoints()  → pinned working IP first (ssh_ok_host), then FQDN,
                            public IPv4, IPv6). Credentials agip only if this box
                            is the login Controller. Never peer-interface hostname
                            (that is another appliance).
  Target.walk_endpoints() → same order as ssh_endpoints().

Health from GET /appliances/status (6.7 labels). error is still configurable;
offline/not active/warning are skipped so we do not push to unreachable boxes.
"""
import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from config import APPLIANCE_FUNCTION_NAMES, HEALTH_STATUS_KEYS, INVENTORY_NAME_WIDTH


@dataclass
class Target:
    """One appliance in the run. API calls use appliance_id; humans use label()."""
    appliance_id: str
    hostname: str
    ssh_fqdn: str = ""
    ssh_ip: str = ""
    ssh_ips: List[str] = field(default_factory=list)
    collective: int = 1
    collective_fqdn: str = ""
    collective_ip: str = ""
    functions: List[str] = field(default_factory=list)
    health: str = "unknown"
    engine_id: str = ""
    auth_hash: str = ""
    priv_hash: str = ""
    status: str = "pending"
    error: str = ""
    walk_ok: Optional[bool] = None
    ssh_password_override: Optional[str] = None
    ssh_ok_host: str = ""

    def label(self) -> str:
        """Human handle: 1.ctrl-a (collective index + hostname)."""
        host = self.hostname or self.ssh_fqdn or self.ssh_ip or self.appliance_id
        return f"{self.collective}.{host}"

    def ssh_endpoints(self) -> List[str]:
        """This appliance's FQDN, then its IPs (private v4, public v4, v6).

        Credentials agip is only appended when this box is the login Controller.
        Trying every Controller's shared agip used to SSH the wrong appliance.
        """
        out: List[str] = []
        # print(f"DEBUG ssh_endpoints: pin={self.ssh_ok_host!r} fqdn={self.ssh_fqdn!r} ips={self.ssh_ips!r}")
        if self.ssh_ok_host:
            out.append(self.ssh_ok_host)
        if self.ssh_fqdn and self.ssh_fqdn not in out:
            out.append(self.ssh_fqdn)
        if self._owns_collective_ip() and self.collective_ip not in out:
            out.append(self.collective_ip)
        for ip in sorted(
            self.ssh_ips or ([self.ssh_ip] if self.ssh_ip else []),
            key=_ip_rank,
        ):
            if ip and ip not in out:
                out.append(ip)
        return out

    def _is_controller_box(self) -> bool:
        return "controller" in self.functions or (
            bool(self.collective_fqdn)
            and bool(self.ssh_fqdn)
            and self.ssh_fqdn.lower() == self.collective_fqdn.lower()
        )

    def _owns_collective_ip(self) -> bool:
        if not self.collective_ip or not self._is_controller_box():
            return False
        if self.ssh_fqdn and self.collective_fqdn:
            if self.ssh_fqdn.lower() == self.collective_fqdn.lower():
                return True
        return self.ssh_ip == self.collective_ip

    def walk_endpoints(self) -> List[str]:
        """Same order as ssh_endpoints(): FQDN first, then IP."""
        # print(f"DEBUG walk_endpoints: {self.ssh_endpoints()!r}")
        return self.ssh_endpoints()


def appliance_functions(appliance: Dict[str, Any]) -> List[str]:
    """Which 6.7 functions are enabled (controller, gateway, …)."""
    found = []
    for name in APPLIANCE_FUNCTION_NAMES:
        block = appliance.get(name)
        if block is True:
            found.append(name)
        elif isinstance(block, dict) and block.get("enabled"):
            found.append(name)
    return found


def _first_status_string(obj: Any, depth: int = 0) -> str:
    """Pull a human status string from nested /appliances/status JSON."""
    if depth > 4 or obj is None:
        return ""
    if isinstance(obj, str) and obj.strip():
        return obj.strip()
    if isinstance(obj, dict):
        # Prefer explicit health fields (6.7 UI: Healthy/Busy/Warning/Error/Offline).
        for key in HEALTH_STATUS_KEYS:
            value = obj.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, dict):
                nested = _first_status_string(value, depth + 1)
                if nested:
                    return nested
        for value in obj.values():
            if isinstance(value, (dict, list)):
                nested = _first_status_string(value, depth + 1)
                if nested:
                    return nested
    if isinstance(obj, list):
        for item in obj:
            nested = _first_status_string(item, depth + 1)
            if nested:
                return nested
    return ""


def appliance_health(appliance: Dict[str, Any], stats: Dict[str, Any]) -> str:
    """Map GET /appliances/status to Admin UI labels (6.7).

    Docs: Healthy, Busy, Warning, Error, Offline, Not Active.
    """
    for source in (stats, appliance):
        if not isinstance(source, dict):
            continue
        found = _first_status_string(source)
        if found:
            return _normalize_health_label(found)
    if appliance.get("activated") is False:
        return "not active"
    return "n/a"


def _normalize_health_label(raw: str) -> str:
    """Normalize API strings to short lowercase labels for the table."""
    text = raw.strip().lower().replace("_", " ")
    aliases = {
        "healthy": "healthy",
        "ok": "healthy",
        "up": "healthy",
        "busy": "busy",
        "warning": "warning",
        "warn": "warning",
        "error": "error",
        "unhealthy": "error",
        "offline": "offline",
        "down": "offline",
        "not active": "not active",
        "notactive": "not active",
        "inactive": "not active",
        "n/a": "n/a",
        "unknown": "n/a",
        "na": "n/a",
    }
    if text in aliases:
        return aliases[text]
    for key, label in aliases.items():
        if key in text:
            return label
    return text[:24]


def _is_ip(value: str) -> bool:
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _ip_rank(ip: str) -> int:
    text = ip.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return 9
    if addr.version == 4:
        return 0 if addr.is_private else 1
    return 2


def _nic_addresses(nic: Dict[str, Any]) -> List[str]:
    found: List[str] = []
    for family in ("ipv4", "ipv6"):
        block = nic.get(family) or {}
        if not isinstance(block, dict):
            continue
        for key in ("static", "dhcp", "addresses"):
            val = block.get(key)
            rows = val if isinstance(val, list) else [val] if val else []
            for addr in rows:
                if isinstance(addr, dict):
                    ip = (addr.get("address") or "").strip()
                else:
                    ip = str(addr or "").strip()
                if ip:
                    found.append(ip)
    return found


def _block_ips(block: Dict[str, Any]) -> List[str]:
    """IPs on admin/peer/client interface objects (not only NIC static)."""
    found: List[str] = []
    if not isinstance(block, dict):
        return found
    for key in ("ipv4", "ipv6", "address", "ip"):
        val = block.get(key)
        if isinstance(val, str) and val.strip():
            found.append(val.strip())
        elif isinstance(val, dict):
            ip = (val.get("address") or val.get("ip") or "").strip()
            if ip:
                found.append(ip)
            found.extend(_nic_addresses({"ipv4": val} if key == "ipv4" else {"ipv6": val}))
    return found


def appliance_hosts(appliance: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Return (this appliance's FQDN, its interface/NIC IPs).

    Hostname order: appliance hostname, admin, client. Peer hostname is the
    other box and is not used. IPs: RFC1918 IPv4, public IPv4, then IPv6.
    """
    names: List[str] = []
    ips: List[str] = []

    def add_ip(raw: str) -> None:
        ip = (raw or "").strip()
        if ip and _is_ip(ip) and ip not in ips:
            ips.append(ip)

    def add_name(raw: str) -> None:
        host = (raw or "").strip()
        if not host:
            return
        if _is_ip(host):
            add_ip(host)
            return
        if host not in names:
            names.append(host)

    for key in ("hostname", "applianceHostname"):
        add_name(appliance.get(key) or "")
    for block_name in ("adminInterface", "clientInterface"):
        block = appliance.get(block_name) or {}
        if isinstance(block, dict):
            add_name(block.get("hostname") or "")
            for ip in _block_ips(block):
                add_ip(ip)
    peer = appliance.get("peerInterface") or {}
    if isinstance(peer, dict):
        for ip in _block_ips(peer):
            add_ip(ip)
    for nic in appliance.get("networking", {}).get("nics", []) or []:
        if isinstance(nic, dict):
            for ip in _nic_addresses(nic):
                add_ip(ip)
    fqdn = next((h for h in names if "." in h), "")
    ips.sort(key=_ip_rank)
    return fqdn, ips


def is_selectable(health: str, skip_status: tuple) -> bool:
    return health.strip().lower() not in skip_status


def prompt_exclusions(targets: List[Target]) -> List[Target]:
    """Step 2: print the table; Enter keeps all.

    Tokens: row number, 1.hostname, unique hostname, SSH IP, or appliance UUID.
    A hostname that exists in two collectives only matches as N.hostname.
    """
    print(
        "\n      #  Collective  Hostname                        SSH IP              Functions              Health"
    )
    for i, t in enumerate(targets, 1):
        funcs = ",".join(t.functions) or "-"
        host = t.ssh_fqdn or t.ssh_ip
        print(
            f"     {i:2d}  {t.collective:<10}  {t.hostname[:INVENTORY_NAME_WIDTH]:<{INVENTORY_NAME_WIDTH}}  {host:<22}  {funcs:<22}  {t.health}"
        )
    raw = input(
        "\n      Exclude (comma-separated numbers, e.g. 1,3 or 1.hostname; Enter for all): "
    ).strip()
    if not raw:
        return list(targets)
    tokens = {part.strip().lower() for part in raw.split(",") if part.strip()}
    host_counts = Counter(t.hostname.lower() for t in targets)
    kept = []
    for i, t in enumerate(targets, 1):
        keys = {
            str(i),
            t.label().lower(),
            t.ssh_fqdn.lower(),
            t.ssh_ip.lower(),
            t.appliance_id.lower(),
        }
        if host_counts[t.hostname.lower()] == 1:
            keys.add(t.hostname.lower())
        if tokens & keys:
            print(f"      Excluding {t.label()}", flush=True)
            continue
        kept.append(t)
    return kept
