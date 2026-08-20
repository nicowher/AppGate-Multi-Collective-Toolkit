"""Controller inventory: parse GET /appliances and prompt which boxes to skip.

SSH uses the 6.7 admin hostname/IP (management path), not a data-plane NIC.
"""
import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from config import APPLIANCE_FUNCTION_NAMES


@dataclass
class Target:
    """One appliance in the run. API calls use appliance_id; humans use label()."""
    appliance_id: str
    hostname: str
    ssh_fqdn: str = ""
    ssh_ip: str = ""
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

    def label(self) -> str:
        """Human handle: 1.hit-agg-011 (collective index + hostname)."""
        host = self.hostname or self.ssh_fqdn or self.ssh_ip or self.appliance_id
        return f"{self.collective}.{host}"

    def ssh_endpoints(self) -> List[str]:
        """FQDN first; configured collective IP if FQDN is NAT'd / not SSH-able.

        Controller boxes: credentials agip is the SSH fallback.
        Gateways: only FQDN (do not SSH the Controller IP by mistake).
        """
        out: List[str] = []
        if self.ssh_fqdn:
            out.append(self.ssh_fqdn)
        use_cfg_ip = bool(self.collective_ip) and (
            "controller" in self.functions
            or (
                self.collective_fqdn
                and self.ssh_fqdn
                and self.ssh_fqdn.lower() == self.collective_fqdn.lower()
            )
        )
        if use_cfg_ip and self.collective_ip not in out:
            out.append(self.collective_ip)
        if not out and self.ssh_ip:
            out.append(self.ssh_ip)
        return out


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


def appliance_health(appliance: Dict[str, Any], stats: Dict[str, Any]) -> str:
    """Best-effort health from GET /appliances/status (not the removed /stats/appliances)."""
    for key in ("status", "health"):
        value = stats.get(key) or appliance.get(key)
        if value:
            return str(value)
    if appliance.get("activated") is False:
        return "not active"
    return "unknown"


def _is_ip(value: str) -> bool:
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def appliance_hosts(appliance: Dict[str, Any]) -> Tuple[str, str]:
    """Return (fqdn, ip) from 6.7 admin/peer/client hostname, then NICs."""
    candidates: List[str] = []
    for block_name in ("adminInterface", "peerInterface", "clientInterface"):
        block = appliance.get(block_name) or {}
        if isinstance(block, dict):
            host = (block.get("hostname") or "").strip()
            if host:
                candidates.append(host)
    for key in ("hostname", "applianceHostname"):
        host = (appliance.get(key) or "").strip()
        if host:
            candidates.append(host)
    for nic in appliance.get("networking", {}).get("nics", []):
        for addr in nic.get("ipv4", {}).get("static", []):
            ip = (addr.get("address") or "").strip()
            if ip:
                candidates.append(ip)
        for addr in nic.get("ipv6", {}).get("static", []):
            ip = (addr.get("address") or "").strip()
            if ip:
                candidates.append(ip)
    fqdn = ""
    ip = ""
    for host in candidates:
        if _is_ip(host):
            if not ip:
                ip = host
        elif not fqdn:
            fqdn = host
    return fqdn, ip


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
            f"     {i:2d}  {t.collective:<10}  {t.hostname[:30]:<30}  {host:<22}  {funcs:<22}  {t.health}"
        )
    raw = input(
        "\n      Exclude (numbers, 1.hostname, hostnames, or IPs; Enter for all): "
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
