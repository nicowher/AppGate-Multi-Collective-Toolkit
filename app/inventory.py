"""Controller inventory: parse GET /appliances and prompt which boxes to skip.

SSH uses the 6.7 admin hostname/IP (management path), not a data-plane NIC.
"""
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from config import APPLIANCE_FUNCTION_NAMES


@dataclass
class Target:
    """One appliance in the run. API calls use appliance_id; humans use label()."""
    appliance_id: str
    hostname: str
    ssh_ip: str
    collective: int = 1
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
        host = self.hostname or self.ssh_ip or self.appliance_id
        return f"{self.collective}.{host}"


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
    """Best-effort health string. unknown is selectable (stats API is often 403)."""
    for key in ("status", "health"):
        value = stats.get(key) or appliance.get(key)
        if value:
            return str(value)
    if appliance.get("activated") is False:
        return "not active"
    return "unknown"


def appliance_ssh_ip(appliance: Dict[str, Any]) -> str:
    """6.7 admin / Appliance Hostname/IP — management path, not a random NIC."""
    for block_name in ("adminInterface", "peerInterface", "clientInterface"):
        block = appliance.get(block_name) or {}
        if isinstance(block, dict):
            host = (block.get("hostname") or "").strip()
            if host:
                return host
    for key in ("hostname", "applianceHostname"):
        host = (appliance.get(key) or "").strip()
        if host:
            return host
    for nic in appliance.get("networking", {}).get("nics", []):
        for addr in nic.get("ipv4", {}).get("static", []):
            ip = (addr.get("address") or "").strip()
            if ip:
                return ip
    return ""


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
        print(
            f"     {i:2d}  {t.collective:<10}  {t.hostname[:30]:<30}  {t.ssh_ip:<18}  {funcs:<22}  {t.health}"
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
