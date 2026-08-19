"""Controller inventory: parse GET /appliances and prompt which boxes to skip.

SSH uses the 6.7 admin hostname/IP (management path), not a data-plane NIC.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Target:
    appliance_id: str
    hostname: str
    ssh_ip: str
    functions: List[str] = field(default_factory=list)
    health: str = "unknown"
    engine_id: str = ""
    auth_hash: str = ""
    priv_hash: str = ""
    status: str = "pending"
    error: str = ""
    walk_ok: Optional[bool] = None

    def label(self) -> str:
        return self.hostname or self.ssh_ip or self.appliance_id


def appliance_functions(appliance: Dict[str, Any]) -> List[str]:
    names = (
        "controller",
        "gateway",
        "logServer",
        "logForwarder",
        "portal",
        "connector",
        "metricsAggregator",
        "connectionBroker",
    )
    found = []
    for name in names:
        block = appliance.get(name)
        if block is True:
            found.append(name)
        elif isinstance(block, dict) and block.get("enabled"):
            found.append(name)
    return found


def appliance_health(appliance: Dict[str, Any], stats: Dict[str, Any]) -> str:
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
    """Print numbered inventory; user types numbers, hostnames, or IPs to drop."""
    print("\n      #  Hostname                        SSH IP              Functions              Health")
    for i, t in enumerate(targets, 1):
        funcs = ",".join(t.functions) or "-"
        print(
            f"     {i:2d}  {t.hostname[:30]:<30}  {t.ssh_ip:<18}  {funcs:<22}  {t.health}"
        )
    raw = input(
        "\n      Exclude (numbers, hostnames, or IPs, comma-separated; Enter for all): "
    ).strip()
    if not raw:
        return list(targets)
    tokens = {part.strip().lower() for part in raw.split(",") if part.strip()}
    kept = []
    for i, t in enumerate(targets, 1):
        keys = {str(i), t.hostname.lower(), t.ssh_ip.lower(), t.appliance_id.lower()}
        if tokens & keys:
            print(f"      Excluding {t.label()}", flush=True)
            continue
        kept.append(t)
    return kept
