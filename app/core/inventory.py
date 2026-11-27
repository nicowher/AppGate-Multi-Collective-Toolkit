"""Appliance table model — not an API client.

HTTP lives in ``api/appgate.py`` (``list_targets``). This module holds the
``Target`` dataclass, health/function helpers, and the step-2 exclude prompt
shared by SNMP credentials and walk.

  Target.label()          → 1.hostname so two sites can share a hostname safely
  Target.ssh_endpoints()  → address found earlier this session, then admin
                            hostname, admin IP, then private IPv4 and IPv6
                            unique-local, public, link-local last. Credentials
                            agip only if this box is the login Controller. Never
                            peer-interface hostname (that is another appliance).
  Target.pin_ssh_host()   → remember the answering address in memory until the
                            toolkit exits. Not saved to disk.
  Target.walk_endpoints() → the session address once SSH found one; else ssh_endpoints().

Health from GET /appliances/status (6.7 labels). error is still configurable;
offline/not active/warning are skipped so we do not push to unreachable boxes.
"""
import ipaddress
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.utils import clean_for_terminal, format_scoped_ip, is_ip
from config import (
    APPLIANCE_FUNCTION_NAMES,
    HEALTH_STATUS_KEYS,
    HEALTH_STATUS_MAX_DEPTH,
    INVENTORY_ADDR_WIDTH,
    INVENTORY_NAME_WIDTH,
)
from core.utils import expand_exclude_tokens

# Working SSH address per appliance for this process only. Never written to disk:
# a NIC that answered yesterday may be gone, and the next launch should search again.
_SESSION_SSH_HOST: Dict[str, str] = {}


def mark_label_collisions(targets: List["Target"]) -> None:
    """Make every label unique within its collective, before anything keys on it.

    A shortened label can match another box (gw1 and gw1_example_com both show
    as 1.gw1), and exclude, report labels and backup file names use the label.
    Colliding boxes keep their full name; if even that matches, a short id
    prefix is added.
    """
    groups: Dict[str, List["Target"]] = {}
    for t in targets:
        groups.setdefault(t.label().lower(), []).append(t)
    for same in groups.values():
        if len(same) > 1:
            for t in same:
                t.label_full = True
    seen: Dict[str, List["Target"]] = {}
    for t in targets:
        seen.setdefault(t.label().lower(), []).append(t)
    for same in seen.values():
        if len(same) > 1:
            for t in same:
                t.label_suffix = "#" + (t.appliance_id or "")[:8]
    # print(f"DEBUG labels: {sum(1 for t in targets if t.label_full)} kept full names")


def _short_name(name: str, collective_fqdn: str) -> str:
    """Drop a trailing copy of the collective's domain from an appliance name, for display.

    Easy to misuse: two appliances whose names differ only by that suffix
    (gw1 and gw1_example_com) get the same label, so a label is not unique and
    must not be used as a key on its own (exclude, backup file names).
    """
    # print(f"DEBUG label: shorten {name!r} under {collective_fqdn!r}")
    domain = (collective_fqdn or "").split(".", 1)[1] if "." in (collective_fqdn or "") else ""
    if not domain or is_ip(collective_fqdn or ""):
        return name
    for suffix in ("." + domain, "_" + domain.replace(".", "_")):
        if len(name) > len(suffix) and name.lower().endswith(suffix.lower()):
            return name[: -len(suffix)]
    return name


# Box status values. One spelling everywhere: a typo in a bare string compared
# silently false, and the run flow, the counts line and the reports all key on these.
STATUS_PENDING = "pending"      # selected, not started (also: confirmed for the live run)
STATUS_PREVIEW = "preview"      # the preview says this box would change
STATUS_UNCHANGED = "unchanged"  # the preview says this box is already set
STATUS_OK = "ok"                # the live step finished on this box
STATUS_FAILED = "failed"        # this box failed; later steps skip it


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
    status: str = STATUS_PENDING
    error: str = ""
    walk_ok: Optional[bool] = None
    ssh_password_override: Optional[str] = None
    ssh_ok_host: str = ""
    self_ips: List[str] = field(default_factory=list)
    # Technical reason behind error, for reports. No secrets (step names, error kind).
    detail: str = ""
    # Set by mark_label_collisions when the short label would match another box
    # in this collective: the full name (and, if needed, an id prefix) is shown.
    label_full: bool = False
    label_suffix: str = ""
    # Error code (core.errors) of a failed box, shown on its Failed line and in reports.
    code: str = ""

    def label(self) -> str:
        """Human handle: 1.ctrl-a (collective index + hostname).

        An appliance name that ends in the collective's own domain (ctrl-a_example_com
        or ctrl-a.example.com under ctrl.example.com) loses that suffix: it repeats
        what the address column already shows and made every table wider. The full
        name still works at the exclude prompt.
        """
        host = self.hostname or self.ssh_fqdn or self.ssh_ip or self.appliance_id
        name = host if self.label_full else _short_name(host, self.collective_fqdn)
        return f"{self.collective}.{name}{self.label_suffix}"

    def __repr__(self) -> str:
        """Label, status and engine-ID length only: a repr in a traceback must not print hashes or addresses in full."""
        return (
            f"Target({self.label()!r}, status={self.status!r}, "
            f"engine_len={len(self.engine_id)})"
        )

    def _session_key(self) -> str:
        """Appliance ids are per Controller, so the Controller name is part of the key."""
        return f"{(self.collective_fqdn or self.collective_ip or self.collective)}|{self.appliance_id}"

    def pin_ssh_host(self, addr: str) -> None:
        """Remember the address that answered for the rest of this toolkit session.

        Memory only. Closing the toolkit forgets it, so a later launch searches
        the address list again instead of trusting a stale NIC.
        """
        if not addr:
            return
        self.ssh_ok_host = addr
        if self.appliance_id:
            _SESSION_SSH_HOST[self._session_key()] = addr

    def forget_ssh_host(self) -> None:
        """Every address failed. The next menu run starts the search from the top."""
        self.ssh_ok_host = ""
        _SESSION_SSH_HOST.pop(self._session_key(), None)

    def session_ssh_host(self) -> str:
        """Address an earlier menu run in this session already found, or empty."""
        return self.ssh_ok_host or _SESSION_SSH_HOST.get(self._session_key(), "")

    def ssh_endpoints(self) -> List[str]:
        """Addresses to try, best first. The first one that answers is pinned for the session.

        Order: the address already found this session, then the admin hostname,
        the admin IP, this box's own Controller agip (login Controller only),
        then the other NIC IPs: private IPv4 and IPv6 unique-local, public, and
        link-local last. Callers stop at the first address that answers, so a
        box with a good admin address costs one connection. The agip of another
        Controller is never added: a shared agip used to SSH the wrong appliance.
        """
        # print(f"DEBUG ssh_endpoints: pin={self.session_ssh_host()!r} admin={self.ssh_fqdn!r} ip={self.ssh_ip!r}")
        out: List[str] = []
        for addr in (self.session_ssh_host(), self.ssh_fqdn, self.ssh_ip):
            if addr and addr not in out:
                out.append(addr)
        if self._owns_collective_ip() and self.collective_ip not in out:
            out.append(self.collective_ip)
        for ip in sorted(self.ssh_ips, key=_ip_rank):
            if ip and ip not in out:
                out.append(ip)
        return out

    def _is_controller_box(self) -> bool:
        """Only the login Controller may be reached on the credentials agip. Any other box on that IP would be the wrong appliance."""
        return "controller" in self.functions or (
            bool(self.collective_fqdn)
            and bool(self.ssh_fqdn)
            and self.ssh_fqdn.lower() == self.collective_fqdn.lower()
        )

    def _owns_collective_ip(self) -> bool:
        """True only when the credentials agip belongs to this box, so that agip is never tried for another appliance."""
        if not self.collective_ip or not self._is_controller_box():
            return False
        if self.ssh_fqdn and self.collective_fqdn:
            if self.ssh_fqdn.lower() == self.collective_fqdn.lower():
                return True
        return self.ssh_ip == self.collective_ip

    def walk_endpoints(self) -> List[str]:
        """The address SSH found this session, if any. Otherwise the same list SSH would try."""
        # print(f"DEBUG walk_endpoints: pin={self.session_ssh_host()!r}")
        pinned = self.session_ssh_host()
        if pinned:
            return [pinned]
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
    """Pull appliance health only from HEALTH_STATUS_KEYS.

    Do not recurse into arbitrary nested dicts (disk/volume status would
    skip a healthy box via APPLIANCE_SKIP_STATUS).
    """
    if depth > HEALTH_STATUS_MAX_DEPTH or obj is None:
        return ""
    if isinstance(obj, str) and obj.strip():
        return obj.strip()
    if isinstance(obj, dict):
        for key in HEALTH_STATUS_KEYS:
            value = obj.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, dict):
                nested = _first_status_string(value, depth + 1)
                if nested:
                    return nested
        # print(f"DEBUG health: no HEALTH_STATUS_KEYS at depth={depth} keys={list(obj)}")
    return ""


def _status_item_health(item: Dict[str, Any]) -> str:
    """Health from one /appliances/status item, in the order the API defines it.

    AppGate's v24/v25 model has a top-level status and state, and the same two
    under details. A Controller can fill only details.status, so it is read
    before the internal state fields. Before this, a v25 box showed "n/a" and
    APPLIANCE_SKIP_STATUS could not skip an unhealthy one.
    """
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    # Order comes from HEALTH_STATUS_KEYS, each key at the top level and then under
    # details, so editing the setting changes this path too.
    for key in HEALTH_STATUS_KEYS:
        for src in (item, details):
            value = src.get(key)
            if isinstance(value, str) and value.strip():
                # print(f"DEBUG health: {key}={value!r} from {'details' if src is details else 'item'}")
                return value.strip()
    return ""


def appliance_health(appliance: Dict[str, Any], stats: Dict[str, Any]) -> str:
    """Map GET /appliances/status to Admin UI labels (6.7).

    Docs: Healthy, Busy, Warning, Error, Offline, Not Active.
    """
    if isinstance(stats, dict):
        found = _status_item_health(stats)
        if found:
            return _normalize_health_label(found)
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
    """Only the full label matches. A prefix of ok would leave a down box in the apply set."""
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
    # print(f"DEBUG health: raw={raw!r} label={text!r}")
    return text[:24]


def _canon_ip(raw: str) -> str:
    """Compare peer and NIC addresses as the same IP. A link-local zone stays, or two scopes look like one address."""
    return format_scoped_ip(raw)


def _ip_rank(ip: str) -> int:
    """Private IPv4 and IPv6 unique-local before public addresses. Link-local is last so a scoped address is not preferred."""
    text = ip.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return 9
    if addr.is_link_local:
        return 2
    if addr.is_private:
        return 0
    return 1


def _nic_addresses(nic: Dict[str, Any]) -> List[str]:
    """IPs from one networking.nics entry (static, dhcp, or addresses under ipv4 and ipv6). A non-dict family block is skipped."""
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


def appliance_ssh_host(appliance: Dict[str, Any]) -> str:
    """Admin interface only. A port-22 probe of the other NICs is what fills SSHBRUTE."""
    admin = appliance.get("adminInterface") or {}
    if isinstance(admin, dict):
        host = (admin.get("hostname") or "").strip()
        if host and "." in host and not is_ip(host):
            return host
        for ip in _block_ips(admin):
            if ip:
                return format_scoped_ip(ip)
    fqdn, ips = appliance_hosts(appliance)
    return fqdn or (ips[0] if ips else "")


def appliance_admin_ip(appliance: Dict[str, Any]) -> str:
    """First admin-interface IP. It is tried right after the admin hostname, before the other NICs."""
    admin = appliance.get("adminInterface") or {}
    if not isinstance(admin, dict):
        return ""
    for ip in _block_ips(admin):
        text = format_scoped_ip(ip)
        if text and is_ip(text):
            return text
    return ""


def appliance_hosts(appliance: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Return (this appliance's FQDN, its interface/NIC IPs).

    Hostname order: appliance hostname, admin, client. The peer hostname is the
    other box and is not used. A peer address is kept only when this box already
    has that address on an admin, client, or NIC entry. Private IPv4 and IPv6
    unique-local are tried before public addresses of either family. Link-local
    is last. A link-local zone is kept.

    Expects the 6.x GET shape: ``networking`` a dict and hostnames strings. A
    null or list ``networking`` raises here, and list_targets then drops every
    appliance of that Controller, not just this one.
    """
    # print(f"DEBUG appliance_hosts: networking={type(appliance.get('networking')).__name__} hostname={type(appliance.get('hostname')).__name__}")
    names: List[str] = []
    ips: List[str] = []

    def add_ip(raw: str) -> None:
        """Keep one canonical copy of each IP, so the address search does not probe the same NIC twice."""
        ip = format_scoped_ip(raw)
        if ip and is_ip(ip) and ip not in ips:
            ips.append(ip)

    def add_name(raw: str) -> None:
        """Keep each hostname once, in the order found, so the preferred SSH name is tried first."""
        host = (raw or "").strip()
        if not host:
            return
        if is_ip(host):
            add_ip(host)
            return
        if host not in names:
            names.append(host)

    for key in ("hostname", "applianceHostname"):
        add_name(appliance.get(key) or "")
    own = set()
    for block_name in ("adminInterface", "clientInterface"):
        block = appliance.get(block_name) or {}
        if isinstance(block, dict):
            add_name(block.get("hostname") or "")
            for ip in _block_ips(block):
                add_ip(ip)
                own.add(_canon_ip(ip))
    for nic in appliance.get("networking", {}).get("nics", []) or []:
        if isinstance(nic, dict):
            for ip in _nic_addresses(nic):
                add_ip(ip)
                own.add(_canon_ip(ip))
    peer = appliance.get("peerInterface") or {}
    if isinstance(peer, dict):
        for ip in _block_ips(peer):
            if _canon_ip(ip) in own:
                add_ip(ip)
    fqdn = next((h for h in names if "." in h), "")
    ips.sort(key=_ip_rank)
    return fqdn, ips


def is_selectable(health: str, skip_status: tuple) -> bool:
    """Skip list is exact. A suffix match would treat a down box as selectable."""
    return health.strip().lower() not in skip_status


def status_self_ips(status: Any) -> List[str]:
    """IPs from GET /appliances/status details.network.details.<nic>.ips."""
    found: List[str] = []
    if not isinstance(status, dict):
        return found
    details = status.get("details")
    net = details.get("network") if isinstance(details, dict) else None
    if not isinstance(net, dict):
        net = status.get("network") if isinstance(status.get("network"), dict) else {}
    extra = net.get("details") if isinstance(net, dict) else None
    if not isinstance(extra, dict):
        return found
    for info in extra.values():
        if not isinstance(info, dict):
            continue
        for ip in info.get("ips") or []:
            text = str(ip or "").strip()
            if text and text not in found:
                found.append(text)
    return found


def _display(text: str) -> str:
    """Controller text for the inventory table, cleaned the same way as every other console string."""
    return clean_for_terminal(text)


def prompt_exclusions(targets: List[Target]) -> List[Target]:
    """Step 2: print the table; Enter keeps all.

    Tokens: row number, ranges (1-10,12-20), 1.hostname, unique hostname,
    SSH IP, or appliance UUID. A hostname in two collectives only matches
    as N.hostname.
    """
    # Hostnames are cleaned in list_targets. The address column is cleaned here for
    # display only, so a control or bidi character cannot reach the terminal while
    # SSH still uses the address as the Controller gave it.
    # Header and rows share one set of widths, so a long FQDN cannot push
    # Functions and Health out from under their headings.
    rows = []
    for i, t in enumerate(targets, 1):
        funcs = ",".join(t.functions) or "-"
        addr = _display(t.ssh_fqdn or t.ssh_ip or "-")
        # Health comes from the Controller too, so it is cleaned like the name and address.
        # print(f"DEBUG table: health={t.health!r}")
        health = "—" if (t.health or "").strip().lower() in ("n/a", "na", "unknown", "") else _display(t.health)
        rows.append((str(i), str(t.collective), t.hostname[:INVENTORY_NAME_WIDTH], addr, funcs, health))
    heads = ("#", "Collective", "Hostname", "SSH address", "Functions", "Health")
    widths = [max([len(h)] + [len(r[c]) for r in rows]) for c, h in enumerate(heads)]
    widths[3] = min(widths[3], INVENTORY_ADDR_WIDTH)
    # print(f"DEBUG table: widths={widths!r}")

    def _line(cells) -> str:
        """Pad each cell to the header widths so rows and header line up; a long address is cut with an ellipsis instead of shifting the health column."""
        out = [cells[0].rjust(widths[0])]
        for c in range(1, 5):
            text = cells[c]
            if c == 3 and len(text) > widths[3]:
                text = text[: widths[3] - 1] + "…"
            out.append(text.ljust(widths[c]))
        out.append(cells[5])
        return "      " + "  ".join(out)

    print("\n" + _line(heads))
    for row in rows:
        print(_line(row))
    host_counts = Counter(t.hostname.lower() for t in targets)

    def _row_keys(i: int, t: Target) -> set:
        """Every name an operator might type for this row (number, label, FQDN, IP, id), so exclude accepts any of them."""
        keys = {
            str(i),
            t.label().lower(),
            t.ssh_fqdn.lower(),
            t.ssh_ip.lower(),
            t.appliance_id.lower(),
        }
        # The full appliance name as N.name, because the label may show a shorter one.
        if t.hostname:
            keys.add(f"{t.collective}.{t.hostname}".lower())
        # A hostname two collectives share is not a key; it must be typed as N.hostname.
        if host_counts[t.hostname.lower()] == 1:
            keys.add(t.hostname.lower())
        keys.discard("")
        return keys

    row_keys = [(t, _row_keys(i, t)) for i, t in enumerate(targets, 1)]
    all_keys = set().union(*(k for _t, k in row_keys)) if row_keys else set()
    while True:
        raw = input(
            "\n      Exclude (e.g. 1,3 or 1-10,12-20 or 1.hostname; Enter for all): "
        ).strip()
        # print(f"DEBUG exclude: raw={raw!r}")
        if not raw:
            return list(targets)
        try:
            tokens = expand_exclude_tokens(raw)
        except ValueError as exc:
            # print("DEBUG exclude: incomplete range")
            print(f"      {exc}", file=sys.stderr)
            continue
        if not tokens:
            # Only commas or spaces: not the same as Enter, so ask rather than run on every box.
            print("      Nothing to exclude was entered. Press Enter to keep all, or list rows.", file=sys.stderr)
            continue
        # Each comma part must hit at least one row. A range counts if any number in
        # it does (1-100 on 4 rows still means rows 1-4). Otherwise a typo, a number
        # past the last row, or a shared hostname was silently ignored and the box
        # the operator meant to skip was changed.
        unmatched = [
            part.strip() for part in raw.split(",")
            if part.strip() and not (expand_exclude_tokens(part) & all_keys)
        ]
        # print(f"DEBUG exclude: tokens={sorted(tokens)[:20]!r} unmatched={unmatched!r}")
        if not unmatched:
            break
        shared = [u for u in unmatched if host_counts.get(u.lower(), 0) > 1]
        print(f"      No appliance matches: {', '.join(_display(u) for u in unmatched)}", file=sys.stderr)
        if shared:
            print(
                f"      {', '.join(_display(u) for u in shared)} is in more than one collective; "
                "use N.hostname (for example 1.hostname).",
                file=sys.stderr,
            )
        print("      Nothing was excluded. Enter the list again.", file=sys.stderr)
    kept = []
    for t, keys in row_keys:
        if tokens & keys:
            print(f"      Excluding {t.label()}", flush=True)
            continue
        kept.append(t)
    return kept
