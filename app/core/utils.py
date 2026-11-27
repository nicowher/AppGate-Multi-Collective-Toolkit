"""Shared helpers for credentials, host validation, pip, and reports.

Lives in ``core/`` so ``app/`` stays menu + config + folders. ``APP_DIR`` is
the parent of this package (``app/``), not ``app/core/``.

  is_valid_host / prompt_until_valid
      Step 0 prompts: IPv4/IPv6/FQDN and re-ask on bad input.

  load_credentials
      Read optional credentials.json next to the OS launcher (repo root).
      Missing or invalid files become {} so prompts still work.
      collectives[] is kept as a list of objects (not stringified).

  vendor site / wheels / ensure_package
      Unpacked wheels in app/vendor/site are appended to sys.path. Installs
      use vendor/requirements.txt hashes and --target vendor/site. An empty
      site extracts a wheel only when its hash is in that pin. Menu U
      reinstalls that pin. It does not take a newer PyPI release.
"""
import hashlib
import unicodedata
import importlib.util
import ipaddress
import json
import os
import re
import socket
import time
import subprocess
import sys
import threading
import zipfile
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from getpass import getpass
from typing import Any, Callable, Dict, Optional

from core.fileperm import FilePermError, require_private_file
from config import (
    APPLIANCE_LIST_MAX,
    DEBUG,
    PIP_INSTALL_TIMEOUT,
    PIP_UPGRADE_TIMEOUT,
    REPORT_FILE_MODE,
    REPORTS_DIRNAME,
    VENDOR_DOWNLOAD_TIMEOUT,
    WRITE_RUN_REPORT,
    YES_ANSWERS,
)

# FQDN: labels of letters/digits/hyphen, at least one dot, TLD 2+ letters.
_FQDN_RE = re.compile(
    r"(?i)^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def debug_log(msg: str) -> None:
    """Full diagnostic line when DEBUG=True. No-op when DEBUG is off."""
    if DEBUG:
        print(f"      DEBUG {msg}", file=sys.stderr)


def print_error(code: str, message: str, *hints: str) -> None:
    """Always-on (DEBUG off too). code is a key of core.errors.CODES; hints are next steps.

    With no hint of its own, the registry's default next step is printed, so every
    code tells the operator what to try. An unregistered code still prints (never
    hide an error), and tests/test_error_codes.py fails on it.
    """
    from core.color import fail
    from core.errors import default_hint

    print(f"{fail('ERROR', stream=sys.stderr)} {code}: {message}", file=sys.stderr)
    shown = [h for h in hints if h] or [default_hint(code)]
    for hint in shown:
        if hint:
            print(f"      Next: {hint}", file=sys.stderr)


class HaltError(Exception):
    """Already printed as ERROR E0x. Tool __main__ should exit without reprinting.

    Deliberately not a ValueError: input-parsing code catches ValueError, and a
    stop raised inside such a block used to be caught and reported a second
    time with the wrong message. Catch HaltError by name.
    """


def print_unexpected_error(exc: BaseException) -> None:
    """An error no step expected: one plain line, and with DEBUG the traceback too.

    The message alone rarely says which file or line failed. The traceback goes
    through redact_preview, so a secret quoted in an exception text is hidden
    the same way it is in error replies. Read DEBUG at call time (menu C).
    """
    import config as _config

    print(f"\nError: {clean_for_terminal(redact_preview(str(exc), 500))}", file=sys.stderr)
    if getattr(_config, "DEBUG", False):
        import traceback

        text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        print("      DEBUG traceback:", file=sys.stderr)
        print(clean_for_terminal(redact_preview(text, 20000), keep_newlines=True), file=sys.stderr)


def make_output_safe() -> None:
    """Never crash on a character the console or log file cannot show.

    With output redirected or piped on Windows, Python writes in the ANSI code
    page (cp1252), and one character outside it (an appliance name, a Controller
    reply) raised UnicodeEncodeError in the middle of a run. The encoding is kept;
    such a character is written as a backslash escape instead.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            # Not a text stream that can be reconfigured (a test capture, a wrapper).
            pass


def run_tool(main_fn: Callable[[], None]) -> None:
    """Run one tool started on its own (python tools/x.py), the same way for every tool.

    One place for what every tool's __main__ used to repeat, with small
    differences: safe output, Ctrl+C as a plain cancel, a halt already
    printed, and an unexpected error printed with the DEBUG traceback. SystemExit
    from the tool keeps its own code.
    """
    make_output_safe()
    try:
        main_fn()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except HaltError:
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 - the last stop before a raw traceback
        print_unexpected_error(exc)
        sys.exit(1)


def halt(code: str, message: str, *hints: str) -> None:
    """Print ERROR code and stop this tool."""
    debug_log(f"halt: {code} {message}")
    print_error(code, message, *hints)
    raise HaltError(f"{code}: {message}")


def expand_exclude_tokens(raw: str) -> set:
    """Comma-separated exclude tokens. ``1-10,12-20`` expands to those row numbers.

    A control character or a format character is rejected so a wrapped or reversed line cannot look like a range and stay one token. Both sides numeric expands. A name with a digit on only one side stays one
    token so it can be excluded. An empty side is still a bad range. The width
    check is last minus first, so a span of APPLIANCE_LIST_MAX is still accepted.
    """
    tokens = set()
    for part in raw.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if any(ord(ch) < 32 or ord(ch) == 127 or unicodedata.category(ch) == "Cf" for ch in part):
            raise ValueError("Exclude token contains a control or format character.")
        if part.isascii() and part.isdigit():
            # Row and collective numbers compare as numbers, so 01 is row 1.
            tokens.add(str(int(part)))
            continue
        # print(f"DEBUG exclude: part={part!r}")
        if "-" in part:
            left, _, right = part.partition("-")
            left, right = left.strip(), right.strip()
            if (left.isdigit() and not right) or (right.isdigit() and not left):
                raise ValueError(
                    f"Exclude range {part!r} is incomplete. Use 1-3 or a single number."
                )
            if left.isdigit() and right.isdigit():
                start, end = int(left), int(right)
                if start > end:
                    start, end = end, start
                if end - start > APPLIANCE_LIST_MAX:
                    raise ValueError(
                        f"Exclude range {start}-{end} is wider than {APPLIANCE_LIST_MAX}."
                    )
                tokens.update(str(n) for n in range(start, end + 1))
                # print(f"DEBUG exclude: span={end - start}")
                continue
        tokens.add(part)
    # print(f"DEBUG exclude: raw={raw!r} tokens={sorted(tokens)[:20]!r} n={len(tokens)}")
    return tokens


def normalize_allow_source(entry: Any) -> Dict[str, Any]:
    """One check for the preview merge and the PUT. A bad nic must fail here so it is not sent.

    netmask must be a whole number or a string of digits. int() alone accepted a
    JSON true (1) and cut a decimal (2.4 -> 2), so a typo became a very wide prefix.
    """
    if not isinstance(entry, dict):
        raise ValueError("allowSources row must be an object")
    raw_mask = entry.get("netmask")
    # print(f"DEBUG allow: netmask type={type(raw_mask).__name__}")
    if isinstance(raw_mask, bool) or not (
        isinstance(raw_mask, int) or (isinstance(raw_mask, str) and raw_mask.strip().isdigit() and raw_mask.strip().isascii())
    ):
        raise ValueError("allowSources netmask must be a whole number (for example 24)")
    mask = int(str(raw_mask).strip())
    address = format_scoped_ip(str(entry.get("address") or ""))
    host = address.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("allowSources address or netmask is invalid") from None
    ceiling = 32 if parsed.version == 4 else 128
    if mask < 1 or mask > ceiling:
        raise ValueError(f"allowSources prefix {mask} is not allowed")
    out = {
        "address": address if parsed.is_link_local and "%" in address else str(parsed),
        "netmask": mask,
    }
    nic = str(entry.get("nic") or "").strip()
    if nic:
        # print(f"DEBUG allow: nic len={len(nic)}")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", nic):
            raise ValueError("allowSources nic is not an interface name")
        out["nic"] = nic
    return out


def format_scoped_ip(raw: str) -> str:
    """Keep a zone only on a link-local address. A global address must not carry one."""
    text = (raw or "").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    host, sep, zone = text.partition("%")
    host, zone = host.strip(), zone.strip()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return text
    if ip.is_link_local and sep and zone:
        return f"{ip}%{zone}"
    return str(ip)


def is_ip(value: str) -> bool:
    """True for an IPv4 or IPv6 address, with or without [brackets] or a link-local %zone.

    The one IP test for the toolkit. Separate copies disagreed on zones, so
    fe80::1%eth0 was an address in one module and a hostname in another.
    """
    text = (value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ipaddress.ip_address(text.split("%", 1)[0])
        return True
    except ValueError:
        return False


# Whole escape sequences (CSI and OSC) are removed before single control bytes,
# so "[2J" is not left behind as text.
_TERM_SEQ = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?")


def clean_for_terminal(text: str, keep_newlines: bool = False) -> str:
    """Remove escape sequences, control bytes, C1 controls and format characters (bidi, zero-width).

    Every Controller-sourced string printed to the console goes through here:
    names, addresses and health in the table, and API error bodies. One cleaner
    keeps them from drifting apart. keep_newlines keeps tab and LF for multi-line
    error text.
    """
    keep = ("\n", "\t") if keep_newlines else ()
    return "".join(
        ch for ch in _TERM_SEQ.sub("", text or "")
        if ch in keep or not (ord(ch) < 32 or 0x7F <= ord(ch) < 0xA0 or unicodedata.category(ch) == "Cf")
    )


def resolve_with_timeout(host: str, port, timeout: float, family: int = 0, socktype: int = 0) -> Optional[list]:
    """getaddrinfo with a time limit. None when the name does not resolve in time.

    getaddrinfo cannot be cancelled, so it runs in a daemon thread: a lookup that
    outlives the timeout finishes in the background and does not hold up the
    toolkit's exit (an executor thread would be joined at interpreter exit).
    """
    box: Dict[str, Any] = {}

    def _lookup() -> None:
        """Runs in a daemon thread so a stuck resolver cannot block the caller past its timeout or delay exit."""
        try:
            box["result"] = socket.getaddrinfo(host, port, family, socktype)
        except (OSError, ValueError, UnicodeError) as exc:
            box["error"] = exc

    worker = threading.Thread(target=_lookup, name="dns-lookup", daemon=True)
    worker.start()
    worker.join(timeout)
    # print(f"DEBUG dns: {host!r} done={not worker.is_alive()} ok={'result' in box}")
    if worker.is_alive() or "result" not in box:
        return None
    return box["result"]


def is_valid_host(value: str) -> bool:
    """True if value is IPv4, IPv6 (optional brackets), or an FQDN."""
    text = (value or "").strip()
    if not text:
        return False
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return bool(_FQDN_RE.fullmatch(text))


def ntp_key_error(host: str, key_type: str, key_no: str, key: str) -> str:
    """Why one NTP row's key settings would be refused, or "" when they are fine.

    One rule set for the file load, the typed prompt and the PUT. Before, each
    place had part of it, so a file row with an unknown or weak keyType, or a key
    with no keyNo, was refused only during the live push, after earlier boxes
    were changed (and they were rolled back).
    - keyType must be a known type (SHA512, SHA384, SHA256, with or without a
      dash; SHA2 means SHA256). MD5 and SHA1 are refused unless LAB_MODE is on.
      SHA384 needs a v25 Controller; that is checked at PUT time, where the
      Controller's API version is known.
    - A key needs a keyType (unless LAB_MODE) and a keyNo, or chrony cannot use it.
    The key value itself is never part of the message.
    """
    import config as _config  # read at call time so a menu C change applies

    lab = bool(getattr(_config, "LAB_MODE", False))
    key_type = (key_type or "").strip()
    if key_type:
        compact = key_type.replace("-", "").upper()
        mapped = _config.NTP_KEY_TYPE_MAP.get(compact)
        if mapped is None:
            return f"NTP keyType {key_type!r} for {host} is not a known type (use SHA512, SHA384 or SHA256)"
        if str(mapped).upper() in _config.NTP_WEAK_KEY_TYPES and not lab:
            return f"NTP keyType {mapped} for {host} is not allowed (DISA/CNSA: use SHA512 or SHA384)"
    if key:
        if not key_type and not lab:
            return f"NTP key for {host} has no keyType (use SHA512 or SHA384)"
        if not (key_no or "").strip():
            return f"NTP key for {host} has no keyNo; chrony needs the key number"
    # print(f"DEBUG ntp key check: {host} type={key_type!r} keyNo={key_no!r} has_key={bool(key)}")
    return ""


# This file lives in app/core/; vendor/ and launchers stay under app/ and repo root.
CORE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.dirname(CORE_DIR)
REPO_ROOT = os.path.dirname(APP_DIR)
VENDOR_DIR = os.path.join(APP_DIR, "vendor")
VENDOR_WHEELS = os.path.join(VENDOR_DIR, "wheels")
VENDOR_SITE = os.path.join(VENDOR_DIR, "site")
VENDOR_REQUIREMENTS = os.path.join(VENDOR_DIR, "requirements.txt")


def install_machine_id() -> str:
    """One UUID per install. A shared constant cannot be revoked for one workstation."""
    import uuid

    folder = os.path.join(REPO_ROOT, "certs")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    path = os.path.join(folder, ".machine-id")
    if os.path.isfile(path):
        text = open(path, encoding="utf-8").read().strip()
        try:
            return str(uuid.UUID(text))
        except ValueError:
            pass
    value = str(uuid.uuid4())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (value + "\n").encode("ascii"))
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(path, 0o600)
    # print(f"DEBUG machine-id: path={path!r} new={not os.path.isfile(path)}")
    return value


def _norm_dist(name: str) -> str:
    """Wheel names and pin names use different separators for the same package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _wheel_name_version(filename: str) -> tuple:
    """Distribution name and version from a wheel file name, so an extract can be matched against the pinned hashes."""
    base = filename[:-4] if filename.lower().endswith(".whl") else filename
    parts = base.split("-")
    for i, part in enumerate(parts):
        if i and part[:1].isdigit():
            return _norm_dist("-".join(parts[:i])), part
    return "", ""


def _pinned_wheels() -> Dict[tuple, set]:
    """Refuse extract when the pin file is missing. A swapped wheel must not become importable."""
    if not os.path.isfile(VENDOR_REQUIREMENTS):
        raise ValueError("Refusing wheel extract; pin file is missing")
    pins: Dict[tuple, set] = {}
    current = None
    with open(VENDOR_REQUIREMENTS, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip().rstrip("\\").strip()
            if not line:
                continue
            if "==" in line and not line.startswith("--"):
                name, _, ver = line.partition("==")
                current = (_norm_dist(name), ver.strip())
                pins.setdefault(current, set())
            elif line.startswith("--hash=sha256:") and current:
                pins[current].add(line.split("sha256:", 1)[1].strip().lower())
    return pins


def _file_sha256(path: str) -> str:
    """Hash a wheel in chunks to compare with the pin before it is unpacked."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_wheel(wheel_path: str, dest: str) -> None:
    """A .. member can write outside vendor/site. Refuse the wheel before any extract."""
    root = os.path.realpath(dest)
    os.makedirs(root, exist_ok=True)
    with zipfile.ZipFile(wheel_path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
                raise ValueError(f"Refusing absolute wheel member: {info.filename}")
            target = os.path.realpath(os.path.join(root, info.filename))
            if target != root and not target.startswith(root + os.sep):
                raise ValueError(f"Refusing wheel member outside {dest}: {info.filename}")
        zf.extractall(root)


def ensure_vendor_site() -> None:
    """Put unpacked wheels on sys.path before imports. An empty site extracts a wheel only after its hash matches the pin."""
    if os.path.isdir(VENDOR_WHEELS) and (
        not os.path.isdir(VENDOR_SITE) or not any(os.scandir(VENDOR_SITE))
    ):
        os.makedirs(VENDOR_SITE, exist_ok=True)
        pins = _pinned_wheels()
        for name in os.listdir(VENDOR_WHEELS):
            if not name.endswith(".whl"):
                continue
            ident = _wheel_name_version(name)
            allowed = pins.get(ident) or set()
            path = os.path.join(VENDOR_WHEELS, name)
            # print(f"DEBUG wheel: name={name!r} pinned={bool(allowed)}")
            if not allowed or _file_sha256(path) not in allowed:
                raise ValueError(f"Refusing wheel not in the pin: {name}")
            _extract_wheel(path, VENDOR_SITE)
    if os.path.isdir(VENDOR_SITE) and VENDOR_SITE not in sys.path:
        sys.path.append(VENDOR_SITE)


ensure_vendor_site()


def vendor_has_wheels() -> bool:
    """True when menu D has already fetched wheels, so an air-gapped host can install without network."""
    return os.path.isdir(VENDOR_WHEELS) and any(
        name.endswith((".whl", ".tar.gz", ".zip"))
        for name in os.listdir(VENDOR_WHEELS)
    )


def _pip_pinned(extra: list, timeout: int) -> None:
    """Install only the saved hashes, into vendor/site, not the system interpreter."""
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--no-deps",
            "-r",
            VENDOR_REQUIREMENTS,
            "--target",
            VENDOR_SITE,
            *extra,
        ],
        check=True,
        timeout=timeout,
    )


def install_from_vendor(package: str) -> bool:
    """Install the pinned set from vendor/wheels. A bare name is not accepted."""
    if not vendor_has_wheels():
        return False
    print(f"      Installing pinned deps for {package} from vendor/wheels ...", file=sys.stderr)
    try:
        os.makedirs(VENDOR_SITE, exist_ok=True)
        _pip_pinned(
            ["--no-index", "--find-links", VENDOR_WHEELS],
            PIP_INSTALL_TIMEOUT,
        )
        if VENDOR_SITE not in sys.path:
            sys.path.append(VENDOR_SITE)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"      vendor install of {package} failed: {exc}", file=sys.stderr)
        return False


def download_vendor_wheels() -> None:
    """Fetch wheels for VENDOR_PACKAGES into vendor/wheels (needs network), then unpack to site."""
    os.makedirs(VENDOR_WHEELS, exist_ok=True)
    print(f"Downloading pinned deps into {VENDOR_WHEELS} ...", file=sys.stderr)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--require-hashes",
            "-r",
            VENDOR_REQUIREMENTS,
            "-d",
            VENDOR_WHEELS,
        ],
        check=True,
        timeout=VENDOR_DOWNLOAD_TIMEOUT,
    )
    os.makedirs(VENDOR_SITE, exist_ok=True)
    for name in os.listdir(VENDOR_WHEELS):
        if name.endswith(".whl"):
            _extract_wheel(os.path.join(VENDOR_WHEELS, name), VENDOR_SITE)
    ensure_vendor_site()
    print(f"Unpacked wheels into {VENDOR_SITE}", file=sys.stderr)


def upgrade_vendor_packages() -> None:
    """Reinstall the pinned set into vendor/site. A newer PyPI release is refused."""
    print("Reinstalling the pinned vendor set into vendor/site ...", file=sys.stderr)
    os.makedirs(VENDOR_SITE, exist_ok=True)
    _pip_pinned([], PIP_UPGRADE_TIMEOUT)


def ensure_package(package: str, import_name: str) -> None:
    """Load a missing dependency from vendor/site (no pip). Git clones may pip."""
    ensure_vendor_site()
    if importlib.util.find_spec(import_name) is not None:
        return
    print(f"Missing required package: {package}", file=sys.stderr)
    site_ok = os.path.isdir(VENDOR_SITE) and any(os.scandir(VENDOR_SITE))
    if site_ok:
        print_error(
            "E15",
            f"Package {package} is not importable from vendor/site",
            "vendor/site must match this OS and Python. Run menu D on this machine.",
        )
        sys.exit(1)
    if install_from_vendor(package) and importlib.util.find_spec(import_name) is not None:
        return
    answer = input(f"Install pinned {package} into vendor/site (needs network)? [y/N]: ").strip().lower()
    if is_yes(answer, default_yes=False):
        os.makedirs(VENDOR_SITE, exist_ok=True)
        _pip_pinned([], PIP_INSTALL_TIMEOUT)
        if VENDOR_SITE not in sys.path:
            sys.path.append(VENDOR_SITE)
        return
    print_error(
        "E15",
        f"Package {package} is not installed",
        "Use a 1.0 release zip (vendor/site) or run menu D, copy app/vendor/, rerun.",
    )
    sys.exit(1)


def prompt_until_valid(
    creds: Dict[str, Any],
    field: str,
    prompt: str,
    *,
    sensitive: bool = False,
    required: bool = True,
    min_len: int = 0,
    pattern: Optional[str] = None,
    pattern_msg: str = "Invalid format. Try again.",
    validator: Optional[Callable[[str], bool]] = None,
    validator_msg: str = "Enter IPv4, IPv6, or an FQDN (e.g. host.example.com).",
) -> str:
    """Read a field from creds or stdin. Invalid values re-prompt; never exit."""
    value = str(creds.get(field) or "").strip()
    from_file = bool(value)
    while True:
        if value:
            if min_len and len(value) < min_len:
                if from_file:
                    print(
                        f"      {field} in credentials.json is {len(value)} character(s); "
                        f"need at least {min_len}. Enter a new value.",
                        file=sys.stderr,
                    )
                    creds[field] = ""
                else:
                    print(
                        f"      {field} entry is {len(value)} character(s); "
                        f"need at least {min_len}.",
                        file=sys.stderr,
                    )
                value = ""
                from_file = False
                continue
            if pattern and not re.fullmatch(pattern, value):
                print(f"      {pattern_msg}", file=sys.stderr)
                value = ""
                from_file = False
                continue
            if validator and not validator(value):
                print(f"      {validator_msg}", file=sys.stderr)
                value = ""
                from_file = False
                continue
            creds[field] = value
            return value
        if not required:
            return ""
        if sensitive:
            if not sys.stdin.isatty():
                raise RuntimeError("Password prompt requires a terminal")
            value = getpass(f"{prompt}: ").strip()
            if value:
                confirm = getpass(f"{prompt} (confirm): ").strip()
                if confirm != value:
                    print("      Entries did not match. Try again.", file=sys.stderr)
                    value = ""
                    continue
        else:
            value = input(f"{prompt}: ").strip()
        from_file = False
        if required and not value:
            print("      This field is required. Try again.", file=sys.stderr)


def read_credentials_text(path: str) -> str:
    """Decode credentials.json the way Windows editors save it: UTF-16 by BOM, else UTF-8 with or without BOM."""
    with open(path, "rb") as fh:
        raw = fh.read()
    # print(f"DEBUG creds: bytes={len(raw)} head={raw[:3]!r}")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def _require_private_credentials(path: str) -> None:
    """Stop with E21 when other users can read or write credentials.json; LAB_MODE only warns.

    It holds every API, SSH and SNMP secret in plain text, so a loose ACL or
    mode used to be one warning while the far less sensitive CA file was a
    hard stop.
    """
    import config as _config

    try:
        require_private_file(path)
    except (FilePermError, OSError) as exc:
        if getattr(_config, "LAB_MODE", False):
            print(f"WARNING: {exc} LAB_MODE is on, so the run continues.", file=sys.stderr)
            return
        halt(
            "E21",
            f"credentials.json permissions: {exc}",
            "Linux/macOS: chmod 600 credentials.json.",
            "Windows: icacls credentials.json /inheritance:r /grant:r <your user>:F "
            "/grant:r SYSTEM:F /grant:r Administrators:F",
        )


def load_credentials(path: str) -> Dict[str, Any]:
    """Load optional credentials.json. A missing file is {}; an unreadable one stops with E21.

    UTF-8 with or without a BOM and UTF-16 (BOM) are read, because Windows
    editors save all three. A file that exists but cannot be read stops the tool:
    carrying on as if there were no file made the run ask for every secret and
    hid the broken file behind one warning. Whole numbers are read as text; a
    true/false or decimal value stops with E21.
    """
    if not os.path.isfile(path):
        # print(f"DEBUG creds: missing {path}")
        return {}
    try:
        data = json.loads(read_credentials_text(path))
        if not isinstance(data, dict):
            raise ValueError(f"the top level is a JSON {type(data).__name__}, not an object")
        # A permission stop (HaltError) passes the except below untouched.
        # print(f"DEBUG creds: permission check on {path}")
        _require_private_credentials(path)
        # print(f"DEBUG creds: loaded keys={list(data)} from {path}")
        if DEBUG:
            print(f"      DEBUG creds: loaded {path} keys={sorted(data)}", file=sys.stderr)
        out: Dict[str, Any] = {}
        wrong_type = []
        for key, value in data.items():
            # Keep objects/arrays (collectives[], mibs[]) — do not stringify them.
            if isinstance(value, (list, dict)):
                out[key] = value
            elif isinstance(value, (bool, float)):
                # str(True) is "True"; it would be sent as a password or user name.
                wrong_type.append(f"{key} is {type(value).__name__}")
            else:
                out[key] = "" if value is None else str(value)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        # ValueError covers JSONDecodeError. RecursionError is a file nested too deep to parse.
        # print(f"DEBUG creds: load failed type={type(exc).__name__} pos={getattr(exc, 'pos', None)}")
        # The reason is the parser position or encoding error, never the file text.
        reason = str(exc)[:200] if not isinstance(exc, RecursionError) else "nested too deeply"
        halt(
            "E21",
            f"Could not read {path}: {reason}",
            "Save it as UTF-8 (with or without BOM) or UTF-16, as one JSON object. "
            "Move it aside to start without it.",
        )
    # print(f"DEBUG creds: wrong-type keys={wrong_type!r}")
    if wrong_type:
        halt(
            "E21",
            f"credentials.json has values that are not text: {', '.join(wrong_type)}",
            'Write each one as a quoted string, for example "ssh_password": "...".',
        )
    return out


def prompt_yes(prompt: str, *, default_yes: bool = False) -> bool:
    """A control character is cancel, not No. Ctrl+X must not continue the job."""
    raw = input(prompt)
    if any(ord(ch) < 32 or ord(ch) == 127 or unicodedata.category(ch) == "Cf" for ch in raw):
        print("\n      Cancelled.", file=sys.stderr)
        raise KeyboardInterrupt
    return is_yes(raw, default_yes=default_yes)


def is_yes(answer: str, *, default_yes: bool = False) -> bool:
    """True for y/yes. Empty input follows *default_yes* (install prompts default yes)."""
    text = (answer or "").strip().lower()
    if not text:
        return default_yes
    return text in YES_ANSWERS


def _utc_stamp() -> str:
    """Microseconds stop two runs in the same second from sharing a filename."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")


def _write_private(path: str, text: str) -> None:
    """Create the file at mode 600 in one call. A later chmod races a local reader."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, REPORT_FILE_MODE)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def write_json_report(prefix: str, payload: Dict[str, Any]) -> None:
    """Write reports/<prefix>-<utc>.json (mode 600). Console dump only if DEBUG.

    Callers must omit passwords, tokens, and Kul hex. This function dumps payload as-is.
    """
    text = json.dumps(payload, indent=2)
    if DEBUG:
        print("\n----- BEGIN RUN REPORT -----", file=sys.stderr)
        print(text, file=sys.stderr)
        print("----- END RUN REPORT -----", file=sys.stderr)
    if not WRITE_RUN_REPORT:
        return
    reports_dir = os.path.join(REPO_ROOT, REPORTS_DIRNAME)
    try:
        os.makedirs(reports_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(reports_dir, 0o700)
        except OSError:
            pass
        path = os.path.join(reports_dir, f"{prefix}-{_utc_stamp()}.json")
        _write_private(path, text + "\n")
        print(f"      Report written: {path}", file=sys.stderr)
    except OSError as exc:
        print_error("E23", f"Could not write report file: {exc}")


_REDACT_KEY_SUBSTR = (
    "password",
    "token",
    "secret",
    "p12",
    "passphrase",
    "community",
    "privatekey",
    "authkey",
    "privkey",
)
# Any key whose name contains one of these words is a secret (authPassphrase,
# newPassword, sshPrivateKey). Over-hiding a field such as keyType in an error
# body is the safer mistake.
_SECRET_WORD = re.compile(
    r"password|passwd|token|secret|passphrase|community|key|snmpd\.conf", re.I
)
# A quoted key, a colon, and a quoted string value. The key is a plain run of
# non-quote characters and the word check runs on it separately, so the match
# time stays linear even for a long or unclosed key (a pattern with the words
# inside the key class backtracked for minutes on a crafted body).
_QUOTED_PAIR = re.compile(r'("([^"\\\n]{0,200})"\s*:\s*")((?:[^"\\]|\\.)*)"')
_QUOTED_PAIR_SQ = re.compile(r"('([^'\\\n]{0,200})'\s*:\s*')((?:[^'\\]|\\.)*)'")
_LOCALIZED_KEY = re.compile(r"(-l\s*0x)[0-9a-f]+", re.I)
_REDACT_KEYS = frozenset(
    {"snmpd.conf", "key", "httpsP12", "awsSecret", "p12", "password", "token"}
)
_replaced_run_dir = ""


def redact_preview(text: str, limit: int = 300) -> str:
    """Cap an error body and hide echoed secrets. Controllers sometimes repeat the POST.

    Redact first, then cut. Cutting first can split a value so the pattern no
    longer matches and the start of the secret is printed.

    A key is hidden when its name contains a secret word (password, token,
    secret, passphrase, community, key, snmpd.conf), in double or single quotes.
    A localized key is hidden after -l with any case and optional space. A
    secret that is not a quoted string value (a bare number) is not matched.
    """
    def _hide(match, quote):
        """Replace the value only when the key names a secret, so other fields stay readable in the preview."""
        if _SECRET_WORD.search(match.group(2)):
            return match.group(1) + "<redacted>" + quote
        return match.group(0)

    hidden = _QUOTED_PAIR.sub(lambda m: _hide(m, '"'), text or "")
    hidden = _QUOTED_PAIR_SQ.sub(lambda m: _hide(m, "'"), hidden)
    hidden = _LOCALIZED_KEY.sub(r"\1<redacted>", hidden)
    # print(f"DEBUG redact: in={len(text or '')} out={len(hidden)} limit={limit}")
    return hidden[:limit]


def redact_for_backup(obj: Any) -> Any:
    """Drop secrets from an appliance GET before writing reports/replaced/."""
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for key, value in obj.items():
            kl = str(key).lower()
            if key in _REDACT_KEYS or any(s in kl for s in _REDACT_KEY_SUBSTR):
                out[key] = f"<redacted:{key}>"
            else:
                out[key] = redact_for_backup(value)
        return out
    if isinstance(obj, list):
        return [redact_for_backup(x) for x in obj]
    return obj


def begin_replaced_run() -> str:
    """One folder per live replace/overwrite run: reports/replaced/<UTC>/."""
    global _replaced_run_dir
    stamp = _utc_stamp()
    _replaced_run_dir = os.path.join(REPO_ROOT, REPORTS_DIRNAME, "replaced", stamp)
    os.makedirs(_replaced_run_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(os.path.dirname(_replaced_run_dir), 0o700)
        os.chmod(_replaced_run_dir, 0o700)
    except OSError:
        pass
    # One line for the folder instead of one "Backup:" line per box.
    print(f"      Pre-change copies go to {_replaced_run_dir}", file=sys.stderr)
    return _replaced_run_dir


def _pick_paths(body: Dict[str, Any], paths: tuple) -> Dict[str, Any]:
    """Only the given dot paths of an appliance document (plus id, name, version)."""
    out: Dict[str, Any] = {k: body[k] for k in ("id", "name", "version") if k in body}

    def _copy(src: Any, dst: Dict[str, Any], path: str) -> None:
        """Copy one dot path. A key may itself contain a dot (snmpd.conf), so the
        whole remaining path is tried as one key before splitting at a dot."""
        if not isinstance(src, dict):
            return
        if path in src:
            dst[path] = src[path]
            return
        head, _, rest = path.partition(".")
        if rest and head in src:
            _copy(src[head], dst.setdefault(head, {}), rest)
            if not dst[head]:
                del dst[head]

    for path in paths:
        _copy(body, out, path)
    return out


def write_replaced_snapshot(kind: str, label: str, body: Dict[str, Any], only: tuple = ()) -> None:
    """Save the pre-change copy (redacted) of what a replace or overwrite is about to change.

    only names the fields this change may touch (the same list the PUT guard
    uses). The file then holds just those fields, not the whole appliance with
    secret-looking keys blanked: a secret under an unexpected field name can no
    longer end up on disk. Rollback uses the in-memory copy, not this file.
    """
    folder = _replaced_run_dir or begin_replaced_run()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", label)[:80] or "appliance"
    path = os.path.join(folder, f"{kind}-{safe}.json")
    try:
        part = _pick_paths(body, only) if only else body
        # print(f"DEBUG backup: {kind} keys={sorted(part)}")
        payload = json.dumps(redact_for_backup(part), indent=2) + "\n"
        _write_private(path, payload)
        if DEBUG:
            print(f"      Backup: {path}", file=sys.stderr)
    except OSError as exc:
        print_error("E23", f"Could not write replace backup: {exc}")


# Per-thread buffer for the box a batch worker is running. None on the main thread.
_BOX_TLS = threading.local()


class _BoxBuffer(list):
    """One box's held output. closed=True sends later writes straight to the real stream."""

    closed = False


class _ThreadRoutedStream:
    """Stand-in for sys.stdout/sys.stderr while a batch runs.

    A worker's writes go to its box's buffer; the main thread's writes (progress
    counter, prompts) pass straight through. The buffer is printed as one block
    when that box finishes, so lines from parallel boxes no longer interleave.
    """

    def __init__(self, real, name: str) -> None:
        """Wrap one real stream; name says which one a buffered chunk returns to."""
        self._real = real
        self._name = name

    def write(self, text: str) -> int:
        """Buffer in a batch worker, write through elsewhere."""
        buf = getattr(_BOX_TLS, "buf", None)
        if buf is None or buf.closed:
            return self._real.write(text)
        buf.append((self._name, text))
        return len(text)

    def flush(self) -> None:
        """A worker's flush waits for its block; the main thread flushes for real."""
        buf = getattr(_BOX_TLS, "buf", None)
        if buf is None or buf.closed:
            self._real.flush()

    def __getattr__(self, name: str):
        """isatty, encoding and the rest come from the real stream (colors check isatty)."""
        return getattr(self._real, name)


def _flush_box(chunks: list, out, err) -> None:
    """Print one finished box's lines together, after clearing a progress counter line."""
    if not chunks:
        return
    out.flush()
    try:
        tty = err.isatty()
    except (AttributeError, ValueError):
        tty = False
    if tty:
        # Wipe a progress counter line ("SSH 2/5") first; a log file or pipe gets no padding.
        err.write("\r" + " " * 40 + "\r")
    for name, text in chunks:
        stream = out if name == "out" else err
        stream.write(text)
        # Flush each piece so stdout and stderr lines keep their order in a pipe or log.
        stream.flush()


def stop_pool_early(pool: ThreadPoolExecutor, futures: Dict[Any, Any], *, wait_running: bool) -> list:
    """Stop a pool that ended early (Ctrl+C, or an error while feeding it): the one rule for every pool.

    Queued work is cancelled. Work already running either finishes before this
    returns (wait_running=True: SSH changes, so their results reach the report)
    or is left to end on its own timeout (False: host-key reads, which change
    nothing and send no password). Returns the keys of the work that had
    started. A second Ctrl+C while waiting stops the wait.
    """
    running = [key for fut, key in futures.items() if fut.running()]
    pool.shutdown(wait=False, cancel_futures=True)
    if wait_running:
        for fut in list(futures):
            if not fut.cancelled():
                try:
                    fut.exception()  # waits for this one
                except CancelledError:
                    pass
    # print(f"DEBUG pool: early stop, running={len(running)} wait={wait_running}")
    return running


def run_target_batch(
    targets: list,
    worker: Callable,
    concurrency: int,
    on_fail: Callable,
    progress: Callable = None,
) -> None:
    """Run one worker per target in a pool. One failure does not stop the rest.

    targets may be a list, or an iterator that yields boxes as they become
    ready (ssh.client.iter_primed_targets): each box's worker starts as soon as
    the box is yielded, not after the last one. If the batch ends early (Ctrl+C,
    including at a later box's host-key prompt, or an error while settling a
    box), queued boxes are cancelled, the boxes already being worked on are
    named and finish before this returns, and their failures still go to
    on_fail, so the report shows what was really changed.

    Each worker's console output is held per box and printed as one block when
    that box finishes (main thread), so parallel boxes do not interleave; the
    real stdout/stderr are put back when the batch ends. on_fail and progress
    run on the main thread, after the box's block.
    """
    sized = hasattr(targets, "__len__")
    if sized and not targets:
        return
    workers = max(1, min(concurrency, len(targets)) if sized else concurrency)
    done = 0
    n = len(targets) if sized else 0
    real_out, real_err = sys.stdout, sys.stderr
    # A nested batch keeps the outer stand-in, so the block still prints once.
    install = not isinstance(real_err, _ThreadRoutedStream)
    if install:
        sys.stdout = _ThreadRoutedStream(real_out, "out")
        sys.stderr = _ThreadRoutedStream(real_err, "err")
    out_w = real_out._real if isinstance(real_out, _ThreadRoutedStream) else real_out
    err_w = real_err._real if isinstance(real_err, _ThreadRoutedStream) else real_err
    buffers: Dict[int, list] = {}
    # Boxes still running, so their held lines can be shown if the batch ends early.
    live: Dict[int, "_BoxBuffer"] = {}

    def _run(target):
        """Worker wrapper: collect this box's output; keep it even when the worker raises.

        With DEBUG, the box's time in this step is added to its block, so a box
        that waited on a timeout stands out.
        """
        buf = _BoxBuffer()
        _BOX_TLS.buf = buf
        live[id(target)] = buf
        started = time.monotonic()
        try:
            return worker(target)
        finally:
            if DEBUG:
                label = target.label() if hasattr(target, "label") else str(target)
                _BOX_TLS.buf.append(("err", f"      DEBUG {label}: {time.monotonic() - started:.1f} s in this step\n"))
            buffers[id(target)] = buf
            live.pop(id(target), None)
            _BOX_TLS.buf = None

    pool = ThreadPoolExecutor(max_workers=workers)
    futures = {}
    handled = set()
    finished = False
    try:
        # Submitting inside the try: an iterator can prompt or be interrupted
        # while it yields, and the streams must still be restored.
        for t in targets:
            futures[pool.submit(_run, t)] = t
        n = len(futures)
        for future in as_completed(futures):
            target = futures[future]
            handled.add(future)
            try:
                future.result()
                _flush_box(buffers.pop(id(target), []), out_w, err_w)
            except Exception as exc:
                _flush_box(buffers.pop(id(target), []), out_w, err_w)
                on_fail(target, exc)
            done += 1
            if progress:
                progress(done, n)
        finished = True
    finally:
        try:
            if finished:
                pool.shutdown(wait=True, cancel_futures=True)
            else:
                # Ended early: name the boxes already being worked on and let
                # them finish, so nothing keeps changing after this returns.
                running = [futures[f] for f in futures if f.running()]
                if running:
                    names = ", ".join(t.label() if hasattr(t, "label") else str(t) for t in running)
                    err_w.write(f"\n      Stopping: waiting for {len(running)} box(es) already started to finish: {names}\n")
                    err_w.flush()
                stop_pool_early(pool, futures, wait_running=True)
                for fut, target in futures.items():
                    if fut in handled or fut.cancelled() or not fut.done():
                        continue
                    exc = fut.exception()
                    if exc is not None:
                        on_fail(target, exc)
        finally:
            # Finished boxes not printed yet, then any box still running (a
            # second Ctrl+C stopped the wait): its lines so far are shown, and
            # anything it writes later goes straight to the console.
            # print(f"DEBUG batch: flushing {len(buffers)} finished and {len(live)} running box(es)")
            for chunks in list(buffers.values()):
                _flush_box(chunks, out_w, err_w)
            for buf in list(live.values()):
                buf.closed = True
                _flush_box(list(buf), out_w, err_w)
            if install:
                sys.stdout, sys.stderr = real_out, real_err
