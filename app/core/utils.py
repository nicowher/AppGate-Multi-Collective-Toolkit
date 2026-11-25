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
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from getpass import getpass
from typing import Any, Callable, Dict, Optional

from config import (
    APPLIANCE_LIST_MAX,
    DEBUG,
    PIP_INSTALL_TIMEOUT,
    PIP_UPGRADE_TIMEOUT,
    REPORT_FILE_MODE,
    REPORTS_DIRNAME,
    VENDOR_DOWNLOAD_TIMEOUT,
    VENDOR_PACKAGES,
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
    """Always-on (DEBUG off too). code like E02. hints are next steps."""
    from core.color import fail

    print(f"{fail('ERROR', stream=sys.stderr)} {code}: {message}", file=sys.stderr)
    for hint in hints:
        if hint:
            print(f"      Next: {hint}", file=sys.stderr)


class HaltError(ValueError):
    """Already printed as ERROR E0x. Tool __main__ should exit without reprinting."""


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
    """One check for the preview merge and the PUT. A bad nic must fail here so it is not sent."""
    if not isinstance(entry, dict):
        raise ValueError("allowSources row must be an object")
    try:
        mask = int(entry.get("netmask"))
    except (TypeError, ValueError):
        raise ValueError("allowSources address or netmask is invalid") from None
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


def load_credentials(path: str) -> Dict[str, Any]:
    """Load optional credentials.json. Missing or invalid files become {}."""
    if not os.path.isfile(path):
        # print(f"DEBUG creds: missing {path}")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        try:
            mode = os.stat(path).st_mode & 0o077
            if mode and os.name == "posix":
                print(
                    f"WARNING: {path} is group/world-readable (mode {mode:03o}). "
                    "chmod 600 this file.",
                    file=sys.stderr,
                )
        except OSError:
            pass
        # print(f"DEBUG creds: loaded keys={list(data)} from {path}")
        if DEBUG:
            print(f"      DEBUG creds: loaded {path} keys={sorted(data)}", file=sys.stderr)
        out: Dict[str, Any] = {}
        for key, value in data.items():
            # Keep objects/arrays (collectives[], mibs[]) — do not stringify them.
            if isinstance(value, (list, dict)):
                out[key] = value
            else:
                out[key] = "" if value is None else str(value)
        return out
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"Warning: Could not load credentials from {path}: {exc}", file=sys.stderr)
        return {}


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
        print(f"      Could not write report file: {exc}", file=sys.stderr)


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
_SECRET_JSON = re.compile(
    r'("(?:password|token|secret|passphrase|community|privateKey|authKey|key)"\s*:\s*")[^"]*"',
    re.I,
)
_REDACT_KEYS = frozenset(
    {"snmpd.conf", "key", "httpsP12", "awsSecret", "p12", "password", "token"}
)
_replaced_run_dir = ""


def redact_preview(text: str, limit: int = 300) -> str:
    """Cap an error body and hide echoed secrets. Controllers sometimes repeat the POST."""
    clipped = (text or "")[:limit]
    return _SECRET_JSON.sub(r'\1<redacted>"', clipped)


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
    return _replaced_run_dir


def write_replaced_snapshot(kind: str, label: str, body: Dict[str, Any]) -> None:
    """Save pre-PUT GET (redacted) so a replace can be rolled back."""
    folder = _replaced_run_dir or begin_replaced_run()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", label)[:80] or "appliance"
    path = os.path.join(folder, f"{kind}-{safe}.json")
    try:
        payload = json.dumps(redact_for_backup(body), indent=2) + "\n"
        _write_private(path, payload)
        print(f"      Backup: {path}", file=sys.stderr)
    except OSError as exc:
        print(f"      Could not write replace backup: {exc}", file=sys.stderr)


def run_target_batch(
    targets: list,
    worker: Callable,
    concurrency: int,
    on_fail: Callable,
    progress: Callable = None,
) -> None:
    """Run one worker per target in a pool. One failure does not stop the rest."""
    if not targets:
        return
    workers = max(1, min(concurrency, len(targets)))
    done = 0
    n = len(targets)
    pool = ThreadPoolExecutor(max_workers=workers)
    futures = {pool.submit(worker, t): t for t in targets}
    try:
        for future in as_completed(futures):
            target = futures[future]
            try:
                future.result()
            except Exception as exc:
                on_fail(target, exc)
            done += 1
            if progress:
                progress(done, n)
    except KeyboardInterrupt:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)
