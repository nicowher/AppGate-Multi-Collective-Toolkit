"""Step 8 / SNMP-Walk: prove the new USM user works (authPriv).

Lives in ``core/``. Called from ``tools/snmp_credentials.py`` (step 8) and
``tools/snmp_walk.py`` (menu 3).


Why walk at all: pin/push can succeed while snmpd still has stale usmUser
keys; a walk with the *passphrases* is the real acceptance test.

Why IP before FQDN: UDP/161 often fails on NAT names that still answer SSH.
Attempts per address are tunable (WALK_IP_ATTEMPTS / WALK_FQDN_ATTEMPTS).

Backends: Net-SNMP snmpwalk → SnmpSoft → pysnmp (auto-install vendor/pip).
"""
import asyncio
import ipaddress
import platform
import shutil
import subprocess
import sys
import time
from typing import List, Optional, Sequence, Tuple, Union

from core.utils import install_from_vendor, is_yes
from config import (
    DEBUG,
    DEFAULT_SNMP_PORT,
    PIP_INSTALL_TIMEOUT,
    PKG_INSTALL_TIMEOUT,
    SNMP_AUTH_PROTOCOL,
    SNMP_PRIV_PROTOCOL,
    SNMPWALK_DETECT_TIMEOUT,
    SNMPWALK_HELP_TIMEOUT,
    SNMPWALK_TIMEOUT,
    SNMPWALK_PROBE_TIMEOUT,
    SNMPWALK_RETRIES,
    SNMP_WALK_OID,
    VALIDATION_RETRY_DELAY,
    WALK_ERROR_PREVIEW,
    WALK_FQDN_ATTEMPTS,
    WALK_IP_ATTEMPTS,
    get_auth_protocol,
    get_priv_protocol,
)


class SNMPValidator:
    """Walk one host list (IPs then FQDNs) until one endpoint succeeds."""

    def __init__(self) -> None:
        self._tool: Optional[Tuple[Optional[str], Optional[str]]] = None
        self._last_walk_error = ""

    def _set_walk_error(self, message: str) -> None:
        self._last_walk_error = message
        if DEBUG:
            print(f"      {message}", file=sys.stderr)

    def validate_snmp_walk(
        self,
        host: Union[str, Sequence[str]],
        user: str,
        auth: str,
        priv: str,
        engine_id: Optional[str] = None,
    ) -> bool:
        hosts: List[str] = [host] if isinstance(host, str) else [h for h in host if h]
        if not hosts:
            return False
        # print(f"DEBUG walk: hosts={hosts} engine={engine_id}")
        if DEBUG:
            print(f"      DEBUG walk: hosts={hosts} engine_set={bool(engine_id)}", file=sys.stderr)
        self._last_walk_error = ""
        for addr in hosts:
            target = self._walk_target(addr)
            attempts = WALK_IP_ATTEMPTS if self._addr_is_ip(target) else WALK_FQDN_ATTEMPTS
            if DEBUG:
                kind = "IP" if self._addr_is_ip(target) else "FQDN"
                print(f"      Walk {kind} {target} ({attempts} attempt(s))...", file=sys.stderr)
            if self._validate_snmp_walk_one(target, user, auth, priv, engine_id, attempts):
                return True
        if self._last_walk_error and not DEBUG:
            print(f"      {self._last_walk_error}", file=sys.stderr)
        return False

    @staticmethod
    def _walk_target(value: str) -> str:
        """Strip IPv6 brackets so pysnmp/Net-SNMP get a bare address."""
        text = (value or "").strip()
        if text.startswith("[") and text.endswith("]"):
            return text[1:-1]
        return text

    @staticmethod
    def _addr_is_ip(value: str) -> bool:
        text = (value or "").strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        try:
            ipaddress.ip_address(text)
            return True
        except ValueError:
            return False

    def _validate_snmp_walk_one(
        self,
        ip: str,
        user: str,
        auth: str,
        priv: str,
        engine_id: Optional[str] = None,
        max_attempts: int = WALK_FQDN_ATTEMPTS,
    ) -> bool:
        # Pick a walk backend. If none is installed, offer native Net-SNMP
        # (Linux/macOS) or fall back to pip/vendor pysnmp (Windows too).
        tool_type, executable = self._cached_detect()
        if tool_type is None:
            print("      SNMP walk tool not found. Installing...", file=sys.stderr)
            if not self._install_snmpwalk():
                print(
                    "      Could not auto-install an SNMP walk tool. "
                    "Install Net-SNMP or run: pip install pysnmp",
                    file=sys.stderr,
                )
                return False
            self._tool = None
            tool_type, executable = self._cached_detect()
            if tool_type is None:
                print("      Auto-install finished but no walk tool is available.", file=sys.stderr)
                return False
            print("      SNMP walk tool installed.", file=sys.stderr)

        # cz-configd / snmpd may still be reloading; retry a few times.
        for attempt in range(1, max_attempts + 1):
            if attempt > 1:
                if DEBUG:
                    print(
                        f"      Retrying SNMP walk (attempt {attempt}/{max_attempts})...",
                        file=sys.stderr,
                    )
                time.sleep(VALIDATION_RETRY_DELAY)

            try:
                # print(f"DEBUG step8: backend={tool_type} target={ip} engine={engine_id}")
                if tool_type == "pysnmp":
                    if DEBUG:
                        print("      Using pysnmp for SNMP walk validation...", file=sys.stderr)
                    if self._validate_snmp_walk_pysnmp(ip, user, auth, priv, engine_id):
                        return True
                    continue

                # Never print -A / -X / -aw / -pw — those are live passphrases.
                if tool_type == "snmpsoft":
                    cmd = [
                        executable,
                        f"-r:{ip}",
                        "-v:3",
                        f"-sn:{user}",
                        f"-ap:{SNMP_AUTH_PROTOCOL}",
                        f"-aw:{auth}",
                        f"-pp:{SNMP_PRIV_PROTOCOL}",
                        f"-pw:{priv}",
                    ]
                    safe_cmd = f"{executable} -r:{ip} -v:3 -sn:{user} (passwords omitted)"
                else:
                    cmd = [
                        executable,
                        "-v3",
                        "-u", user,
                        "-l", "authPriv",
                        "-a", SNMP_AUTH_PROTOCOL,
                        "-A", auth,
                        "-x", SNMP_PRIV_PROTOCOL,
                        "-X", priv,
                        ip,
                    ]
                    safe_cmd = (
                        f"{executable} -v3 -u {user} -l authPriv "
                        f"-a {SNMP_AUTH_PROTOCOL} -x {SNMP_PRIV_PROTOCOL} {ip} "
                        "(passwords omitted)"
                    )

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=SNMPWALK_TIMEOUT)
                if result.returncode == 0:
                    return True
                self._set_walk_error(
                    f"SNMP walk failed (rc={result.returncode}): "
                    f"{result.stderr.strip()[:WALK_ERROR_PREVIEW] or result.stdout.strip()[:WALK_ERROR_PREVIEW]}"
                )
                if DEBUG:
                    print(f"      cmd: {safe_cmd}", file=sys.stderr)
            except subprocess.TimeoutExpired:
                self._set_walk_error(f"SNMP walk timed out after {SNMPWALK_TIMEOUT}s")

        if DEBUG:
            print(f"      SNMP walk validation failed after {max_attempts} attempts", file=sys.stderr)
        return False

    def _cached_detect(self) -> Tuple[Optional[str], Optional[str]]:
        if self._tool is None:
            self._tool = self._detect_snmpwalk()
        return self._tool

    def _detect_snmpwalk(self) -> Tuple[Optional[str], Optional[str]]:
        """Return (backend, executable). backend is snmpsoft, netsnmp, pysnmp, or None."""
        candidates = ["snmpwalk", "snmpwalk.exe", "SnmpWalk.exe", "SnmpWalk"]

        for candidate in candidates:
            if shutil.which(candidate) is None:
                continue
            try:
                probe = subprocess.run(
                    [candidate], capture_output=True, text=True, timeout=SNMPWALK_DETECT_TIMEOUT
                )
                if "SnmpSoft" in ((probe.stdout or "") + (probe.stderr or "")):
                    return ("snmpsoft", candidate)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

        for candidate in candidates:
            if shutil.which(candidate) is None:
                continue
            try:
                probe = subprocess.run(
                    [candidate, "--help"],
                    capture_output=True,
                    text=True,
                    timeout=SNMPWALK_HELP_TIMEOUT,
                )
                output = (probe.stdout or "") + (probe.stderr or "")
                if "NET-SNMP" in output or "snmpwalk" in output.lower():
                    return ("netsnmp", candidate)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

        try:
            import pysnmp  # noqa: F401
            return ("pysnmp", None)
        except ImportError:
            return (None, None)

    def _install_snmpwalk(self) -> bool:
        """Ask to install Net-SNMP on Linux/macOS; Windows always uses pysnmp."""
        system = platform.system()
        native_ok = False
        try:
            if system in ("Linux", "Darwin"):
                answer = input(
                    "      Install Net-SNMP via the system package manager? [Y/n]: "
                ).strip().lower()
                if is_yes(answer, default_yes=True):
                    print("      Attempting to install Net-SNMP...", file=sys.stderr)
                    if system == "Linux":
                        native_ok = self._install_snmpwalk_linux()
                    else:
                        native_ok = self._install_snmpwalk_macos()
                else:
                    print("      Skipping native Net-SNMP install.", file=sys.stderr)
            elif system == "Windows":
                print(
                    "      Windows: no safe automatic Net-SNMP installer. "
                    "Falling back to pysnmp.",
                    file=sys.stderr,
                )
            else:
                print(f"      Unsupported platform: {system}", file=sys.stderr)
        except Exception as exc:
            print(f"      Native installation attempt failed: {exc}", file=sys.stderr)

        if native_ok:
            return True
        print("      Installing pysnmp via pip...", file=sys.stderr)
        return self._install_pysnmp()

    def _install_snmpwalk_linux(self) -> bool:
        if shutil.which("apt-get"):
            print("      Detected Debian/Ubuntu. Installing via apt-get...", file=sys.stderr)
            subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False, timeout=PKG_INSTALL_TIMEOUT)
            subprocess.run(["sudo", "apt-get", "install", "-y", "snmp"], check=True, timeout=PKG_INSTALL_TIMEOUT)
        elif shutil.which("dnf"):
            print("      Detected Fedora/RHEL. Installing via dnf...", file=sys.stderr)
            subprocess.run(["sudo", "dnf", "install", "-y", "net-snmp-utils"], check=True, timeout=PKG_INSTALL_TIMEOUT)
        elif shutil.which("yum"):
            print("      Detected RHEL/CentOS. Installing via yum...", file=sys.stderr)
            subprocess.run(["sudo", "yum", "install", "-y", "net-snmp-utils"], check=True, timeout=PKG_INSTALL_TIMEOUT)
        else:
            print("      No supported package manager found (apt-get/dnf/yum).", file=sys.stderr)
            return False
        return self._detect_snmpwalk()[0] is not None

    def _install_snmpwalk_macos(self) -> bool:
        print("      Detected macOS. Installing via Homebrew...", file=sys.stderr)
        subprocess.run(["brew", "install", "net-snmp"], check=True, timeout=PKG_INSTALL_TIMEOUT)
        return self._detect_snmpwalk()[0] is not None

    def _install_pysnmp(self) -> bool:
        if install_from_vendor("pysnmp"):
            return self._detect_snmpwalk()[0] is not None
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "pysnmp"],
                check=True,
                timeout=PIP_INSTALL_TIMEOUT,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()[:WALK_ERROR_PREVIEW]
            print(f"      pip install pysnmp failed (rc={exc.returncode}): {stderr}", file=sys.stderr)
            return False
        except subprocess.TimeoutExpired:
            print("      pip install pysnmp timed out.", file=sys.stderr)
            return False
        return self._detect_snmpwalk()[0] is not None

    def _usm(self, engine_id: Optional[str] = None):
        kwargs = {
            "authProtocol": get_auth_protocol(),
            "privProtocol": get_priv_protocol(),
        }
        if engine_id:
            hex_id = engine_id[2:] if engine_id.lower().startswith("0x") else engine_id
            try:
                from pysnmp.proto.rfc1902 import OctetString
                kwargs["securityEngineId"] = OctetString(hexValue=hex_id)
            except (ImportError, ValueError, TypeError):
                pass
        return kwargs

    def _validate_snmp_walk_pysnmp(
        self, ip: str, user: str, auth: str, priv: str, engine_id: Optional[str] = None
    ) -> bool:
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                UsmUserData,
                walk_cmd,
            )
        except ImportError:
            try:
                from pysnmp.hlapi import (
                    ContextData,
                    ObjectIdentity,
                    ObjectType,
                    SnmpEngine,
                    UdpTransportTarget,
                    UsmUserData,
                    nextCmd,
                )
            except ImportError:
                print("      pysnmp library not available.", file=sys.stderr)
                return False
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                UsmUserData(user, auth, priv, **self._usm(engine_id)),
                UdpTransportTarget(
                    (ip, DEFAULT_SNMP_PORT),
                    timeout=SNMPWALK_PROBE_TIMEOUT,
                    retries=SNMPWALK_RETRIES,
                ),
                ContextData(),
                ObjectType(ObjectIdentity(SNMP_WALK_OID)),
            ):
                if errorIndication:
                    self._set_walk_error(f"SNMP walk (pysnmp): {errorIndication}")
                    return False
                if errorStatus:
                    self._set_walk_error(
                        f"SNMP walk (pysnmp): {errorStatus.prettyPrint()}"
                    )
                    return False
                return True
            return False

        async def _async_walk():
            transport = await UdpTransportTarget.create(
                (ip, DEFAULT_SNMP_PORT),
                timeout=SNMPWALK_PROBE_TIMEOUT,
                retries=SNMPWALK_RETRIES,
            )
            engine = SnmpEngine()
            agen = walk_cmd(
                engine,
                UsmUserData(user, auth, priv, **self._usm(engine_id)),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(SNMP_WALK_OID)),
            )
            try:
                async for (errorIndication, errorStatus, errorIndex, varBinds) in agen:
                    if errorIndication:
                        self._set_walk_error(f"SNMP walk (pysnmp): {errorIndication}")
                        return False
                    if errorStatus:
                        self._set_walk_error(
                            f"SNMP walk (pysnmp): {errorStatus.prettyPrint()}"
                        )
                        return False
                    return True
                return False
            finally:
                try:
                    await agen.aclose()
                except Exception:
                    pass
                dispatcher = getattr(engine, "transport_dispatcher", None) or getattr(
                    engine, "transportDispatcher", None
                )
                if dispatcher is not None:
                    for name in ("close_dispatcher", "closeDispatcher"):
                        closer = getattr(dispatcher, name, None)
                        if closer:
                            try:
                                closer()
                            except Exception:
                                pass
                            break

        try:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(_async_walk())
            finally:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.close()
        except Exception as exc:
            self._set_walk_error(f"SNMP walk (pysnmp) encountered an error: {exc}")
            return False
