import asyncio
import platform
import shutil
import subprocess
import sys
import time
from typing import Optional, Tuple

from utils import install_from_vendor
from config import (
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
    VALIDATION_RETRIES,
    VALIDATION_RETRY_DELAY,
    get_auth_protocol,
    get_priv_protocol,
)


class SNMPValidator:
    """Walk the appliance with the new SNMPv3 user to confirm the push worked.

    Backends, in order: Net-SNMP snmpwalk, SnmpSoft SnmpWalk.exe, then pysnmp.
    Walks use plaintext passwords — hashes live only on the appliance.
    """

    def validate_snmp_walk(
        self, ip: str, user: str, auth: str, priv: str, engine_id: Optional[str] = None
    ) -> bool:
        tool_type, executable = self._detect_snmpwalk()
        if tool_type is None:
            print("      SNMP walk tool not found. Installing...", file=sys.stderr)
            if not self._install_snmpwalk():
                print(
                    "      Could not auto-install an SNMP walk tool. "
                    "Install Net-SNMP or run: pip install pysnmp",
                    file=sys.stderr,
                )
                return False
            tool_type, executable = self._detect_snmpwalk()
            if tool_type is None:
                print("      Auto-install finished but no walk tool is available.", file=sys.stderr)
                return False
            print("      SNMP walk tool installed.", file=sys.stderr)

        for attempt in range(1, VALIDATION_RETRIES + 1):
            if attempt > 1:
                print(
                    f"      Retrying SNMP walk (attempt {attempt}/{VALIDATION_RETRIES})...",
                    file=sys.stderr,
                )
                time.sleep(VALIDATION_RETRY_DELAY)

            try:
                if tool_type == "pysnmp":
                    print("      Using pysnmp for SNMP walk validation...", file=sys.stderr)
                    if self._validate_snmp_walk_pysnmp(ip, user, auth, priv, engine_id):
                        return True
                    continue

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
                print(
                    f"      SNMP walk failed (rc={result.returncode}): "
                    f"{result.stderr.strip()[:500] or result.stdout.strip()[:500]}",
                    file=sys.stderr,
                )
                print(f"      cmd: {safe_cmd}", file=sys.stderr)
            except subprocess.TimeoutExpired:
                print(f"      SNMP walk timed out after {SNMPWALK_TIMEOUT}s", file=sys.stderr)

        print(f"      SNMP walk validation failed after {VALIDATION_RETRIES} attempts", file=sys.stderr)
        return False

    def _detect_snmpwalk(self) -> Tuple[Optional[str], Optional[str]]:
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
            except Exception:
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
            except Exception:
                pass

        try:
            import pysnmp  # noqa: F401
            return ("pysnmp", None)
        except ImportError:
            return (None, None)

    def _install_snmpwalk(self) -> bool:
        system = platform.system()
        native_ok = False
        try:
            if system in ("Linux", "Darwin"):
                answer = input(
                    "      Install Net-SNMP via the system package manager? [Y/n]: "
                ).strip().lower()
                if answer in ("", "y", "yes"):
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
            stderr = (exc.stderr or "").strip()[:500]
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
            except Exception:
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
                    print(f"      SNMP walk (pysnmp): {errorIndication}", file=sys.stderr)
                    return False
                if errorStatus:
                    print(f"      SNMP walk (pysnmp): {errorStatus.prettyPrint()}", file=sys.stderr)
                    return False
                return True
            return False

        async def _async_walk():
            transport = await UdpTransportTarget.create(
                (ip, DEFAULT_SNMP_PORT),
                timeout=SNMPWALK_PROBE_TIMEOUT,
                retries=SNMPWALK_RETRIES,
            )
            async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
                SnmpEngine(),
                UsmUserData(user, auth, priv, **self._usm(engine_id)),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(SNMP_WALK_OID)),
            ):
                if errorIndication:
                    print(f"      SNMP walk (pysnmp): {errorIndication}", file=sys.stderr)
                    return False
                if errorStatus:
                    print(f"      SNMP walk (pysnmp): {errorStatus.prettyPrint()}", file=sys.stderr)
                    return False
                return True
            return False

        try:
            return asyncio.run(_async_walk())
        except Exception as exc:
            print(f"      SNMP walk (pysnmp) encountered an error: {exc}", file=sys.stderr)
            return False
