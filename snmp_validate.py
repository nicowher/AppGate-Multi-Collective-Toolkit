import asyncio
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
from typing import Optional, Tuple


class SNMPValidator:
    DEFAULT_SNMP_PORT = 161
    VALIDATION_RETRIES = 3
    VALIDATION_RETRY_DELAY = 2

    def validate_snmp_walk(self, ip: str, user: str, auth: str, priv: str) -> bool:
        """Run an SNMP walk to verify the new SNMPv3 credentials."""
        last_error = ""
        for attempt in range(1, self.VALIDATION_RETRIES + 1):
            if attempt > 1:
                print(
                    f"      Retrying SNMP walk validation (attempt {attempt}/{self.VALIDATION_RETRIES})...",
                    file=sys.stderr,
                )
                time.sleep(self.VALIDATION_RETRY_DELAY)

            tool_type, executable = self._detect_snmpwalk()

            if tool_type is None:
                print(
                    "      SNMP walk tool not found. Attempting auto-install...",
                    file=sys.stderr,
                )
                if self._install_snmpwalk():
                    tool_type, executable = self._detect_snmpwalk()
                    if tool_type is not None:
                        print("      SNMP walk tool installed. Retrying validation...", file=sys.stderr)
                    else:
                        print(
                            "      Auto-install completed but no SNMP walk tool "
                            "is still available.",
                            file=sys.stderr,
                        )
                        return False
                else:
                    print(
                        "      Could not auto-install any SNMP walk tool. "
                        "Install Net-SNMP, SnmpWalk, or run 'pip install pysnmp' manually.",
                        file=sys.stderr,
                    )
                    return False

            if tool_type == "snmpsoft":
                cmd = [
                    executable,
                    f"-r:{ip}",
                    "-v:3",
                    f"-sn:{user}",
                    "-ap:SHA256", f"-aw:{auth}",
                    "-pp:AES256", f"-pw:{priv}",
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    last_error = (
                        f"      SNMP walk failed (rc={result.returncode}): "
                        f"{result.stderr.strip()[:500] or result.stdout.strip()[:500]}"
                    )
                    print(last_error, file=sys.stderr)
                    print(f"      cmd: {' '.join(cmd)}", file=sys.stderr)
                    continue
                return True

            if tool_type == "pysnmp":
                print("      Using pysnmp for SNMP walk validation...", file=sys.stderr)
                ok = self._validate_snmp_walk_pysnmp(ip, user, auth, priv)
                if not ok:
                    last_error = "      SNMP walk (pysnmp) failed"
                    continue
                return True

            cmd = [
                executable,
                "-v3",
                "-u", user,
                "-l", "authPriv",
                "-a", "SHA256", "-A", auth,
                "-x", "AES256", "-X", priv,
                ip,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                last_error = (
                    f"      SNMP walk failed (rc={result.returncode}): "
                    f"{result.stderr.strip()[:500] or result.stdout.strip()[:500]}"
                )
                print(last_error, file=sys.stderr)
                print(f"      cmd: {' '.join(cmd)}", file=sys.stderr)
                continue
            return True

        print(f"      SNMP walk validation failed after {self.VALIDATION_RETRIES} attempts", file=sys.stderr)
        return False

    def _detect_snmpwalk(self) -> Tuple[Optional[str], Optional[str]]:
        """Detect an available SNMP walk tool."""
        candidates = ["snmpwalk", "snmpwalk.exe", "SnmpWalk.exe", "SnmpWalk"]

        for candidate in candidates:
            if shutil.which(candidate) is None:
                continue
            try:
                probe = subprocess.run(
                    [candidate], capture_output=True, text=True, timeout=2
                )
                output = (probe.stdout or "") + (probe.stderr or "")
                if "SnmpSoft" in output:
                    return ("snmpsoft", candidate)
            except Exception:
                pass

        for candidate in candidates:
            if shutil.which(candidate) is None:
                continue
            try:
                probe = subprocess.run(
                    [candidate, "--help"], capture_output=True, text=True, timeout=5
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
            pass

        return (None, None)

    def _install_snmpwalk(self) -> bool:
        """Attempt to install Net-SNMP via the system package manager."""
        system = platform.system()
        print("      Attempting to install Net-SNMP...", file=sys.stderr)

        native_ok = False
        try:
            if system == "Linux":
                native_ok = self._install_snmpwalk_linux()
            elif system == "Darwin":
                native_ok = self._install_snmpwalk_macos()
            elif system == "Windows":
                native_ok = self._install_snmpwalk_windows()
            else:
                print(f"      Unsupported platform: {system}", file=sys.stderr)
        except Exception as exc:
            print(f"      Native installation attempt failed: {exc}", file=sys.stderr)

        if native_ok:
            return True

        print("      Native install unavailable/failed. Falling back to pysnmp...", file=sys.stderr)
        return self._install_pysnmp()

    def _install_snmpwalk_linux(self) -> bool:
        """Install Net-SNMP on Linux via the available package manager."""
        if shutil.which("apt-get"):
            print("      Detected Debian/Ubuntu. Installing via apt-get...", file=sys.stderr)
            subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False, timeout=120)
            subprocess.run(["sudo", "apt-get", "install", "-y", "snmp"], check=True, timeout=300)
        elif shutil.which("dnf"):
            print("      Detected Fedora/RHEL. Installing via dnf...", file=sys.stderr)
            subprocess.run(["sudo", "dnf", "install", "-y", "net-snmp-utils"], check=True, timeout=300)
        elif shutil.which("yum"):
            print("      Detected RHEL/CentOS. Installing via yum...", file=sys.stderr)
            subprocess.run(["sudo", "yum", "install", "-y", "net-snmp-utils"], check=True, timeout=300)
        else:
            print("      No supported package manager found (apt-get/dnf/yum).", file=sys.stderr)
            return False
        return self._detect_snmpwalk()[0] is not None

    def _install_snmpwalk_windows(self) -> bool:
        """Install Net-SNMP on Windows by downloading the official binary."""
        url = (
            "https://sourceforge.net/projects/net-snmp/files/"
            "net-snmp%20binaries/5.5-binaries/net-snmp-5.5.0-2.x64.exe/download"
        )
        installer_name = "net-snmp-5.5.0-2.x64.exe"
        download_dir = os.path.join(os.environ.get("TEMP", os.environ.get("TMP", ".")))
        installer_path = os.path.join(download_dir, installer_name)

        print(f"      Downloading Net-SNMP installer from SourceForge...", file=sys.stderr)
        try:
            urllib.request.urlretrieve(url, installer_path)
        except Exception as exc:
            print(f"      Download failed: {exc}", file=sys.stderr)
            print(
                "      Manual install: download from "
                "https://sourceforge.net/projects/net-snmp/files/net-snmp%20binaries/",
                file=sys.stderr,
            )
            return False

        print("      Running silent install...", file=sys.stderr)
        try:
            subprocess.run([installer_path, "/S"], check=True, timeout=120)
        except subprocess.CalledProcessError as exc:
            print(f"      Silent install failed (rc={exc.returncode}).", file=sys.stderr)
            return False
        except subprocess.TimeoutExpired:
            print("      Silent install timed out.", file=sys.stderr)
            return False
        finally:
            try:
                os.remove(installer_path)
            except OSError:
                pass

        win_bindir = os.path.join(os.environ.get("SystemDrive", "C:"), "usr", "bin")
        net_snmp_bindir = os.path.join(os.environ.get("SystemDrive", "C:"), "net-snmp", "bin")
        for path_dir in (win_bindir, net_snmp_bindir):
            if os.path.isdir(path_dir) and path_dir not in os.environ.get("PATH", ""):
                os.environ["PATH"] = path_dir + os.pathsep + os.environ.get("PATH", "")

        return self._detect_snmpwalk()[0] is not None

    def _install_snmpwalk_macos(self) -> bool:
        """Install Net-SNMP on macOS via Homebrew."""
        print("      Detected macOS. Installing via Homebrew...", file=sys.stderr)
        subprocess.run(["brew", "install", "net-snmp"], check=True, timeout=300)
        return self._detect_snmpwalk()[0] is not None

    def _install_pysnmp(self) -> bool:
        """Install the pysnmp Python library via pip (cross-platform)."""
        print("      Installing pysnmp via pip...", file=sys.stderr)
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "pysnmp"],
                check=True,
                timeout=120,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip()[:500] if exc.stderr else ""
            print(f"      pip install pysnmp failed (rc={exc.returncode}): {stderr}", file=sys.stderr)
            return False
        except subprocess.TimeoutExpired:
            print("      pip install pysnmp timed out.", file=sys.stderr)
            return False
        return self._detect_snmpwalk()[0] is not None

    def _validate_snmp_walk_pysnmp(self, ip: str, user: str, auth: str, priv: str) -> bool:
        """Perform an SNMP walk using the pysnmp Python library."""
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                SnmpEngine,
                UsmUserData,
                UdpTransportTarget,
                ContextData,
                ObjectType,
                ObjectIdentity,
                walk_cmd,
                usmHMAC192SHA256AuthProtocol,
                usmAesCfb256Protocol,
            )
        except ImportError:
            try:
                from pysnmp.hlapi import (
                    SnmpEngine,
                    UsmUserData,
                    UdpTransportTarget,
                    ContextData,
                    nextCmd,
                    ObjectType,
                    ObjectIdentity,
                    ObjectIdentity,
                    usmAesCfb256Protocol,
                )
                try:
                    from pysnmp.hlapi import usmHMAC192SHA256AuthProtocol
                except ImportError:
                    usmHMAC192SHA256AuthProtocol = (1, 3, 6, 1, 6, 3, 10, 1, 1, 5)
            except ImportError:
                print("      pysnmp library not available.", file=sys.stderr)
                return False
            else:
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    SnmpEngine(),
                    UsmUserData(
                        user,
                        auth,
                        priv,
                        authProtocol=usmHMAC192SHA256AuthProtocol,
                        privProtocol=usmAesCfb256Protocol,
                    ),
                    UdpTransportTarget((ip, self.DEFAULT_SNMP_PORT), timeout=10, retries=2),
                    ContextData(),
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.1")),
                ):
                    if errorIndication:
                        print(f"      SNMP walk (pysnmp): {errorIndication}", file=sys.stderr)
                        return False
                    if errorStatus:
                        print(
                            f"      SNMP walk (pysnmp): {errorStatus.prettyPrint()}",
                            file=sys.stderr,
                        )
                        return False
                    return True
                return False

        async def _async_walk():
            transport = await UdpTransportTarget.create(
                (ip, self.DEFAULT_SNMP_PORT), timeout=10, retries=2
            )
            async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
                SnmpEngine(),
                UsmUserData(
                    user,
                    auth,
                    priv,
                    authProtocol=usmHMAC192SHA256AuthProtocol,
                    privProtocol=usmAesCfb256Protocol,
                ),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1")),
            ):
                if errorIndication:
                    print(f"      SNMP walk (pysnmp): {errorIndication}", file=sys.stderr)
                    return False
                if errorStatus:
                    print(
                        f"      SNMP walk (pysnmp): {errorStatus.prettyPrint()}",
                        file=sys.stderr,
                    )
                    return False
                return True
            return False

        try:
            return asyncio.run(_async_walk())
        except Exception as exc:
            print(f"      SNMP walk (pysnmp) encountered an error: {exc}", file=sys.stderr)
            return False
