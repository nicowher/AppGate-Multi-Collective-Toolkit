#!/usr/bin/env python3
"""
AppGate SNMPv3 Configuration Script

Automates SNMPv3 user configuration on AppGate appliances by:
1. Prompting for SNMP credentials, read-only user, and AppGate IP
2. Authenticating to AppGate API to obtain token
3. Retrieving the appliance's SNMP Engine ID via SSH
4. Generating SNMPv3 password hashes via snmpv3-hashgen
5. Pushing updated snmpd.conf to the AppGate API
6. Validating configuration with an SNMP walk
"""

import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import uuid
import urllib.request
from getpass import getpass
from typing import Any, Dict, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_PATH = os.path.join(SCRIPT_DIR, "credentials.json")


def ensure_package(package: str, import_name: str) -> None:
    module = importlib.util.find_spec(import_name)
    spec = module.find_spec(import_name)
    if spec is not None:
        return
    print(f"Missing required package: {package}", file=sys.stderr)
    answer = input(f"Install {package} now via pip? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes"):
        subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)
        return
    print(f"Please install {package} manually and rerun.", file=sys.stderr)
    sys.exit(1)


try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    ensure_package("requests", "requests")
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    import paramiko
except ImportError:
    ensure_package("paramiko", "paramiko")
    import paramiko


def load_credentials() -> Dict[str, str]:
    if not os.path.isfile(CREDENTIALS_PATH):
        return {}
    try:
        with open(CREDENTIALS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        return {k: str(v) for k, v in data.items()}
    except Exception as exc:
        print(f"Warning: Could not load credentials from {CREDENTIALS_PATH}: {exc}", file=sys.stderr)
        return {}


class AppGateSNMPConfig:
    """Encapsulates AppGate SNMPv3 configuration workflow."""

    DEFAULT_API_VERSION = "24"
    DEFAULT_PROVIDER = "local"
    DEFAULT_SNMP_PORT = 161
    MACHINE_ID = "f0031c00-0522-43b3-a642-ae23cfd1bc22"

    def __init__(self, agip: str, api_version: Optional[str] = None, provider: str = DEFAULT_PROVIDER) -> None:
        self.agip = agip
        self.api_version = api_version or self.DEFAULT_API_VERSION
        self.provider = provider
        self.base_url = f"https://{agip}:8443/admin"
        self.machine_id = self.MACHINE_ID

        self.headers: Dict[str, str] = {
            "Accept": f"application/vnd.appgate.peer-v{self.api_version}+json",
            "Content-Type": "application/json",
        }

        # State variables (equivalent to the {{...}} placeholders)
        self.AGAPIKey: Optional[str] = None
        self.EngineID: Optional[str] = None
        self.SNMPUser: Optional[str] = None
        self.SNMPAuth: Optional[str] = None
        self.SNMPAuthHash: Optional[str] = None
        self.SNMPPriv: Optional[str] = None
        self.SNMPPrivHash: Optional[str] = None
        self.appliance_id: Optional[str] = None
        self.ssh_user: Optional[str] = None
        self.ssh_password: Optional[str] = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def login(self, username: str, password: str, provider: Optional[str] = None) -> str:
        """Authenticate to the AppGate API and store the bearer token."""
        provider_name = provider or self.provider
        payload = {
            "machineId": self.machine_id,
            "providerName": provider_name,
            "username": username,
            "password": password,
        }

        response = requests.post(
            f"{self.base_url}/login",
            headers=self.headers,
            json=payload,
            verify=False,
            timeout=30,
        )

        if response.status_code != 200:
            self._handle_login_error(response, username, provider_name)

        data = response.json()
        self.AGAPIKey = data.get("token")
        if not self.AGAPIKey:
            body_preview = (response.text or "")[:300]
            raise ValueError(
                f"Login response did not contain an API token. "
                f"HTTP {response.status_code}. Response body: {body_preview}"
            )

        self.headers["Authorization"] = f"Bearer {self.AGAPIKey}"
        return self.AGAPIKey

    def _handle_login_error(self, response: requests.Response, username: str, provider: str) -> None:
        """Provide actionable guidance for common 401/403 responses."""
        try:
            body = response.json()
            msg = body.get("message", response.text)
            err_id = body.get("id", "")
            failure = body.get("failureType", "")
        except Exception:
            msg = response.text or f"HTTP {response.status_code}"
            err_id = ""
            failure = ""

        if response.status_code == 401:
            if "MFA" in msg or failure == "MfaRequired" or "twoFactor" in msg.lower():
                print(
                    "ERROR: Admin MFA is enabled. Either disable MFA for this API user in AppGate, "
                    "or use a SAML/OIDC provider that supports token-based login.",
                    file=sys.stderr,
                )
            elif "unauthorized" in err_id or "Invalid username or password" in msg:
                print(
                    "ERROR: Invalid username or password. Verify the credentials and try again.",
                    file=sys.stderr,
                )
            else:
                print(f"ERROR: Login failed (HTTP 401): {msg}", file=sys.stderr)
            print(
                "\nTroubleshooting tips:\n"
                "  - Confirm the account has API access and is exempt from Admin MFA\n"
                "  - Verify providerName is correct (common values: 'local', 'saml', 'oidc')\n"
                "  - Ensure the machineId is accepted by the Controller\n",
                file=sys.stderr,
            )
        elif response.status_code == 403:
            print(
                f"ERROR: Insufficient permissions (HTTP 403): {msg}\n"
                "Ensure the API user has the required admin role privileges.",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: Login failed (HTTP {response.status_code}): {msg}", file=sys.stderr)

        raise SystemExit(1)

    # ------------------------------------------------------------------
    # Appliance discovery
    # ------------------------------------------------------------------
    def get_appliances(self) -> list:
        """Return all appliances visible to the current API user."""
        response = requests.get(
            f"{self.base_url}/appliances",
            headers=self.headers,
            verify=False,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        if "data" not in data:
            raise ValueError(
                f"Unexpected appliances response format. "
                f"HTTP {response.status_code}. Body preview: {(response.text or '')[:300]}"
            )
        return data.get("data", [])

    def find_appliance_by_ip(self, ip: str) -> Dict[str, Any]:
        """Locate the appliance object whose interface matches *ip*."""
        for appliance in self.get_appliances():
            if self._ip_matches_appliance(ip, appliance):
                self.appliance_id = appliance["id"]
                return appliance
        raise ValueError(f"Appliance with IP address {ip} not found in AppGate")

    @staticmethod
    def _ip_matches_appliance(ip: str, appliance: Dict[str, Any]) -> bool:
        for iface in (
            appliance.get("adminInterface", {}),
            appliance.get("clientInterface", {}),
        ):
            if iface.get("hostname") == ip:
                return True

        for nic in appliance.get("networking", {}).get("nics", []):
            for addr in nic.get("ipv4", {}).get("static", []):
                if addr.get("address") == ip:
                    return True
            for addr in nic.get("ipv6", {}).get("static", []):
                if addr.get("address") == ip:
                    return True
        return False

    # ------------------------------------------------------------------
    # Engine ID retrieval
    # ------------------------------------------------------------------
    def get_engine_id(self) -> str:
        """
        Pull the SNMP Engine ID from the appliance via SSH.

        Runs ``grep -E usmUser /var/lib/snmp/snmpd.conf`` on the appliance
        and extracts the engine ID from the first matching line.
        """
        if not self.ssh_user or not self.ssh_password:
            raise ValueError("SSH credentials are required to retrieve the Engine ID")

        engine = self._ssh_query_engine_id(self.agip)
        if not engine:
            raise ValueError("Could not retrieve Engine ID from appliance via SSH")

        self.EngineID = engine
        return self.EngineID

    def _ssh_query_engine_id(self, ip: str) -> Optional[str]:
        """SSH to the appliance and extract engine ID from snmpd.conf."""
        if paramiko is None:
            raise RuntimeError(
                "paramiko is required for SSH engine ID retrieval. "
                "Install it with: pip install paramiko"
            )

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=ip,
                username=self.ssh_user,
                password=self.ssh_password,
                timeout=15,
                allow_agent=False,
                look_for_keys=False,
                auth_timeout=15,
            )

            commands = [
                "sudo -S grep -E 'usmUser' /var/lib/snmp/snmpd.conf | head -n 1",
                "sudo -S grep -E 'oldEngineID' /var/lib/snmp/snmpd.conf | head -n 1",
                "sudo -S find / -name 'snmpd.conf' -type f 2>/dev/null | head -n 10",
                "sudo -S grep -R -E 'usmUser' /var/lib/snmp/ /var/net-snmp/ /etc/snmp/ 2>/dev/null | head -n 1",
            ]

            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(cmd)
                stdout.channel.settimeout(15)
                stdin.write(self.ssh_password + "\n")
                stdin.flush()

                output = stdout.read().decode("utf-8", errors="replace")
                err_output = stderr.read().decode("utf-8", errors="replace")
                exit_status = stdout.channel.recv_exit_status()

                if exit_status not in (0, 1) or err_output.strip():
                    print(f"      SSH command failed (exit {exit_status}): {err_output.strip()}", file=sys.stderr)

                if output.strip():
                    print(f"      SSH command succeeded: {cmd}", file=sys.stderr)
                    match = re.search(r"0x([0-9a-fA-F]{32,})", output)
                    if match:
                        return match.group(1)

            print(
                "      No engine ID found. Tried commands:\n"
                + "\n".join(f"        - {cmd}" for cmd in commands)
                + "\n      Check SSH access, sudo permissions, and snmpd.conf location.",
                file=sys.stderr,
            )
        except paramiko.AuthenticationException as exc:
            print(
                f"      SSH authentication failed: {exc}. "
                f"Trying keyboard-interactive fallback...",
                file=sys.stderr,
            )
            return self._ssh_query_engine_id_keyboard_interactive(ip)
        except paramiko.SSHException as exc:
            print(f"      SSH connection error: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"      SSH error: {exc}", file=sys.stderr)
        finally:
            try:
                client.close()
            except Exception:
                pass
        return None

    def _ssh_query_engine_id_keyboard_interactive(self, ip: str) -> Optional[str]:
        """Fallback SSH using keyboard-interactive authentication."""
        if paramiko is None:
            return None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            def handler(title, instructions, prompt_list):
                responses = []
                for prompt in prompt_list:
                    if "password" in prompt[0].lower():
                        responses.append(self.ssh_password)
                    else:
                        responses.append("")
                return responses

            client.connect(
                hostname=ip,
                username=self.ssh_user,
                timeout=15,
                allow_agent=False,
                look_for_keys=False,
                auth_timeout=15,
                password=self.ssh_password,
            )
            stdin, stdout, stderr = client.exec_command(
                "sudo -S grep -E 'usmUser' /var/lib/snmp/snmpd.conf | head -n 1",
            )
            stdout.channel.settimeout(15)
            stdin.write(self.ssh_password + "\n")
            stdin.flush()

            output = stdout.read().decode("utf-8", errors="replace")
            err_output = stderr.read().decode("utf-8", errors="replace")
            exit_status = stdout.channel.recv_exit_status()

            if exit_status not in (0, 1) or err_output.strip():
                print(
                    f"      Keyboard-interactive SSH command failed (exit {exit_status}): "
                    f"{err_output.strip()}",
                    file=sys.stderr,
                )

            if output.strip():
                print(f"      Keyboard-interactive SSH command succeeded", file=sys.stderr)
                match = re.search(r"0x([0-9a-fA-F]{32,})", output)
                if match:
                    return match.group(1)
        except Exception as exc:
            print(f"      Keyboard-interactive SSH also failed: {exc}", file=sys.stderr)
        finally:
            try:
                client.close()
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------
    # Hash generation
    # ------------------------------------------------------------------
    def generate_hashes(self, user: str, auth: str, priv: str, engine_id: str) -> Dict[str, Any]:
        """
        Execute ``snmpv3-hashgen`` and return the parsed JSON output.

        Stores the resulting hashes on the instance.
        """
        script_path = self._resolve_hashgen_script()

        if script_path.endswith(".py"):
            cmd = [sys.executable, script_path]
        else:
            cmd = [script_path]

        cmd.extend([
            "--user", user,
            "--auth", auth,
            "--priv", priv,
            "--engine", engine_id,
            "--hash", "sha1",
            "--mode", "priv",
            "--json",
        ])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"snmpv3-hashgen failed (rc={exc.returncode}). "
                f"stderr: {exc.stderr.strip()[:500]}"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"snmpv3-hashgen executable not found: {cmd[0]}. "
                "Ensure it is installed and in PATH."
            ) from exc
        data = json.loads(result.stdout)

        self.SNMPUser = data["user"]
        self.SNMPAuthHash = data["hashes"]["auth"]
        self.SNMPPrivHash = data["hashes"]["priv"]

        return data

    @staticmethod
    def _resolve_hashgen_script() -> str:
        """Locate the snmpv3-hashgen CLI script."""
        workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates = [
            "snmpv3-hashgen",
            "snmpv3_hashgen",
            os.path.join(workspace_root, "SNMPv3-Hash-Generator", "scripts", "snmpv3_hashgen.py"),
        ]

        for candidate in candidates:
            try:
                if candidate.endswith(".py"):
                    subprocess.run(
                        [sys.executable, candidate, "--help"],
                        capture_output=True,
                        check=True,
                        timeout=5,
                    )
                    return candidate
                subprocess.run(
                    [candidate, "--help"],
                    capture_output=True,
                    check=True,
                    timeout=5,
                )
                return candidate
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue

        raise FileNotFoundError(
            f"snmpv3-hashgen tool not found. Checked: {candidates}. "
            "Ensure it is installed and in PATH."
        )

    # ------------------------------------------------------------------
    # AppGate API update
    # ------------------------------------------------------------------
    def update_snmp_config(
        self,
        user: str,
        auth_hash: str,
        priv_hash: str,
        rouser_line: str = "",
        enabled: bool = True,
    ) -> bool:
        """
        Push the updated ``snmpd.conf`` to the AppGate appliance.

        AppGate requires the **entire** appliance object on PUT, so we
        GET the current state, modify the ``snmpServer`` block, and PUT
        the full object back.
        """
        if not self.appliance_id:
            raise RuntimeError("Appliance ID is not set. Run find_appliance_by_ip first.")

        # Fetch current appliance configuration
        response = requests.get(
            f"{self.base_url}/appliances/{self.appliance_id}",
            headers=self.headers,
            verify=False,
            timeout=30,
        )
        response.raise_for_status()
        appliance = response.json()

        # Build createUser line
        create_user_line = (
            f"createUser {user} SHA -l 0x{auth_hash} AES -l 0x{priv_hash}"
        )

        # Merge with existing snmpd.conf (avoid duplicate lines)
        existing_conf = appliance.get("snmpServer", {}).get("snmpd.conf", "")
        lines = existing_conf.splitlines() if existing_conf else []
        lines = [
            line for line in lines
            if not re.match(rf"^createUser\s+{re.escape(user)}\s", line)
        ]
        lines = [
            line for line in lines
            if not re.match(rf"^(rouser|deleteUser)\s+{re.escape(user)}\s", line)
        ]
        if rouser_line:
            lines.append(rouser_line)
        lines.append(f"deleteUser {user}")
        lines.append(create_user_line)
        if self.EngineID:
            lines.append(f"exactEngineID 0x{self.EngineID}")
        new_conf = "\n".join(lines)

        # Update the snmpServer block
        appliance["snmpServer"] = {
            "enabled": enabled,
            "snmpd.conf": new_conf,
            "tcpPort": self.DEFAULT_SNMP_PORT,
            "udpPort": self.DEFAULT_SNMP_PORT,
        }

        # PUT the full appliance object back
        put_response = requests.put(
            f"{self.base_url}/appliances/{self.appliance_id}",
            headers=self.headers,
            json=appliance,
            verify=False,
            timeout=30,
        )
        if put_response.status_code != 200:
            body_preview = (put_response.text or "")[:500]
            raise RuntimeError(
                f"Failed to update SNMP config (HTTP {put_response.status_code}): {body_preview}"
            )
        return True

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def _detect_snmpwalk(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect an available SNMP walk tool.

        Returns ``(tool_type, executable_path)`` where *tool_type* is
        ``"netsnmp"`` (Net-SNMP on Linux/macOS/Windows), ``"snmpsoft"``
        (SnmpSoft SnmpWalk on Windows), or ``"pysnmp"`` (Python library).
        Returns ``(None, None)`` when nothing suitable is found.
        """
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
        """
        Attempt to install Net-SNMP via the system package manager.

        After installation the ``PATH`` is refreshed so that a subsequent
        ``_detect_snmpwalk`` call can find the freshly installed binary.
        If the native install fails, ``pysnmp`` is installed via pip as a
        cross-platform fallback.

        Returns ``True`` if an SNMP walk tool is available afterwards.
        """
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
        """
        Install Net-SNMP on Windows by downloading the official binary
        from SourceForge and running a silent install.
        """
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

        # Add common install dirs to PATH for this session
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

    def _validate_snmp_walk_pysnmp(
        self, ip: str, user: str, auth: str, priv: str
    ) -> bool:
        """Perform an SNMP walk using the pysnmp Python library."""
        try:
            from pysnmp.hlapi import (
                SnmpEngine,
                UsmUserData,
                UdpTransportTarget,
                ContextData,
                nextCmd,
                ObjectType,
                ObjectIdentity,
                usmHMACSHAAuthProtocol,
                usmAesCfb128Protocol,
            )
        except ImportError:
            try:
                from pysnmp.hlapi.v1arch import (
                    SnmpEngine,
                    UsmUserData,
                    UdpTransportTarget,
                    ContextData,
                    nextCmd,
                    ObjectType,
                    ObjectIdentity,
                    usmHMACSHAAuthProtocol,
                    usmAesCfb128Protocol,
                )
            except ImportError:
                print("      pysnmp library not available.", file=sys.stderr)
                return False

        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                UsmUserData(
                    user,
                    auth,
                    priv,
                    authProtocol=usmHMACSHAAuthProtocol,
                    privProtocol=usmAesCfb128Protocol,
                ),
                UdpTransportTarget((ip, self.DEFAULT_SNMP_PORT)),
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
        except Exception as exc:
            print(f"      SNMP walk (pysnmp) encountered an error: {exc}", file=sys.stderr)
            return False

    def validate_snmp_walk(self, ip: str, user: str, auth: str, priv: str) -> bool:
        """Run an SNMP walk to verify the new SNMPv3 credentials.

        Supports three backends, in order of preference:
        1. Net-SNMP ``snmpwalk`` (Linux/macOS/Windows)
        2. SnmpSoft ``SnmpWalk.exe`` (Windows)
        3. ``pysnmp`` Python library (cross-platform)

        If no SNMP walk tool is found, an attempt is made to install one
        automatically and the walk is retried.
        """
        candidates = ["snmpwalk", "snmpwalk.exe", "SnmpWalk.exe", "SnmpWalk", "pysnmp"]

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
                "-ap:SHA", f"-aw:{auth}",
                "-pp:AES128", f"-pw:{priv}",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(
                    f"      SNMP walk failed (rc={result.returncode}): "
                    f"{result.stderr.strip()[:500] or result.stdout.strip()[:500]}",
                    file=sys.stderr,
                )
                print(f"      cmd: {' '.join(cmd)}", file=sys.stderr)
                return False
            return True

        if tool_type == "pysnmp":
            print("      Using pysnmp for SNMP walk validation...", file=sys.stderr)
            return self._validate_snmp_walk_pysnmp(ip, user, auth, priv)

        cmd = [
            executable,
            "-v3",
            "-u", user,
            "-l", "authPriv",
            "-a", "SHA", "-A", auth,
            "-x", "AES", "-X", priv,
            ip,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(
                f"      SNMP walk failed (rc={result.returncode}): "
                f"{result.stderr.strip()[:500] or result.stdout.strip()[:500]}",
                file=sys.stderr,
            )
            print(f"      cmd: {' '.join(cmd)}", file=sys.stderr)
            return False
        return True


# ----------------------------------------------------------------------
# Interactive prompts
# ----------------------------------------------------------------------
def prompt_snmp_inputs(creds: Dict[str, str]) -> Dict[str, str]:
    """Collect SNMP and AppGate IP from the operator."""
    print("=" * 60)
    print("AppGate SNMPv3 Configuration Script")
    print("=" * 60)

    inputs = {
        "snmp_user": input(f"SNMP User [{creds.get('snmp_user', '')}]: ").strip() or creds.get("snmp_user", ""),
        "snmp_auth": input(f"SNMP Auth [{creds.get('snmp_auth', '')}]: ").strip() or creds.get("snmp_auth", ""),
        "snmp_priv": input(f"SNMP Priv [{creds.get('snmp_priv', '')}]: ").strip() or creds.get("snmp_priv", ""),
        "agip":      input(f"AppGate IP Address [{creds.get('agip', '')}]: ").strip() or creds.get("agip", ""),
        "rouser":    input(f"SNMP Read-Only Username (rouser) [{creds.get('rouser', '')}]: ").strip() or creds.get("rouser", ""),
    }

    if not all(inputs[k] for k in ("snmp_user", "snmp_auth", "snmp_priv", "agip")):
        raise ValueError("All required input fields are missing")
    return inputs


def prompt_admin_credentials(creds: Dict[str, str]) -> Tuple[str, str]:
    """Collect AppGate API admin credentials."""
    print("\nAppGate API Authentication")
    username = input(f"AppGate Admin Username [{creds.get('admin_username', '')}]: ").strip() or creds.get("admin_username", "")
    password = getpass(f"AppGate Admin Password [{creds.get('admin_password', '')}]: ").strip() or creds.get("admin_password", "")

    if not username or not password:
        raise ValueError("Admin credentials are required")
    return username, password


def prompt_ssh_credentials(creds: Dict[str, str]) -> Tuple[str, str]:
    """Collect SSH credentials for the AppGate appliance."""
    print("\nAppliance SSH Authentication")
    username = input(f"SSH Username [{creds.get('ssh_username', '')}]: ").strip() or creds.get("ssh_username", "")
    password = getpass(f"SSH Password [{creds.get('ssh_password', '')}]: ").strip() or creds.get("ssh_password", "")

    if not username or not password:
        raise ValueError("SSH credentials are required")
    return username, password


# ----------------------------------------------------------------------
# Main workflow
# ----------------------------------------------------------------------
def main() -> None:
    try:
        creds = load_credentials()

        def require(field: str, prompt: str, sensitive: bool = False) -> str:
            value = creds.get(field, "")
            if not value:
                if sensitive:
                    value = getpass(f"{prompt}: ").strip()
                else:
                    value = input(f"{prompt}: ").strip()
            return value

        inputs = {
            "snmp_user": require("snmp_user", "SNMP User"),
            "snmp_auth": require("snmp_auth", "SNMP Auth", sensitive=True),
            "snmp_priv": require("snmp_priv", "SNMP Priv", sensitive=True),
            "agip":      require("agip", "AppGate IP Address"),
            "rouser":    require("rouser", "SNMP Read-Only Username (rouser)"),
        }

        if not all(inputs[k] for k in ("snmp_user", "snmp_auth", "snmp_priv", "agip")):
            raise ValueError("All required input fields are missing")

        admin_user = require("admin_username", "AppGate Admin Username")
        admin_pass = require("admin_password", "AppGate Admin Password", sensitive=True)
        ssh_user   = require("ssh_username", "SSH Username")
        ssh_pass   = require("ssh_password", "SSH Password", sensitive=True)

        config = AppGateSNMPConfig(inputs["agip"])
        config.SNMPUser = inputs["snmp_user"]
        config.SNMPAuth = inputs["snmp_auth"]
        config.SNMPPriv = inputs["snmp_priv"]
        config.ssh_user = ssh_user
        config.ssh_password = ssh_pass

        # 1. Authenticate
        print("\n[1/6] Authenticating to AppGate API...")
        token = config.login(admin_user, admin_pass)
        print(f"      API Key obtained: {token[:12]}...")

        # 2. Locate appliance
        print("\n[2/6] Locating appliance...")
        appliance = config.find_appliance_by_ip(inputs["agip"])
        print(f"      Found: {appliance.get('name', 'N/A')} ({config.appliance_id})")

        # 3. Retrieve Engine ID
        print("\n[3/6] Retrieving Engine ID via SSH...")
        engine_id = config.get_engine_id()
        if engine_id.lower().startswith("0x"):
            engine_id = engine_id[2:]
        config.EngineID = engine_id
        print(f"      Engine ID: {engine_id}")

        # 4. Generate hashes
        print("\n[4/6] Generating SNMPv3 password hashes...")
        config.generate_hashes(config.SNMPUser, config.SNMPAuth, config.SNMPPriv, config.EngineID)
        print(f"      Auth Hash: {config.SNMPAuthHash}")
        print(f"      Priv Hash: {config.SNMPPrivHash}")

        # 5. Push to AppGate
        print("\n[5/6] Updating AppGate SNMP configuration...")
        rouser_line = ""
        if inputs.get("rouser"):
            rouser_line = f"rouser {inputs['rouser']} priv"
        config.update_snmp_config(
            config.SNMPUser,
            config.SNMPAuthHash,
            config.SNMPPrivHash,
            rouser_line,
        )
        print("      SNMP configuration updated successfully")

        # 6. Validate
        print("\n[6/6] Validating SNMP walk...")
        ok = config.validate_snmp_walk(
            inputs["agip"], config.SNMPUser, config.SNMPAuth, config.SNMPPriv
        )
        print("      SNMP walk validation " + ("PASSED" if ok else "FAILED"))

        # Summary
        print("\n" + "=" * 60)
        print("Configuration Summary")
        print("=" * 60)
        print(f"User:           {config.SNMPUser}")
        print(f"Auth:           {config.SNMPAuth} / {config.SNMPAuthHash}")
        print(f"Priv:           {config.SNMPPriv} / {config.SNMPPrivHash}")
        print(f"Engine:         {config.EngineID}")
        if rouser_line:
            print(f"Read-Only:      {rouser_line}")
        print(
            f"ESXi USM String: "
            f"{config.SNMPUser}/{config.SNMPAuthHash}/{config.SNMPPrivHash}/priv"
        )
        print("=" * 60)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
