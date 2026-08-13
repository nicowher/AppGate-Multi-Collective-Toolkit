#!/usr/bin/env python3
"""
AppGate SNMPv3 Configuration Script

Automates SNMPv3 user configuration on AppGate appliances by:
1. Prompting for SNMP credentials and AppGate IP
2. Authenticating to AppGate API to obtain token
3. Retrieving the appliance's SNMP Engine ID via SSH
4. Generating SNMPv3 password hashes via snmpv3-hashgen
5. Pushing updated snmpd.conf to the AppGate API
6. Validating configuration with an SNMP walk
"""

import json
import os
import re
import subprocess
import sys
import uuid
from getpass import getpass
from typing import Any, Dict, Optional, Tuple

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Error: 'requests' library is required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import paramiko
except ImportError:
    paramiko = None


class AppGateSNMPConfig:
    """Encapsulates AppGate SNMPv3 configuration workflow."""

    DEFAULT_API_VERSION = "23"
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
            "Content-Type": "application/JSON",
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
            raise ValueError("Login response did not contain an API token")

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
        return response.json().get("data", [])

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
                stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
                stdin.write(self.ssh_password + "\n")
                stdin.flush()
                stdin.channel.shutdown_write()

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
                "      No engine ID found in /var/lib/snmp/snmpd.conf. "
                "Check permissions or file path.",
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
                "grep -E 'usmUser' /var/lib/snmp/snmpd.conf | head -n 1",
                timeout=15,
            )
            output = stdout.read().decode("utf-8", errors="replace")
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

        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
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
            "snmpv3-hashgen tool not found. Ensure it is installed and in PATH."
        )

    # ------------------------------------------------------------------
    # AppGate API update
    # ------------------------------------------------------------------
    def update_snmp_config(
        self,
        user: str,
        auth_hash: str,
        priv_hash: str,
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

        # Merge with existing snmpd.conf (avoid duplicate createUser lines)
        existing_conf = appliance.get("snmpServer", {}).get("snmpd.conf", "")
        lines = existing_conf.splitlines() if existing_conf else []
        lines = [
            line for line in lines
            if not re.match(rf"^createUser\s+{re.escape(user)}\s", line)
        ]
        lines.append(create_user_line)
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
        put_response.raise_for_status()
        return True

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def validate_snmp_walk(self, ip: str, user: str, auth: str, priv: str) -> bool:
        """Run ``snmpwalk`` to verify the new SNMPv3 credentials."""
        candidates = ["snmpwalk", "snmpwalk.exe", "SnmpWalk.exe", "SnmpWalk"]
        cmd = None

        for candidate in candidates:
            try:
                probe = subprocess.run([candidate], capture_output=True, text=True, timeout=2)
                output = (probe.stdout or "") + (probe.stderr or "")
                if "SnmpSoft" in output:
                    cmd = [
                        candidate,
                        f"-r:{ip}",
                        "-v:3",
                        f"-sn:{user}",
                        "-ap:SHA", f"-aw:{auth}",
                        "-pp:AES128", f"-pw:{priv}",
                    ]
                    break
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue

        if cmd is None:
            for candidate in candidates:
                try:
                    subprocess.run([candidate, "--help"], capture_output=True, check=True, timeout=5)
                    cmd = [
                        candidate,
                        "-v3",
                        "-u", user,
                        "-l", "authPriv",
                        "-a", "SHA", "-A", auth,
                        "-x", "AES", "-X", priv,
                        ip,
                    ]
                    break
                except (FileNotFoundError, subprocess.CalledProcessError):
                    continue

        if cmd is None:
            print(
                "      SNMP validation skipped: snmpwalk/SnmpWalk is not installed or not in PATH. "
                "Install Net-SNMP to enable automatic validation.",
                file=sys.stderr,
            )
            return False

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return True

            print(f"      SNMP walk failed (rc={result.returncode})", file=sys.stderr)
            if result.stdout.strip():
                print(f"      stdout: {result.stdout.strip()[:500]}", file=sys.stderr)
            if result.stderr.strip():
                print(f"      stderr: {result.stderr.strip()[:500]}", file=sys.stderr)
            print(f"      cmd: {' '.join(cmd)}", file=sys.stderr)
            return False
        except FileNotFoundError:
            print(
                "      SNMP validation skipped: snmpwalk is not installed or not in PATH. "
                "Install Net-SNMP to enable automatic validation.",
                file=sys.stderr,
            )
            return False


# ----------------------------------------------------------------------
# Interactive prompts
# ----------------------------------------------------------------------
def prompt_snmp_inputs() -> Dict[str, str]:
    """Collect SNMP and AppGate IP from the operator."""
    print("=" * 60)
    print("AppGate SNMPv3 Configuration Script")
    print("=" * 60)

    inputs = {
        "snmp_user": input("SNMP User: ").strip(),
        "snmp_auth": input("SNMP Auth: ").strip(),
        "snmp_priv": input("SNMP Priv: ").strip(),
        "agip":      input("AppGate IP Address: ").strip(),
    }

    if not all(inputs.values()):
        raise ValueError("All input fields are required")
    return inputs


def prompt_admin_credentials() -> Tuple[str, str]:
    """Collect AppGate API admin credentials."""
    print("\nAppGate API Authentication")
    username = input("AppGate Admin Username: ").strip()
    password = getpass("AppGate Admin Password: ").strip()

    if not username or not password:
        raise ValueError("Admin credentials are required")
    return username, password


def prompt_ssh_credentials() -> Tuple[str, str]:
    """Collect SSH credentials for the AppGate appliance."""
    print("\nAppliance SSH Authentication")
    username = input("SSH Username: ").strip()
    password = getpass("SSH Password: ").strip()

    if not username or not password:
        raise ValueError("SSH credentials are required")
    return username, password


# ----------------------------------------------------------------------
# Main workflow
# ----------------------------------------------------------------------
def main() -> None:
    try:
        inputs = prompt_snmp_inputs()
        admin_user, admin_pass = prompt_admin_credentials()
        ssh_user, ssh_pass = prompt_ssh_credentials()

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
        config.update_snmp_config(config.SNMPUser, config.SNMPAuthHash, config.SNMPPrivHash)
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
