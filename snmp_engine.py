from utils import ensure_package

try:
    import paramiko
except ImportError:
    ensure_package("paramiko", "paramiko")
    import paramiko

import re
import sys
from typing import List, Optional

from config import SSH_AUTH_TIMEOUT, SSH_TIMEOUT

ENGINE_ID_RE = re.compile(r"0x([0-9a-fA-F]{32,})")

# Stay inside SNMP dirs. Do not `find /` as root.
ENGINE_ID_COMMANDS = [
    "sudo -S grep -E 'usmUser' /var/lib/snmp/snmpd.conf | head -n 1",
    "sudo -S grep -E 'oldEngineID' /var/lib/snmp/snmpd.conf | head -n 1",
    "sudo -S grep -R -E 'usmUser' /var/lib/snmp/ /var/net-snmp/ /etc/snmp/ 2>/dev/null | head -n 1",
]


class SNMPEngineFetcher:
    def __init__(self, ssh_user: str, ssh_password: str) -> None:
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password

    def get_engine_id(self, ip: str) -> str:
        """SSH to the appliance and pull the SNMP Engine ID from snmpd.conf."""
        if not self.ssh_user or not self.ssh_password:
            raise ValueError("SSH credentials are required to retrieve the Engine ID")

        engine = self._ssh_query_engine_id(ip)
        if not engine:
            raise ValueError("Could not retrieve Engine ID from appliance via SSH")
        return engine

    def _ssh_query_engine_id(self, ip: str) -> Optional[str]:
        # WarningPolicy still connects on unknown host keys (prints a warning).
        # Add the appliance key to known_hosts on trusted networks.
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        try:
            client.connect(
                hostname=ip,
                username=self.ssh_user,
                password=self.ssh_password,
                timeout=SSH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
                auth_timeout=SSH_AUTH_TIMEOUT,
            )
            return self._extract_engine_id(client, ENGINE_ID_COMMANDS)
        except paramiko.AuthenticationException as exc:
            print(
                f"      SSH authentication failed: {exc}. "
                "Trying keyboard-interactive fallback...",
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
        """Retry with keyboard-interactive auth (common on PAM-backed appliances)."""

        def handler(title, instructions, prompt_list):
            responses = []
            for prompt in prompt_list:
                if "password" in prompt[0].lower():
                    responses.append(self.ssh_password)
                else:
                    responses.append("")
            return responses

        transport = None
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        try:
            transport = paramiko.Transport((ip, 22))
            transport.banner_timeout = SSH_TIMEOUT
            transport.auth_timeout = SSH_AUTH_TIMEOUT
            transport.start_client(timeout=SSH_TIMEOUT)
            transport.auth_interactive(self.ssh_user, handler)
            client._transport = transport
            return self._extract_engine_id(client, ENGINE_ID_COMMANDS[:1])
        except Exception as exc:
            print(f"      Keyboard-interactive SSH also failed: {exc}", file=sys.stderr)
        finally:
            try:
                client.close()
            except Exception:
                pass
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
        return None

    def _extract_engine_id(self, client: paramiko.SSHClient, commands: List[str]) -> Optional[str]:
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            stdout.channel.settimeout(SSH_TIMEOUT)
            stdin.write(self.ssh_password + "\n")
            stdin.flush()

            output = stdout.read().decode("utf-8", errors="replace")
            err_output = stderr.read().decode("utf-8", errors="replace")
            exit_status = stdout.channel.recv_exit_status()

            if exit_status not in (0, 1):
                print(
                    f"      SSH command failed (exit {exit_status}): {err_output.strip()}",
                    file=sys.stderr,
                )

            if output.strip():
                print(f"      SSH command succeeded: {cmd}", file=sys.stderr)
                match = ENGINE_ID_RE.search(output)
                if match:
                    return match.group(1)

        print(
            "      No engine ID found. Tried commands:\n"
            + "\n".join(f"        - {cmd}" for cmd in commands)
            + "\n      Check SSH access, sudo permissions, and snmpd.conf location.",
            file=sys.stderr,
        )
        return None
