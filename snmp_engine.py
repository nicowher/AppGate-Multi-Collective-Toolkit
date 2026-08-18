from utils import ensure_package

try:
    import paramiko
except ImportError:
    ensure_package("paramiko", "paramiko")
    import paramiko

import re
import sys
from typing import Optional


class SNMPEngineFetcher:
    def __init__(self, ssh_user: str, ssh_password: str) -> None:
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password

    def get_engine_id(self, ip: str) -> str:
        """Pull the SNMP Engine ID from the appliance via SSH."""
        if not self.ssh_user or not self.ssh_password:
            raise ValueError("SSH credentials are required to retrieve the Engine ID")

        engine = self._ssh_query_engine_id(ip)
        if not engine:
            raise ValueError("Could not retrieve Engine ID from appliance via SSH")

        return engine

    def _ssh_query_engine_id(self, ip: str) -> Optional[str]:
        """SSH to the appliance and extract engine ID from snmpd.conf."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        try:
            client.connect(
                hostname=ip,
                username=self.ssh_user,
                password=self.ssh_password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
                auth_timeout=10,
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

                if exit_status not in (0, 1):
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
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
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
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
                auth_timeout=10,
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

            if exit_status not in (0, 1):
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
