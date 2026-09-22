"""SSH after NTP PUT: restart cz-customization (no Admin API for that unit).

chronyc ntpdata is the CLI check; there is no REST equivalent.
"""
from typing import Sequence, Union

from config import ACAS_SSH_TIMEOUT, NTP_CUSTOMIZATION_UNIT

from .client import SSHSession


class NtpSsh(SSHSession):
    def restart_customization(self, host: Union[str, Sequence[str]]) -> str:
        # print(f"DEBUG ntp-ssh: restart {NTP_CUSTOMIZATION_UNIT} hosts={host!r}")
        def _run(client) -> str:
            return self._run(
                client,
                f"sudo -S systemctl restart {NTP_CUSTOMIZATION_UNIT}",
                sudo=True,
                timeout=ACAS_SSH_TIMEOUT,
            )

        return self._with_ssh_endpoints(
            host, _run, error="cz-customization restart failed"
        )

    def ntpdata(
        self,
        host: Union[str, Sequence[str]],
        servers: Sequence = (),
    ) -> str:
        """sudo chronyc: sources list plus ntpdata per configured hostname."""
        def _run(client) -> str:
            chunks = [
                self._run(client, "sudo -S chronyc -n sources", sudo=True, check=False)
            ]
            names = []
            for entry in servers or ():
                if isinstance(entry, dict):
                    name = str(entry.get("hostname") or "").strip()
                else:
                    name = str(entry or "").strip()
                if name and name not in names:
                    names.append(name)
            if names:
                for name in names:
                    chunks.append(
                        self._run(
                            client,
                            f"sudo -S chronyc ntpdata {name}",
                            sudo=True,
                            check=False,
                        )
                    )
            else:
                chunks.append(
                    self._run(client, "sudo -S chronyc ntpdata", sudo=True, check=False)
                )
            return "\n".join(chunks)

        return self._with_ssh_endpoints(host, _run, error="chronyc ntpdata failed")
