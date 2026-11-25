"""SSH after NTP PUT: restart cz-customization (no Admin API for that unit).

chronyc ntpdata is the CLI check; there is no REST equivalent.
"""
from typing import Sequence, Union

import shlex

from config import ACAS_SSH_TIMEOUT, NTP_CUSTOMIZATION_UNIT
from core.utils import is_valid_host

from .client import SSHSession


class NtpSsh(SSHSession):
    """SSH for menu 5. There is no Admin API for these steps."""
    def restart_customization(self, host: Union[str, Sequence[str]]) -> str:
        """cz-customization applies the NTP PUT to chrony. It has no API trigger, so it is restarted over SSH."""
        # print(f"DEBUG ntp-ssh: restart {NTP_CUSTOMIZATION_UNIT} hosts={host!r}")
        def _run(client) -> str:
            return self._run(
                client,
                f"sudo -S systemctl restart {shlex.quote(NTP_CUSTOMIZATION_UNIT)}",
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
        """sudo chronyc: sources list plus ntpdata per configured hostname.

        The name is operator data on a root shell. It is not a constant.
        """
        # print(f"DEBUG ntpdata: n={len(servers or ())}")
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
                    if not is_valid_host(name):
                        raise ValueError(f"NTP hostname is not an IP or FQDN: {name!r}")
                    names.append(name)
            if names:
                for name in names:
                    chunks.append(
                        self._run(
                            client,
                            f"sudo -S chronyc ntpdata {shlex.quote(name)}",
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
