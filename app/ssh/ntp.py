"""SSH after NTP PUT: restart cz-customization (no Admin API for that unit).

chronyc ntpdata is the CLI check; there is no REST equivalent.
"""
from typing import Sequence, Union

from config import ACAS_SSH_TIMEOUT, NTP_CUSTOMIZATION_UNIT

from .client import SSHSession


class NtpSsh(SSHSession):
    def restart_customization(self, host: Union[str, Sequence[str]]) -> str:
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

    def ntpdata(self, host: Union[str, Sequence[str]]) -> str:
        def _run(client) -> str:
            return self._run(client, "chronyc ntpdata", check=False)

        return self._with_ssh_endpoints(host, _run, error="chronyc ntpdata failed")
