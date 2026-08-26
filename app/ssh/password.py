"""Set appliance cz password via cz-config (SHA-512 crypt).

Remote (as root via sudo):

  IFS= read -r PW   # new password on stdin after sudo -S (not in argv/ps)
  HASH=$(printf '%s\\n' "$PW" | openssl passwd -6 -stdin)
  cz-config set users/0/encrypted-password "$HASH"
  cz-config set -j users/0/nopasswd false

Plaintext never goes into cz-config or the remote command line.
"""
import sys
from typing import Sequence, Union

from config import ACAS_SSH_TIMEOUT, DEBUG, SSH_LOG_PREVIEW

from .client import SSHSession


class CzPassword(SSHSession):
    """FQDN-first SSH to apply a new cz password on one appliance."""

    def verify_login(self, host: Union[str, Sequence[str]]) -> bool:
        """Connect with this session's password. True if auth works."""
        # print(f"DEBUG czpw: verify_login hosts={host!r} user={self.ssh_user}")
        def _ok(client) -> bool:
            self._run(client, "true", check=False)
            return True

        try:
            return bool(
                self._with_ssh_endpoints(host, _ok, error="login verify failed")
            )
        except ValueError:
            return False

    def set_password(self, host: Union[str, Sequence[str]], new_password: str) -> str:
        # print(f"DEBUG czpw: hosts={host!r} new_len={len(new_password)}")
        if not (new_password or "").strip():
            raise ValueError("New SSH password is empty")
        return self._run_script(host, new_password)

    def _script(self) -> str:
        return r"""
IFS= read -r PW || exit 1
echo STEP_HASH_START
HASH=$(printf '%s\n' "$PW" | openssl passwd -6 -stdin) || {
  echo STEP_HASH_FAIL
  exit 1
}
echo STEP_HASH_OK
echo STEP_CZCONFIG_PASSWORD
cz-config set users/0/encrypted-password "$HASH" || {
  echo STEP_CZCONFIG_PASSWORD_FAIL
  exit 1
}
echo STEP_CZCONFIG_NOPASSWD
cz-config set -j users/0/nopasswd false || {
  echo STEP_CZCONFIG_NOPASSWD_FAIL
  exit 1
}
echo STEP_PASSWORD_OK
"""

    def _run_script(self, host: Union[str, Sequence[str]], new_password: str) -> str:
        script = self._script()
        if DEBUG:
            print(f"      DEBUG czpw: script_len={len(script)}", file=sys.stderr)
        result = self._with_ssh_endpoints(
            host,
            lambda c, s=script, p=new_password: self._sudo_script(
                c, s, timeout=ACAS_SSH_TIMEOUT, extra_stdin=p
            ),
            error="SSH failed",
        )
        rc, text = result
        # print(f"DEBUG czpw: rc={rc} text={text[:80]!r}")
        if rc != 0 or "STEP_PASSWORD_OK" not in text:
            steps = " ".join(ln for ln in text.splitlines() if ln.startswith("STEP_"))
            raise ValueError(
                f"Password update failed (exit {rc}): {(steps or text.strip())[:SSH_LOG_PREVIEW]}"
            )
        return text
