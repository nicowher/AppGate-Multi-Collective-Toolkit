"""SSH overlays for ACAS scan prep (unharden) and restore (harden).

Why not Controller API: a PUT would make flush/NOPASSWD/banner the new
desired state. cz-configd would then keep the box unhardened. Overlay
locally, then ``systemctl restart cz-configd`` so STIG files come back.

Unharden order (SSH, FQDN first):
  1. iptables/ip6tables SSHBRUTE → ACCEPT  (scanners hammer SSH)
  2. sudoers drop-in NOPASSWD              (sudo password hangs scans)
  3. banner TTY guard                      (read -p y/N hangs scans)

Harden order:
  1. restore ``*.pre-acas`` banner backups
  2. remove sudoers drop-in (and legacy names)
  3. restart cz-configd (rewrites STIG-owned files / SSHBRUTE)
"""
import re
import shlex
import sys
from typing import Sequence, Union

from config import (
    ACAS_BANNER_GREP_TIMEOUT,
    ACAS_BANNER_NEEDLE,
    ACAS_BANNER_PATHS,
    ACAS_BANNER_SEARCH_ROOTS,
    ACAS_BANNER_TTY_GUARD,
    ACAS_CZCONFIGD_UNIT,
    ACAS_IPTABLES_BINS,
    ACAS_IPTABLES_CHAIN,
    ACAS_SSH_TIMEOUT,
    ACAS_SUDOERS_DROPIN,
    ACAS_SUDOERS_DROPIN_LEGACY,
    DEBUG,
    SSH_LOG_PREVIEW,
)

from .client import SSHSession

SUDOERS_DROPIN = ACAS_SUDOERS_DROPIN
USER_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _quote_words(values: Sequence[str]) -> str:
    return " ".join(shlex.quote(v) for v in values if v)


class AcasPrep(SSHSession):
    """FQDN-first SSH for ACAS unharden / harden."""

    def unharden(self, host: Union[str, Sequence[str]]) -> str:
        # print(f"DEBUG acas: unharden hosts={host!r}")
        return self._run_script(host, self._unharden_script())

    def harden(self, host: Union[str, Sequence[str]]) -> str:
        # print(f"DEBUG acas: harden hosts={host!r}")
        return self._run_script(host, self._harden_script())

    def _unharden_script(self) -> str:
        user = (self.ssh_user or "").strip()
        if not USER_RE.fullmatch(user):
            raise ValueError(f"Unsafe SSH username for sudoers: {user!r}")
        bins = _quote_words(ACAS_IPTABLES_BINS)
        chain = shlex.quote(ACAS_IPTABLES_CHAIN)
        drop = shlex.quote(ACAS_SUDOERS_DROPIN)
        user_q = shlex.quote(f"{user} ALL=(ALL) NOPASSWD: ALL")
        paths = _quote_words(ACAS_BANNER_PATHS)
        roots = _quote_words(ACAS_BANNER_SEARCH_ROOTS)
        needle = shlex.quote(ACAS_BANNER_NEEDLE)
        guard = ACAS_BANNER_TTY_GUARD
        grep_to = int(ACAS_BANNER_GREP_TIMEOUT)
        return f"""
echo STEP_IPTABLES_START
for bin in {bins}; do
  if "$bin" -L {chain} >/dev/null 2>&1; then
    "$bin" -F {chain}
    "$bin" -A {chain} -j ACCEPT
    echo STEP_IPTABLES_OK "$bin"
  else
    echo STEP_IPTABLES_SKIP "$bin" no {chain} chain
  fi
done

echo STEP_SUDOERS_START
DROP={drop}
printf '%s\\n' {user_q} > "$DROP"
chmod 440 "$DROP"
if visudo -cf "$DROP" >/dev/null 2>&1; then
  echo STEP_SUDOERS_OK
else
  rm -f "$DROP"
  echo STEP_SUDOERS_FAIL
  exit 1
fi

echo STEP_BANNER_START
banner_found=0
banner_ok=0
candidates=""
for f in {paths}; do
  [ -f "$f" ] || continue
  if grep -qF {needle} "$f"; then
    candidates="$candidates
$f"
  fi
done
if [ -z "$candidates" ]; then
  candidates=$(timeout {grep_to} grep -rlF {needle} {roots} 2>/dev/null || true)
fi
while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ -f "$f" ] || continue
  banner_found=1
  if grep -qF {shlex.quote(guard)} "$f"; then
    echo "STEP_BANNER_ALREADY $f"
    banner_ok=1
    continue
  fi
  if ! grep -q 'SSH_CLIENT' "$f"; then
    echo "STEP_BANNER_SKIP no SSH_CLIENT in $f"
    continue
  fi
  [ -f "${{f}}.pre-acas" ] || cp -a "$f" "${{f}}.pre-acas"
  tmp="${{f}}.acas.$$"
  awk '
    {{ print }}
    !ins && /SSH_CLIENT/ {{ print "{guard}"; ins=1 }}
    ins && !closed && /^done[[:space:]]*$/ {{ print "fi"; closed=1 }}
  ' "$f" > "$tmp"
  if bash -n "$tmp" 2>/dev/null; then
    mv "$tmp" "$f"
    echo "STEP_BANNER_OK $f"
    banner_ok=1
  else
    rm -f "$tmp"
    echo "STEP_BANNER_SKIP bash -n failed $f"
  fi
done <<EOF
$candidates
EOF
if [ "$banner_found" -eq 0 ]; then
  echo STEP_BANNER_SKIP no banner script found
elif [ "$banner_ok" -eq 0 ]; then
  echo STEP_BANNER_SKIP could not patch
fi
echo STEP_UNHARDEN_DONE
"""

    def _harden_script(self) -> str:
        dropins = _quote_words((ACAS_SUDOERS_DROPIN,) + tuple(ACAS_SUDOERS_DROPIN_LEGACY))
        paths = _quote_words(ACAS_BANNER_PATHS)
        unit = shlex.quote(ACAS_CZCONFIGD_UNIT)
        return f"""
echo STEP_BANNER_RESTORE
for f in {paths}; do
  if [ -f "${{f}}.pre-acas" ]; then
    mv "${{f}}.pre-acas" "$f"
    echo "STEP_BANNER_RESTORED $f"
  fi
done
echo STEP_SUDOERS_REMOVE
rm -f {dropins}
echo STEP_CZCONFIGD_RESTART
systemctl restart {unit}
echo STEP_HARDEN_DONE
"""

    def _run_script(self, host: Union[str, Sequence[str]], script: str) -> str:
        if DEBUG:
            print(
                f"      DEBUG acas: script_len={len(script)} timeout={ACAS_SSH_TIMEOUT}",
                file=sys.stderr,
            )
        result = self._with_ssh_endpoints(
            host,
            lambda c, s=script: self._sudo_script(c, s, timeout=ACAS_SSH_TIMEOUT),
            error="SSH failed",
        )
        rc, text = result
        # print(f"DEBUG acas: rc={rc} steps={[ln for ln in text.splitlines() if ln.startswith('STEP_')]}")
        if rc != 0 or "STEP_SUDOERS_FAIL" in text:
            steps = " ".join(ln for ln in text.splitlines() if ln.startswith("STEP_"))
            raise ValueError(
                f"ACAS script failed (exit {rc}): {(steps or text.strip())[:SSH_LOG_PREVIEW]}"
            )
        return text
