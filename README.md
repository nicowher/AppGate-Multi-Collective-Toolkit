# AppGate Multi-Collective Toolkit

One launcher for **several AppGate SDP collectives** at once: SNMPv3 USM, ACAS scan prep, cz SSH password, NTP, walks, and config knobs. Works in lab and production, including air-gapped hosts.

GitHub: https://github.com/nicowher/AppGate-Multi-Collective-Toolkit

This is **not** [sdpctl](https://github.com/appgate/sdpctl). Use sdpctl for backup/upgrade. This toolkit is SNMP, ACAS overlays, cz passwords, NTP, allowed sources, and multi-collective fan-out in one run.

## Menu

| Key | Tool |
| --- | --- |
| **1** | SNMP Credential Tool — localize and push SNMPv3 USM (SHA-512 / AES-256) |
| **2** | ACAS scan prep — unharden for scanning, then harden (`cz-configd`) |
| **3** | SNMP Walk — validate authPriv only (no SSH / no config push) |
| **4** | Update cz SSH password — `openssl passwd -6` + `cz-config` + login verify |
| **5** | NTP servers — find each box's SSH address, PUT `ntp.servers`, then restart cz-customization + chronyc verify |
| **6** | Allowed sources — per type/slot (`ssh`/`spa`/`admin`/`https`/`ping`/`snmp`), exclude-self /32|/128 |
| **C** | Configure — edit `DEBUG`, `LAB_MODE`, SSH/walk timeouts in `config.py` |
| **D** | Download deps — `pip download` into `app/vendor/wheels` (source tree only; hidden in the GitHub zip) |
| **U** | Reinstall the pinned vendor set into `vendor/site` (source tree only; hidden in the GitHub zip) |
| **Q** | Quit |

## Shared behavior (all mutating / inventory tools)

- **`credentials.json`** (gitignored): global defaults plus `collectives[]`. It holds every secret in plain text, so each tool stops with **E21** when other users can read or write it (POSIX group/other bits, or a Windows ACL entry for anyone but you, Administrators and SYSTEM); with `LAB_MODE` on this is only a warning. Fix with `chmod 600 credentials.json`, or on Windows `icacls credentials.json /inheritance:r /grant:r <your user>:F /grant:r SYSTEM:F /grant:r Administrators:F`. Required per collective: `fqdn` (`agip` recommended). API user/pass for every tool that talks to the Controller. SSH user/pass for 1, 2, 4, 5 (not walk). SNMP only for 1 and 3; `ssh_password_new` only for 4; `ntp_servers` only for 5; `mibs` never required. Old `admin_*` keys still load as `api_*`. A value written as true/false or a decimal number (top level, in a collective row, or in `mibs`) stops the tool with **E21**; write it as a quoted string. A whole number is read as text. The file may be UTF-8 (with or without a BOM) or UTF-16, as Windows editors save it. A file that exists but cannot be read (bad JSON, another encoding, not one JSON object) stops the tool with **E21** and the parser's reason; move it aside to start without it.
- **Credential entry:** if **every** collective already has a field (including a single collective with per-row secrets and empty top-level keys), that field is **not** prompted globally. A global answer fills only empty fields. A row that already has its own value keeps it. 1 collective fills that row; 2+ collectives then offer **1) global**, **2) per collective**, **3) global then override**. Short file secrets are discarded; typed replacements are kept. Missing or short `snmp_priv` is prompted. It is not copied from `snmp_auth`.
- **Exclude collectives** (number, range `1-3`, or FQDN) then **exclude appliances** (`1,3` / `1-10,12-20` / `1.hostname`). `1-10,12-20` leaves row 11. A name with a digit on only one side of a hyphen stays one token and can be excluded. `1-` and `-3` are rejected and asked again. A token with a control character or a format character, including a right-to-left mark, is rejected and asked again. A range whose last number is more than 10000 past the first is rejected. `1-10001` is still accepted. A comma part that matches no row (a typo, a number past the last row, or a bare hostname that two collectives share) is listed as **No appliance matches** and the question is asked again; nothing is excluded until every part matches. Input made only of commas is asked again rather than treated like Enter, and a row number with leading zeros (`01`) means row 1. A range counts when any number in it matches, so `1-100` on four rows still means rows 1-4. The collective exclude works the same way.
- **SSH address, found once per session:** the toolkit tries the admin-interface hostname, then the admin IP, then the box's other IPs, and stops at the first one that answers. That address is remembered in memory until the toolkit exits, so later steps and later menus go straight to it. It is not saved to disk. Gateways never use the Controller IP.
- **`LAB_MODE`** (bottom of `app/config.py`) drives SSH host-key policy, SNMP min passphrase (8 lab / 15 off-lab), and the STIG cz-password check. It does not skip the Controller CA and it does not print localized keys. **Defaults off.** **`DEBUG` and `DRY_RUN` are separate.**
- **Controller CA:** copy the AppGate CA export into `certs/`. `AppGate_SDP_<host>_CA.cer` is accepted, as are `<host>.cer` and `<host>.pem`. The file name is the host you dial. FQDN and IP may share one file. If the FQDN `.cer` is present, the IP fallback uses it. Several collectives means several files. Current and next CA can be in the same PEM. Login uses that file as `verify` and does not download a CA. A missing file skips that host. A file that is not a CA certificate (`CA:TRUE`), a PEM or `certs/` directory that is group/world writable on Unix, or a PEM, `certs/`, or the parent of `certs/` writable by Everyone, Users, or Authenticated Users on Windows (in-process DACL, allow-ACEs and object allow-ACEs, matched by SID; an unparsed ACE type stops login), or a host-name collision stops login and does not send a password. If `cryptography` is missing, login stops with that reason instead of a traceback. `INSECURE_API=True` prints a warning at startup. `INSECURE_API=True` skips the file (`verify` off) and does not change SSH or STIG. `LAB_MODE` does not control this. A release zip ignores `INSECURE_API`.
- **Production SSH:** `SSH_STRICT_HOST_KEY` follows `LAB_MODE` (`True` when lab is off). An unknown or changed key prompts once per appliance. Yes stores it. No skips that box. A non-interactive run still needs `SSH_KNOWN_HOSTS` or `ssh_host_keys`. Lab mode still accepts any host key if that prompt is not reached.
- **Ctrl+C during a tool:** `Cancel this job and return to menu? [y/N]` (default N continues). Second Ctrl+C cancels. `SIGTERM` and `SIGHUP` exit without that prompt. In-flight SSH/walks are not killed instantly. At the menu / Return to menu, Ctrl+C just redisplays the menu.
- **Preview first**, then Apply. Replace (menu 6) uses **y** then type **YES**. `DRY_RUN=True` skips Apply.
- **Color:** status words only (OK, Failed, ERROR, WARNING, ok, timeout). Set `NO_COLOR=1` to disable.
- **Output encoding:** the menu and each tool run on its own replace a character the console or log file cannot show with a backslash escape, so a run logged with `> file` or a pipe on Windows (cp1252) does not stop on an unusual appliance name or Controller reply. Ctrl+C, a run-stopping error and an unexpected error end every tool the same way.
- **Console layout:** each step starts with a thin rule and `[n/N] Title  scope` (box count, parallelism). Every box gets one aligned line per step: **OK**, **Failed** (with its error code), **Plan** (preview) or **Skip**. Lines from boxes that run in parallel are held until that box finishes and printed together, so they never interleave. If a parallel step stops early (Ctrl+C, including at a host-key prompt, or an error), queued boxes are cancelled, the boxes already being worked on are named (`Stopping: waiting for N box(es) already started to finish: …`) and finish first, and their results and failures reach the report; a second Ctrl+C stops the wait. The live step of every menu acts only on the boxes the confirm prompt counted. Appliance labels drop a hostname suffix that only repeats the collective's domain (`1.ctrl-a_example_com` shows as `1.ctrl-a`); the full name still works at the exclude prompt. When the short label would match another box in the same collective, both keep their full names (and an id prefix if even those match), so exclude, reports and backup file names never mix two boxes. Each run ends with a counts line (`Done: 3 OK, 1 failed`, or `Preview: 2 would change, 1 already set`) and one line per failed box with its code. Apply prompts name the box count. Replace and overwrite runs print the backup folder once.
- **DEBUG on:** unfiltered — every SSH try, per-address walk progress, snmpd and USM progress lines, no `SSH n/N` counter, dumps uncolored. DEBUG also prints, with no secrets:
  - a run header with the effective settings (`CNSA_STRICT`, `LAB_MODE`, `INSECURE_API`, `DRY_RUN`, timeouts, concurrency, `SSH_KNOWN_HOSTS`) and the Python, OpenSSL, paramiko, requests, cryptography, pysnmp and urllib3 versions;
  - one line per Controller request (method, URL path, status, milliseconds; never the query values, body or token);
  - the Controller's negotiated TLS after login (version, cipher, certificate key type and size or curve, signature hash), from one extra handshake that sends no request;
  - per SSH session: new login with the negotiated cipher, MAC, key exchange (read from paramiko's own log, which stays off the console) and host-key type, or a reused pooled session;
  - what each SSH hostname resolved to during the address search;
  - each step's duration, not counting time spent waiting at a prompt (shown separately), and each box's time in a parallel step;
  - at the end of a menu 1, 2, 4 or 5 run, the SSH connections per address (logins and host-key reads), which is what SSHBRUTE counts;
  - for an unexpected error, the traceback, passed through the same redaction as error replies.
  An unexpected error in a tool no longer ends the menu: it prints `Error: …` and returns to the menu. **DEBUG off:** `SSH n/N`, one line per box per step. Preview prints **OK already set** when nothing would change (NTP add only; overwrite always previews because keys are not in the peek).
- **DEBUG off:** GUI names (SSH, SPA/HTTPS, Admin/API, Ping, SNMP), no engine-ID hex, no Python dicts. **DEBUG on:** plus raw API fields, endpoints, engine hex, STEP_* (ACAS), SSH script preview.
- **Shared run path:** `core/run.py` (login, inventory/exclude, add vs replace, result line). Appliance PUT helpers: `api/snmp.py`, `api/ntp.py`, `api/allow_sources.py` mixins on `AppGateClient`.
- **TLS:** the CA file is required unless `INSECURE_API=True`. That switch is not lab mode.
- **SSH:** before parallel work, one address per appliance is found: host keys for all boxes are read in parallel with no password, then the main thread settles each box (prompt and pin) as soon as its read finishes. An address found earlier in this session is reused with no probe. Otherwise the order is: admin-interface hostname, admin IP, this box's own Controller `agip` (login Controller only), then the other NIC IPs: private IPv4 and IPv6 unique-local, public, and link-local last (zone kept). `peerInterface.hostname` is never used. Each address is checked by reading its SSH host key without logging in (`SSH_PRIME_TIMEOUT`). No DNS, a timeout, or a refused port moves to the next address. A DNS lookup waits at most `SSH_PRIME_TIMEOUT`; a slower answer counts as no DNS, so a dead resolver costs a few seconds per name instead of stalling the run. The first address that answers decides, and the password is sent only later, once, by the worker on that address. The address is kept in memory until the toolkit exits, never on disk. If it stops answering later in the session, the worker goes down the rest of the list once and remembers the new address. A fallback address gets the password only when it shows the same host key as this box's approved key. If every address fails, the remembered address is dropped so the next menu searches again. An auth failure or a host-key mismatch stops that box at the address where it happens, so a wrong password is not tried on every NIC. Password retry is per hostname; confirm mismatch re-asks. Workers never call `input()`. Menus 1, 2, 4 and 5 keep one SSH session per box for the whole run (keepalive every 15 s), so menu 1's engine-ID read and purge, and menu 5's restart and verify, share one login. A session the box dropped is replaced by a new login before any command runs on it. The harden recheck of cz-configd and the menu 4 login with the new password always use a new session. All sessions close when the menu run ends. **DEBUG off:** `SSH n/N` and failures only. **DEBUG on:** every try, uncolored. An unknown or changed SSH host key prompts once per appliance on the main thread. Yes stores that key. A later run uses the saved key and does not prompt again. Another address of the same box that shows the same key is accepted without a prompt. No skips that box. If no address answers, or the username is missing, that appliance fails, later SSH steps skip it, and the next one is still checked. Workers do not ask.
- **Reports:** `reports/run-*.json`, `dryrun-*.json`, `walk-*.json`, `acas-*.json`, `cz-password-*.json`, `ntp-*.json` (no passwords/tokens; `0600` on Unix). They are not free of site data: collective FQDNs and admin IPs and appliance labels appear, and the menu 2 and 4 reports list each box's SSH addresses in their own fields, so handle them as internal records. In the menu 1, 5 and 6 reports, a box's SSH addresses inside `error` and `detail` are replaced by their position in the address order (`address 1`, `address 2`, …); the console shows the full text. Console JSON only if `DEBUG=True`. A failed box records a plain `error` and, in every tool's report, the technical `detail` (SSH error kind, script steps, or API status; no passwords). The same SSH problem gets the same message in every menu.
- **Logout:** when the process exits, each logged-in Controller gets `DELETE /admin/login`. A logout failure is ignored, so a finished job still looks finished.
- **Dependencies:** unpacked wheels in `app/vendor/site` are appended to `sys.path`, not put in front. Installs use `app/vendor/requirements.txt` hashes and `--target vendor/site`. An empty `vendor/site` extracts a wheel only when its hash is in that pin. Menu U reinstalls that pin. It does not take a newer PyPI release. The pin needs Python 3.11.5+. Release zips include a Windows amd64 / **Python 3.14** `vendor/site`.

## 1) SNMP Credential Tool

Configures **authPriv** SNMPv3 USM on selected appliances so a scanner (e.g. ESXi) can walk them. Needs API + SSH + SNMP secrets. A failed appliance PUT rolls back earlier boxes in that step and stops. A later SSH or walk failure does not roll back the PUT.

**CLI (`[1/8]` … `[8/8]`):**

1. **Authenticate** to each Controller (`POST /admin/login`). Production requires a hand-placed Controller CA before the password is sent. There is no proceed-anyway prompt. `INSECURE_API` is the only skip. `LAB_MODE` does not skip it. Before the password is sent, `GET /admin/version` sets `Accept` to `peerVersion`. It asks with `application/json` first (as AppGate documents for that endpoint); a 406 that names the peer version is used as the answer (the highest one named, if several). A peer version that is not a plain number is ignored. The learned version is kept per Controller for this session, so later menus skip the check. Peer 24 sends `machineId`; peer 25 sends `deviceId` (same UUID). Login does not follow redirects. FQDN first; IP if connect/HTTP fails (not on 401/403).
2. **Inventory** `GET /admin/appliances` + status, then the exclude table (Enter = all). The run **previews first** (no pin/push/purge/walk/snmpd restart). Apply is offered after the preview unless `DRY_RUN=True`.
3. **Pin** `engineIDType 3` via appliance PUT (dry-run prints only). PUT is the full GET document: only `snmpd.conf` / `enabled` may change; `site` object becomes the same UUID (never stripped); `tcpPort` is never added. Any other field diff aborts (`DEBUG` dumps redacted GET/PUT).
4. **SSH** (address found and host key checked on the main thread, then up to `SSH_CONCURRENCY` in parallel). **DEBUG off:** `SSH n/N` and one line per box. **DEBUG on:** every try and the engine ID itself. Read `oldEngineID` from persistent snmpd.conf and check it against `eth0` MAC (RFC 3411 type 3). **Live** restarts snmpd so type 3 applies; **preview does not**.
5. **Localize** auth/priv in-process (RFC 3414) per engine ID. The privacy key is cut to 32 bytes for AES-256. Uses that collective’s `snmp_*` if set. A shared engine ID fails both appliances before the PUT. Localized keys are not printed.
6. **Push** via Controller: **1) Add** keeps other USM users and add/updates this username; **2) Replace** drops other `createUser`, `rouser`, and `rwuser` lines, including a leading space (backup under `reports/replaced/`). Then `createUser` (localized `-l 0x…`), optional `rouser`, `engineIDType 3`. No `exactEngineID`. `rocommunity`, `rwcommunity`, `com2sec`, `authcommunity`, and `authuser` are stripped the same way. After the SSH purge confirms the new user, the `createUser` line is removed so the localized hash is not left in the API copy. User, hashes, and the `rouser` line are each refused if they hold a line break. The first failed push stops this step for every collective: earlier boxes are rolled back, and every box not reached yet is marked **Failed** ("this step stopped after … failed") and left unchanged. Step 3 behaves the same way.
7. **SSH purge:** only on boxes whose step 6 push succeeded and were not rolled back. Stop snmpd, delete leftover persistent `usmUser`, start snmpd so `createUser` recreates the user. **Add** clears only this user's saved rows; **Replace** clears every user's saved rows (other users' localized keys no longer stay on disk), and all of them are put back if the new key never appears. A box that was never pushed keeps its existing SNMP user. The user's persistent rows are copied before the delete. If snmpd does not write the new key within `USM_RECREATE_WAITS`, snmpd is stopped, the old rows are put back, and snmpd is started again, so the box keeps its old SNMP user instead of none, and the box is marked **Failed**. The rows go to the box over SSH input and are never printed.
8. **Walk** in parallel (`WALK_CONCURRENCY`): the SSH-working address only (`ssh_ok_host`). `WALK_*_ATTEMPTS` on that one host. `SKIP_CREDENTIAL_WALK` skips this step on dry-run and live (menu 3 unchanged). Engine ID hex is console/report only when `DEBUG=True`.

After a dry-run preview: **Push SNMP config to N boxes now?** re-runs 3–8 live. The replace backup is named with the appliance label. Report: `reports/run-*.json` or `dryrun-*.json`. In `dryrun-*.json`, each box lists its `planned_actions`; a box that already failed in the preview (for example no SSH address answered) lists only `skipped: <reason>`, because the live run does not touch it.

## 2) ACAS scan prep

Temporary overlays so ACAS/Nessus can SSH without hanging or lockout. **Do not PUT these via the appliance API** — that would make unharden the source of truth. Check the **same hostname** you selected (not a connector that was not in the list).

Submenu: **1) Unharden** or **2) Harden**. Then `[1/3]` login, `[2/3]` inventory / exclude, preview, then Apply. `[3/3]` SSH (`SSH_CONCURRENCY`). The SSH address and host key are checked first; a box with no answering address is skipped. Unharden prints: **This weakens STIG until you harden again.** A failed box gets a plain-language reason on the console, and the report keeps the technical `detail` (SSH error kind or the script steps that ran; no passwords).

**Unharden (order matters):**

1. `cz-config set -j users/0/nopasswd true` and write `/etc/sudoers.d/cz-acas-scan`. `/etc/sudoers` is rewritten to a **single** `# BEGIN ACAS-SCAN` block (safe to re-run; old duplicate NOPASSWD lines are stripped). `visudo -cf` before replace.
2. Patch `/etc/profile.d/ssh_confirm.sh`: wrap the `read -p` / y/N loop in `if [ -t 0 ]`. **Interactive SSH still prompts.** Scanners (no TTY) skip it. Missing file (typical gateway) is a **skip**, not a fail. Backup `*.pre-acas` + `bash -n` before replace.
3. `mkdir -p /home/svc-acas` (SCAP).
4. **Last:** `iptables` / `ip6tables` `-w -F SSHBRUTE; -A ACCEPT`. The pre-flush rules are saved under `/run/mct-sshbrute`, mode `0700`, only if no saved copy is there yet. Harden deletes the copy after a good restore, so one that is still present means the chain was never restored; a second unharden keeps it (`STEP_IPTABLES_SAVED_KEPT`) instead of saving the already-open chain. `/run` is cleared on reboot. A symlink is refused. Harden restores the saved rules with `iptables-restore --noflush` (and `ip6tables-restore`): the flush and the re-add are one commit, so quoted rules such as `--comment "…"` come back exactly, and a failed restore leaves the chain as it was and keeps the saved copy for another try. After the live chain matches the saved copy, the file is deleted. A family with no saved copy and no SSHBRUTE chain (unharden skipped it too) is skipped with `STEP_IPTABLES_RESTORE_SKIP`, not failed. If a later step fails, the previous sudoers file is restored. Check: `sudo iptables -S SSHBRUTE`.

**Harden:** remove the sudoers drop-in first, then `nopasswd false`, restore iptables, compare the saved rules, then delete the file. Then restore `*.pre-acas` and `nohup systemctl restart cz-configd` (foreground restart drops SSH). A restore failure no longer leaves the drop-in in place. Re-harden as soon as the scan finishes.

Report: `reports/acas-unharden-*.json` / `acas-harden-*.json`.

## 3) SNMP Walk

Validate-only: **no SSH to appliances and no config push.** Confirms authPriv with current `snmp_*`.

- **1) Single IP / FQDN** — always prompted (never defaults to Controller `agip`). SNMP secrets only; **no SSH**. Then *Walk another?*. No `walk-*.json` for this path.
- **2) Pull from Controller(s)** — `[1/3]` login, `[2/3]` inventory / exclude, `[3/3]` parallel walks (`WALK_CONCURRENCY`), one result line per box, then the closing counts with each failed box (E10) and the E10 hints once. API secrets for inventory; **no SSH**. Missing health shows **—**. Health is read in `HEALTH_STATUS_KEYS` order, each key at the top of the status item and then under `details` (so `status`, `details.status`, …, `state`, `details.state`, matching AppGate's v24/v25 status model), so a v25 Controller that reports health only under `details` is read correctly. If every status row comes back with `status` n/a and no `details` (seen on a v25 Controller), `/appliances/status` is asked once more with no `range` parameter (the documented default), and that reply is used when it carries `details`. A retry that gave nothing better is not repeated for that Controller for the rest of the session, because the status call queries every appliance and can be slow. If it still has none, the toolkit prints a note that this Controller returned no live status: health shows a dash and `APPLIANCE_SKIP_STATUS` cannot skip offline boxes for that collective. Only the vendor Accept header is sent; AppGate's spec allows `application/json` on `/admin/version` only. Report: `reports/walk-*.json`.

Each inventory host is walked on the address SSH found this session, if any, otherwise down the same list SSH would try, with `WALK_FQDN_ATTEMPTS` / `WALK_IP_ATTEMPTS` tries. Net-SNMP reads passphrases from a `0600` `snmp.conf` (not `-A`/`-X` on the command line). SnmpSoft is not used. pysnmp is the fallback, and the Windows release zip uses pysnmp.

## 4) Update cz SSH password

Sets the appliance **cz** password the way the GUI/cz-configd does (survives reboot). After every selected box accepts it, the tool rewrites `credentials.json`. The per-row write matches FQDN. A row with no FQDN is left unchanged, and the tool says so.

`[1/3]` login, `[2/3]` inventory / exclude, preview, then Apply. `[3/3]` SSH.

On each selected box (after the SSH address and host-key check):

1. `openssl passwd -6` with the **new** password on stdin (not in `ps` argv).
2. `cz-config set users/0/encrypted-password "$HASH"`.
3. `cz-config set -j users/0/nopasswd false` (sudo password required again).
4. Wait `CZ_PASSWORD_VERIFY_DELAY`, then SSH again with the **new** password → **OK** or **Failed**.

`ssh_password_new` is required for this tool only. Global-only value prints a warning (every collective gets the same new password). STIG complexity (15 chars, upper/lower/digit/special) when `LAB_MODE=False`. Report: `reports/cz-password-*.json`. After a run where every selected box took the new password, `credentials.json` is updated per collective, and only for a collective whose every listed appliance changed: that row gets its own `ssh_password`. A collective where some boxes were excluded is left unchanged and reported ("N of M boxes now use the NEW SSH password"). With `collectives[]`, the top-level `ssh_password` is never rewritten, so an excluded collective that inherits it keeps the old value its boxes still use. The top-level `ssh_password_new` is cleared only when every collective in the file changed.

## 5) NTP servers

Pushes NTP the Admin UI way (`ntp.servers` on the appliance object) so it survives reboot. Then applies a customization workaround (no REST for that).

`[1/4]` login, `[2/4]` inventory / exclude. Shows **current NTP from GET** (one sample appliance). **1) Add** (update `key`/`keyType`/`keyNo` if hostname matches, else append). A hostname-only row clears the old key. **2) Overwrite** the whole list. Dry run treats a key change as a change.

Preview first. After Apply, each box's SSH address and host key are found before any PUT; a box with no answering address is not changed and is reported as failed (the other boxes still run). **Add** prints **OK already set** when that hostname is already there. A box shown as already set is skipped by Apply: no PUT, restart or verify. **Overwrite** always previews (the peek is hostnames only, so a key change would be invisible). `[3/4]` GET appliance, set `ntp.servers`, PUT the same document. Only `ntp` / legacy `ntpServer(s)` plus `site` UUID reshape may differ; otherwise abort. SHA256 keys without `HEX:` get that prefix. Put `key` in `credentials.json`. After chrony verifies, the key is removed from the appliance document. A later customization restart can drop that key from chrony until menu 5 is run again. A failed PUT restores earlier boxes from the in-memory pre-PUT copy and stops. Overwrite writes a secret-free GET to `reports/replaced/<UTC>/`. That file cannot restore secrets. If the restart fails after the PUT, the report says the NTP change is saved on the Controller but not applied; run menu 5 again on that box. `[4/4]` SSH restarts the NTP apply service (`cz-customization.service`), wait `NTP_VERIFY_DELAY`, then `sudo chronyc ntpdata <host>` → **OK** only if a `Leap status : Normal` line, a `Stratum : 1`-`15` line, and that hostname all appear. Each field is matched as a whole line, so "Not synchronised" never passes. Report: `reports/ntp-*.json` (hostnames only, no keys).

## 6) Allowed sources

Updates 6.7.4 `allowSources` (`address`, `netmask`, `nic`). **No SSH.** A non-IP address, a `netmask` that is not a whole number (`true`, `2.4`), or a prefix outside 1-32 for IPv4 or 1-128 for IPv6, fails that appliance. Before a live change, rows with a prefix shorter than `ALLOW_SOURCES_WIDE_V4` (/8) or `ALLOW_SOURCES_WIDE_V6` (/16) are listed and need a **y**; anything else cancels with nothing changed. The other appliances are still planned. A `nic` that is not a plain interface name fails that appliance. An empty `nic` still means Any. JSON is **`all` then appliance type → slot → entries**. `all` applies to every box; type blocks merge on top (deduped). Multi-function boxes also merge **per slot**.

| Slot | GUI | PUT field |
| --- | --- | --- |
| `ssh` | System Settings → SSH Server → Allowed Sources | `sshServer.allowSources` |
| `spa` | Functions → System TLS Connection (SPA) | `clientInterface.allowSources` |
| `admin` | Admin/API TLS — Controller or LogServer | `adminInterface.allowSources` |
| `https` | Functions → HTTPS Settings — Portal | `clientInterface.allowSources` (portal) |
| `ping` | Miscellaneous → Allow Ping Sources | `ping.allowSources` |
| `snmp` | Miscellaneous → SNMP Server → Sources | `snmpServer.allowSources` |

Every type has `ssh`, `spa`, `ping`, `snmp`. **`admin` only on `controller` and `logServer`.** **`https` only on `portal`.** `spa` and `https` share `clientInterface` (union if both apply).

Blank `nic` (or omit it) means **Any NIC**. The PUT omits `nic`; `"nic": ""` is HTTP 422. `allowed_sources` may be global or on a `collectives[]` row.

PUT only that field, and only if `allowSources` already exists on the parent. Does not create `sshServer` / etc. **/32 and /128** matching **this** box’s IPs are dropped. **1) Add** per slot (**OK already set** if those rows are already there). **2) Replace** per slot (empty replace refused; backup `reports/replaced/`). Preview first. Replace always shows the full plan, then **y** then type **YES** (cannot be disabled). The plan is keyed by appliance id. Before PUT, **E20** if this computer’s outbound IP or an `ALLOW_SOURCES_PROTECTED` address would not match new **SSH** or **Admin/API / SPA/HTTPS**. A hostname is resolved on both address families. The lookup uses the SSH prime timeout and continues if it fails. A failed PUT restores earlier boxes from the in-memory pre-PUT copy and stops. If that restore fails, the tool names the boxes that stayed changed. Unexpected PUT diffs abort. Client Profile View still required on portals.

## C) Configure

Interactive editor for `app/config.py`. Lists `DEBUG`, `LAB_MODE`, `INSECURE_API`, `CNSA_STRICT`, `DRY_RUN`, `SKIP_CREDENTIAL_WALK`, lockout flags, SSH/walk timeouts, concurrency, retries. Enter keeps the current value; **S** writes the file atomically (a setting assigned more than once in `config.py` is refused and nothing is written) and **exits the toolkit** (relaunch so imports see the new values); **Q** cancels and returns to the menu. Flipping `LAB_MODE` off→on requires confirm. That flag changes SSH host-key checks and STIG floors. It does not skip the Controller CA. Saving `INSECURE_API=True` requires `y` then `YES`.

## D / U) Dependencies

- **D:** `pip download` into `app/vendor/wheels` on a **networked machine with the same OS and Python**, then unpack into `app/vendor/site`. Copy `app/vendor/` to the air-gap host.  
- **U:** reinstall `app/vendor/requirements.txt` into `vendor/site` (needs network). A newer release is refused until that file changes.  
- A GitHub **release zip** includes `app/vendor/RELEASE` (gitignored) so **D** and **U** are omitted. Source clones have no that file, so D/U stay on the menu. The Windows zip also omits the Linux and macOS launchers.

## Launchers

| OS | Launcher |
| --- | --- |
| Windows | `MultiCollectiveToolkit-Windows.bat` |
| Linux | `./MultiCollectiveToolkit-Linux.sh` |
| macOS | `MultiCollectiveToolkit-macOS.command` |

Double-click the launcher for the menu, or pass a tool: `MultiCollectiveToolkit-Windows.bat 1` / `python app/main.py walk`. On Linux/macOS: `chmod +x` once. On macOS, right-click → Open the first time.

## Prerequisites

- Python 3.11.5+ (Windows release zips are built for **Python 3.14**)
- SSH to the appliance with sudo
- AppGate admin API (MFA-exempt local user recommended)

**API Admin Role** (6.7: Privileges = action + target). Scope All, or tags/IDs that cover the objects on the selected appliances. `View` + target **All** works but is broader than needed.

| Action | Target | Needed for |
| --- | --- | --- |
| View | Appliance | All API tools (login / inventory) |
| Edit | Appliance | Menus 1, 5, and 6 (full appliance PUT) |
| View | Site | Menus 1, 5, and 6 (PUT re-checks `site`) |
| View | Client Profile | Menus 1, 5, and 6 on **portal** appliances (`portal.profiles[]` are client profile names; missing View → HTTP 422) |

Optional walk backend: Linux `snmp` / `net-snmp-utils` or macOS `brew install net-snmp`. Passphrases go in a mode `0600` `snmp.conf`, not on the command line. The walk passes `-e` when an engine ID is known and stops at `SNMP_WALK_OID`. SnmpSoft is not used. Otherwise walks use `pysnmp`. The Windows release zip uses pysnmp.

```bash
python -m unittest discover -s tests
```

The tests cover SNMP key localization (`tests/test_snmp_hashgen.py`) and the error-code registry (`tests/test_error_codes.py`: every code used is in `app/core/errors.py` and in the table below, and the reverse). They read source and fixed vectors only; no Controller or SSH host is contacted.

## credentials.json (optional, gitignored)

Copy `credentials.example.json` to `credentials.json` next to the launchers. Missing keys are prompted. Secrets use `getpass` (typed twice). Do not commit this file.

**Global** (top-level): used by every collective unless that row overrides the same key.

| Field | Required | Used by | Meaning |
| --- | --- | --- | --- |
| `ssh_host_keys` | Production SSH | known_hosts | OpenSSH lines from outside the admin API. Optional when a terminal can answer the host-key prompt. Required for a non-interactive run unless `SSH_KNOWN_HOSTS` is set. |
| `ssh_username` | Menus 1, 2, 4, 5 | SSH | Appliance login (usually `cz`). Not used by walk. |
| `ssh_password` | Menus 1, 2, 4, 5 | SSH | Current sudo/SSH password. Not used by walk. |
| `ssh_password_new` | Menu 4 only | cz password | Replacement cz password. Prefer per-collective. Global-only prints a warning |
| `api_username` | All tools | Controller API | Admin API user (old name: `admin_username`) |
| `api_password` | All tools | Controller API | Admin API password (old name: `admin_password`) |
| `snmp_user` | Menus 1 and 3 | SNMPv3 | USM user name: 1-32 letters, digits, underscore, dot, or hyphen. A longer or other name stops menus 1 and 3 with **E21** before login |
| `snmp_auth` | Menus 1 and 3 | SNMPv3 | Auth passphrase (min 8 lab / 15 if `LAB_MODE=False`). No spaces or control characters (**E21**); the walk passes it as one token |
| `snmp_priv` | Menus 1 and 3 | SNMPv3 | Priv passphrase. Prompted if missing or too short. No spaces or control characters (**E21**). Identical to auth prints a DISA warning |
| `rouser` | Optional | Menu 1 | Read-only username written into snmpd.conf |
| `mibs` | Never | Reserved | Array of MIB/OID names (e.g. `["SNMPv2-MIB"]`) |
| `ntp_servers` | Menu 5 | NTP | Array of hostname strings or `{hostname, keyType, keyNo, key}` objects. A present value that is not an array, a bad row, a hostname that is not an IP or FQDN, a `keyNo` of true/false, a decimal, or outside 1-4294967295 (a leading zero is dropped: `007` is key 7), or a field with a control character stops the load with **E12**. A typed hostname is checked the same way and asked again. A missing value is prompted. SHA256, SHA384 and SHA512 keys get `HEX:` prepended. The key settings are checked by one rule at load (**E12**), at the typed prompt (asked again) and before the PUT: `key` and `keyType` must be text; `keyType` must be SHA512, SHA384 or SHA256 (with or without a dash; `SHA2` means SHA256), with MD5, SHA1 and `SHA` (SHA-1) refused unless `LAB_MODE`; SHA384 needs a v25 Controller (AppGate's v24 API lists SHA512 but not SHA384) and is refused before the PUT on v24; with `CNSA_STRICT` on, SHA256 gets a warning because CNSA 2.0 wants SHA384 or SHA512; a `key` needs a `keyType` (unless `LAB_MODE`) and a `keyNo`. A `keyType` with no `key` is allowed. A bad row therefore stops menu 5 before any box is changed. Collective list overrides global |
| `allowed_sources` | Menu 6 | allowSources | `all` then type → slot → `{address, netmask, nic?}`. Omit `nic` for Any. A `nic` that is not a plain interface name fails that appliance. Collective object overrides global |

**Each object in `collectives[]`:**

| Field | Required | Meaning |
| --- | --- | --- |
| `fqdn` | Yes | Controller admin hostname (API/SSH/walk first) |
| `agip` | Recommended | Controller IP if the FQDN fails |
| Any global key above | Optional | Override for this collective only. Omit or `""` = inherit global |

A one-controller file (no `collectives[]`, just top-level `fqdn`/`agip`) still works as collective `1`.

```json
{
  "ssh_username": "cz",
  "ssh_password": "sshpass-example-15",
  "ssh_password_new": "",
  "api_username": "api-shared",
  "api_password": "...",
  "snmp_user": "myuser",
  "snmp_auth": "authpass-example15",
  "snmp_priv": "privpass-example15",
  "rouser": "readonlyuser",
  "mibs": ["SNMPv2-MIB"],
  "ntp_servers": [
    { "hostname": "time.example.com", "keyType": "SHA256", "keyNo": "1", "key": "aabbccdd" }
  ],
  "allowed_sources": {
    "all": {
      "ssh": [ { "address": "192.0.2.0", "netmask": 24 } ],
      "spa": [],
      "ping": [],
      "snmp": []
    },
    "controller": { "admin": [] },
    "portal": { "https": [] }
  },
  "collectives": [
    {
      "fqdn": "ctrl-a.example.com",
      "agip": "192.0.2.10",
      "api_username": "api-a",
      "api_password": "...",
      "ssh_password_new": "",
      "mibs": []
    },
    { "fqdn": "ctrl-b.example.com", "agip": "192.0.2.11" }
  ]
}
```

## Standards (NSA / DISA / RFC)

Applies mainly to **menu 1** (SNMP) and **menu 4** (cz password).

| Area | What this toolkit does |
| --- | --- |
| RFC 3411 | Engine ID type 3 = enterprise + `0x03` + MAC. Checked against `ETH_IFACE`. |
| RFC 3414 | Password-to-key localization (SHA-512). |
| RFC 7860 | Auth HMAC-SHA-512. |
| RFC 3826 family | Privacy AES-256 CFB. |
| DISA / SolarWinds | Default SHA-512 + AES-256 CFB. MD5 and SHA-1 rejected for SNMP. SHA-512 auth is supported on current SolarWinds. AES-GCM is not available on this SNMP path, so this is not full CNSA 2.0. NTP `keyType` MD5/SHA1 refused when `LAB_MODE=False`; SHA512 and SHA384 are accepted, and SHA256 is warned about under `CNSA_STRICT`. |
| DISA | authPriv only; v1/v2c stripped; passphrase floor; STIG cz password when `LAB_MODE=False`. |

**Known deviations (`app/config.py`):**

- `LAB_MODE=False`: CA pin, SSH host-key prompt then reject if not stored, SNMP passphrase ≥15, STIG cz password on. Localized keys are not printed in either mode. Set `LAB_MODE=True` only in lab.
- `DEBUG` is **False** (engine IDs stay off the console and out of reports in production). The shipped `config.py` has it off.
- AppGate `createUser` stores a vendor priv OID that is still AES-256 CFB.

## Tunables (`app/config.py`)

Switches:

| Variable | Default | What it does |
| --- | --- | --- |
| `LAB_MODE` | `False` | **SSH and STIG only.** `True`: accept any SSH host key, SNMP passphrase min 8, skip STIG cz-password check. Does **not** skip the Controller CA file and does **not** print localized keys. |
| `DEBUG` | `False` | **Console noise (keep off in production).** `True`: step traces, full JSON dump, pysnmp CFB warning, MAC/oldEngineID lines. Does **not** change TLS, SSH keys, or STIG. Unrelated to `LAB_MODE`. |
| `CNSA_STRICT` | `True` | **SSH and Controller API.** On by default: CNSA-grade algorithms only. SSH: `aes256-ctr`/`aes256-gcm`, `hmac-sha2-512`, P-384/P-521 or DH group16+ key exchange, P-384/P-521 or `rsa-sha2-512` host keys (RSA 3072 bits or more, checked before any password). API: TLS 1.2 with ECDHE AES-256-GCM-SHA384 on P-384, RSA keys 3072 bits or more; TLS 1.3 is off because Python cannot limit its ciphers. Each Controller CA still has its own trust context. A box or Controller that cannot meet it fails with a reason. AppGate documents SSH ciphers as `aes*-ctr` only, so `aes256-ctr` is what appliances negotiate. A Controller certificate key below P-384 or RSA-3072 is refused: at the handshake by the strict TLS settings, and again by a key check before the login password is sent (one extra handshake per Controller login; E18). Verified on v24 and v25 Controllers and their appliances. Set `False` in menu C only for a box or Controller that cannot meet it. |
| `INSECURE_API` | `False` | **API only.** `True`: do not require `certs/AppGate_SDP_<host>_CA.cer` (or `<host>.cer` / `.pem`) and do not verify the Controller certificate. The FQDN file is reused for that Controller's IP fallback. Does not change SSH or STIG. A release zip ignores this. |
| `DRY_RUN` | `False` | **Preview only.** `True`: still previews, never offers Apply. Unrelated to `LAB_MODE`. |
| `SKIP_CREDENTIAL_WALK` | `False` | **Skip step 8 walk** on menu 1 dry-run and live push. Menu 3 is unchanged. |
| `ALLOW_SOURCES_LOCKOUT_SSH` | `True` | Menu 6 replace: **E20** if this host would miss new SSH rules. The check tests this computer's route to the admin address and, when an earlier menu found one, to the address SSH uses this session. |
| `ALLOW_SOURCES_WIDE_V4` / `ALLOW_SOURCES_WIDE_V6` | `8` / `16` | Menu 6 asks before applying a prefix shorter than these. |
| `ALLOW_SOURCES_LOCKOUT_HTTPS` | `True` | Menu 6 replace: **E20** if this host would miss new Admin/API or SPA/HTTPS rules. |
| `ALLOW_SOURCES_PROTECTED` | `()` | Extra IPs or CIDRs that must still match those rules. Empty checks only this host. |

Other knobs:

| Variable | Meaning |
| --- | --- |
| `CA_DIRNAME` | Folder of hand-placed Controller CA files. Default `certs`. Names: `AppGate_SDP_<host>_CA.cer`, `<host>.cer`, `<host>.pem`. DER is converted under `certs/.converted/` and removed when the process exits. |
| `SSH_KNOWN_HOSTS` | Optional pin file. If unset, an accepted prompt is stored under `certs/known_hosts`. Strict mode does not load `~/.ssh/known_hosts`. Wildcard lines are refused. |
| `SSH_PRIME_TIMEOUT` | Seconds each address gets to show its SSH host key during the address search, and the most a DNS lookup for an SSH name may wait (default 3; skips dead NICs and dead resolvers). Host keys for all boxes are read in parallel (`SSH_CONCURRENCY` at a time) with no login; within a box the addresses are still tried in order and the first that answers wins, so the connection count is unchanged. Each box is settled on the main thread as soon as its own read finishes (prompts and pins one at a time), and in menus 1, 2 and 4 its SSH work starts right away, so reachable boxes do not wait for an unreachable box to time out. Each address that fails is named with its reason (timed out, connection refused, connection reset, unreachable, no DNS, SSH handshake failed, SSH banner timed out, or a network error) on screen and in the report `detail`, and a later SSH step that fails uses the same words; when every address timed out, the toolkit suggests checking SSHBRUTE or a firewall from the console. |
| `APPLIANCE_PUT_REUSE_SEC` | Seconds a successful appliance PUT reply (AppGate returns the full updated appliance) may stand in for the next GET of that appliance in the same run (default 0: always GET; turn it on, for example 30, only after a live test shows the Controller refuses a stale `If-Match` with 409 or 412). Saves a GET per later step in menu 1 (pin, push, key strip). Longer reuse widens the window in which another admin's edit to the same appliance could be overwritten. A rollback always GETs. Not in menu C; edit `config.py`. |
| `SSH_CONCURRENCY` / `WALK_CONCURRENCY` | Parallel SSH / SNMP walks (default 5) |
| `SNMP_HASH_ALGO` / `SNMP_AUTH_PROTOCOL` / `SNMP_PRIV_PROTOCOL` | Must stay in sync (SHA-512 / AES-256) |
| `CZ_PASSWORD_VERIFY_DELAY` | Seconds to wait before SSH login-verify after cz-config set |
| `NTP_VERIFY_DELAY` / `NTP_CUSTOMIZATION_UNIT` | Wait after customization restart; systemd unit name |
| `ACAS_*` | Banner, sudoers drop-in, SSHBRUTE, cz-configd unit, `ACAS_SCAP_HOME` (`/home/svc-acas`) |
| `INVENTORY_NAME_WIDTH` / `INVENTORY_ADDR_WIDTH` | Inventory table column caps for hostname (default 30) and SSH address (default 40; a longer name is cut with `…`) |
| `WALK_IP_ATTEMPTS` / `WALK_FQDN_ATTEMPTS` | Walk tries per address (default 2) |
| `WRITE_RUN_REPORT` / `REPORTS_DIRNAME` | Write `reports/*.json` |
| `MENU_CHOICE_ALIASES` | CLI tokens → `1` / `2` / `3` / `4` / `5` / `6` / `c` / `d` / `u` |
| `SNMP_RELOAD_DELAY` | Wait after API pin/push so cz-configd can settle |

## Security notes

- Every appliance PUT sends `If-Match` with the version from the last read of that appliance. With `APPLIANCE_PUT_REUSE_SEC` above 0, that last read can be this run's own previous PUT reply (up to that many seconds old) instead of a fresh GET. The AppGate API does not document whether a stale `If-Match` is refused, so set it to 0 where several admins edit the same appliances at once.
- `DEBUG` and `LAB_MODE` default off. `INSECURE_API` defaults off and is the only switch that skips the Controller CA. Menu C requires `y` then `YES` before saving that on. Turning `CNSA_STRICT` off also asks for a yes, because it relaxes TLS and SSH for every Controller and box. `LAB_MODE` does not skip the CA.
- Tokens and passphrases are not printed. A DEBUG login retry prints status only. Controller error bodies, in DEBUG and normal output, hide the value of any quoted key whose name contains `password`, `passwd`, `token`, `secret`, `passphrase`, `community`, `key`, or `snmpd.conf` (for example `authPassphrase`, `newPassword`, `keyType`), in double or single quotes, and any localized SNMP key after `-l` (any case, with or without a space), before they are shortened. Control and escape sequences are removed whole. Appliance names from the Controller are cleaned the same way before they reach the table, result lines, or reports. New cz password is not on the remote argv. The localized hash is passed to `cz-config` on the appliance. Appliance PUT sends `If-Match` from the GET ETag, version, or updated time. A GET without one of those refuses the PUT.
- Login probes `GET /admin/version` and sets `Accept` to `peerVersion`. Peer 24 sends `machineId`. Peer 25 sends `deviceId`. The version probe, login, and later API calls do not follow redirects. A retry happens only if the Controller names `peer-vN` in the error. The device UUID is per install in `certs/.machine-id`, not a shared constant.
- Unharden creates `/home/svc-acas`. Harden removes it. A sudoers rewrite is mode `440`. A `visudo` failure fails the harden.
- A new SSH password must differ from the current one. Passwordless sudo is turned off before the new hash is written. If every selected box accepts it, `credentials.json` is rewritten for rows that match by FQDN. Two appliances with the same engine ID are not localized. Allow-source plans are keyed by appliance id.
- Ctrl+C during a live ACAS, password, NTP, or allow-sources apply still writes the report.
- The default `CNSA_STRICT=True` limits SSH and the Controller API to the CNSA suite. With `CNSA_STRICT=False`, SSH still refuses SHA-1, CBC, `ssh-rsa`/`ssh-dss` keys, and the SHA-1 Diffie-Hellman groups, but allows AES-128/192, SHA-256 MACs, P-256 and Curve25519 key exchange, `diffie-hellman-group14-sha256`, and Ed25519 or P-256 host keys, and the Controller API uses Python's default TLS (1.2 or later) and does not restrict ciphers. A status read failure does not treat the box as healthy. A health string matches the full label only. Prefix `0` allow-sources are refused. Menu C caps concurrency at 8.
- Reports store hash *lengths*, not hex. Engine ID hex only if `DEBUG=True`. `PRINT_ESXI_KEYS` still follows `LAB_MODE`, but the summary does not print those keys.
- Replace/overwrite writes a pre-change copy to `reports/replaced/<UTC>/` before PUT. It holds only the fields that change may touch (SNMP config, NTP, or allowSources), plus id, name and version, and secret-looking values in it are replaced with `<redacted:field>`; the rest of the appliance is not written. That file can restore `allowSources`. It cannot restore SNMP config or NTP keys. Use the Admin UI or a snapshot for those.
- `credentials.json` is gitignored. New report files are created mode `0600`. The reports directory is set to mode `0700` on each write.
- ACAS unharden weakens STIG until you harden again.
- Identical `snmp_auth` / `snmp_priv` prints a DISA warning.

## Error codes

Per-box errors skip that appliance and continue. The console line starts with the code, then a sentence (**Failed** … `E07` No SSH address answered …), and each report entry of a failed box has a `code` field. Run-stopping errors print `ERROR Exx:` with a **Next:** hint. The codes, titles and default hints live in `app/core/errors.py`; `tests/test_error_codes.py` fails when a code is used but not listed there or in this table, or the reverse.

| Code | When | What to do |
| --- | --- | --- |
| **E01** | No collectives | Add `collectives[].fqdn` (and `agip`) or enter when prompted |
| **E02** | Controller login failed | API user/password, admin role, MFA exemption, port **8443** `/admin`. A v25 403 after a matched Accept is rights, not the header. |
| **E03** | No appliances with SSH | Activated boxes with hostname/SSH IP; Appliance **View** on tags |
| **E04** | Nothing left after appliance exclude | Enter to keep all, or exclude fewer |
| **E05** | No Controller left, or a duplicate FQDN | Enter to keep all, or use a different FQDN |
| **E06** | CA file missing, not a CA, or ACL too open | Place the Controller CA in `certs/`. Restrict the file, `certs/`, and its parent. `INSECURE_API=True` skips the file. `LAB_MODE` does not. |
| **E07** | No SSH address answered, or SSH host key not accepted | Each address tried is named with its reason (timed out, refused, …). Check port 22 from this computer and SSHBRUTE on the box. A declined key prompt, or a run with no terminal, also gives E07: add the key to `SSH_KNOWN_HOSTS` or `ssh_host_keys` for a non-interactive run. |
| **E08** | Appliance PUT refused / HTTP 422 | Unexpected field diff, missing `site`, or **View** on **Client Profile** (`portal.profiles[]`). Not SSH. |
| **E09** | SNMP engine-ID / SSH box failed | Try a new SSH password after FQDN+IP; sudo; `engineIDType 3`; `ETH_IFACE` MAC |
| **E10** | SNMP walk failed | UDP/161, user/auth/priv, leftover `usmUser`; others still walk |
| **E11** | NTP PUT failed | PUT must be `ntp.servers` objects (`hostname`, `keyType`, `keyNo`, `key`) |
| **E12** | No NTP servers in creds, or a bad NTP row | `ntp_servers` entries must be a hostname or an object with `hostname`. A control character is rejected. |
| **E13** | cz password change or login verify failed | Hash may still be set; SSH with `ssh_password_new` or retry menu 4 |
| **E14** | ACAS unharden or harden failed on a box | The report lists the script steps that ran. Check the box before rerunning. |
| **E15** | pip / vendor wheels | Menu **D** on matching OS/Python; copy `app/vendor/` |
| **E16** | No snmpwalk/pysnmp | Install Net-SNMP or use menu D for the pinned `pysnmp`. Workers cannot install. |
| **E17** | NTP chronyc / cz-customization failed | Wait `NTP_VERIFY_DELAY`; `chronyc ntpdata` must show the configured hostname |
| **E18** | `CNSA_STRICT` refused the Controller's TLS or the box's SSH crypto | The peer offers no CNSA-grade algorithm or key. Fix the peer's TLS or SSH settings first. `CNSA_STRICT` is one global setting: turning it off in menu C relaxes TLS and SSH for every Controller and box until it is turned back on. |
| **E19** | Allowed sources missing (menu 6, before login) | Add `allowed_sources` (`all` or on that `collectives[]` row). The message names each Controller. |
| **E20** | This computer would no longer be allowed to SSH/HTTPS to the host | Add this computer's address, use Add, or turn off lockout in Configure |
| **E21** | `credentials.json` cannot be read, or a value cannot be used | The file is not valid JSON in UTF-8 or UTF-16, or a value is true/false or a decimal instead of text, `mibs` holds a non-name, or an SNMP user or passphrase breaks the USM or walk rules. The message names the key and collective, never the value |
| **E22** | `config.py` setting error | A bad `ALLOW_SOURCES_PROTECTED` entry, or a menu C save refused because a setting is assigned twice (`config.py` is not changed). Fix the named setting. |
| **E23** | Report or backup file could not be written | Check free space and permissions on `reports/`. The run itself is not stopped. |

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| 401 login failed | API user, MFA exemption, `APPGATE_PROVIDER` |
| 403 Forbidden | Admin role: Appliance View (+ Edit for menus 1/5/6), Site View, Client Profile View on portals |
| HTTP 422 `portal.profiles[0]` | **View** on **Client Profile** (not a Portal Profile type) |
| TLS verify failed | Production: CA pin mismatch (E06). Lab: `LAB_MODE=True` |
| Health shows **—** | `/appliances/status` empty or 403 |
| Gateway missing from list | Need Appliance **View** on those tags |
| Engine ID not found | `engineIDType 3`, SSH/sudo, MAC on `ETH_IFACE` |
| Walk / digest error | Leftover `usmUser`, algorithm mismatch |
| Unknown SSH host key | Prompt once per appliance. Yes stores the key. No skips that box. A non-interactive run still needs `SSH_KNOWN_HOSTS` or `ssh_host_keys` |
| SSH slow while finding addresses | Dead overlay IPs: each address waits up to `SSH_PRIME_TIMEOUT` for its host key, and the search stops at the first one that answers. Later menus in the same session skip the search |
| Gateway getaddrinfo / wrong NIC | A name that does not resolve is skipped and the admin IP is tried next. The box fails only if no address answers |
| SSH `TimeoutError` right after another menu ran | SSHBRUTE may be rate-limiting new port-22 connections from this host. Wait a minute and run again |
| Connector SSH'd a Controller | `peerInterface.hostname` is ignored. A peer address is tried only when this box already has it |
| Both appliances same engine ID | Localization fails both boxes before the PUT. Fix the appliance engine ID, not `agip`. |
| ACAS banner still hangs **interactive** SSH | Intended. Test: `ssh -T user@host` |
| ACAS visudo shows no NOPASSWD | Check `cz-config get users/0/nopasswd` and the drop-in |
| Menu U fails on air-gap | Use **D**, copy `app/vendor/` |
| Appliance dropped out of a Site | Old bug: 422 retry stripped `site`. Now refuse if site has no UUID; PUT keeps the GET body |
| SNMP PUT added TCP 161 | No longer injects `tcpPort`. Unexpected diffs abort |
| Refusing PUT; unexpected field changes | `DEBUG=True` dumps a secret-free GET/PUT. SNMP may change `snmpd.conf`/`enabled`. NTP may change `ntp`. Menu 6 may change existing `allowSources` only |
| Toolkit stops with "Input closed" | Standard input ended (Ctrl+D, Ctrl+Z then Enter on Windows, or no terminal). Nothing further is applied. Run it again from a terminal |
| Need a flow trace | `DEBUG = True`; optional `# print(f"DEBUG ...")` |

## Layout

| Path | Role |
| --- | --- |
| `MultiCollectiveToolkit-<OS>.*` | Starts `app/main.py` |
| `app/main.py` | Menu only |
| `app/config.py` | Algorithms, timeouts, `LAB_MODE` |
| `app/tools/` | SNMP credentials, ACAS, walk, cz password, NTP, allowed sources, settings, deps |
| `app/api/` | Admin API HTTP client (SNMP, NTP, allowSources mixins) |
| `app/ssh/` | SSH session, SNMP engine/USM, ACAS, cz password, NTP verify |
| `app/core/` | Inventory, prompts, shared run steps and result lines (`run.py`), console layout (`ui.py`), error-code registry (`errors.py`), CA pin, hashgen, walk, utils |
| `app/vendor/` | Offline wheels (not committed) |
| `certs/` | Pinned Controller CAs (gitignored) |
| `credentials.example.json` | Template. `controller.ssh` shows the `{address, netmask, nic}` shape; other slots are empty |
