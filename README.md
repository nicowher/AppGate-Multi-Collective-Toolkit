# AppGate Multi-Collective Toolkit

One launcher for **several AppGate SDP collectives** at once: SNMPv3 USM, ACAS scan prep, cz SSH password, NTP, walks, and config knobs. Works in lab and production, including air-gapped hosts.

GitHub: https://github.com/nicowher/AppGate-Multi-Collective-Toolkit

This is **not** [sdpctl](https://github.com/appgate/sdpctl). Use sdpctl for backup/upgrade. This toolkit is SNMP, ACAS overlays, cz passwords, NTP, and multi-collective fan-out in one run.

## Menu

| Key | Tool |
| --- | --- |
| **1** | SNMP Credential Tool — localize and push SNMPv3 USM (SHA-256 / AES-256) |
| **2** | ACAS scan prep — unharden for scanning, then harden (`cz-configd`) |
| **3** | SNMP Walk — validate authPriv only (no SSH / no config push) |
| **4** | Update cz SSH password — `openssl passwd -6` + `cz-config` + login verify |
| **5** | NTP servers — PUT `ntp.servers`, then restart cz-customization + chronyc verify |
| **C** | Configure — edit `DEBUG`, `LAB_MODE`, SSH/walk timeouts in `config.py` |
| **D** | Download deps — `pip download` into `app/vendor/wheels` (air-gap; does not install) |
| **U** | Update deps — `pip install --upgrade` (needs network; does not refresh wheels) |
| **Q** | Quit |

## Shared behavior (all mutating / inventory tools)

- **`credentials.json`** (gitignored): global defaults plus `collectives[]`. Required per collective: `fqdn` (`agip` recommended). SSH user/pass and API user/pass are required for every tool; SNMP only for 1 and 3; `ssh_password_new` only for 4; `ntp_servers` only for 5; `mibs` never required. Old `admin_*` keys still load as `api_*`.
- **Credential entry** (2+ collectives): **1) global**, **2) per collective**, **3) global then override** selected rows. Short file secrets are discarded; typed replacements are kept. Short/missing `snmp_priv` reuses `snmp_auth`.
- **Exclude collectives** (number or FQDN) then **exclude appliances** (`1.hostname`).
- **FQDN first**, then IP. Gateways never use the Controller IP.
- **`LAB_MODE`** (bottom of `app/config.py`) drives TLS verify, SSH host-key policy, ESXi Kul printing, SNMP min passphrase (8 lab / 15 off-lab), and STIG cz-password check. **`DEBUG` and `DRY_RUN` are separate.**
- **TLS:** `LAB_MODE=False` verifies Controller certs. On failure: `Certificate could not be verified. Proceed anyway? [y/N]:`.
- **SSH keys:** unknown hosts are prompted **on the main thread** before parallel SSH (`Trust and save this host key?`) into `~/.ssh/known_hosts` (`0600`). Workers never call `input()`. After FQDN **and IP** fail: `Try a new password? [y/N]` (main thread only; not for “connected but command failed”).
- **Reports:** `reports/run-*.json`, `dryrun-*.json`, `walk-*.json`, `acas-*.json`, `cz-password-*.json`, `ntp-*.json` (no passwords/tokens; `0600` on Unix). Console JSON only if `DEBUG=True`.
- Missing packages install from `app/vendor/wheels` first, then optional online pip.

## 1) SNMP Credential Tool

Configures **authPriv** SNMPv3 USM on selected appliances so a scanner (e.g. ESXi) can walk them. Needs API + SSH + SNMP secrets. One failed box does not stop the rest.

**CLI (`[1/8]` … `[8/8]`):**

1. **Authenticate** to each Controller (`POST /admin/login`). FQDN first; IP if TLS/connect fails (not on 401/403). Self-signed: `Proceed anyway? [y/N]`.
2. **Inventory** `GET /admin/appliances` + status. **Dry-run only? [y/N]** (preview hashes; no pin/push/purge/walk/snmpd restart). Then the exclude table (Enter = all).
3. **Pin** `engineIDType 3` via appliance PUT (dry-run prints only).
4. **SSH** (host keys primed on the main thread, then up to `SSH_CONCURRENCY` in parallel). Read `oldEngineID` from persistent snmpd.conf and check it against `eth0` MAC (RFC 3411 type 3). **Live** restarts snmpd so type 3 applies; **dry-run does not**.
5. **Localize** auth/priv in-process (RFC 3414 SHA-256) per engine ID. Uses that collective’s `snmp_*` if set. Prints ESXi `user/Kul/Kul/priv` when `PRINT_ESXI_KEYS` (follows `LAB_MODE`).
6. **Push** via Controller: `deleteUser`, `createUser` with localized `-l 0x…` hashes, optional `rouser`, `engineIDType 3`. No `exactEngineID` (cz-configd truncates it). SNMPv1/v2c community lines are stripped.
7. **SSH purge:** stop snmpd, delete leftover persistent `usmUser`, start snmpd so `createUser` recreates the user.
8. **Walk** in parallel (`WALK_CONCURRENCY`): FQDN then IP, `WALK_*_ATTEMPTS` each. First success wins.

After a dry-run preview: **Push config to these appliances now?** re-runs 3–8 live. Report: `reports/run-*.json` or `dryrun-*.json`.

## 2) ACAS scan prep

Temporary overlays so ACAS/Nessus can SSH without hanging or lockout. **Do not PUT these via the appliance API** — that would make unharden the source of truth. Check the **same hostname** you selected (not a connector that was not in the list).

Submenu: **1) Unharden** or **2) Harden**. Then `[1/3]` login, `[2/3]` inventory / exclude / dry-run, `[3/3]` SSH (`SSH_CONCURRENCY`). Host keys primed first.

**Unharden (order matters):**

1. `cz-config set -j users/0/nopasswd true` and write `/etc/sudoers.d/cz-acas-scan` (`/etc/sudoers` is autogenerated; visudo-only edits get wiped). Optional marked append to `/etc/sudoers` if still writable.
2. Patch `/etc/profile.d/ssh_confirm.sh`: wrap the `read -p` / y/N loop in `if [ -t 0 ]`. **Interactive SSH still prompts.** Scanners (no TTY) skip it. Missing file (typical gateway) is a **skip**, not a fail. Backup `*.pre-acas` + `bash -n` before replace.
3. **Last:** `iptables` / `ip6tables` `-w -F SSHBRUTE; -A ACCEPT` (`cz-config set` rebuilds the chain if you flush first). Hardened chain is SET/LOG/DROP/ACCEPT; unharden should be ACCEPT only. Check: `sudo iptables -S SSHBRUTE`.

**Harden:** `nopasswd false`, restore `*.pre-acas`, remove drop-in, `nohup systemctl restart cz-configd` (foreground restart drops SSH). Re-harden as soon as the scan finishes — NOPASSWD + open SSHBRUTE are STIG findings if left on.

Report: `reports/acas-unharden-*.json` / `acas-harden-*.json`.

## 3) SNMP Walk

Validate-only: **no SSH to appliances and no config push.** Confirms authPriv with current `snmp_*`.

- **1) Single IP / FQDN** — walk that host (then *Walk another?*). SNMP secrets required; no Controller login.
- **2) Pull from Controller(s)** — `[1/3]` login, `[2/3]` inventory / exclude, `[3/3]` parallel walks (`WALK_CONCURRENCY`). SSH/API secrets still required for inventory. Health from `GET /admin/appliances/status` (often `n/a`).

Each host: FQDN then IP, `WALK_FQDN_ATTEMPTS` / `WALK_IP_ATTEMPTS`. pysnmp if Net-SNMP is not on PATH. Report: `reports/walk-*.json`.

## 4) Update cz SSH password

Sets the appliance **cz** password the way the GUI/cz-configd does (survives reboot). Does **not** rewrite `credentials.json` — update `ssh_password` yourself before other tools.

`[1/3]` login, `[2/3]` inventory / exclude / dry-run, `[3/3]` SSH.

On each selected box (after host-key prime):

1. `openssl passwd -6` with the **new** password on stdin (not in `ps` argv).
2. `cz-config set users/0/encrypted-password "$HASH"`.
3. `cz-config set -j users/0/nopasswd false` (sudo password required again).
4. Wait `CZ_PASSWORD_VERIFY_DELAY`, then SSH again with the **new** password → `login PASS` or `FAIL`.

`ssh_password_new` is required for this tool only. Global-only value prints a warning (every collective gets the same new password). STIG complexity (15 chars, upper/lower/digit/special) when `LAB_MODE=False`. Report: `reports/cz-password-*.json`.

## 5) NTP servers

Pushes NTP the Admin UI way (`ntp.servers` on the appliance object) so it survives reboot. Then applies a customization workaround (no REST for that).

`[1/4]` login, `[2/4]` inventory / exclude. Shows **current NTP from GET** (one sample appliance). **1) Add** (update `key`/`keyType`/`keyNo` if hostname matches, else append) or **2) Overwrite** the whole list.

`[3/4]` PUT `/admin/appliances/{id}` with `ntp: { servers: [ { hostname, keyType?, keyNo?, key? } ] }`. SHA256 keys without `HEX:` get that prefix. GET does not return the secret; put `key` in `credentials.json`.

`[4/4]` SSH `systemctl restart cz-customization.service` (needed so NTP actually applies), wait `NTP_VERIFY_DELAY`, then `chronyc ntpdata` → PASS if the configured hostname or Leap status appears. Report: `reports/ntp-*.json` (hostnames only, no keys).

## C) Configure

Interactive editor for `app/config.py`. Lists `DEBUG`, `LAB_MODE`, `DRY_RUN`, SSH/walk timeouts, concurrency, retries. Enter keeps the current value; **S** writes the file; **Q** cancels. `TLS_VERIFY` / `SSH_STRICT_HOST_KEY` follow `LAB_MODE`. If a tool already ran this session, restart the launcher so every import sees the new values.

## D / U) Dependencies

- **D:** `pip download` into `app/vendor/wheels` on a **networked machine with the same OS and Python**. Copy the project to the air-gap host.  
- **U:** `pip install --upgrade` into this interpreter (needs network).

## Launchers

| OS | Launcher |
| --- | --- |
| Windows | `MultiCollectiveToolkit-Windows.bat` |
| Linux | `./MultiCollectiveToolkit-Linux.sh` |
| macOS | `MultiCollectiveToolkit-macOS.command` |

Double-click the launcher for the menu, or pass a tool: `MultiCollectiveToolkit-Windows.bat 1` / `python app/main.py walk`. On Linux/macOS: `chmod +x` once. On macOS, right-click → Open the first time.

## Prerequisites

- Python 3.7+
- SSH to the appliance with sudo
- AppGate admin API (MFA-exempt local user recommended)

Optional walk backend: Linux `snmp` / `net-snmp-utils`, macOS `brew install net-snmp`, or Windows Net-SNMP. Otherwise walks use `pysnmp`.

```bash
python -m unittest tests.test_snmp_hashgen
```

## credentials.json (optional, gitignored)

Copy `credentials.example.json` to `credentials.json` next to the launchers. Missing keys are prompted. Secrets use `getpass` (typed twice). Do not commit this file.

**Global** (top-level): used by every collective unless that row overrides the same key.

| Field | Required | Used by | Meaning |
| --- | --- | --- | --- |
| `ssh_username` | All tools | SSH | Appliance login (usually `cz`) |
| `ssh_password` | All tools | SSH | Current sudo/SSH password |
| `ssh_password_new` | Menu 4 only | cz password | Replacement cz password. Prefer per-collective. Global-only prints a warning |
| `api_username` | All tools | Controller API | Admin API user (old name: `admin_username`) |
| `api_password` | All tools | Controller API | Admin API password (old name: `admin_password`) |
| `snmp_user` | Menus 1 and 3 | SNMPv3 | USM user name |
| `snmp_auth` | Menus 1 and 3 | SNMPv3 | Auth passphrase (min 8 lab / 15 if `LAB_MODE=False`) |
| `snmp_priv` | Menus 1 and 3 | SNMPv3 | Priv passphrase. If missing or too short, auth is reused |
| `rouser` | Optional | Menu 1 | Read-only username written into snmpd.conf |
| `mibs` | Never | Reserved | Array of MIB/OID names (e.g. `["SNMPv2-MIB"]`) |
| `ntp_servers` | Menu 5 | NTP | Array of `{hostname, keyType, keyNo, key}`. SHA256 keys get `HEX:` prepended. Collective list overrides global |

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
  "ssh_password": "sshpass",
  "ssh_password_new": "",
  "api_username": "api-shared",
  "api_password": "...",
  "snmp_user": "myuser",
  "snmp_auth": "authpass",
  "snmp_priv": "privpass",
  "rouser": "readonlyuser",
  "mibs": ["SNMPv2-MIB"],
  "ntp_servers": [
    { "hostname": "time.example.com", "keyType": "SHA256", "keyNo": "1", "key": "aabbccdd" }
  ],
  "collectives": [
    {
      "fqdn": "ctrl-a.example.com",
      "agip": "192.168.1.10",
      "api_username": "api-a",
      "api_password": "...",
      "ssh_password_new": "",
      "mibs": []
    },
    { "fqdn": "ctrl-b.example.com", "agip": "10.0.0.10" }
  ]
}
```

## Standards (NSA / DISA / RFC)

Applies mainly to **menu 1** (SNMP) and **menu 4** (cz password).

| Area | What this toolkit does |
| --- | --- |
| RFC 3411 | Engine ID type 3 = enterprise + `0x03` + MAC. Checked against `ETH_IFACE`. |
| RFC 3414 | Password-to-key localization (SHA-256). |
| RFC 7630 / 7860 | Auth HMAC-SHA-256. |
| RFC 3826 family | Privacy AES-256 CFB. |
| CNSA 2.0 | Default SHA-256 + AES-256. MD5 and SHA-1 rejected. |
| DISA | authPriv only; v1/v2c stripped; passphrase floor; STIG cz password when `LAB_MODE=False`. |

**Known deviations (`app/config.py`):**

- `LAB_MODE=False`: TLS on, SSH TOFU, no ESXi Kul dump, SNMP passphrase ≥15, STIG cz password on. Set `LAB_MODE=True` only in lab.
- `DEBUG` is **False**.
- AppGate `createUser` stores a vendor priv OID that is still AES-256 CFB.

## Tunables (`app/config.py`)

Three switches people actually flip:

| Variable | Default | What it does |
| --- | --- | --- |
| `LAB_MODE` | `False` | **Security posture.** `True`: skip TLS verify, WarningPolicy SSH keys, print ESXi Kul, SNMP passphrase min 8, skip STIG cz-password check. `False`: verify TLS (prompt after cert fail), prompt/save SSH host keys, hide Kul, SNMP min 15, STIG cz password on. |
| `DEBUG` | `False` | **Console noise.** `True`: step traces (`DEBUG step2:…`) and full JSON report dump. Does **not** change TLS, SSH keys, or STIG. Unrelated to `LAB_MODE`. |
| `DRY_RUN` | `False` | **Force preview.** `True`: skip the “Dry-run only?” prompt and never pin/push/purge/walk/restart snmpd. You can still dry-run when this is `False` by answering `y` at the prompt. Unrelated to `LAB_MODE`. |

Other knobs:

| Variable | Meaning |
| --- | --- |
| `SSH_KNOWN_HOSTS` | Empty = `~/.ssh/known_hosts` (created `0600` if missing) |
| `SSH_CONCURRENCY` / `WALK_CONCURRENCY` | Parallel SSH / SNMP walks (default 5) |
| `SNMP_HASH_ALGO` / `SNMP_AUTH_PROTOCOL` / `SNMP_PRIV_PROTOCOL` | Must stay in sync (SHA-256 / AES-256) |
| `CZ_PASSWORD_VERIFY_DELAY` | Seconds to wait before SSH login-verify after cz-config set |
| `NTP_VERIFY_DELAY` / `NTP_CUSTOMIZATION_UNIT` | Wait after customization restart; systemd unit name |
| `ACAS_*` | Banner file, sudoers drop-in, SSHBRUTE chain, cz-configd unit |
| `WALK_IP_ATTEMPTS` / `WALK_FQDN_ATTEMPTS` | Walk tries per address (default 2) |
| `WRITE_RUN_REPORT` / `REPORTS_DIRNAME` | Write `reports/*.json` |
| `MENU_CHOICE_ALIASES` | CLI tokens → `1` / `2` / `3` / `4` / `d` / `u` |
| `SNMP_RELOAD_DELAY` | Wait after API pin/push so cz-configd can settle |

## Security notes

- Tokens and passphrases are not printed. New cz password is not on the remote argv.
- Reports store hash *lengths*, not hex. `PRINT_ESXI_KEYS` follows `LAB_MODE`.
- `credentials.json` is gitignored. Reports are `0600` where the OS honors it.
- ACAS unharden leaves `NOPASSWD` and an open `SSHBRUTE` until harden.
- Identical `snmp_auth` / `snmp_priv` prints a DISA warning.

## Error codes

Printed even when `DEBUG=False`. Per-box errors skip that appliance and continue. `ERROR E0x` is the operator line; the tool does not print it twice.

| Code | When | What to do |
| --- | --- | --- |
| **E01** | No collectives | Add `collectives[].fqdn` (and `agip`) or enter when prompted |
| **E02** | Controller login failed | API user/password, MFA exemption, `Proceed anyway?` for self-signed, port **8443** `/admin` |
| **E03** | No appliances with SSH | Activated boxes with hostname/SSH IP; Appliance **View** on tags |
| **E04** | Nothing left after appliance exclude | Enter to keep all, or exclude fewer |
| **E05** | All collectives excluded | Enter to keep all Controllers |
| **E06** | TLS cert not trusted | Answer **y** on Proceed anyway, `LAB_MODE=True`, or trust the CA |
| **E07** | SSH host key rejected | Answer **y** to Trust and save, or pin `~/.ssh/known_hosts` |
| **E09** | SNMP engine-ID / box failed | Try a new SSH password after FQDN+IP; sudo; `engineIDType 3`; eth0 MAC |
| **E10** | SNMP walk failed | UDP/161, user/auth/priv, leftover `usmUser`; others still walk |
| **E11** | NTP PUT/verify failed | PUT must be `ntp.servers` objects; then `cz-customization` + `chronyc ntpdata` |
| **E12** | No NTP servers in creds | `ntp_servers[].hostname` in credentials.json or at the prompt |
| **E13** | cz password login verify failed | Hash may still be set; SSH with `ssh_password_new` or retry menu 4 |
| **E14** | ACAS SSH overlay failed | Confirm selected hostname; Try a new password; others continue |
| **E15** | pip / vendor wheels | Menu **D** on matching OS/Python; copy `app/vendor/` |

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| 401 login failed | API user, MFA exemption, `APPGATE_PROVIDER` |
| 403 Forbidden | Admin role can edit/view appliances |
| TLS verify failed | Self-signed: answer Proceed anyway, or `LAB_MODE=True` |
| Health always `n/a` | `/appliances/status` empty or 403 |
| Gateway missing from list | Need Appliance **View** on those tags |
| Engine ID not found | `engineIDType 3`, SSH/sudo, MAC on `ETH_IFACE` |
| Walk / digest error | Leftover `usmUser`, algorithm mismatch |
| Unknown SSH host key | Answer the **main-thread** prompt |
| SSH hang on host-key prompt | Old bug; keys are primed before the pool |
| ACAS banner still hangs **interactive** SSH | Intended. Test: `ssh -T user@host` |
| ACAS visudo shows no NOPASSWD | Check `cz-config get users/0/nopasswd` and the drop-in |
| Menu U fails on air-gap | Use **D**, copy `app/vendor/` |
| Need a flow trace | `DEBUG = True`; optional `# print(f"DEBUG ...")` |

## Layout

| Path | Role |
| --- | --- |
| `MultiCollectiveToolkit-<OS>.*` | Starts `app/main.py` |
| `app/main.py` | Menu only |
| `app/config.py` | Algorithms, timeouts, `LAB_MODE` |
| `app/tools/` | SNMP credentials, ACAS, walk, cz password, NTP, deps |
| `app/api/` | Admin API HTTP client |
| `app/ssh/` | SSH session, SNMP engine/USM, ACAS, cz password |
| `app/core/` | Inventory, prompts, hashgen, walk, utils |
| `app/vendor/` | Offline wheels (not committed) |
| `credentials.example.json` | Empty template |
