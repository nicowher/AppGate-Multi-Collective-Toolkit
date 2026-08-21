# AppGate SNMPv3 Passwordinator

Generates localized SNMPv3 USM keys and pushes them to an AppGate SDP appliance. Designed for lab and production use, including air-gapped networks.

Repository: https://github.com/nicowher/AppGate-SNMPv3-Passwordinator

## What it does

Double-click a launcher (or run it from a terminal). It reads `credentials.json`, prompts for any missing fields, then:

1. Logs in to **every** Controller in `collectives[]` (array order = collective `1`, `2`, …). Each has its own API account and bearer token. A failed login skips that collective
2. Pulls appliances from each successful login. One exclude list; handles are `1.hostname` (avoids name clashes across sites)
3. Pushes `engineIDType 3` via the Controller API for each selected appliance, then waits for cz-configd
4. SSHes in batches (`SSH_CONCURRENCY`, default 5): restart snmpd, read `oldEngineID`, check MAC (RFC 3411 type 3)
5. Localizes auth/priv per engine ID (RFC 3414, SHA-256)
6. Pushes `deleteUser` then `createUser` / `rouser` / `engineIDType 3` one appliance at a time. No `exactEngineID`. v1/v2c communities stripped
7. SSH: **stop snmpd**, delete persistent `usmUser` (net-snmp will not update an existing user’s password), **start snmpd** so `/etc` `createUser` writes the new keys
8. Walks every pushed appliance: **IP first** (NAT), then FQDN. Attempts are `WALK_IP_ATTEMPTS` / `WALK_FQDN_ATTEMPTS` (default 2 each). Gateways never use the Controller IP.

Same SNMP user/auth/priv for every device. SSH/engine-ID failures skip that box; the rest still get pushed and walked.

`SNMP-Walk-<OS>` asks **1) single FQDN/IP** (then *Walk another?*) or **2) pull list from Controller(s)** (same FQDN-first login / exclude as Passwordinator). No SSH and no config push. Health uses `GET /admin/appliances/status` (not the removed `/stats/appliances`).

**Reports:** `WRITE_RUN_REPORT = True` prints JSON and writes timestamped `reports/run-*.json` / `dryrun-*.json` / `walk-*.json` (no passwords/tokens; hash *lengths* only in the file).

**Dry-run flow:** After inventory loads → **Dry-run only?** → exclude appliances → preview (engine ID read without snmpd restart + hashes) → report → **Push config now?** (`y` = live pin/push/purge/walk + second report). `DRY_RUN = True` in `config.py` skips the first prompt.

Missing Python packages install from `app/vendor/wheels` first (air-gapped), then offer online pip if you allow it.

## Launchers

Keep `README.md`, credentials files, and launchers in this folder. Python lives in `app/`.

| OS | Configure appliance | Walk only | Prefetch wheels |
| --- | --- | --- | --- |
| Windows | `Passwordinator-Windows.bat` | `SNMP-Walk-Windows.bat` | `Download-Deps-Windows.bat` |
| Linux | `./Passwordinator-Linux.sh` | `./SNMP-Walk-Linux.sh` | `./Download-Deps-Linux.sh` |
| macOS | `Passwordinator-macOS.command` | `SNMP-Walk-macOS.command` | `Download-Deps-macOS.command` |

On Linux/macOS: `chmod +x *.sh *.command` once. On macOS, right-click → Open the first time.

Shared: `snmp_user`, `snmp_auth`, `snmp_priv`, `ssh_username`, `ssh_password`. `rouser` is optional.

Per collective: required `fqdn`, optional `agip`, `admin_username`, `admin_password`. API: FQDN then IP (not on 401/403). SSH: FQDN then IP (Controller uses credentials `agip`; gateway uses appliance `ssh_ip`). SNMP walk: **IP first**, then FQDN (`WALK_IP_ATTEMPTS` / `WALK_FQDN_ATTEMPTS`). Gateways never walk the Controller IP.

A single-controller file still works (collective `1`) but you will be prompted for `fqdn` if it is missing.

## Prerequisites

- Python 3.7+
- SSH to the appliance with sudo
- AppGate admin API access (MFA-exempt local user recommended)

```bash
Download-Deps-Windows.bat          # Windows
./Download-Deps-Linux.sh           # Linux
open Download-Deps-macOS.command   # macOS
```

Optional walk backend: Linux `snmp` / `net-snmp-utils`, macOS `brew install net-snmp`, or Windows Net-SNMP. Otherwise validation uses `pysnmp`.

## credentials.json (optional, gitignored)

Copy `credentials.example.json` to `credentials.json` next to the launchers. Missing keys are prompted. Secrets use `getpass`. `agip` is the **Controller** IP for Passwordinator. SNMP-Walk uses it as the single walk target. Do not commit this file.

```json
{
  "snmp_user": "myuser",
  "snmp_auth": "authpass",
  "snmp_priv": "privpass",
  "rouser": "readonlyuser",
  "ssh_username": "admin",
  "ssh_password": "sshpass",
  "collectives": [
    { "fqdn": "ctrl-a.example.com", "agip": "192.168.1.10", "admin_username": "api-a", "admin_password": "..." },
    { "fqdn": "ctrl-b.example.com", "agip": "10.0.0.10", "admin_username": "api-b", "admin_password": "..." }
  ]
}
```

## Air-gapped install

On a **networked machine with the same OS and Python version**:

```bash
./Download-Deps-Linux.sh
```

That fills `app/vendor/wheels/` (`requests`, `paramiko`, `pysnmp` and their dependencies). Copy the whole project folder to the air-gapped host. Launchers install from `app/vendor/` before any network pip.

Wheels are gitignored. A GitHub ZIP has no wheels until you run Download-Deps. This repo’s cache (if you copy it) is only valid for that OS/Python.

Hashing is in-process. No `snmpv3-hashgen` binary is required.

RFC 3414 / CNSA checks:

```bash
python -m unittest tests.test_snmp_hashgen
```

## Standards (NSA / DISA / RFC)

| Area | What this tool does |
| --- | --- |
| RFC 3411 | Engine ID type 3 = 4-byte enterprise (MSB set) + `0x03` + 6-byte MAC. Validated against `ETH_IFACE`. |
| RFC 3414 | Password-to-key: expand passphrase to 1 MiB, `Ku = H(expanded)`, `Kul = H(Ku \|\| engineID \|\| Ku)`. |
| RFC 7630 / 7860 | Auth HMAC-SHA-256 (`usmHMAC192SHA256AuthProtocol`). |
| RFC 3826 family | Privacy AES-256 CFB (`AES256` / `usmAesCfb256Protocol`). |
| CNSA 2.0 (NSA) | Default SHA-256 + AES-256. MD5 and SHA-1 are rejected. |
| DISA SNMP STIG | authPriv only; v1/v2c communities stripped from pushed config; min passphrase length; no default `public` community written by this tool. |
| Timeouts | Every SSH, HTTPS, pip, and walk call has a timeout so the tool cannot hang on a dead socket. |

**Known deviations (set in `app/config.py`):**

- `TLS_VERIFY` / `SSH_STRICT_HOST_KEY` live at the **bottom of `app/config.py`**. Lab = both `False` (self-signed). Production = both `True` after you trust the CA and pin SSH host keys. The script warns at start when either is False.
- AppGate `createUser` stores a vendor priv OID (`.1.3.6.1.4.1.14832.1.4`) that is still AES-256 CFB; walks use pysnmp’s AES-256 protocol object.

## Tunables (`app/config.py`)

| Variable | Meaning |
| --- | --- |
| `SNMP_HASH_ALGO` / `SNMP_AUTH_PROTOCOL` / `SNMP_PRIV_PROTOCOL` | Must stay in sync |
| `ALLOWED_HASH_ALGOS` | CNSA-allowed localization hashes |
| `SNMP_MIN_PASSPHRASE_LEN` | Raise to 15 for stricter sites |
| `ENGINE_ID_TYPE` / `ETH_IFACE` | Type 3 + MAC source |
| `SSH_CONCURRENCY` | Parallel SSH sessions (default 5) |
| `APPLIANCE_SKIP_STATUS` | Health values skipped (offline / not active / warning). `error` is still configured. |
| `TLS_VERIFY` / `SSH_STRICT_HOST_KEY` / `SSH_PORT` | Transport hardening |
| `APPGATE_*` | API version, port, provider, machineId |
| `STRIP_V1V2_COMMUNITIES` | Drop `rocommunity` / `rwcommunity` |
| `WRITE_RUN_REPORT` | Write `reports/run-*.json` at end (default on) |
| `REPORTS_DIRNAME` | Report folder under repo root (`reports`) |
| `DRY_RUN` | Preview: no pin/push/purge/walk/snmpd restart |
| `DEBUG` | Extra console dump (off) |
| `WALK_IP_ATTEMPTS` / `WALK_FQDN_ATTEMPTS` | Walk tries per IP / per FQDN (default 2) |
| `SNMPD_STOP_RETRIES` / `USM_SED_RETRIES` / `USM_RECREATE_WAITS` | Persistent USM purge timing |
| `APPLIANCE_STATUS_PATH` | `GET /appliances/status` (6.3+) |
| `YES_ANSWERS` | Accepted yes replies (`y`, `yes`) |
| Timeouts and `SNMP_RELOAD_DELAY` | Hang prevention and cz-configd wait |

Older boxes that only speak SHA-1 / AES-128 will fail validation. Changing algorithms is a policy exception, not the default.

## Security notes

- API tokens and walk passphrases are not printed.
- Localized hashes in the summary are USM keys for ESXi, not the original passwords.
- Windows never downloads a Net-SNMP installer.
- Persistent USM edits stay under `/var/lib/snmp` and `/var/net-snmp` (no `find /`).
- `credentials.json` is gitignored.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| 401 login failed | API user, MFA exemption, `APPGATE_PROVIDER` (`local` / `saml` / `oidc`) |
| 403 Forbidden | Admin role can edit appliances |
| Gateway missing from list | 6.7 lists only appliances this user can **View**. Edit without View is not enough. Grant Appliance View on all tags / All appliances. |
| Engine ID not found | API `engineIDType 3`, SSH/sudo, `oldEngineID` after restart, MAC on `ETH_IFACE` |
| Passphrase too short | Increase length or lower `SNMP_MIN_PASSPHRASE_LEN` |
| Walk timeout then pass | cz-configd may drop SNMP iptables briefly; retries usually recover |
| SSH to Controller FQDN times out | NAT/DNS: set `agip` in that collective; SSH retries the configured IP |
| Unknown ssh-rsa host key | Expected when `SSH_STRICT_HOST_KEY` is False |
| Vendor install failed | Wheels built for another OS/Python — rerun Download-Deps on a matching host |

## Layout

| Path | Role |
| --- | --- |
| `Passwordinator-<OS>.*` | Full configure + validate |
| `SNMP-Walk-<OS>.*` | Walk only |
| `Download-Deps-<OS>.*` | Prefetch `app/vendor/wheels` |
| `credentials.example.json` | Empty template |
| `app/main.py` | Multi-appliance workflow |
| `app/inventory.py` | Controller list + exclude prompt |
| `app/config.py` | Algorithms, timeouts, paths |
| `app/appgate.py` | Admin API |
| `app/snmp_engine.py` | SSH engine ID + USM purge |
| `app/snmp_hashgen.py` | RFC 3414 localization |
| `app/snmp_validate.py` | Walk + optional tool install |
| `app/snmp_walk_test.py` | Standalone walk |
| `app/utils.py` | Vendor pip + credentials load |
| `app/vendor/` | Offline wheel cache (not committed) |
