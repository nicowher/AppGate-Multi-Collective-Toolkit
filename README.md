# AppGate SNMPv3 Passwordinator

Generates localized SNMPv3 USM keys and pushes them to an AppGate SDP appliance. Designed for lab and production use, including air-gapped networks.

Repository: https://github.com/nicowher/AppGate-SNMPv3-Passwordinator

## What it does

Double-click a launcher (or run it from a terminal). It reads `credentials.json`, prompts for any missing fields, then:

1. Logs in to the **Controller** (`agip` is the Controller only)
2. Pulls appliances from `GET /appliances` (6.7). Keeps activated/healthy boxes with an admin hostname/IP. You can exclude any from the printed list
3. Pushes `engineIDType 3` via the Controller API for each selected appliance, then waits for cz-configd
4. SSHes in batches (`SSH_CONCURRENCY`, default 5): restart snmpd, read `oldEngineID`, check MAC (RFC 3411 type 3)
5. Localizes auth/priv per engine ID (RFC 3414, SHA-256)
6. Pushes `deleteUser` then `createUser` / `rouser` / `engineIDType 3` one appliance at a time. No `exactEngineID`. v1/v2c communities stripped
7. SSH again in batches: purge leftover `usmUser` from persistent store, restart snmpd
8. Walks every appliance that was pushed. Any failure exits 1

Same SNMP user/auth/priv for every device. SSH/engine-ID failures skip that box; the rest still get pushed and walked.

`SNMP-Walk-<OS>` only walks (no API/SSH). Prompt for the **appliance** IP to walk — that is not the Controller unless you intend to query the Controller. Same SHA-256 / AES-256 and passphrase rules as Passwordinator.

With `DEBUG = True` in `app/config.py` (leave on until you have validated a run), Passwordinator and SNMP-Walk print a JSON block between `BEGIN DEBUG REPORT` and `END DEBUG REPORT`. No passwords or tokens. Extra `# print("DEBUG stepN: ...")` lines are in the sources — uncomment those for step-level traces.

Missing Python packages install from `app/vendor/wheels` first (air-gapped), then offer online pip if you allow it.

## Launchers

Keep `README.md`, credentials files, and launchers in this folder. Python lives in `app/`.

| OS | Configure appliance | Walk only | Prefetch wheels |
| --- | --- | --- | --- |
| Windows | `Passwordinator-Windows.bat` | `SNMP-Walk-Windows.bat` | `Download-Deps-Windows.bat` |
| Linux | `./Passwordinator-Linux.sh` | `./SNMP-Walk-Linux.sh` | `./Download-Deps-Linux.sh` |
| macOS | `Passwordinator-macOS.command` | `SNMP-Walk-macOS.command` | `Download-Deps-macOS.command` |

On Linux/macOS: `chmod +x *.sh *.command` once. On macOS, right-click → Open the first time.

Required fields: `snmp_user`, `snmp_auth`, `snmp_priv`, `agip` (**Controller IP**), `admin_username`, `admin_password`, `ssh_username`, `ssh_password`. `rouser` is optional. Passphrases must be at least `SNMP_MIN_PASSPHRASE_LEN` (default 8). Appliance IPs are **not** typed in; they come from the Controller.

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
  "agip": "192.168.1.10",
  "rouser": "readonlyuser",
  "admin_username": "admin",
  "admin_password": "adminpass",
  "ssh_username": "admin",
  "ssh_password": "sshpass"
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

- `TLS_VERIFY = False` — appliances usually have a self-signed cert. Set `True` when you trust the CA (DISA prefers this).
- `SSH_STRICT_HOST_KEY = False` — unknown host keys warn, then connect. Set `True` after pinning the appliance in `known_hosts`.
- AppGate `createUser` stores a vendor priv OID (`.1.3.6.1.4.1.14832.1.4`) that is still AES-256 CFB; walks use pysnmp’s AES-256 protocol object.

## Tunables (`app/config.py`)

| Variable | Meaning |
| --- | --- |
| `SNMP_HASH_ALGO` / `SNMP_AUTH_PROTOCOL` / `SNMP_PRIV_PROTOCOL` | Must stay in sync |
| `ALLOWED_HASH_ALGOS` | CNSA-allowed localization hashes |
| `SNMP_MIN_PASSPHRASE_LEN` | Raise to 15 for stricter sites |
| `ENGINE_ID_TYPE` / `ETH_IFACE` | Type 3 + MAC source |
| `SSH_CONCURRENCY` | Parallel SSH sessions (default 5) |
| `APPLIANCE_SKIP_STATUS` | Health values skipped (offline / error / not active) |
| `TLS_VERIFY` / `SSH_STRICT_HOST_KEY` / `SSH_PORT` | Transport hardening |
| `APPGATE_*` | API version, port, provider, machineId |
| `STRIP_V1V2_COMMUNITIES` | Drop `rocommunity` / `rwcommunity` |
| `DEBUG` | JSON report at end (on). Uncomment `# print("DEBUG ...")` in sources for traces |
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
