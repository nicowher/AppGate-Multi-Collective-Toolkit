# AppGate SNMPv3 Passwordinator

Generates localized SNMPv3 hashes and pushes them to an AppGate appliance.

## What it does

Double-click a launcher (or run it from a terminal). It reads `credentials.json`, prompts for any missing fields, then:

1. Logs in to the AppGate admin API
2. Finds the appliance that owns the given IP
3. Pushes `engineIDType 3` via the API, SSHes in, restarts snmpd, reads `oldEngineID`, and checks it against the configured interface MAC (RFC 3411)
4. Localizes the auth/priv passwords in-process (RFC 3414 / SHA-256)
5. Purges leftover `usmUser` rows over SSH, then pushes `createUser` / `rouser` / `engineIDType 3` (no `exactEngineID`)
6. Walks the appliance to confirm the new credentials work

`SNMP-Walk` only does step 6 — useful after a previous run.

Missing tools are installed on prompt. Local files in `app/vendor/` are used first (air-gapped).

## Prerequisites

- Python 3.7+
- SSH to the appliance with sudo
- AppGate admin API access (MFA-exempt local user recommended)

```bash
# Windows
Download-Deps-Windows.bat

# Linux
chmod +x *.sh
./Download-Deps-Linux.sh

# macOS
chmod +x *.command
open Download-Deps-macOS.command
```

Optional but more reliable for validation:

- Linux: `snmp` / `net-snmp-utils`
- macOS: `brew install net-snmp`
- Windows: Net-SNMP in PATH, or rely on the `pysnmp` fallback

## Usage

Keep `README.md`, credentials files, and the OS launchers in this folder. Python sources and `vendor/` live in `app/`.

| OS | Configure appliance | Walk only | Offline cache |
| --- | --- | --- | --- |
| Windows | `Passwordinator-Windows.bat` | `SNMP-Walk-Windows.bat` | `Download-Deps-Windows.bat` |
| Linux | `./Passwordinator-Linux.sh` | `./SNMP-Walk-Linux.sh` | `./Download-Deps-Linux.sh` |
| macOS | `Passwordinator-macOS.command` | `SNMP-Walk-macOS.command` | `Download-Deps-macOS.command` |

On macOS, double-click the `.command` file (or right-click → Open the first time).

Required fields: `snmp_user`, `snmp_auth`, `snmp_priv`, `agip`, plus admin and SSH credentials. `rouser` is optional.

## credentials.json (optional, gitignored)

Copy `credentials.example.json` to `credentials.json` in this folder (next to the launchers), then fill in your values. Any missing key is prompted interactively. Sensitive prompts use `getpass`.

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

Do not commit this file.

## Air-gapped / offline install

On a networked machine with the same OS and Python version:

```bash
./Download-Deps-Linux.sh
```

That fills `app/vendor/wheels/` (`requests`, `paramiko`, `pysnmp` and their deps). Copy the whole project folder to the air-gapped host. The launcher installs those wheels from `app/vendor/` before touching the network. Password hashing does not need a separate hashgen tool.

Net-SNMP is optional; validation falls back to the vendored `pysnmp` wheel.

## Algorithms

Algorithms, timeouts, API port, `ETH_IFACE`, and file paths live in `app/config.py`. Auth/priv settings must stay in sync:

- Hash: SHA-256
- Auth: SHA256
- Priv: AES-256

Older appliances that only speak SHA-1 / AES-128 will fail validation with `Wrong SNMP PDU digest`. Change the three values in `app/config.py` together if you must match an older box.

## Security notes

- `TLS_VERIFY` is `False` because appliances usually have a self-signed cert. Set it `True` if you trust the CA.
- SSH uses `WarningPolicy` (unknown host keys warn, then connect). Pin the host key when you can.
- API tokens and SNMP passwords are not printed. Failed walk commands omit passphrases.
- Windows does **not** download a Net-SNMP installer. Use a local install or `pysnmp`.
- Engine ID is `engineIDType 3` (MAC). Persistent USM users are edited over SSH; the script does not `find /` as root.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| 401 login failed | API user, MFA exemption, `providerName` (`local` / `saml` / `oidc`) |
| 403 Forbidden | Admin role can edit appliances |
| Engine ID not found | API `engineIDType 3`, SSH/sudo, `oldEngineID` after snmpd restart, MAC on `ETH_IFACE` (`eth0` by default) |
| Hash generation failed | Rare — hashing is in-process; check the engine ID is valid hex |
| Walk failed / digest error | Leftover `usmUser` in `/var/lib/snmp/snmpd.conf`, truncated `exactEngineID`, algorithm mismatch, short reload wait |
| Unknown ssh-rsa host key warning | Expected on first connect with `WarningPolicy` |

## Layout

| File | Role |
| --- | --- |
| `Passwordinator-<OS>.*` | Configure appliance |
| `SNMP-Walk-<OS>.*` | Walk-only check |
| `Download-Deps-<OS>.*` | Prefetch `app/vendor/` |
| `credentials.example.json` | Empty credentials template |
| `app/` | Python sources and optional `vendor/` wheel cache |
