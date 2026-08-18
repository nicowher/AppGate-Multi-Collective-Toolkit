# AppGate SNMPv3 Passwordinator

Generates localized SNMPv3 hashes and pushes them to an AppGate appliance.

## What it does

`python main.py` reads `credentials.json`, prompts for any missing fields, then:

1. Logs in to the AppGate admin API
2. Finds the appliance that owns the given IP
3. SSHes in and reads the SNMP Engine ID
4. Hashes the auth/priv passwords with `snmpv3-hashgen` (bundled)
5. Deletes the old SNMPv3 user, then writes the new `createUser` / `rouser` lines
6. Walks the appliance to confirm the new credentials work

`python snmp_walk_test.py` only does step 6 — useful after a previous run.

Missing tools are installed on prompt: `requests`, `paramiko`, `pysnmp`, Linux/macOS Net-SNMP, and `snmpv3-hashgen`. Local files in `vendor/` are used first (air-gapped).

## Prerequisites

- Python 3.7+
- SSH to the appliance with sudo
- AppGate admin API access (MFA-exempt local user recommended)

```bash
python download_deps.py
pip install requests paramiko
```

Optional but more reliable for validation:

- Linux: `snmp` / `net-snmp-utils`
- macOS: `brew install net-snmp`
- Windows: Net-SNMP in PATH, or rely on the `pysnmp` fallback

## Usage

```bash
python main.py
python snmp_walk_test.py
```

Required fields: `snmp_user`, `snmp_auth`, `snmp_priv`, `agip`, plus admin and SSH credentials. `rouser` is optional.

## credentials.json (optional, gitignored)

Copy `credentials.example.json` and rename it to `credentials.json` next to `main.py`, then fill in your values. Any missing key is prompted interactively. Sensitive prompts use `getpass`.

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
python download_deps.py
```

That fills `vendor/wheels/` (requests, paramiko, pysnmp + deps) and `vendor/SNMPv3-Hash-Generator.zip`. Copy the whole project folder to the air-gapped host. `main.py` installs from `vendor/` before touching the network.

Net-SNMP is optional; validation falls back to the vendored `pysnmp` wheel.

## Algorithms

Defaults live in `config.py` and must stay in sync:

- Hash: SHA-256
- Auth: SHA256
- Priv: AES-256

Older appliances that only speak SHA-1 / AES-128 will fail validation with `Wrong SNMP PDU digest`. Change the three values in `config.py` together if you must match an older box.

## Security notes

- `TLS_VERIFY` is `False` because appliances usually have a self-signed cert. Set it `True` if you trust the CA.
- SSH uses `WarningPolicy` (unknown host keys warn, then connect). Pin the host key when you can.
- API tokens and SNMP passwords are not printed. Failed walk commands omit passphrases.
- Windows does **not** download a Net-SNMP installer. Use a local install or `pysnmp`.
- Engine ID lookup greps SNMP directories only — it does not `find /` as root.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| 401 login failed | API user, MFA exemption, `providerName` (`local` / `saml` / `oidc`) |
| 403 Forbidden | Admin role can edit appliances |
| Engine ID not found | SSH, sudo, `/var/lib/snmp/snmpd.conf` |
| Hash generation failed | Run `python download_deps.py` or keep `vendor/SNMPv3-Hash-Generator.zip` |
| Walk failed / digest error | Daemon reload wait, algorithm mismatch, install Net-SNMP |
| Unknown ssh-rsa host key warning | Expected on first connect with `WarningPolicy` |

## Layout

| File | Role |
| --- | --- |
| `main.py` | Interactive workflow |
| `snmp_walk_test.py` | Walk-only check |
| `config.py` | Algorithms, timeouts, TLS |
| `appgate.py` | Admin API |
| `snmp_engine.py` | SSH Engine ID |
| `snmp_hashgen.py` | Localized hashes |
| `snmp_validate.py` | Walk + tool install |
| `utils.py` | credentials.json + vendor/pip helper |
| `download_deps.py` | Prefetch wheels + hashgen zip into `vendor/` |
| `vendor/` | Offline install cache (not committed) |
