# AppGate SNMPv3 Passwordinator

Tool to generate and push hashed SNMPv3 credentials to AppGate Appliances.

## Overview

This script automates SNMPv3 user configuration on AppGate appliances by:
1. Prompting for SNMP credentials, read-only user, and AppGate IP
2. Authenticating to the AppGate API to obtain a token
3. Retrieving the appliance's SNMP Engine ID via SSH
4. Generating SNMPv3 password hashes via `snmpv3-hashgen`
5. Pushing the updated `snmpd.conf` to the AppGate API
6. Validating the configuration with an SNMP walk

## Prerequisites

- Python 3.7+
- `pip install requests paramiko`
- `snmpv3-hashgen` tool installed and available in PATH (see `SNMPv3-Hash-Generator/`)
- (Optional) `snmpwalk` or `SnmpWalk.exe` installed for automatic validation
- SSH access to the AppGate appliance with sudo permissions

## Usage

Run the script directly with Python:

```bash
python main.py
```

The script will interactively prompt for:

1. **SNMP User** - The SNMPv3 username to configure
2. **SNMP Auth** - The SNMPv3 authentication password
3. **SNMP Priv** - The SNMPv3 privacy password
4. **AppGate IP Address** - The IP address of the target AppGate appliance
5. **SNMP Read-Only Username (rouser)** - Optional read-only user
6. **AppGate Admin Username** - Admin username for API authentication
7. **AppGate Admin Password** - Admin password for API authentication
8. **SSH Username** - SSH username for appliance access
9. **SSH Password** - SSH password for appliance access

## Workflow Steps

1. **Authenticate to AppGate API** - Logs in using the provided admin credentials and stores the bearer token.
2. **Locate Appliance** - Finds the appliance matching the provided IP address via the API.
3. **Retrieve Engine ID** - Connects to the appliance via SSH and extracts the SNMP Engine ID from `snmpd.conf`.
4. **Generate Hashes** - Runs `snmpv3-hashgen` with the provided credentials and Engine ID to generate auth and priv hashes.
5. **Update Configuration** - Pushes the updated `snmpd.conf` (with new user, hashes, and Engine ID) to the AppGate API.
6. **Validate** - Attempts an SNMP walk against the appliance to verify the new credentials work.

## Manual SNMP Walk Validation

A standalone test script is included for manual SNMP walk validation:

```bash
python snmp_walk_test.py
```

This script reads credentials from `credentials.json` and runs a pysnmp SNMP walk against the appliance using the plaintext passwords. It requires:

- `pysnmp` installed (`pip install pysnmp`)
- `credentials.json` populated with `agip`, `snmp_user`, `snmp_auth`, and `snmp_priv`
- UDP port 161 accessible from this machine to the appliance

## Credentials File (Optional)

You can pre-populate inputs in a `credentials.json` file in the same directory as the script to skip interactive prompts:

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

## Output

Upon successful completion, the script prints:
- The generated auth and priv hashes
- The Engine ID
- An ESXi USM string in the format: `user/auth_hash/priv_hash/priv`

## Troubleshooting

- **401 Login Failed**: Ensure the admin account has API access, is exempt from Admin MFA, and the `providerName` is correct (e.g., `local`, `saml`, `oidc`).
- **403 Forbidden**: Ensure the API user has the required admin role privileges.
- **Engine ID Not Found**: Verify SSH access, sudo permissions, and that `snmpd.conf` exists on the appliance.
- **Hash Generation Failed**: Ensure `snmpv3-hashgen` is installed and in PATH.
- **SNMP Walk Skipped**: Install Net-SNMP or SnmpWalk to enable automatic validation.
