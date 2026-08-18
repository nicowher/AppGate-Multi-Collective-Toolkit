from getpass import getpass
from typing import Dict, Tuple


def prompt_snmp_inputs(creds: Dict[str, str]) -> Dict[str, str]:
    """Collect SNMP and AppGate IP from the operator."""
    print("=" * 60)
    print("AppGate SNMPv3 Configuration Script")
    print("=" * 60)

    inputs = {
        "snmp_user": input(f"SNMP User [{creds.get('snmp_user', '')}]: ").strip() or creds.get("snmp_user", ""),
        "snmp_auth": input(f"SNMP Auth [{creds.get('snmp_auth', '')}]: ").strip() or creds.get("snmp_auth", ""),
        "snmp_priv": input(f"SNMP Priv [{creds.get('snmp_priv', '')}]: ").strip() or creds.get("snmp_priv", ""),
        "agip":      input(f"AppGate IP Address [{creds.get('agip', '')}]: ").strip() or creds.get("agip", ""),
        "rouser":    input(f"SNMP Read-Only Username (rouser) [{creds.get('rouser', '')}]: ").strip() or creds.get("rouser", ""),
    }

    if not all(inputs[k] for k in ("snmp_user", "snmp_auth", "snmp_priv", "agip")):
        raise ValueError("All required input fields are missing")
    return inputs


def prompt_admin_credentials(creds: Dict[str, str]) -> Tuple[str, str]:
    """Collect AppGate API admin credentials."""
    print("\nAppGate API Authentication")
    username = input(f"AppGate Admin Username [{creds.get('admin_username', '')}]: ").strip() or creds.get("admin_username", "")
    password = getpass(f"AppGate Admin Password [{creds.get('admin_password', '')}]: ").strip() or creds.get("admin_password", "")

    if not username or not password:
        raise ValueError("Admin credentials are required")
    return username, password


def prompt_ssh_credentials(creds: Dict[str, str]) -> Tuple[str, str]:
    """Collect SSH credentials for the AppGate appliance."""
    print("\nAppliance SSH Authentication")
    username = input(f"SSH Username [{creds.get('ssh_username', '')}]: ").strip() or creds.get("ssh_username", "")
    password = getpass(f"SSH Password [{creds.get('ssh_password', '')}]: ").strip() or creds.get("ssh_password", "")

    if not username or not password:
        raise ValueError("SSH credentials are required")
    return username, password
