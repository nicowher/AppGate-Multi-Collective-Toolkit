import os
import sys
import time
from getpass import getpass

from appgate import AppGateClient
from config import SNMP_RELOAD_DELAY
from snmp_engine import SNMPEngineFetcher
from snmp_hashgen import SNMPHashGenerator
from snmp_validate import SNMPValidator
from utils import load_credentials

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_PATH = os.path.join(SCRIPT_DIR, "credentials.json")


def main() -> None:
    try:
        # Fill gaps from credentials.json; prompt only for what is missing.
        creds = load_credentials(CREDENTIALS_PATH)

        def require(field: str, prompt: str, sensitive: bool = False) -> str:
            value = creds.get(field, "")
            if not value:
                if sensitive:
                    value = getpass(f"{prompt}: ").strip()
                else:
                    value = input(f"{prompt}: ").strip()
            return value

        inputs = {
            "snmp_user": require("snmp_user", "SNMP User"),
            "snmp_auth": require("snmp_auth", "SNMP Auth", sensitive=True),
            "snmp_priv": require("snmp_priv", "SNMP Priv", sensitive=True),
            "agip": require("agip", "AppGate IP Address"),
            "rouser": require("rouser", "SNMP Read-Only Username (rouser)"),
        }

        if not all(inputs[k] for k in ("snmp_user", "snmp_auth", "snmp_priv", "agip")):
            raise ValueError("snmp_user, snmp_auth, snmp_priv, and agip are required")

        admin_user = require("admin_username", "AppGate Admin Username")
        admin_pass = require("admin_password", "AppGate Admin Password", sensitive=True)
        ssh_user = require("ssh_username", "SSH Username")
        ssh_pass = require("ssh_password", "SSH Password", sensitive=True)

        client = AppGateClient(inputs["agip"])
        engine_fetcher = SNMPEngineFetcher(ssh_user, ssh_pass)
        hashgen = SNMPHashGenerator()
        validator = SNMPValidator()

        print("\n[1/6] Authenticating to AppGate API...")
        client.login(admin_user, admin_pass)
        print("      Authenticated")

        print("\n[2/6] Locating appliance...")
        appliance = client.find_appliance_by_ip(inputs["agip"])
        print(f"      Found: {appliance.get('name', 'N/A')} ({client.appliance_id})")

        print("\n[3/6] Retrieving Engine ID via SSH...")
        engine_id = engine_fetcher.get_engine_id(inputs["agip"])
        if engine_id.lower().startswith("0x"):
            engine_id = engine_id[2:]
        print(f"      Engine ID: {engine_id}")

        print("\n[4/6] Generating SNMPv3 password hashes...")
        hash_data = hashgen.generate_hashes(
            inputs["snmp_user"], inputs["snmp_auth"], inputs["snmp_priv"], engine_id
        )
        auth_hash = hash_data["hashes"]["auth"]
        priv_hash = hash_data["hashes"]["priv"]
        print(f"      Auth Hash: {auth_hash}")
        print(f"      Priv Hash: {priv_hash}")

        # API deleteUser does not clear /var/lib/snmp/snmpd.conf usmUser rows.
        print("\n[5a/6] Deleting existing SNMP user from appliance...")
        engine_fetcher.purge_persistent_user(inputs["agip"], inputs["snmp_user"])
        client.delete_snmp_user(inputs["snmp_user"], engine_id=engine_id)
        print("      Existing SNMP user deleted")

        print("\n[5b/6] Updating AppGate SNMP configuration...")
        rouser_line = f"rouser {inputs['rouser']} priv" if inputs.get("rouser") else ""
        client.update_snmp_config(
            inputs["snmp_user"],
            auth_hash,
            priv_hash,
            rouser_line,
            engine_id=engine_id,
        )
        print("      SNMP configuration updated successfully")

        print("\n[6/6] Validating SNMP walk...")
        print("      Waiting for SNMP daemon to reload...", file=sys.stderr)
        time.sleep(SNMP_RELOAD_DELAY)
        ok = validator.validate_snmp_walk(
            inputs["agip"],
            inputs["snmp_user"],
            inputs["snmp_auth"],
            inputs["snmp_priv"],
            engine_id=engine_id,
        )
        print("      SNMP walk validation " + ("PASSED" if ok else "FAILED"))

        print("\n" + "=" * 60)
        print("Configuration Summary")
        print("=" * 60)
        print(f"User:           {inputs['snmp_user']}")
        print(f"Auth Hash:      {auth_hash}")
        print(f"Priv Hash:      {priv_hash}")
        print(f"Engine:         {engine_id}")
        if rouser_line:
            print(f"Read-Only:      {rouser_line}")
        print(f"ESXi USM String: {inputs['snmp_user']}/{auth_hash}/{priv_hash}/priv")
        print("=" * 60)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
