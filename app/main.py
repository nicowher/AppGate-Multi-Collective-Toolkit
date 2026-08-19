"""Interactive AppGate SNMPv3 configure-and-validate workflow.

Run order (printed as [1/6] … [6/6]):

  0.  Load credentials.json; prompt only for missing fields
  1.  Log in to the AppGate admin API
  2.  Find the appliance that owns the given IP
  3.  Pin engineIDType 3 via API, then SSH in and read oldEngineID
  4.  Localize auth/priv passphrases (RFC 3414) against that engine ID
  5a. Purge leftover USM rows over SSH, then deleteUser via API
  5b. Push createUser / rouser / engineIDType 3
  6.  Walk the appliance with authPriv; fail the run if the walk fails
"""
import os
import sys
import time
from getpass import getpass

from appgate import AppGateClient
from config import CREDENTIALS_FILENAME, SNMP_MIN_PASSPHRASE_LEN, SNMP_RELOAD_DELAY
from snmp_engine import SNMPEngineFetcher
from snmp_hashgen import SNMPHashGenerator
from snmp_validate import SNMPValidator
from utils import REPO_ROOT, load_credentials

CREDENTIALS_PATH = os.path.join(REPO_ROOT, CREDENTIALS_FILENAME)


def main() -> None:
    try:
        # ------------------------------------------------------------------
        # Step 0 — gather inputs
        # credentials.json (optional, gitignored) fills what it can.
        # Anything still empty is prompted. Secrets use getpass (no echo).
        # ------------------------------------------------------------------
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
        if not all((admin_user, admin_pass, ssh_user, ssh_pass)):
            raise ValueError("admin_username, admin_password, ssh_username, and ssh_password are required")

        # DISA / CNSA: reject short passphrases before we touch the appliance.
        for label, secret in (("snmp_auth", inputs["snmp_auth"]), ("snmp_priv", inputs["snmp_priv"])):
            if len(secret) < SNMP_MIN_PASSPHRASE_LEN:
                raise ValueError(
                    f"{label} must be at least {SNMP_MIN_PASSPHRASE_LEN} characters (DISA / CNSA guidance)"
                )

        client = AppGateClient(inputs["agip"])
        engine_fetcher = SNMPEngineFetcher(ssh_user, ssh_pass)
        hashgen = SNMPHashGenerator()
        validator = SNMPValidator()

        # ------------------------------------------------------------------
        # Step 1/6 — API login
        # Stores a bearer token on the client. MFA-exempt local user is
        # recommended; 401/403 print troubleshooting tips and exit.
        # ------------------------------------------------------------------
        print("\n[1/6] Authenticating to AppGate API...")
        client.login(admin_user, admin_pass)
        print("      Authenticated")

        # ------------------------------------------------------------------
        # Step 2/6 — locate the appliance object
        # Matches admin/client hostname or a NIC static address.
        # Sets client.appliance_id used by every later PUT.
        # ------------------------------------------------------------------
        print("\n[2/6] Locating appliance...")
        appliance = client.find_appliance_by_ip(inputs["agip"])
        print(f"      Found: {appliance.get('name', 'N/A')} ({client.appliance_id})")

        # ------------------------------------------------------------------
        # Step 3/6 — engine ID
        # cz-configd owns /etc/snmp/snmpd.conf, so engineIDType 3 must go
        # through the API first. After cz-configd reloads, SSH restarts
        # snmpd, reads oldEngineID, and checks it against ETH_IFACE MAC
        # (RFC 3411 type 3). We never push exactEngineID (cz-configd
        # truncates it and breaks 11-byte type-3 IDs).
        # ------------------------------------------------------------------
        print("\n[3/6] Retrieving Engine ID via SSH...")
        print("      Pushing engineIDType via API (cz-configd owns snmpd.conf)...", file=sys.stderr)
        client.ensure_engine_id_type3()
        time.sleep(SNMP_RELOAD_DELAY)
        engine_id = engine_fetcher.get_engine_id(inputs["agip"])
        if engine_id.lower().startswith("0x"):
            engine_id = engine_id[2:]
        print(f"      Engine ID: {engine_id}")

        # ------------------------------------------------------------------
        # Step 4/6 — localize passphrases
        # In-process RFC 3414: expand passphrase to 1 MiB, Ku = H(expanded),
        # Kul = H(Ku || engineID || Ku). Hashes are what createUser stores;
        # walks later use the original passphrases.
        # ------------------------------------------------------------------
        print("\n[4/6] Generating SNMPv3 password hashes...")
        hash_data = hashgen.generate_hashes(
            inputs["snmp_user"], inputs["snmp_auth"], inputs["snmp_priv"], engine_id
        )
        auth_hash = hash_data["hashes"]["auth"]
        priv_hash = hash_data["hashes"]["priv"]
        print(f"      Auth Hash: {auth_hash}")
        print(f"      Priv Hash: {priv_hash}")

        # ------------------------------------------------------------------
        # Step 5a/6 — remove the old USM user
        # API deleteUser only edits the appliance snmpd.conf blob.
        # net-snmp also keeps usmUser rows in /var/lib/snmp (and
        # /var/net-snmp). Leftover rows make createUser a no-op and
        # leave the old keys (Wrong SNMP PDU digest).
        # ------------------------------------------------------------------
        print("\n[5a/6] Deleting existing SNMP user from appliance...")
        engine_fetcher.purge_persistent_user(inputs["agip"], inputs["snmp_user"])
        client.delete_snmp_user(inputs["snmp_user"])
        time.sleep(SNMP_RELOAD_DELAY)
        print("      Existing SNMP user deleted")

        # ------------------------------------------------------------------
        # Step 5b/6 — push the new SNMPv3 config
        # Final snmpd.conf: createUser (localized keys), optional rouser,
        # engineIDType 3. SNMPv1/v2c communities are stripped.
        # ------------------------------------------------------------------
        print("\n[5b/6] Updating AppGate SNMP configuration...")
        rouser_line = f"rouser {inputs['rouser']} priv" if inputs.get("rouser") else ""
        client.update_snmp_config(
            inputs["snmp_user"],
            auth_hash,
            priv_hash,
            rouser_line,
        )
        print("      SNMP configuration updated successfully")

        # ------------------------------------------------------------------
        # Step 6/6 — authPriv walk
        # Wait for cz-configd + snmpd, then walk. A failed walk exits 1
        # with no success summary (do not treat a dead push as success).
        # ------------------------------------------------------------------
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
        if not ok:
            sys.exit(1)

        print("\n" + "=" * 60)
        print("Configuration Summary")
        print("=" * 60)
        print(f"User:           {inputs['snmp_user']}")
        print(f"Auth Hash:      {auth_hash}")
        print(f"Priv Hash:      {priv_hash}")
        print(f"Engine:         {engine_id}")
        if rouser_line:
            print(f"Read-Only:      {rouser_line}")
        # Localized keys for ESXi USM — not the original passphrases.
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
