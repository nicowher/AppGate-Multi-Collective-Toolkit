"""Error code registry: one place for what each Exx means and the first thing to try.

Why a registry: codes used to be string literals in many files, with their meanings
only in the README table, and the two drifted (documented codes nothing printed, a
comment naming a code nothing defined). The call site still writes the message,
because only it knows the box, address or Controller reply. This file holds the
fixed part: the title and a default next step. tests/test_error_codes.py checks
that every code the toolkit uses is here and in the README table, and the reverse.
"""
from typing import Dict, Tuple

# code -> (title, default next step). Keep in step with the README "Error codes" table.
CODES: Dict[str, Tuple[str, str]] = {
    "E01": ("No collectives", "Add collectives[].fqdn (and agip) to credentials.json, or enter them when prompted."),
    "E02": ("Controller login failed", "Check API user/password, admin role, MFA exemption, and port 8443 /admin."),
    "E03": ("No appliances with SSH", "Activated boxes need a hostname or SSH IP; the API user needs Appliance View."),
    "E04": ("Nothing left after appliance exclude", "Press Enter to keep all, or exclude fewer."),
    "E05": ("No Controller left, or a duplicate FQDN", "Press Enter to keep all, or use a different FQDN."),
    "E06": ("Controller CA file missing, not a CA, or ACL too open", "Place the Controller CA in certs/ and restrict the file and folder."),
    "E07": ("No SSH address answered, or host key not accepted", "Check port 22 from this computer, SSHBRUTE on the box, and accept the key in a terminal."),
    "E08": ("Appliance PUT refused", "Unexpected field change, missing site, or the API user lacks a View right. Not SSH."),
    "E09": ("SNMP engine-ID read or SSH step failed", "Check sudo, engineIDType 3 and ETH_IFACE on the box."),
    "E10": ("SNMP walk failed", "Check UDP 161, the SNMP user, auth and priv, and leftover usmUser rows."),
    "E11": ("NTP PUT failed", "Each ntp.servers row needs hostname, and keyType/keyNo/key that the Controller accepts."),
    "E12": ("No NTP servers, or a bad NTP row", "Fix the ntp_servers row named in the message."),
    "E13": ("cz password change or login verify failed", "The hash may be set already: try SSH with ssh_password_new, or rerun menu 4."),
    "E14": ("ACAS unharden or harden failed", "The report lists the script steps that ran; check the box before rerunning."),
    "E15": ("pip / vendor wheels", "Run menu D on a matching OS and Python, then copy app/vendor/."),
    "E16": ("No snmpwalk or pysnmp", "Install Net-SNMP or use menu D for the pinned pysnmp."),
    "E17": ("NTP chronyc or cz-customization failed", "Wait NTP_VERIFY_DELAY; chronyc ntpdata must show the configured server."),
    "E18": ("CNSA_STRICT refused the Controller or box crypto", "Fix the peer's TLS or SSH settings first. CNSA_STRICT is global: turning it off relaxes every Controller and box."),
    "E19": ("Allowed sources missing", "Add allowed_sources (all, or on that collectives[] row) in credentials.json."),
    "E20": ("This computer would lose SSH or HTTPS access", "Add this computer's address, use Add, or turn off the lockout check in menu C."),
    "E21": ("credentials.json cannot be read, or a value cannot be used", "Fix the file or the value named in the message."),
    "E22": ("config.py setting error", "Fix the setting named in the message in app/config.py."),
    "E23": ("Report or backup file could not be written", "Check free space and permissions on reports/."),
}


def title(code: str) -> str:
    """The table title for code, or "" for a code that is not registered (the unit test fails on that)."""
    return CODES.get(code, ("", ""))[0]


def default_hint(code: str) -> str:
    """The default next step for code, used when the caller gives no hint of its own."""
    return CODES.get(code, ("", ""))[1]
