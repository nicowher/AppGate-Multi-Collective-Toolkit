import warnings

# ============================================================================
# SNMPv3 Algorithm Configuration
# ============================================================================
# Why SHA-256 + AES-256: CNSA 2.0 / DISA baseline for SNMPv3 authPriv.
# All three paths must use the same trio or walks fail with digest errors:
#   1. createUser line (api/appgate.py)
#   2. RFC 3414 localization (core/snmp_hashgen.py)
#   3. walk client (core/snmp_validate.py / tools/snmp_walk.py)
#
# If you still see "Wrong SNMP PDU digest" after a password change, it is
# usually stale usmUser in /var/lib/snmp (step 7), not these algorithm names.
# Older appliances that only do SHA-1/AES-128 need a coordinated change of
# all three values below (not recommended for regulated environments).
# ============================================================================
SNMP_HASH_ALGO = "sha256"
SNMP_AUTH_PROTOCOL = "SHA256"
SNMP_PRIV_PROTOCOL = "AES256"
# CNSA 2.0 / DISA: do not localize with MD5 or SHA-1.
ALLOWED_HASH_ALGOS = ("sha256", "sha384", "sha512")
# RFC 3414 floor is 8. DISA SNMP STIG often wants 15 — raise here for those sites.
SNMP_MIN_PASSPHRASE_LEN = 8
# RFC 3414 password-to-key expansion (1 MiB).
RFC3414_KDF_LEN = 1048576
# DISA: do not leave SNMPv1/v2c community strings in the pushed config.
STRIP_V1V2_COMMUNITIES = True

# ============================================================================
# pysnmp Protocol Objects
# ============================================================================
# Lazy-imported to avoid hard failures on systems without pysnmp installed.
# Falls back to raw OID tuples if the import fails.
# ============================================================================
def get_auth_protocol():
    try:
        from pysnmp.hlapi.v3arch.asyncio import usmHMAC192SHA256AuthProtocol
        return usmHMAC192SHA256AuthProtocol
    except ImportError:
        try:
            from pysnmp.hlapi import usmHMAC192SHA256AuthProtocol
            return usmHMAC192SHA256AuthProtocol
        except ImportError:
            return (1, 3, 6, 1, 6, 3, 10, 1, 1, 5)

def get_priv_protocol():
    try:
        from pysnmp.hlapi.v3arch.asyncio import usmAesCfb256Protocol
        return usmAesCfb256Protocol
    except ImportError:
        try:
            from pysnmp.hlapi import usmAesCfb256Protocol
            return usmAesCfb256Protocol
        except ImportError:
            return (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 102)

# ============================================================================
# Cryptography Deprecation Warning Suppression
# ============================================================================
# pysnmp uses cryptography's CFB mode which moved to a deprecated location.
# This is safe to suppress until pysnmp updates its dependency.
warnings.filterwarnings(
    "ignore",
    message="CFB has been moved to cryptography.hazmat.decrepit.ciphers.modes.CFB",
    category=DeprecationWarning,
)

def warn_insecure_transport() -> None:
    """DISA: warn when lab defaults weaken transport or dump run data.

    Called at the start of mutating / walk tools (not the menu itself).
    Production: TLS_VERIFY=True, SSH_STRICT_HOST_KEY=True, DEBUG=False.
    """
    import sys
    if not (TLS_VERIFY and SSH_STRICT_HOST_KEY):
        print(
            "WARNING: Insecure transport defaults are on "
            f"(TLS_VERIFY={TLS_VERIFY}, SSH_STRICT_HOST_KEY={SSH_STRICT_HOST_KEY}). "
            "Admin and SSH secrets can be MITM'd. Set both True in app/config.py "
            "on untrusted networks (DISA / CNSA).",
            file=sys.stderr,
        )
    if DEBUG:
        print(
            "WARNING: DEBUG=True — hostnames, engine IDs, and hash lengths print "
            "to the console (no passwords/tokens). Set DEBUG=False for production.",
            file=sys.stderr,
        )

SSH_PORT = 22
# Parallel SSH sessions (engine-ID pass and later USM purge pass).
SSH_CONCURRENCY = 5
# Lab troubleshooting: full JSON dump to the console at end of run (no passwords/tokens).
# DISA: set False before a production run so engine IDs / inventory stay off the console.
DEBUG = False
# Write timestamped reports/*.json; console dump only if DEBUG is on.
WRITE_RUN_REPORT = True
# Live/dry-run summary prints ESXi USM keys (Kul). DISA: False — keys go in reports lengths only.
PRINT_ESXI_KEYS = True
# Unix mode for new report files (owner read/write only). Windows ignores most bits.
REPORT_FILE_MODE = 0o600
# When True: first pass is dry-run without asking. Prompt can still enable dry-run when False.
DRY_RUN = False
# Directory for run-*.json / dryrun-*.json / walk-*.json (under repo root).
REPORTS_DIRNAME = "reports"
SNMPD_STOP_RETRIES = 5
# Seconds between snmpd stop polls (step 7 must see a dead daemon before sed).
SNMPD_STOP_POLL_SEC = 1
USM_SED_RETRIES = 3
USM_RECREATE_WAITS = 5
# Truncate API/SSH/walk error bodies so we never dump a full token-bearing payload.
LOGIN_BODY_PREVIEW = 300
API_ERROR_BODY_PREVIEW = 500
SSH_LOG_PREVIEW = 300
WALK_ERROR_PREVIEW = 500
# Summary banner width (step 8 human table).
SUMMARY_WIDTH = 60
# Inventory table hostname column (step 2).
INVENTORY_NAME_WIDTH = 30
# pip download of vendor wheels is slower than a single install.
VENDOR_DOWNLOAD_TIMEOUT = 300
# RFC 3411 engine ID is 5–32 octets. Type-3 MAC IDs are 11.
ENGINE_ID_MIN_OCTETS = 5
ENGINE_ID_MAX_OCTETS = 32
# Accepted answers for yes/no prompts (Add another Controller, Walk another IP).
YES_ANSWERS = ("y", "yes")
NO_ANSWERS = ("n", "no")
# CLI menu first-arg aliases → 1 configure | 2 acas | 3 walk | d deps | u pip-upgrade | q quit
MENU_CHOICE_ALIASES = {
    "1": "1",
    "configure": "1",
    "credential": "1",
    "credentials": "1",
    "snmp-credential": "1",
    "snmp-credentials": "1",
    "main": "1",
    "2": "2",
    "acas": "2",
    "harden": "2",
    "unharden": "2",
    "reharden": "2",
    "deharden": "2",
    "3": "3",
    "walk": "3",
    "snmp-walk": "3",
    "snmpwalk": "3",
    "d": "d",
    "deps": "d",
    "download": "d",
    "download-deps": "d",
    "u": "u",
    "update": "u",
    "upgrade": "u",
    "update-deps": "u",
    "pip-update": "u",
    "q": "q",
    "quit": "q",
    "exit": "q",
}
# 6.7 health values we will not SSH or configure. "error" is allowed (still push).
APPLIANCE_SKIP_STATUS = (
    "offline",
    "not active",
    "not_active",
    "inactive",
    "warning",
)
# Safe for snmpd.conf lines and remote sed (DISA: no metacharacters).
SNMP_NAME_RE = r"^[A-Za-z0-9_.-]+$"
# Keys searched in GET /appliances/status JSON (not metrics like volume).
HEALTH_STATUS_KEYS = (
    "status",
    "health",
    "overallStatus",
    "applianceStatus",
    "state",
)

# ============================================================================
# SNMP Defaults
# ============================================================================
DEFAULT_SNMP_PORT = 161
ETH_IFACE = "eth0"
ENGINE_ID_TYPE = 3
APPLIANCE_LIST_PAGE = 50
APPLIANCE_LIST_MAX = 10000
# 6.3+ health endpoint (replaces removed /admin/stats/appliances).
APPLIANCE_STATUS_PATH = "/appliances/status"
APPLIANCE_FUNCTION_NAMES = (
    "controller",
    "gateway",
    "logServer",
    "logForwarder",
    "portal",
    "connector",
    "metricsAggregator",
    "connectionBroker",
)
SNMP_WALK_OID = "1.3.6.1.2.1.1"
SNMPWALK_PROBE_TIMEOUT = 5
SNMPWALK_RETRIES = 1
CREDENTIALS_FILENAME = "credentials.json"

SNMP_PERSISTENT_CONF = "/var/lib/snmp/snmpd.conf"
SNMP_PERSISTENT_CONF_ALT = "/var/net-snmp/snmpd.conf"

# AppGate admin API
APPGATE_API_VERSION = "24"
APPGATE_ADMIN_PORT = 8443
APPGATE_ADMIN_PREFIX = "/admin"
APPGATE_PROVIDER = "local"
APPGATE_MACHINE_ID = "f0031c00-0522-43b3-a642-ae23cfd1bc22"
# Do not fall back to IP on these (credentials/ACL, not a bad FQDN).
API_AUTH_FAIL_CODES = (401, 403)

# ============================================================================
# Timeouts (seconds)
# ============================================================================
# Keep these reasonable — too long and failures feel sluggish,
# too short and legitimate operations time out on slow networks.
SSH_TIMEOUT = 10
SSH_AUTH_TIMEOUT = 10
# cz-configd restart (ACAS harden) can outlast a normal SSH command.
ACAS_SSH_TIMEOUT = 90
# ACAS unharden is SSH overlay only (API would persist STIG-hostile state).
ACAS_SUDOERS_DROPIN = "/etc/sudoers.d/cz-acas-scan"
ACAS_IPTABLES_CHAIN = "SSHBRUTE"
ACAS_IPTABLES_BINS = ("iptables", "ip6tables")
ACAS_CZCONFIGD_UNIT = "cz-configd.service"
ACAS_BANNER_TTY_GUARD = "if [ -t 0 ]; then"
ACAS_BANNER_FILE = "/etc/profile.d/ssh_confirm.sh"
ACAS_SUDOERS_FILE = "/etc/sudoers"
ACAS_SUDOERS_MARK_BEGIN = "# BEGIN ACAS-SCAN"
ACAS_SUDOERS_MARK_END = "# END ACAS-SCAN"
ACAS_MODES = ("unharden", "deharden", "harden", "reharden")
API_TIMEOUT = 15
SNMPWALK_TIMEOUT = 15
SNMPWALK_DETECT_TIMEOUT = 1
SNMPWALK_HELP_TIMEOUT = 3

# ============================================================================
# SNMP Validation Retries
# ============================================================================
# The appliance SNMP daemon needs time to reload after config push.
# A brief delay + retry tolerance handles this without being excessive.
VALIDATION_RETRY_DELAY = 3
# Step 8 / SNMP-Walk: attempts per FQDN then per IP (NAT: name often fails UDP).
WALK_FQDN_ATTEMPTS = 2
WALK_IP_ATTEMPTS = 2

# ============================================================================
# SNMP Daemon Reload Wait (seconds)
# ============================================================================
# After pushing config, wait this long before validating.
# The appliance's cz-configd must regenerate the running config.
SNMP_RELOAD_DELAY = 5

# ============================================================================
# Package Install Timeouts (seconds)
# ============================================================================
PIP_INSTALL_TIMEOUT = 120
PIP_UPGRADE_TIMEOUT = 300
PKG_INSTALL_TIMEOUT = 300

# ============================================================================
# Offline vendor cache (relative to this repo)
# ============================================================================
# Menu option D / python app/main.py d — then copy app/vendor/ to air-gap hosts.
VENDOR_PACKAGES = ("requests", "paramiko", "pysnmp")

# ============================================================================
# Lab / production transport switch (keep at the bottom)
# ============================================================================
# Why defaults are False: lab Controllers use self-signed certs and first-run
# SSH host keys. That is a MITM risk on untrusted networks — warn_insecure_transport()
# prints at start. Production: set both True after trusting the CA and known_hosts.
TLS_VERIFY = False
SSH_STRICT_HOST_KEY = False
