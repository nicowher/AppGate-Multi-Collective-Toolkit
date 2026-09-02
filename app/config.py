import sys
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
# Floor 8 (RFC 3414). LAB_MODE=False at bottom raises this to 15 (DISA).
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
    """LAB_MODE on: warning only, never blocks. Off: no prompt here (ask after TLS fail)."""
    if LAB_MODE:
        print(
            "WARNING: LAB_MODE=True — TLS/SSH verification off; STIG new-password skipped.",
            file=sys.stderr,
        )
    if DEBUG:
        print(
            "WARNING: DEBUG=True — hostnames, engine IDs, and hash lengths print "
            "to the console (no passwords/tokens). Set DEBUG=False for production.",
            file=sys.stderr,
        )


_skip_tls_asked = False
_skip_tls_ok = False


def confirm_skip_tls_verify() -> bool:
    """Once per run: untrusted cert. Default No. LAB_MODE already skips verify."""
    global _skip_tls_asked, _skip_tls_ok
    if LAB_MODE:
        return True
    if _skip_tls_asked:
        return _skip_tls_ok
    _skip_tls_asked = True
    # print(f"DEBUG tls: confirm_skip asked for this run")
    ans = input(
        "Certificate could not be verified. Proceed anyway? [y/N]: "
    ).strip().lower()
    _skip_tls_ok = ans in YES_ANSWERS
    if not _skip_tls_ok:
        print(
            "ERROR E06: TLS certificate not trusted; login skipped for this host.",
            file=sys.stderr,
        )
        print(
            "      Next: answer y to Proceed anyway, set LAB_MODE=True, or trust the Controller CA.",
            file=sys.stderr,
        )
    return _skip_tls_ok

SSH_PORT = 22
# Empty = ~/.ssh/known_hosts (created if missing). Used when SSH_STRICT_HOST_KEY.
SSH_KNOWN_HOSTS = ""
# Parallel SSH sessions (engine-ID pass and later USM purge pass).
SSH_CONCURRENCY = 5
# Parallel SNMP walks (menu 3 inventory + credentials step 8). One validator per worker.
WALK_CONCURRENCY = 5
# Lab troubleshooting: full JSON dump to the console at end of run (no passwords/tokens).
# DISA: set False before a production run so engine IDs / inventory stay off the console.
DEBUG = False
# Write timestamped reports/*.json; console dump only if DEBUG is on.
WRITE_RUN_REPORT = True
# Overridden at bottom from LAB_MODE (lab prints Kul; production does not).
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
# CLI menu first-arg aliases → 1 configure | 2 acas | 3 walk | 4 cz-password | d deps | u pip-upgrade | q quit
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
    "4": "4",
    "password": "4",
    "passwd": "4",
    "cz-password": "4",
    "ssh-password": "4",
    "5": "5",
    "ntp": "5",
    "c": "c",
    "config": "c",
    "configure-settings": "c",
    "settings": "c",
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
# LAB_MODE only (DEBUG stays independent).
# True: skip TLS/SSH verify, print ESXi Kul, SNMP pw min 8, skip STIG cz pw.
# False: TLS verify (prompt after fail), SSH TOFU into known_hosts, SNMP pw min 15, STIG cz pw.
LAB_MODE = False
TLS_VERIFY = not LAB_MODE
SSH_STRICT_HOST_KEY = not LAB_MODE
PRINT_ESXI_KEYS = LAB_MODE
SNMP_MIN_PASSPHRASE_LEN = 8 if LAB_MODE else 15
STIG_PASSWORD_MIN_LEN = 15
# Pause after cz-config set so SSH login-verify uses the new hash.
CZ_PASSWORD_VERIFY_DELAY = 2
NTP_CUSTOMIZATION_UNIT = "cz-customization.service"
NTP_VERIFY_DELAY = 5
