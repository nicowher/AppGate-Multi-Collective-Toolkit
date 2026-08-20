import warnings

# ============================================================================
# SNMPv3 Algorithm Configuration
# ============================================================================
# CNSA 2.0 (Commercial National Security Algorithm Suite 2.0) compliant:
#   - Authentication: SHA-256 (usmHMAC192SHA256AuthProtocol)
#   - Privacy:       AES-256 (usmAesCfb256Protocol)
#
# These must match between:
#   1. The createUser line pushed to the appliance (appgate.py)
#   2. In-process RFC 3414 localization (snmp_hashgen.py)
#   3. The SNMP walk validation tools (snmp_validate.py, snmp_walk_test.py)
#
# NOTE: Some older AppGate appliance versions only support SHA-1/AES-128.
# If validation fails with "Wrong SNMP PDU digest", check the appliance's
# persistent data in /var/lib/snmp/snmpd.conf to see which algorithms
# it actually supports.
# ============================================================================
SNMP_HASH_ALGO = "sha256"
SNMP_AUTH_PROTOCOL = "SHA256"
SNMP_PRIV_PROTOCOL = "AES256"
# CNSA 2.0 / DISA: do not localize with MD5 or SHA-1.
ALLOWED_HASH_ALGOS = ("sha256", "sha384", "sha512")
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
    """Print a DISA-style warning if TLS or SSH host-key checks are off."""
    import sys
    if TLS_VERIFY and SSH_STRICT_HOST_KEY:
        return
    print(
        "WARNING: Insecure transport defaults are on "
        f"(TLS_VERIFY={TLS_VERIFY}, SSH_STRICT_HOST_KEY={SSH_STRICT_HOST_KEY}). "
        "Admin and SSH secrets can be MITM'd. Set both True in app/config.py "
        "on untrusted networks (DISA / CNSA).",
        file=sys.stderr,
    )
SSH_PORT = 22
# Parallel SSH sessions (engine-ID pass and later USM purge pass).
SSH_CONCURRENCY = 5
# Print a JSON debug report at the end (no passwords/tokens). Paste it back for review.
DEBUG = False
SNMPD_STOP_RETRIES = 5
USM_SED_RETRIES = 3
USM_RECREATE_WAITS = 5
# Accepted answers for yes/no prompts (Add another Controller, Walk another IP).
YES_ANSWERS = ("y", "yes")
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
PKG_INSTALL_TIMEOUT = 300

# ============================================================================
# Offline vendor cache (relative to this repo)
# ============================================================================
# Download-Deps-<OS> — run on a networked box, then copy app/vendor/ over.
VENDOR_PACKAGES = ("requests", "paramiko", "pysnmp")

# ============================================================================
# Lab / production transport switch (keep at the bottom)
# ============================================================================
# Lab (no CA / no known_hosts): leave both False. Passwordinator warns at start.
# Production: set both True after you trust the Controller cert and pin SSH keys.
TLS_VERIFY = False
SSH_STRICT_HOST_KEY = False
