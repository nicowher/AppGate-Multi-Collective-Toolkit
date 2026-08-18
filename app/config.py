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

# ============================================================================
# TLS / Certificate Verification
# ============================================================================
# Set to True to verify the AppGate appliance's TLS certificate.
# The appliance uses a self-signed cert by default, so this is False
# unless you have installed a trusted CA-signed certificate.
# WARNING: Setting this to False disables TLS verification and makes
# you vulnerable to MITM attacks. Only do this on trusted networks.
# ============================================================================
TLS_VERIFY = False

# ============================================================================
# SNMP Defaults
# ============================================================================
DEFAULT_SNMP_PORT = 161
ETH_IFACE = "eth0"
ENGINE_ID_TYPE = 3
SNMP_WALK_OID = "1.3.6.1.2.1.1"
SNMPWALK_PROBE_TIMEOUT = 5
SNMPWALK_RETRIES = 1
CREDENTIALS_FILENAME = "credentials.json"

NET_SNMP_CONF = "/etc/snmp/snmpd.conf"
SNMP_PERSISTENT_CONF = "/var/lib/snmp/snmpd.conf"
SNMP_PERSISTENT_CONF_ALT = "/var/net-snmp/snmpd.conf"

# AppGate admin API
APPGATE_API_VERSION = "24"
APPGATE_ADMIN_PORT = 8443
APPGATE_ADMIN_PREFIX = "/admin"
APPGATE_PROVIDER = "local"
APPGATE_MACHINE_ID = "f0031c00-0522-43b3-a642-ae23cfd1bc22"

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
VALIDATION_RETRIES = 3
VALIDATION_RETRY_DELAY = 3

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
