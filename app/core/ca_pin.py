"""Controller CA file check. Not a download.

The operator copies the CA off the appliance and drops it in certs/.
The file name is the host string used in the login URL. FQDN and IP are
separate files. Several collectives means several files in that folder.
"""
from __future__ import annotations

import atexit
import os
import re
import ssl

from config import CA_DIRNAME
from core.utils import REPO_ROOT

_seen_safe = {}
_converted_pems = []
_ACE_COUNT_CAP = 128


class CaPinError(RuntimeError):
    """No usable CA file for this host. Do not send credentials."""

    def __init__(self, message: str, *, fatal: bool = False) -> None:
        """fatal=True stops the FQDN/IP fallback. A missing file is not fatal."""
        super().__init__(message)
        self.fatal = fatal


def _safe_host(host: str) -> str:
    """File name only. Slashes must not escape certs/."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", host)[:80] or "controller"
    prior = _seen_safe.get(safe)
    if prior is not None and prior != host:
        raise CaPinError(
            f"CA file name {safe}.pem already used for {prior}, not {host}.",
            fatal=True,
        )
    _seen_safe[safe] = host
    return safe


def ca_candidates(host: str) -> list:
    """AppGate export is AppGate_SDP_<host>_CA.cer. Short names still work."""
    folder = os.path.join(REPO_ROOT, CA_DIRNAME)
    safe = _safe_host(host)
    names = [
        f"AppGate_SDP_{safe}_CA.cer",
        f"AppGate_SDP_{safe}_CA.pem",
        safe + ".cer",
        safe + ".pem",
    ]
    found = []
    if os.path.isdir(folder):
        have = {item.lower(): item for item in os.listdir(folder)}
        for name in names:
            hit = have.get(name.lower())
            if hit:
                found.append(os.path.join(folder, hit))
    return found or [os.path.join(folder, names[0])]


def _ensure_dir(path: str) -> None:
    """Create certs/ as 0700 so other users cannot drop a PEM in beside yours."""
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    if os.name == "posix":
        os.chmod(folder, 0o700)


def _reject_loose(path: str, *, directory: bool = False) -> None:
    """Check the PEM and certs/. Delete-child on the folder replaces the file even if the file ACL is tight."""
    if os.name == "posix":
        mode = os.stat(path).st_mode
        if mode & 0o022:
            kind = "directory" if directory else "file"
            raise CaPinError(
                f"{path} is a group or world writable {kind}. Restrict it before login.",
                fatal=True,
            )
        return
    _reject_loose_windows(path, directory=directory)


def _require_ca(path: str, pem: str) -> None:
    """A leaf is not a trust anchor. Weak keys or a private key must not become verify=."""
    if "PRIVATE KEY" in pem:
        raise CaPinError(
            f"{path} contains a private key. Export the CA certificate only.",
            fatal=True,
        )
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
    except ImportError as exc:
        raise CaPinError(
            f"Cannot validate {path}. Install cryptography before login.",
            fatal=True,
        ) from exc

    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound as exc:
        raise CaPinError(f"{path} is not a CA certificate.", fatal=True) from exc
    if not ext.value.ca:
        raise CaPinError(f"{path} is not a CA certificate.", fatal=True)
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.value.key_cert_sign:
        raise CaPinError(f"{path} CA key cannot sign certificates.", fatal=True)
    sig = cert.signature_hash_algorithm
    if sig is None or sig.name.lower() in ("md5", "sha1"):
        raise CaPinError(f"{path} CA signature is MD5 or SHA-1.", fatal=True)
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 3072:
            raise CaPinError(f"{path} CA RSA key is below 3072 bits.", fatal=True)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        if pub.key_size < 384:
            raise CaPinError(f"{path} CA EC key is below P-384.", fatal=True)
    else:
        raise CaPinError(f"{path} CA key must be RSA-3072 or ECDSA P-384 or stronger.", fatal=True)


def _windows_write_sids() -> set:
    """Only this user, Administrators, and SYSTEM may write the trust anchor."""
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.windll.advapi32
    kernel = ctypes.windll.kernel32
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise CaPinError("Could not read the current user token.", fatal=True)
    try:
        needed = wintypes.DWORD(0)
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value or 64)
        if not advapi.GetTokenInformation(token, 1, buf, len(buf), ctypes.byref(needed)):
            raise CaPinError("Could not read the current user SID.", fatal=True)
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_str = ctypes.c_wchar_p()
        if not advapi.ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_str)) or not sid_str:
            raise CaPinError("Could not format the current user SID.", fatal=True)
        try:
            own = (sid_str.value or "").encode("ascii")
        finally:
            kernel.LocalFree(ctypes.cast(sid_str, ctypes.c_void_p))
    finally:
        kernel.CloseHandle(token)
    if not own:
        raise CaPinError("Current user SID was empty.", fatal=True)
    return {own, b"S-1-5-18", b"S-1-5-32-544"}


def _reject_loose_windows(path: str, *, directory: bool = False) -> None:
    """Read the DACL in-process. SIDs, not names, and no PowerShell."""
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.windll.advapi32
    kernel = ctypes.windll.kernel32
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    advapi.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    SE_FILE_OBJECT = 1
    DACL_SECURITY_INFORMATION = 0x4
    ACCESS_ALLOWED_ACE_TYPE = 0
    ACCESS_DENIED_ACE_TYPE = 1
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 5
    ACCESS_DENIED_OBJECT_ACE_TYPE = 6
    ACE_OBJECT_TYPE_PRESENT = 0x1
    ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2
    # GENERIC_ALL and MAXIMUM_ALLOWED are write even when the specific bits are unset.
    write_bits = (
        0x02 | 0x04 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000
        | 0x02000000 | 0x10000000 | 0x40000000
    )
    allowed = _windows_write_sids()
    if directory:
        write_bits |= 0x40

    def refuse(reason: str) -> None:
        raise CaPinError(
            f"Could not verify permissions on {path}. Refusing to use it. {reason}",
            fatal=True,
        )

    sd = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    status = advapi.GetNamedSecurityInfoW(
        path,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(sd),
    )
    if status != 0 or not sd:
        refuse(f"GetNamedSecurityInfo returned {status}.")
    try:
        if not dacl:
            raise CaPinError(
                f"{path} has no DACL, so any user can write it. Restrict the ACL before login.",
                fatal=True,
            )
        class ACL_SIZE(ctypes.Structure):
            _fields_ = [
                ("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD),
            ]

        info = ACL_SIZE()
        if not advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            refuse("GetAclInformation failed.")
        if info.AceCount > _ACE_COUNT_CAP:
            refuse(f"ACL has {info.AceCount} ACEs.")
        for index in range(info.AceCount):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)) or not ace:
                refuse(f"GetAce failed at {index}.")
            header = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))
            ace_type = header[0]
            ace_size = header[2] | (header[3] << 8)
            if ace_type in (ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE):
                continue
            mask = ctypes.cast(ace, ctypes.POINTER(wintypes.DWORD))[1]
            if ace_type == ACCESS_ALLOWED_ACE_TYPE:
                sid_off = 8
            elif ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                flags = ctypes.cast(ace, ctypes.POINTER(wintypes.DWORD))[2]
                sid_off = 12
                if flags & ACE_OBJECT_TYPE_PRESENT:
                    sid_off += 16
                if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
                    sid_off += 16
            else:
                refuse(f"Unhandled ACE type {ace_type} at {index}.")
                continue
            if sid_off + 8 > ace_size:
                refuse(f"ACE {index} is shorter than its SID.")
            sid_ptr = ctypes.c_void_p(ace.value + sid_off)
            sid_str = ctypes.c_wchar_p()
            if not advapi.ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_str)) or not sid_str:
                refuse(f"Could not read ACE SID at {index}.")
            try:
                sid = (sid_str.value or "").encode("ascii")
            finally:
                kernel.LocalFree(ctypes.cast(sid_str, ctypes.c_void_p))
            if mask & write_bits and sid not in allowed:
                raise CaPinError(
                    f"{path} is writable by other users. Restrict the ACL before login.",
                    fatal=True,
                )
    finally:
        kernel.LocalFree(sd)


def _parse_pem(path: str, text: str) -> None:
    """Reject a file that is not a certificate before any password is sent."""
    chunks = text.split("-----END CERTIFICATE-----")
    found = 0
    for chunk in chunks:
        if "BEGIN CERTIFICATE" not in chunk:
            continue
        body = chunk.split("BEGIN CERTIFICATE-----", 1)[-1]
        pem = "-----BEGIN CERTIFICATE-----" + body + "-----END CERTIFICATE-----\n"
        try:
            ssl.PEM_cert_to_DER_cert(pem)
        except ssl.SSLError as exc:
            raise CaPinError(f"{path} is not a valid certificate: {exc}", fatal=True) from exc
        _require_ca(path, pem)
        found += 1
    if not found:
        raise CaPinError(
            f"{path} has no PEM certificate. Export the Controller CA, not a key or a leaf-only note.",
            fatal=True,
        )


def _as_verify_pem(path: str, raw: bytes) -> str:
    """requests verify= needs PEM. A DER .cer is converted under certs/.converted, not the default temp directory."""
    # print(f"DEBUG ca: verify path={path!r} der={b'BEGIN CERTIFICATE' not in raw}")
    if b"BEGIN CERTIFICATE" in raw:
        text = raw.decode("utf-8", errors="replace")
        _parse_pem(path, text)
        return path
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
    except ImportError as exc:
        raise CaPinError(
            f"Cannot validate {path}. Install cryptography before login.",
            fatal=True,
        ) from exc
    try:
        cert = x509.load_der_x509_certificate(raw)
    except ValueError as exc:
        raise CaPinError(f"{path} is not a PEM or DER certificate.", fatal=True) from exc
    pem = cert.public_bytes(Encoding.PEM).decode("ascii")
    _require_ca(path, pem)
    return _write_converted_pem(path, pem)


def _write_converted_pem(source: str, pem: str) -> str:
    """Keep the converted trust file under certs/, not the default temp directory."""
    # print(f"DEBUG ca: convert source={source!r}")
    folder = os.path.join(REPO_ROOT, CA_DIRNAME, ".converted")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    if os.name == "posix":
        os.chmod(folder, 0o700)
    _reject_loose(folder, directory=True)
    name = os.path.basename(source) + ".pem"
    dest = os.path.join(folder, name)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem.encode("ascii"))
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(dest, 0o600)
    _reject_loose(dest)
    _converted_pems.append(dest)
    return dest


def release_converted_cas() -> None:
    """Drop converted PEMs when this process ends. They are not a second trust store."""
    while _converted_pems:
        path = _converted_pems.pop()
        try:
            os.remove(path)
        except OSError:
            pass


atexit.register(release_converted_cas)


def require_ca_file(host: str) -> str:
    """Return a PEM path for verify=. Never fetches a CA to pin it."""
    folder = os.path.join(REPO_ROOT, CA_DIRNAME)
    _ensure_dir(os.path.join(folder, "x"))
    _reject_loose(folder, directory=True)
    parent = os.path.dirname(folder)
    if parent and parent != folder:
        _reject_loose(parent, directory=True)
    paths = ca_candidates(host)
    path = next((item for item in paths if os.path.isfile(item)), "")
    if not path:
        raise CaPinError(
            f"No CA file for {host}. Copy the AppGate .cer to {paths[0]}."
        )
    _reject_loose(path)
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise CaPinError(f"Could not read CA file {path}: {exc}", fatal=True) from exc
    if b"PRIVATE KEY" in raw:
        raise CaPinError(
            f"{path} contains a private key. Export the CA certificate only.",
            fatal=True,
        )
    return _as_verify_pem(path, raw)
