"""Controller CA file check. Not a download.

The operator copies the CA off the appliance and drops it in certs/.
The file name is the host string used in the login URL. FQDN and IP are
separate files. Several collectives means several files in that folder.
"""
from __future__ import annotations

import os
import re
import ssl

from config import CA_DIRNAME
from core.utils import REPO_ROOT

_seen_safe = {}


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


def ca_path_for(host: str) -> str:
    """Path the operator must fill. Not created here."""
    return os.path.join(REPO_ROOT, CA_DIRNAME, f"{_safe_host(host)}.pem")


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
    """A leaf is not a trust anchor. Reject anything without CA:TRUE."""
    try:
        from cryptography import x509
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
    broad = {b"S-1-1-0", b"S-1-5-11", b"S-1-5-32-545"}
    write_bits = 0x02 | 0x04 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000
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
        for index in range(info.AceCount):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)) or not ace:
                refuse(f"GetAce failed at {index}.")
            header = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))
            ace_type = header[0]
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
            sid_ptr = ctypes.c_void_p(ace.value + sid_off)
            sid_str = ctypes.c_wchar_p()
            if not advapi.ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_str)) or not sid_str:
                refuse(f"Could not read ACE SID at {index}.")
            try:
                sid = (sid_str.value or "").encode("ascii")
            finally:
                kernel.LocalFree(ctypes.cast(sid_str, ctypes.c_void_p))
            if sid in broad and mask & write_bits:
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


def require_ca_file(host: str) -> str:
    """Return the PEM path or stop. Never fetches a CA to pin it."""
    # print(f"DEBUG ca: host={host!r} path={ca_path_for(host)!r}")
    path = ca_path_for(host)
    _ensure_dir(path)
    cert_dir = os.path.dirname(path)
    _reject_loose(cert_dir, directory=True)
    parent = os.path.dirname(cert_dir)
    if parent and parent != cert_dir:
        _reject_loose(parent, directory=True)
    if not os.path.isfile(path):
        raise CaPinError(
            f"No CA file for {host}. Copy the Controller CA from the appliance to {path}."
        )
    _reject_loose(path)
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise CaPinError(f"Could not read CA file {path}: {exc}", fatal=True) from exc
    _parse_pem(path, text)
    return path
