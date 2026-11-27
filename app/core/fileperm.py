"""File permission checks: who besides this user may read or write a file or folder.

Why a module of its own: the same checks guard the Controller CA files
(writers matter: a swapped CA would be trusted) and credentials.json (readers
matter too: it holds every password). They used to live in the CA module and
raise its error, so credentials code imported the CA module lazily to dodge an
import cycle and caught a CA error for a non-CA file. This module imports
nothing from the toolkit.

POSIX: group/other permission bits. Windows: the file's DACL read in-process
(SIDs, no PowerShell); only this user, Administrators and SYSTEM may have the
checked access. An ACL that cannot be read fails closed.
"""
import os

# Most ACEs a DACL may have before it is refused as unreadable in practice.
_ACE_COUNT_CAP = 128


class FilePermError(RuntimeError):
    """Other users can read or write a file this toolkit must keep private, or its ACL cannot be checked."""


def reject_loose(path: str, *, directory: bool = False) -> None:
    """Refuse a file or folder that other users can write (group/other bits, or a Windows ACL entry).

    Used for CA files, certs/ and the folder of credentials.json. A folder is
    checked too because delete-child on it lets someone replace the file even
    when the file's own ACL is tight. Raises FilePermError.
    """
    if os.name == "posix":
        mode = os.stat(path).st_mode
        if mode & 0o022:
            kind = "directory" if directory else "file"
            raise FilePermError(
                f"{path} is a group or world writable {kind}. Restrict it before login."
            )
        return
    _reject_loose_windows(path, directory=directory)


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
        raise FilePermError("Could not read the current user token.")
    try:
        needed = wintypes.DWORD(0)
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value or 64)
        if not advapi.GetTokenInformation(token, 1, buf, len(buf), ctypes.byref(needed)):
            raise FilePermError("Could not read the current user SID.")
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_str = ctypes.c_wchar_p()
        if not advapi.ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_str)) or not sid_str:
            raise FilePermError("Could not format the current user SID.")
        try:
            own = (sid_str.value or "").encode("ascii")
        finally:
            kernel.LocalFree(ctypes.cast(sid_str, ctypes.c_void_p))
    finally:
        kernel.CloseHandle(token)
    if not own:
        raise FilePermError("Current user SID was empty.")
    return {own, b"S-1-5-18", b"S-1-5-32-544"}


def require_private_file(path: str) -> None:
    """Refuse a secrets file (credentials.json) that other users can read or write.

    The same ACL check the Controller CA files get, but stricter: the CA file is
    public and only writers matter; this file holds every password, so readers
    matter too. Only this user, Administrators and SYSTEM may have access on
    Windows; group/other bits must be clear on POSIX. Its folder must not be
    writable by others either. Raises FilePermError.
    """
    if os.name == "posix":
        mode = os.stat(path).st_mode & 0o077
        if mode:
            raise FilePermError(
                f"{path} can be read or written by other users (mode {mode:03o})."
            )
    else:
        _reject_loose_windows(path, readers=True)
    # The folder too: anyone who can write it can delete and replace the file,
    # and the tool would push what that file says (allowed sources, NTP, SNMP).
    # print(f"DEBUG acl: checking the folder of {path}")
    reject_loose(os.path.dirname(os.path.abspath(path)) or ".", directory=True)


def _reject_loose_windows(path: str, *, directory: bool = False, readers: bool = False) -> None:
    """Read the DACL in-process. SIDs, not names, and no PowerShell.

    readers=True also refuses read access for anyone but this user,
    Administrators and SYSTEM (a secrets file); otherwise only writers count.
    """
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
    if readers:
        # FILE_READ_DATA and GENERIC_READ: who can read the secrets, not only change them.
        write_bits |= 0x01 | 0x80000000

    def refuse(reason: str) -> None:
        """Any unreadable ACL fails closed: a CA file whose writers cannot be checked could have been swapped."""
        raise FilePermError(
            f"Could not verify permissions on {path}. Refusing to use it. {reason}"
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
            raise FilePermError(
                f"{path} has no DACL, so any user can write it. Restrict the ACL before login."
            )
        class ACL_SIZE(ctypes.Structure):
            """ctypes ACL_SIZE_INFORMATION for GetAclInformation. The ACE count bounds the walk in the Windows permission check."""
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
                # print(f"DEBUG acl: {path} other SID {sid!r} mask=0x{mask:08x}")
                raise FilePermError(
                    f"{path} is {'readable or writable' if readers else 'writable'} by other users. "
                    "Restrict the ACL before login."
                )
    finally:
        kernel.LocalFree(sd)
