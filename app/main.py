"""AppGate Multi-Collective Toolkit — CLI menu.

OS launchers only run this file so menu/args stay in one place (not duplicated
in .bat/.sh). ``cli()`` shows the menu or dispatches 1/2/3/4/5/c/d/u/q.

Why a menu here, not in each launcher: Windows .bat, Linux .sh, and macOS
.command stay thin wrappers. HaltError from a tool returns to this menu
instead of reprinting the traceback.

``app/`` is menu + config plus folders: ``tools/``, ``api/``, ``ssh/``, ``core/``.
"""
import os
import signal
import sys
from typing import List, Optional

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_VENDOR_SITE = os.path.join(_APP_DIR, "vendor", "site")
if os.path.isdir(_VENDOR_SITE):
    sys.path.append(_VENDOR_SITE)
# Pack script drops this file into the GitHub zip only (gitignored). Hides D/U.
IS_RELEASE = os.path.isfile(os.path.join(_APP_DIR, "vendor", "RELEASE"))

from config import ACAS_MODES, DEBUG, MENU_CHOICE_ALIASES, NO_ANSWERS, YES_ANSWERS
from core.utils import HaltError

_sigint_asking = False


def _ask_cancel_job() -> bool:
    """Confirm Ctrl+C. Second Ctrl+C during the prompt also cancels."""
    try:
        ans = input("\nCancel this job and return to menu? [y/N]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return True
    return ans in YES_ANSWERS


_STDIN_WAIT_NAMES = frozenset(
    {
        "input",
        "raw_input",
        "readline",
        "read",
        "getpass",
        "prompt_until_valid",
        "_require",
        "_ask_cancel_job",
    }
)


def _in_stdin_wait(frame) -> bool:
    """True if Ctrl+C hit an input() prompt (Windows frame is often prompt_until_valid)."""
    cur = frame
    while cur is not None:
        if cur.f_code.co_name in _STDIN_WAIT_NAMES:
            return True
        cur = cur.f_back
    return False


def _signal_exit(_signum, _frame) -> None:
    """A kill must not ask. KeyboardInterrupt is the cancel prompt, so this uses SystemExit."""
    raise SystemExit(143)


def _sigint_confirm_cancel(signum, frame) -> None:
    """Ask before cancelling. Never nest input() — readline cannot re-enter."""
    global _sigint_asking
    # print(f"DEBUG sigint: asking={_sigint_asking}")
    if _sigint_asking or _in_stdin_wait(frame):
        raise KeyboardInterrupt
    _sigint_asking = True
    try:
        try:
            if _ask_cancel_job():
                raise KeyboardInterrupt
        except RuntimeError:
            raise KeyboardInterrupt
        print("      Continuing job...", file=sys.stderr)
    finally:
        _sigint_asking = False


def _menu_select_hint() -> str:
    """A release zip has no D/U menu, so the hint must not offer it."""
    return "1, 2, 3, 4, 5, 6, C, or Q" if IS_RELEASE else "1, 2, 3, 4, 5, 6, C, D, U, or Q"


def _normalize_menu_choice(raw: str) -> str:
    """Map user/argv token to 1|2|3|4|5|6|c|d|u|q (empty if unknown)."""
    choice = MENU_CHOICE_ALIASES.get((raw or "").strip().lower(), "")
    if IS_RELEASE and choice in ("d", "u"):
        return ""
    return choice


def _prompt_menu_choice() -> str:
    """Interactive 1/2/3/D/U/Q menu (launchers only start this file)."""
    from core.color import dim, fail, heading, step

    print(heading("AppGate Multi-Collective Toolkit"))
    print()
    print(f"  {step('1)')} SNMP Credential Tool  {dim('(configure SNMPv3 USM)')}")
    print(f"  {step('2)')} ACAS scan prep        {dim('(unharden / harden)')}")
    print(f"  {step('3)')} SNMP Walk             {dim('(validate only)')}")
    print(f"  {step('4)')} Update cz SSH password")
    print(f"  {step('5)')} NTP servers           {dim('(Controller API)')}")
    print(f"  {step('6)')} Allowed sources       {dim('(who can reach this box)')}")
    print(f"  {step('C)')} Configure             {dim('(DEBUG, LAB_MODE, timeouts)')}")
    if not IS_RELEASE:
        print(f"  {step('D)')} Download deps         {dim('(prefetch vendor wheels)')}")
        print(f"  {step('U)')} Update deps           {dim('(reinstall pinned set)')}")
    print(f"  {step('Q)')} Quit")
    print()
    while True:
        raw = input(f"Select {_menu_select_hint()}: ")
        choice = _normalize_menu_choice(raw)
        if choice:
            return choice
        print(fail("Invalid choice."))


def _dispatch_tool(choice: str) -> int:
    """Import and run one tool. Imports stay lazy so menu D works before paramiko is installed."""
    if choice == "1":
        from tools.snmp_credentials import main as creds_main
        creds_main()
        return 0
    if choice == "2":
        from tools.acas import main as acas_main
        acas_main()
        return 0
    if choice == "3":
        from tools.snmp_walk import main as walk_main
        walk_main()
        return 0
    if choice == "4":
        from tools.cz_password import main as czpw_main
        czpw_main()
        return 0
    if choice == "5":
        from tools.ntp import main as ntp_main
        ntp_main()
        return 0
    if choice == "6":
        from tools.allowed_sources import main as allow_main
        allow_main()
        return 0
    if choice == "c":
        from tools.settings import main as settings_main
        return 0 if settings_main() else -1
    if choice == "d":
        if IS_RELEASE:
            return 1
        from tools.download_deps import main as deps_main
        deps_main()
        return 0
    if choice == "u":
        if IS_RELEASE:
            return 1
        from tools.download_deps import upgrade_main
        upgrade_main()
        return 0
    return 1


def _debug_run_header() -> None:
    """DEBUG: the effective settings and library versions, the first thing to check on an odd run.

    Versions come from package metadata, not imports, so menu D still works
    before paramiko is installed. No credentials or secrets are printed.
    """
    import platform
    import ssl

    import config as _config
    from importlib import metadata

    names = (
        "CNSA_STRICT", "LAB_MODE", "INSECURE_API", "DRY_RUN", "SSH_STRICT_HOST_KEY",
        "SSH_PORT", "SSH_TIMEOUT", "SSH_AUTH_TIMEOUT", "SSH_PRIME_TIMEOUT", "SSH_CONCURRENCY",
        "WALK_CONCURRENCY", "API_TIMEOUT", "SSH_KNOWN_HOSTS", "WRITE_RUN_REPORT",
    )
    settings = ", ".join(f"{n}={getattr(_config, n, '?')!r}" for n in names)
    versions = [f"python {platform.python_version()}", ssl.OPENSSL_VERSION]
    for dist in ("paramiko", "requests", "cryptography", "pysnmp", "urllib3"):
        try:
            versions.append(f"{dist} {metadata.version(dist)}")
        except metadata.PackageNotFoundError:
            versions.append(f"{dist} not installed")
    print(f"      DEBUG settings: {settings}", file=sys.stderr)
    print(f"      DEBUG versions: {', '.join(versions)} ({platform.platform()})", file=sys.stderr)


def _run_selected_tool(choice: str, rest: List[str]) -> int:
    """Run SNMP credentials (1), ACAS (2), snmp_walk (3), download_deps (d), or pip upgrade (u).

    rest becomes sys.argv[1:] for that tool. SystemExit from tools is converted
    to a return code so the interactive menu can continue.
    """
    old_argv = sys.argv[:]
    prev_sigint = signal.getsignal(signal.SIGINT)
    exit_sigs = []
    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is not None:
            exit_sigs.append((sig, signal.getsignal(sig)))
    try:
        signal.signal(signal.SIGINT, _sigint_confirm_cancel)
        for sig, _prev in exit_sigs:
            signal.signal(sig, _signal_exit)
        sys.argv = [old_argv[0]] + rest
        # print(f"DEBUG cli: choice={choice} argv={sys.argv!r}")
        if DEBUG:
            print(f"      DEBUG cli: choice={choice} rest={rest!r}", file=sys.stderr)
            _debug_run_header()
        if choice in ("1", "2", "4", "5"):
            # One SSH login per box for the whole run (see ssh_session_pool).
            from ssh.client import ssh_session_pool

            with ssh_session_pool():
                return _dispatch_tool(choice)
        return _dispatch_tool(choice)
    except KeyboardInterrupt:
        if _ask_cancel_job():
            print("\nOperation cancelled by user", file=sys.stderr)
            return 130
        print("      Restarting this tool...", file=sys.stderr)
        return -2
    except HaltError:
        return 1
    except Exception as exc:  # noqa: BLE001 - the menu must survive one tool's bug
        # Before, an unexpected error here ended the whole toolkit with a raw
        # traceback. Now it prints like a tool run on its own, and DEBUG adds the
        # redacted traceback; the menu then offers to continue.
        from core.utils import print_unexpected_error

        print_unexpected_error(exc)
        return 1
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 1
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        for sig, prev in exit_sigs:
            signal.signal(sig, prev)
        sys.argv = old_argv


def cli(argv: Optional[List[str]] = None) -> None:
    """Entry for OS launchers.

    No args  → interactive menu (return to menu after each tool).
    First arg 1|2|3|4|5|c|d|u|walk|acas|ntp|deps → run that tool once; remaining args go to Python.

    Closed input (Ctrl+D, Ctrl+Z then Enter on Windows, or an empty pipe) ends the
    toolkit with a message. No later prompt can be answered, so it is a cancel, and
    any yes/no that was waiting stays No.
    """
    # Output redirected or piped on Windows is cp1252; an unusual character must
    # not stop a run (core.utils.make_output_safe).
    # print(f"DEBUG cli: stdout={sys.stdout.encoding} stderr={sys.stderr.encoding}")
    from core.utils import make_output_safe

    make_output_safe()
    try:
        _cli(argv)
    except EOFError:
        # print("DEBUG cli: EOF on stdin")
        print("\nInput closed. Stopping; nothing further was applied.", file=sys.stderr)
        sys.exit(1)


def _cli(argv: Optional[List[str]] = None) -> None:
    """Menu loop. cli() wraps it so closed input is a clean stop, not a traceback."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and not _normalize_menu_choice(args[0]):
        print(f"Invalid choice. Use {_menu_select_hint()}.", file=sys.stderr)
        sys.exit(2)
    noninteractive = bool(args) and bool(_normalize_menu_choice(args[0]))
    while True:
        try:
            if noninteractive:
                raw0 = args[0].strip().lower()
                choice = _normalize_menu_choice(args[0])
                rest = args[1:]
                # "harden"/"unharden" alias to tool 2 — keep the token as the ACAS mode.
                if raw0 in ACAS_MODES:
                    rest = [raw0] + rest
            else:
                choice = _prompt_menu_choice()
                rest = []
        except KeyboardInterrupt:
            print()
            continue
        if choice == "q":
            return
        if not choice:
            print(f"Invalid choice. Use {_menu_select_hint()}.", file=sys.stderr)
            if noninteractive:
                sys.exit(2)
            continue
        try:
            code = _run_selected_tool(choice, rest)
            while code == -2:
                code = _run_selected_tool(choice, rest)
        except KeyboardInterrupt:
            if _ask_cancel_job():
                print("\nOperation cancelled by user", file=sys.stderr)
                if noninteractive:
                    sys.exit(1)
                print()
                continue
            print("      Restarting this tool...", file=sys.stderr)
            code = -2
            while code == -2:
                code = _run_selected_tool(choice, rest)
        if choice == "c":
            if noninteractive:
                sys.exit(0 if code < 0 else code)
            if code == 0:
                return
            continue
        if noninteractive:
            sys.exit(code if code >= 0 else 1)
        if code == 130:
            print()
            continue
        print()
        try:
            again = input("Return to menu? [Y/n]: ").strip().lower()
        except KeyboardInterrupt:
            print()
            continue
        if again in NO_ANSWERS:
            if code:
                sys.exit(code)
            return


if __name__ == "__main__":
    cli()
