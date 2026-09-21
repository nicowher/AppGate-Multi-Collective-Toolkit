"""AppGate Multi-Collective Toolkit — CLI menu.

OS launchers only run this file so menu/args stay in one place (not duplicated
in .bat/.sh). ``cli()`` shows the menu or dispatches 1/2/3/4/5/c/d/u/q.

Why a menu here, not in each launcher: Windows .bat, Linux .sh, and macOS
.command stay thin wrappers. HaltError from a tool returns to this menu
instead of reprinting the traceback.

``app/`` is menu + config plus folders: ``tools/``, ``api/``, ``ssh/``, ``core/``.
"""
import signal
import sys
from typing import List, Optional

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


def _sigint_confirm_cancel(signum, frame) -> None:
    """Ask before cancelling. Do not nest input() inside another input/getpass."""
    global _sigint_asking
    # print(f"DEBUG sigint: asking={_sigint_asking}")
    if _sigint_asking:
        raise KeyboardInterrupt
    name = frame.f_code.co_name if frame is not None else ""
    if name in ("input", "raw_input", "readline", "read", "getpass"):
        raise KeyboardInterrupt
    _sigint_asking = True
    try:
        if _ask_cancel_job():
            raise KeyboardInterrupt
        print("      Continuing job...", file=sys.stderr)
    finally:
        _sigint_asking = False


def _normalize_menu_choice(raw: str) -> str:
    """Map user/argv token to 1|2|3|4|5|c|d|u|q (empty if unknown)."""
    return MENU_CHOICE_ALIASES.get((raw or "").strip().lower(), "")


def _prompt_menu_choice() -> str:
    """Interactive 1/2/3/D/U/Q menu (launchers only start this file)."""
    print("AppGate Multi-Collective Toolkit")
    print()
    print("  1) SNMP Credential Tool  (configure SNMPv3 USM)")
    print("  2) ACAS scan prep        (unharden / harden)")
    print("  3) SNMP Walk             (validate only)")
    print("  4) Update cz SSH password")
    print("  5) NTP servers            (Controller API / cz-configd)")
    print("  C) Configure             (DEBUG, LAB_MODE, timeouts)")
    print("  D) Download deps         (prefetch vendor wheels)")
    print("  U) Update deps           (pip install --upgrade)")
    print("  Q) Quit")
    print()
    while True:
        raw = input("Select 1, 2, 3, 4, 5, C, D, U, or Q: ")
        choice = _normalize_menu_choice(raw)
        if choice:
            return choice
        # print(f"DEBUG menu: invalid choice raw={raw!r}")
        print("Invalid choice.")


def _run_selected_tool(choice: str, rest: List[str]) -> int:
    """Run SNMP credentials (1), ACAS (2), snmp_walk (3), download_deps (d), or pip upgrade (u).

    rest becomes sys.argv[1:] for that tool. SystemExit from tools is converted
    to a return code so the interactive menu can continue.
    """
    old_argv = sys.argv[:]
    prev_sigint = signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGINT, _sigint_confirm_cancel)
        sys.argv = [old_argv[0]] + rest
        # print(f"DEBUG cli: choice={choice} argv={sys.argv!r}")
        if DEBUG:
            print(f"      DEBUG cli: choice={choice} rest={rest!r}", file=sys.stderr)
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
        if choice == "c":
            from tools.settings import main as settings_main
            return 0 if settings_main() else -1
        if choice == "d":
            from tools.download_deps import main as deps_main
            deps_main()
            return 0
        if choice == "u":
            from tools.download_deps import upgrade_main
            upgrade_main()
            return 0
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        return 130
    except HaltError:
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
        sys.argv = old_argv


def cli(argv: Optional[List[str]] = None) -> None:
    """Entry for OS launchers.

    No args  → interactive menu (return to menu after each tool).
    First arg 1|2|3|4|5|c|d|u|walk|acas|ntp|deps → run that tool once; remaining args go to Python.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if args and not _normalize_menu_choice(args[0]):
        print("Invalid choice. Use 1, 2, 3, 4, 5, C, D, U, or Q.", file=sys.stderr)
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
            if choice == "q":
                return
            if not choice:
                print("Invalid choice. Use 1, 2, 3, 4, 5, C, D, U, or Q.", file=sys.stderr)
                if noninteractive:
                    sys.exit(2)
                continue
            code = _run_selected_tool(choice, rest)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user", file=sys.stderr)
            code = 130
            if noninteractive:
                sys.exit(1)
            print()
            continue
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
