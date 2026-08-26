"""AppGate Multi-Collective Toolkit — CLI menu.

OS launchers only run this file so menu/args stay in one place (not duplicated
in .bat/.sh). ``cli()`` shows the menu or dispatches 1/2/3.

``app/`` is menu + config plus folders: ``tools/``, ``api/``, ``ssh/``, ``core/``.
"""
import sys
from typing import List, Optional

from config import DEBUG, MENU_CHOICE_ALIASES, NO_ANSWERS


def _normalize_menu_choice(raw: str) -> str:
    """Map user/argv token to 1|2|3|q (empty if unknown)."""
    return MENU_CHOICE_ALIASES.get((raw or "").strip().lower(), "")


def _prompt_menu_choice() -> str:
    """Interactive 1/2/3/Q menu (launchers only start this file)."""
    print("AppGate Multi-Collective Toolkit")
    print()
    print("  1) SNMP Credential Tool  (configure SNMPv3 USM)")
    print("  2) Download deps         (prefetch vendor wheels)")
    print("  3) SNMP Walk             (validate only)")
    print("  Q) Quit")
    print()
    while True:
        choice = _normalize_menu_choice(input("Select 1, 2, 3, or Q: "))
        if choice:
            return choice
        print("Invalid choice.")


def _run_selected_tool(choice: str, rest: List[str]) -> int:
    """Run SNMP credentials (1), download_deps (2), or snmp_walk (3).

    rest becomes sys.argv[1:] for that tool. SystemExit from tools is converted
    to a return code so the interactive menu can continue.
    """
    old_argv = sys.argv[:]
    try:
        sys.argv = [old_argv[0]] + rest
        # print(f"DEBUG cli: choice={choice} argv={sys.argv!r}")
        if DEBUG:
            print(f"      DEBUG cli: choice={choice} rest={rest!r}", file=sys.stderr)
        if choice == "1":
            from tools.snmp_credentials import main as creds_main
            creds_main()
            return 0
        if choice == "2":
            from tools.download_deps import main as deps_main
            deps_main()
            return 0
        if choice == "3":
            from tools.snmp_walk import main as walk_main
            walk_main()
            return 0
        return 1
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 1
    finally:
        sys.argv = old_argv


def cli(argv: Optional[List[str]] = None) -> None:
    """Entry for OS launchers.

    No args  → interactive menu (return to menu after each tool).
    First arg 1|2|3|walk|deps → run that tool once; remaining args go to Python.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    noninteractive = bool(args) and bool(_normalize_menu_choice(args[0]))
    try:
        while True:
            if noninteractive:
                choice = _normalize_menu_choice(args[0])
                rest = args[1:]
            else:
                choice = _prompt_menu_choice()
                rest = []
            if choice == "q":
                return
            if not choice:
                print("Invalid choice. Use 1, 2, 3, or Q.", file=sys.stderr)
                if noninteractive:
                    sys.exit(2)
                continue
            code = _run_selected_tool(choice, rest)
            if noninteractive:
                sys.exit(code)
            print()
            again = input("Return to menu? [Y/n]: ").strip().lower()
            if again in NO_ANSWERS:
                if code:
                    sys.exit(code)
                return
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cli()
