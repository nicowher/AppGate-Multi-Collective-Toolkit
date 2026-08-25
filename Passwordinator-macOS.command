#!/bin/sh
# Thin wrapper: menu/dry-run/dispatch live in app/main.py (Finder double-click OK).
#   ./Passwordinator-macOS.command
#   ./Passwordinator-macOS.command 1
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  python3 app/main.py "$@"
  rc=$?
else
  python app/main.py "$@"
  rc=$?
fi
# Pause only for interactive launches (no args).
if [ -z "$1" ]; then
  echo
  printf "Press Enter to close..."
  read -r _
fi
exit "$rc"
