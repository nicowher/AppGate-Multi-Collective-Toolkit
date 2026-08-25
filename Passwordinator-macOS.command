#!/bin/sh
# All menu/args handled in app/main.py (cli).
#   open Passwordinator-macOS.command
#   ./Passwordinator-macOS.command 1
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  python3 app/main.py "$@"
  rc=$?
else
  python app/main.py "$@"
  rc=$?
fi
echo
printf "Press Enter to close..."
read -r _
exit "$rc"
