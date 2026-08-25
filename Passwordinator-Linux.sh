#!/bin/sh
# Thin OS wrapper only. Menu, dry-run, and tool dispatch live in app/main.py (cli).
#   ./Passwordinator-Linux.sh
#   ./Passwordinator-Linux.sh 1
#   ./Passwordinator-Linux.sh 3
#   ./Passwordinator-Linux.sh walk
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  python3 app/main.py "$@"
  rc=$?
else
  python app/main.py "$@"
  rc=$?
fi
# Pause when launched with no args (interactive). Skip when args passed.
if [ -z "$1" ]; then
  echo
  printf "Press Enter to close..."
  read -r _
fi
exit "$rc"
