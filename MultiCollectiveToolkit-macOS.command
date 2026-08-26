#!/bin/sh
# AppGate Multi-Collective Toolkit — thin OS wrapper (Finder double-click OK).
# Menu/dispatch live in app/main.py (cli). Tools are app/tools/*.py.
#   ./MultiCollectiveToolkit-macOS.command
#   ./MultiCollectiveToolkit-macOS.command 1
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  python3 app/main.py "$@"
  rc=$?
else
  python app/main.py "$@"
  rc=$?
fi
if [ -z "$1" ]; then
  echo
  printf "Press Enter to close..."
  read -r _
fi
exit "$rc"
