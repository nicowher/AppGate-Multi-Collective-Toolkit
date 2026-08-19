#!/bin/sh
# Walk only (step 6). No API login or SSH.
# 1) Run from this folder so credentials.json is found.
cd "$(dirname "$0")"
# 2) Prefer python3, else python on PATH.
if command -v python3 >/dev/null 2>&1; then
  python3 app/snmp_walk_test.py "$@"
else
  python app/snmp_walk_test.py "$@"
fi
echo
printf "Press Enter to close..."
read -r _
