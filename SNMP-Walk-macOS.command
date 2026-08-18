#!/bin/sh
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  python3 app/snmp_walk_test.py "$@"
else
  python app/snmp_walk_test.py "$@"
fi
echo
printf "Press Enter to close..."
read -r _
