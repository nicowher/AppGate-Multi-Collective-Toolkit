#!/bin/sh
set -e
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  exec python3 app/snmp_walk_test.py "$@"
fi
exec python app/snmp_walk_test.py "$@"
