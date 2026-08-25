#!/bin/sh
# Unified launcher: Passwordinator, Download-Deps, or SNMP-Walk.
cd "$(dirname "$0")"

run_py() {
  if command -v python3 >/dev/null 2>&1; then
    python3 "$@"
  else
    python "$@"
  fi
}

while true; do
  clear 2>/dev/null || true
  echo "AppGate SNMPv3 Passwordinator"
  echo ""
  echo "  1) Passwordinator  (configure appliances)"
  echo "  2) Download deps   (prefetch vendor wheels)"
  echo "  3) SNMP Walk       (validate only)"
  echo "  Q) Quit"
  echo ""
  printf "Select 1, 2, 3, or Q: "
  read -r choice
  case "$choice" in
    1) run_py app/main.py "$@" ;;
    2) run_py app/download_deps.py "$@" ;;
    3) run_py app/snmp_walk_test.py "$@" ;;
    q|Q) break ;;
    *) echo "Invalid choice."; continue ;;
  esac
  echo ""
  printf "Return to menu? [Y/n]: "
  read -r again
  case "$again" in
    n|N) break ;;
  esac
done
