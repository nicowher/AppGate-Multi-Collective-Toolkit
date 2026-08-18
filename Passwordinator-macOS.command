#!/bin/sh
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  python3 app/main.py "$@"
else
  python app/main.py "$@"
fi
echo
printf "Press Enter to close..."
read -r _
