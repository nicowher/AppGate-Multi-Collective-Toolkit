#!/bin/sh
# Full configure + validate (steps 0–6 in app/main.py).
# 1) Run from this folder so credentials.json is found.
cd "$(dirname "$0")"
# 2) Prefer python3, else python on PATH.
if command -v python3 >/dev/null 2>&1; then
  python3 app/main.py "$@"
else
  python app/main.py "$@"
fi
echo
printf "Press Enter to close..."
read -r _
