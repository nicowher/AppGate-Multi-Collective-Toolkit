#!/bin/sh
# Prefetch wheels into app/vendor/wheels (not part of the 6-step flow).
# Run on a networked box that matches the target OS/Python, then copy
# the whole project to the air-gapped host.
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  python3 app/download_deps.py "$@"
else
  python app/download_deps.py "$@"
fi
echo
printf "Press Enter to close..."
read -r _
