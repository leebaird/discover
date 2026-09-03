#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Open theHarvester API key file in the desktop default app.
# Audit Config → APIs uses this (discover-theharvester: or statusd).
#
# Usage:
#   open-theharvester-keys.sh
#   open-theharvester-keys.sh discover-theharvester:

set -euo pipefail

FILE="${HOME}/.theHarvester/api-keys.yaml"
SRC="${HOME}/theHarvester/theHarvester/data/api-keys.yaml"

if [ ! -f "$FILE" ]; then
    if [ ! -f "$SRC" ]; then
        echo "[!] Not found: $FILE"
        echo "    Seed missing: $SRC"
        sleep 2
        exit 1
    fi

    mkdir -p "${HOME}/.theHarvester"
    cp -f "$SRC" "$FILE"
    chmod 600 "$FILE" 2>/dev/null || true
fi

# Background so statusd / the protocol handler do not wait on the editor.
if command -v open >/dev/null 2>&1; then
    open "$FILE" >/dev/null 2>&1 &
    exit 0
fi

if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$FILE" >/dev/null 2>&1 &
    exit 0
fi

echo "[!] open is not installed."
sleep 2
exit 1
