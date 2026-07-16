#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Desktop protocol handler for discover-scan: URLs.
# Example: discover-scan://nikto?url=https%3A%2F%2Fhost&software=Drupal%3A7

set -euo pipefail

RAW="${1:-}"
RAW="${RAW#discover-scan:}"
RAW="${RAW#//}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run-host-scan.sh"

# Parse tool and query
TOOL="${RAW%%[?/]*}"
QUERY=""
case "$RAW" in
    *\?*) QUERY="${RAW#*\?}" ;;
esac

# Also support discover-scan:nikto/https://host
if [[ "$TOOL" == *http* ]] || [ -z "$TOOL" ]; then
    TOOL=""
fi

urldecode(){
    python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$1"
}

URL=""
SOFTWARE=""
REPORT=""

if [ -n "$QUERY" ]; then
    IFS='&' read -ra PARTS <<< "$QUERY"
    for part in "${PARTS[@]}"; do
        key="${part%%=*}"
        val="${part#*=}"
        key=$(urldecode "$key")
        val=$(urldecode "$val")
        case "$key" in
            url|u) URL="$val" ;;
            software|s) SOFTWARE="$val" ;;
            report|r) REPORT="$val" ;;
            tool|t) TOOL="$val" ;;
        esac
    done
fi

# Path form: nikto/https://example.com
if [ -z "$URL" ] && [[ "$RAW" == */http* ]]; then
    TOOL="${RAW%%/*}"
    URL=$(urldecode "${RAW#*/}")
    URL="${URL%%\?*}"
fi

[ -n "$TOOL" ] || { echo "Missing tool"; sleep 3; exit 1; }
[ -n "$URL" ] || { echo "Missing url"; sleep 3; exit 1; }

# Ensure executable
chmod +x "$RUNNER" 2>/dev/null || true

exec "$RUNNER" "$TOOL" "$URL" "$SOFTWARE" "$REPORT"
