#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Open each unique URL from an ffuf JSON results file in Firefox (one process
# per tab, same pattern as open-cve-tabs.sh / recon/domain.sh).
#
# Usage:
#   open-ffuf-tabs.sh /path/to/ffuf.json
#   open-ffuf-tabs.sh discover-ffuf:/path/to/ffuf.json
#   open-ffuf-tabs.sh discover-ffuf://path/to/ffuf.json

set -euo pipefail

MAX_TABS="${DISCOVER_FFUF_MAX_TABS:-40}"
SLEEP_SECS="${DISCOVER_FFUF_TAB_SLEEP:-0.8}"

f_trim(){
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

f_resolve_json_path(){
    local raw
    raw=$(f_trim "${1:-}")
    raw="${raw#discover-ffuf:}"
    raw="${raw#DISCOVER-FFUF:}"
    raw="${raw#//}"

    # URL-decode (paths may contain %20 etc.)
    raw=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$raw")

    if [ -z "$raw" ]; then
        return 1
    fi

    # If a run directory was passed, prefer ffuf.json inside it
    if [ -d "$raw" ] && [ -f "$raw/ffuf.json" ]; then
        printf '%s' "$raw/ffuf.json"
        return 0
    fi

    # Relative path: resolve against current engagement report
    if [[ "$raw" != /* ]]; then
        local report=""
        if [ -f "${HOME}/.discover/current-report" ]; then
            report=$(head -n 1 "${HOME}/.discover/current-report" 2>/dev/null || true)
            report=$(f_trim "$report")
            report="${report/#\~/$HOME}"
        fi
        if [ -n "$report" ] && [ -f "$report/$raw" ]; then
            printf '%s' "$report/$raw"
            return 0
        fi
        if [ -f "$raw" ]; then
            printf '%s' "$(cd "$(dirname "$raw")" && pwd)/$(basename "$raw")"
            return 0
        fi
        return 1
    fi

    if [ -f "$raw" ]; then
        printf '%s' "$raw"
        return 0
    fi
    return 1
}

f_extract_urls(){
    local json_path="$1"
    python3 - "$json_path" "$MAX_TABS" <<'PY'
import json, sys
from pathlib import Path

path = Path(sys.argv[1])
max_tabs = int(sys.argv[2])
try:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
except Exception:
    sys.exit(1)

seen = set()
urls = []
for row in data.get("results") or []:
    if not isinstance(row, dict):
        continue
    url = (row.get("url") or "").strip()
    if not url or not url.startswith(("http://", "https://")):
        continue
    if url in seen:
        continue
    seen.add(url)
    urls.append(url)

# Stable order: as in file
for url in urls[:max_tabs]:
    print(url)
if len(urls) > max_tabs:
    print(f"# truncated {len(urls) - max_tabs} of {len(urls)} unique URLs (cap {max_tabs})", file=sys.stderr)
PY
}

JSON_PATH=$(f_resolve_json_path "${1:-}" || true)
if [ -z "$JSON_PATH" ] || [ ! -f "$JSON_PATH" ]; then
    echo "[!] ffuf JSON not found: ${1:-}"
    sleep 2
    exit 1
fi

if ! command -v firefox >/dev/null 2>&1; then
    echo "[!] firefox is not installed."
    sleep 2
    exit 1
fi

mapfile -t URLS < <(f_extract_urls "$JSON_PATH")
if [ "${#URLS[@]}" -eq 0 ]; then
    echo "[!] No HTTP(S) finding URLs in $JSON_PATH"
    sleep 2
    exit 1
fi

echo "Opening ${#URLS[@]} finding URL(s) from:"
echo "  $JSON_PATH"
echo

for url in "${URLS[@]}"; do
    [ -n "$url" ] || continue
    [[ "$url" == \#* ]] && continue
    firefox "$url" 2>/dev/null &
    sleep "$SLEEP_SECS"
done

exit 0
