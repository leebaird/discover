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
#   open-ffuf-tabs.sh discover-ferox:/path/to/ferox.json

set -euo pipefail

MAX_TABS="${DISCOVER_FFUF_MAX_TABS:-40}"
# OPSEC: base delay between tabs; each wait is base * (1 ± jitter).
# Default 1.5s ± 40% → roughly 0.9–2.1s (avoids a fixed robotic cadence).
SLEEP_SECS="${DISCOVER_FFUF_TAB_SLEEP:-1.5}"
JITTER_FRAC="${DISCOVER_FFUF_TAB_JITTER:-0.4}"

# Sleep base*(1±jitter); floor 0.05s so empty/zero base still yields a pause.
f_tab_sleep(){
    python3 -c '
import random, sys
base = float(sys.argv[1])
jitter = max(0.0, float(sys.argv[2]))
delay = base * (1.0 + random.uniform(-jitter, jitter))
print(f"{max(0.05, delay):.3f}")
' "${1:-1.5}" "${2:-0.4}"
}

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
    raw="${raw#discover-ferox:}"
    raw="${raw#DISCOVER-FEROX:}"
    raw="${raw#//}"

    # URL-decode (paths may contain %20 etc.)
    raw=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$raw")

    if [ -z "$raw" ]; then
        return 1
    fi

    # If a run directory was passed, prefer ffuf.json / ferox.json inside it
    if [ -d "$raw" ]; then
        if [ -f "$raw/ffuf.json" ]; then
            printf '%s' "$raw/ffuf.json"
            return 0
        fi

        if [ -f "$raw/ferox.json" ]; then
            printf '%s' "$raw/ferox.json"
            return 0
        fi
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
    data = None

seen = set()
urls = []

def add_url(url):
    url = (url or "").strip()
    if not url or not url.startswith(("http://", "https://")):
        return
    if url in seen:
        return
    seen.add(url)
    urls.append(url)

# ffuf: { "results": [ { "url": "..." }, ... ] }
if isinstance(data, dict):
    for row in data.get("results") or []:
        if isinstance(row, dict):
            add_url(row.get("url"))
    add_url(data.get("url"))
elif isinstance(data, list):
    for row in data:
        if isinstance(row, dict):
            add_url(row.get("url"))

# feroxbuster --json: NDJSON (one object per line)
if not urls:
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw or raw[0] not in "{[":
            continue
        try:
            row = json.loads(raw)
        except Exception:
            continue
        if isinstance(row, dict):
            # ferox configuration/statistics lines are not findings
            if row.get("type") and row.get("type") != "response":
                continue
            add_url(row.get("url") or row.get("original_url"))

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
    sleep "$(f_tab_sleep "$SLEEP_SECS" "$JITTER_FRAC")"
done

exit 0
