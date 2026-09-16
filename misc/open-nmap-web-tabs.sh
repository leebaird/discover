#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Open each nmap HTTP(S) URL from a host-scan run in Firefox.
#
# Usage:
#   open-nmap-web-tabs.sh /path/to/web-urls.txt
#   open-nmap-web-tabs.sh discover-nmap-web:/path/to/web-urls.txt
#   open-nmap-web-tabs.sh discover-nmap-web://path/to/run-dir

set -euo pipefail

MAX_TABS="${DISCOVER_NMAP_WEB_MAX_TABS:-40}"
SLEEP_SECS="${DISCOVER_NMAP_WEB_TAB_SLEEP:-1.5}"
JITTER_FRAC="${DISCOVER_NMAP_WEB_TAB_JITTER:-0.4}"

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

f_resolve_list_path(){
    local raw
    raw=$(f_trim "${1:-}")
    raw="${raw#discover-nmap-web:}"
    raw="${raw#DISCOVER-NMAP-WEB:}"
    raw="${raw#//}"

    raw=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$raw")

    if [ -z "$raw" ]; then
        return 1
    fi

    if [ -d "$raw" ] && [ -f "$raw/web-urls.txt" ]; then
        printf '%s' "$raw/web-urls.txt"
        return 0
    fi

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

LIST_PATH=$(f_resolve_list_path "${1:-}" || true)

if [ -z "$LIST_PATH" ] || [ ! -f "$LIST_PATH" ]; then
    echo "[!] nmap web URL list not found: ${1:-}"
    sleep 2
    exit 1
fi

if ! command -v firefox >/dev/null 2>&1; then
    echo "[!] firefox is not installed."
    sleep 2
    exit 1
fi

mapfile -t URLS < <(python3 - "$LIST_PATH" "$MAX_TABS" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
max_tabs = int(sys.argv[2])
seen = set()
urls = []
for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
    url = raw.strip()
    if not url or url.startswith("#"):
        continue
    if not url.startswith(("http://", "https://")):
        continue
    if url in seen:
        continue
    seen.add(url)
    urls.append(url)

for url in urls[:max_tabs]:
    print(url)
if len(urls) > max_tabs:
    print(
        f"# truncated {len(urls) - max_tabs} of {len(urls)} unique URLs (cap {max_tabs})",
        file=sys.stderr,
    )
PY
)

if [ "${#URLS[@]}" -eq 0 ]; then
    echo "[!] No HTTP(S) URLs in $LIST_PATH"
    sleep 2
    exit 1
fi

echo "Opening ${#URLS[@]} URL(s) from:"
echo "  $LIST_PATH"
echo

for url in "${URLS[@]}"; do
    [ -n "$url" ] || continue
    [[ "$url" == \#* ]] && continue
    firefox "$url" 2>/dev/null &
    sleep "$(f_tab_sleep "$SLEEP_SECS" "$JITTER_FRAC")"
done

exit 0
