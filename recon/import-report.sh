#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Open an existing Discover report for additional testing.
# Sets the current engagement so future host-scan launches know the report root.
# Client ZIPs are separate exports; this path is always operator mode on the live tree.

# Colors / separators: inherit from Discover when launched from the menu.
BLUE=${BLUE:-'\033[1;34m'}
YELLOW=${YELLOW:-'\033[1;33m'}
RED=${RED:-'\033[1;31m'}
NC=${NC:-'\033[0m'}
SMALL=${SMALL:-'========================================'}
MEDIUM=${MEDIUM:-'=================================================================='}

if ! declare -F f_banner >/dev/null 2>&1; then
    f_banner(){ echo; }
fi

f_import_report_die(){
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] $1${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    sleep 2
    exit 1
}

f_import_report_warn(){
    echo -e "${YELLOW}[!] $1${NC}"
}

# True if dir looks like a Discover engagement report root.
f_import_report_is_report_dir(){
    local dir="$1"

    [ -n "$dir" ] || return 1
    [ -d "$dir" ] || return 1
    [ -r "$dir" ] || return 1
    [ -x "$dir" ] || return 1
    [ -d "$dir/pages" ] || return 1
    [ -f "$dir/index.htm" ] || [ -f "$dir/pages/active.htm" ] || [ -f "$dir/pages/subdomains.htm" ] || [ -f "$dir/pages/passive.htm" ]
}

# Resolve Discover install root (for assets / helpers).
f_import_report_discover_root(){
    if [ -n "${DISCOVER:-}" ] && [ -d "$DISCOVER" ]; then
        printf '%s' "$DISCOVER"
        return 0
    fi
    if [ -f "$(dirname "$0")/../discover.sh" ]; then
        (cd "$(dirname "$0")/.." && pwd)
        return 0
    fi
    return 1
}

f_import_report_open_browser(){
    local page="$1"

    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$page" >/dev/null 2>&1 &
        return 0
    fi
    if command -v sensible-browser >/dev/null 2>&1; then
        sensible-browser "$page" >/dev/null 2>&1 &
        return 0
    fi
    return 1
}

# Copy operator UI assets into an older engagement tree when missing/outdated.
f_import_report_sync_assets(){
    local report="$1"
    local src_root="$2"
    local src js

    [ -n "$src_root" ] || return 0
    src="$src_root/report/assets"
    [ -d "$src" ] || return 0

    mkdir -p "$report/assets/javascript" "$report/assets/css" 2>/dev/null || {
        f_import_report_warn "Could not create report assets dirs (host-scan UI may be incomplete)."
        return 1
    }

    for js in \
        inc-host-scan.js \
        inc-shodan.js \
        inc-subdomains-filter.js \
        inc-data-table.js \
        inc-audit-status.js \
        inc-active-cve-tabs.js
    do
        if [ -f "$src/javascript/$js" ]; then
            cp -f "$src/javascript/$js" "$report/assets/javascript/$js" 2>/dev/null || \
                f_import_report_warn "Could not copy $js into report assets."
        fi
    done

    # Column layout for filtered host-scan toggle + Shodan lives in modern.css
    if [ -f "$src/css/modern.css" ]; then
        cp -f "$src/css/modern.css" "$report/assets/css/modern.css" 2>/dev/null || \
            f_import_report_warn "Could not copy modern.css into report assets."
        # Bust browser cache on Subdomains after layout / host-scan / Shodan fixes.
        if [ -f "$report/pages/subdomains.htm" ]; then
            sed -i \
                -e 's|modern\.css?v=[^"]*|modern.css?v=ws17|g' \
                -e 's|inc-host-scan\.js?v=[0-9]*|inc-host-scan.js?v=5|g' \
                -e 's|inc-shodan\.js?v=[0-9]*|inc-shodan.js?v=13|g' \
                "$report/pages/subdomains.htm" 2>/dev/null || true
        fi
    fi
}

# Add Audit under Reports → after Active (pages/*.htm and root index.htm).
f_import_report_ensure_audit_nav(){
    local report="$1"

    [ -d "$report" ] || return 0
    command -v python3 >/dev/null 2>&1 || return 0

    python3 - "$report" <<'PY'
import sys
from pathlib import Path

report = Path(sys.argv[1])
# (already-has markers, patterns to insert after Active)
variants = [
    # pages/*.htm — relative Active/Audit
    {
        "has": ('href="audit.htm"',),
        "need": 'href="active.htm"',
        "patterns": [
            (
                '<li class="active"><a href="active.htm">Active</a></li>',
                '<li class="active"><a href="active.htm">Active</a></li>\n'
                '                        <li><a href="audit.htm">Audit</a></li>',
            ),
            (
                '<li><a href="active.htm">Active</a></li>',
                '<li><a href="active.htm">Active</a></li>\n'
                '                        <li><a href="audit.htm">Audit</a></li>',
            ),
        ],
    },
    # root index.htm — pages/ prefix
    {
        "has": ('href="pages/audit.htm"', 'href="audit.htm"'),
        "need": 'href="pages/active.htm"',
        "patterns": [
            (
                '<li class="active"><a href="pages/active.htm">Active</a></li>',
                '<li class="active"><a href="pages/active.htm">Active</a></li>\n'
                '                        <li><a href="pages/audit.htm">Audit</a></li>',
            ),
            (
                '<li><a href="pages/active.htm">Active</a></li>',
                '<li><a href="pages/active.htm">Active</a></li>\n'
                '                        <li><a href="pages/audit.htm">Audit</a></li>',
            ),
        ],
    },
]

files = []
pages_dir = report / "pages"
if pages_dir.is_dir():
    files.extend(sorted(pages_dir.glob("*.htm")))
for name in ("index.htm", "index.html"):
    p = report / name
    if p.is_file():
        files.append(p)

for page in files:
    try:
        text = page.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    for variant in variants:
        if not any(h in text for h in variant["has"]) and variant["need"] in text:
            for old, new in variant["patterns"]:
                if old in text:
                    text = text.replace(old, new, 1)
                    try:
                        page.write_text(text, encoding="utf-8")
                    except OSError:
                        pass
                    break
            break
PY
}

# Ensure Subdomains page has filter + host-scan scripts (no fragile sed).
f_import_report_ensure_subdomains_ui(){
    local page="$1"

    [ -f "$page" ] || return 0
    command -v python3 >/dev/null 2>&1 || return 0

    python3 - "$page" <<'PY'
import sys
from pathlib import Path

page = Path(sys.argv[1])
try:
    text = page.read_text(encoding="utf-8", errors="replace")
except OSError:
    sys.exit(0)

changed = False

# Required scripts (idempotent: only insert when key filename is absent).
need = [
    ("inc-subdomains-filter.js", '<script src="../assets/javascript/inc-subdomains-filter.js?v=5"></script>'),
    ("tools/shodan/index.js", '<script src="../tools/shodan/index.js"></script>'),
    ("inc-shodan.js", '<script src="../assets/javascript/inc-shodan.js?v=13"></script>'),
    ("inc-host-scan.js", '<script src="../assets/javascript/inc-host-scan.js?v=5"></script>'),
]
insert = [tag for key, tag in need if key not in text]
if insert:
    block = "\n".join(insert) + "\n"
    lower = text.lower()
    idx = lower.rfind("</body>")
    if idx != -1:
        text = text[:idx] + block + text[idx:]
    else:
        text = text.rstrip() + "\n" + block
    changed = True

if changed:
    try:
        page.write_text(text, encoding="utf-8")
    except OSError:
        sys.exit(0)
PY
}

# Restart localhost statusd so it pins this engagement (not a previous one).
f_import_report_restart_statusd(){
    local statusd="$1"
    local report="$2"
    local port="${3:-17322}"
    local pid

    [ -f "$statusd" ] || return 0

    # Free the port if something already answers on it.
    if curl -fsS --connect-timeout 1 --max-time 2 "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
        if command -v fuser >/dev/null 2>&1; then
            fuser -k "${port}/tcp" >/dev/null 2>&1 || true
        elif command -v lsof >/dev/null 2>&1; then
            pid=$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)
            if [ -n "$pid" ]; then
                # shellcheck disable=SC2086
                kill $pid >/dev/null 2>&1 || true
            fi
        else
            # Narrow pattern: script path + space (avoids matching this shell / pkill itself).
            pkill -f "host-scan-statusd\\.py " >/dev/null 2>&1 || true
        fi
        sleep 0.2
    fi

    nohup python3 "$statusd" "$report" "$port" >/dev/null 2>&1 &
    sleep 0.3
}

clear
f_banner

echo -e "${BLUE}Import report.${NC}"
echo
echo "Open an existing Discover report for additional testing."
echo
echo -n "Enter the location of your report: "
read -r DISCOVER_REPORT

# Normalize input (CR, whitespace, leading ~).
DISCOVER_REPORT="${DISCOVER_REPORT//$'\r'/}"
DISCOVER_REPORT="${DISCOVER_REPORT#"${DISCOVER_REPORT%%[![:space:]]*}"}"
DISCOVER_REPORT="${DISCOVER_REPORT%"${DISCOVER_REPORT##*[![:space:]]}"}"
DISCOVER_REPORT="${DISCOVER_REPORT/#\~/$HOME}"

# Empty enter — same pattern as Active / Import names.
if [ -z "$DISCOVER_REPORT" ]; then
    f_import_report_die "No report location provided."
fi

# If the user pointed at a page file, resolve to the report root.
#   pages/*  → two levels up (…/pages/active.htm → report root)
#   index.htm / other files → one level up (…/index.htm → report root)
if [ -f "$DISCOVER_REPORT" ]; then
    case "$DISCOVER_REPORT" in
        */pages/*)
            if ! DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")/.." && pwd)"; then
                f_import_report_die "Report not found."
            fi
            ;;
        *)
            if ! DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")" && pwd)"; then
                f_import_report_die "Report not found."
            fi
            ;;
    esac
fi

# Wrong path / not a Discover report — exit like other options.
if ! f_import_report_is_report_dir "$DISCOVER_REPORT"; then
    f_import_report_die "Report not found."
fi

DISCOVER_REPORT="$(cd "$DISCOVER_REPORT" && pwd)" || f_import_report_die "Report not found."
export DISCOVER_REPORT

DISCOVER_ROOT=""
if DISCOVER_ROOT="$(f_import_report_discover_root)"; then
    :
else
    DISCOVER_ROOT=""
fi

# Persist current engagement for helpers / future discover-scan bridge.
SESSION_DIR="${HOME}/.discover"
mkdir -p "$SESSION_DIR" || f_import_report_die "Could not create $SESSION_DIR."
if ! printf '%s\n' "$DISCOVER_REPORT" > "$SESSION_DIR/current-report"; then
    f_import_report_die "Could not write $SESSION_DIR/current-report."
fi
chmod 600 "$SESSION_DIR/current-report" 2>/dev/null || true

# Operator mode on the live tree (client exports stamp client mode only on copies).
MODE_DIR="$DISCOVER_REPORT/assets"
MODE_FILE="$MODE_DIR/report-mode.json"
if mkdir -p "$MODE_DIR" 2>/dev/null \
    && cat > "$MODE_FILE" <<'EOF'
{
  "mode": "operator",
  "launches": true
}
EOF
then
    chmod 644 "$MODE_FILE" 2>/dev/null || true
else
    f_import_report_warn "Could not write operator mode stamp (scan launches may be disabled)."
fi

# Ensure audit + host-scan directories exist.
mkdir -p "$DISCOVER_REPORT/tools/audit" "$DISCOVER_REPORT/tools/host-scans" 2>/dev/null || true

# Sync host-scan / filter JS into older report trees.
if [ -n "$DISCOVER_ROOT" ]; then
    f_import_report_sync_assets "$DISCOVER_REPORT" "$DISCOVER_ROOT"
fi

# Seed audit log if missing (format locked for Audit page).
AUDIT_LOG="$DISCOVER_REPORT/tools/audit/log.txt"
if [ ! -f "$AUDIT_LOG" ]; then
    touch "$AUDIT_LOG" 2>/dev/null || true
fi

# Build/refresh Audit page
if [ -n "$DISCOVER_ROOT" ] && [ -f "$DISCOVER_ROOT/recon/audit-build.py" ]; then
    python3 "$DISCOVER_ROOT/recon/audit-build.py" "$DISCOVER_REPORT" "$DISCOVER_ROOT/report/pages/audit.htm" >/dev/null 2>&1 || true
elif [ -f "$(dirname "$0")/audit-build.py" ]; then
    python3 "$(dirname "$0")/audit-build.py" "$DISCOVER_REPORT" >/dev/null 2>&1 || true
fi

# Audit under Reports on every page; host-scan UI on Subdomains when filtered
f_import_report_ensure_audit_nav "$DISCOVER_REPORT"
f_import_report_ensure_subdomains_ui "$DISCOVER_REPORT/pages/subdomains.htm"

# Localhost status helper for live host-scan UI (rebind to this engagement)
STATUSD=""
if [ -n "$DISCOVER_ROOT" ] && [ -f "$DISCOVER_ROOT/misc/host-scan-statusd.py" ]; then
    STATUSD="$DISCOVER_ROOT/misc/host-scan-statusd.py"
elif [ -f "$(dirname "$0")/../misc/host-scan-statusd.py" ]; then
    STATUSD="$(cd "$(dirname "$0")/../misc" && pwd)/host-scan-statusd.py"
fi
if [ -n "$STATUSD" ]; then
    f_import_report_restart_statusd "$STATUSD" "$DISCOVER_REPORT" 17322
fi

OPEN_PAGE=""
if [ -f "$DISCOVER_REPORT/index.htm" ]; then
    OPEN_PAGE="$DISCOVER_REPORT/index.htm"
elif [ -f "$DISCOVER_REPORT/pages/active.htm" ]; then
    OPEN_PAGE="$DISCOVER_REPORT/pages/active.htm"
elif [ -f "$DISCOVER_REPORT/pages/subdomains.htm" ]; then
    OPEN_PAGE="$DISCOVER_REPORT/pages/subdomains.htm"
elif [ -f "$DISCOVER_REPORT/pages/passive.htm" ]; then
    OPEN_PAGE="$DISCOVER_REPORT/pages/passive.htm"
fi

echo
echo -e "Report:  ${YELLOW}$DISCOVER_REPORT${NC}"
echo -e "Session: ${YELLOW}$SESSION_DIR/current-report${NC}"
echo

if [ -n "$OPEN_PAGE" ]; then
    if f_import_report_open_browser "$OPEN_PAGE"; then
        echo "[*] Opening report in browser."
    else
        echo "[*] Open this file in a browser:"
        echo "    $OPEN_PAGE"
    fi
else
    f_import_report_warn "No index/active/subdomains/passive page found to open."
fi

echo
exit 0
