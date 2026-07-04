# Multi-target loading and parallel execution

WEBAPI_FILE="${WEBAPI_FILE:-}"
WEBAPI_MAX_TARGETS="${WEBAPI_MAX_TARGETS:-0}"
WEBAPI_WORKERS="${WEBAPI_WORKERS:-1}"
WEBAPI_INPUT_FORMAT="${WEBAPI_INPUT_FORMAT:-}"

f_webapi_detect_input_format(){
    local path="$1"
    if [ -n "$WEBAPI_INPUT_FORMAT" ]; then
        printf '%s' "$WEBAPI_INPUT_FORMAT"
        return 0
    fi
    case "$path" in
        *.csv) echo csv ;;
        *.json) echo json ;;
        *) echo text ;;
    esac
}

f_webapi_load_targets(){
    local -n _out=$1
    local src="$2" fmt
    _out=()
    if [ -n "$WEBAPI_URL" ]; then
        _out+=("$WEBAPI_URL")
        return 0
    fi
    [ -n "$src" ] && [ -f "$src" ] || return 0
    fmt=$(f_webapi_detect_input_format "$src")
    case "$fmt" in
        csv)
            while IFS= read -r u; do
                [ -n "$u" ] && _out+=("$u")
            done < <(python3 - "$src" <<'PY'
import csv, sys
with open(sys.argv[1], newline='', encoding='utf-8', errors='replace') as fh:
    rows = list(csv.DictReader(fh))
    key = 'url' if rows and 'url' in rows[0] else list(rows[0].keys())[0] if rows else 'url'
    for r in rows:
        v = (r.get(key) or '').strip()
        if v: print(v)
PY
)
            ;;
        json)
            while IFS= read -r u; do
                [ -n "$u" ] && _out+=("$u")
            done < <(jq -r '.[] | .url // .target // .[]? // empty' "$src" 2>/dev/null; \
                jq -r '.url // .target // empty' "$src" 2>/dev/null)
            ;;
        *)
            while IFS= read -r line || [ -n "$line" ]; do
                line="${line%%#*}"
                line="${line// /}"
                [ -n "$line" ] || continue
                _out+=("$line")
            done < "$src"
            ;;
    esac
}

f_webapi_run_all(){
    local targets=() t rc=0 i=0 total workers running

    f_webapi_load_targets targets "$WEBAPI_FILE"
    if [ ${#targets[@]} -eq 0 ]; then
        [ -n "$WEBAPI_URL" ] && f_webapi_run_scan "$WEBAPI_URL" && return $?
        echo -e "${RED}[!] No targets (--url or --file required)${NC}"
        return 1
    fi

    if [ "${WEBAPI_MAX_TARGETS:-0}" -gt 0 ] && [ ${#targets[@]} -gt "$WEBAPI_MAX_TARGETS" ]; then
        targets=("${targets[@]:0:$WEBAPI_MAX_TARGETS}")
        f_webapi_log "Capped targets to $WEBAPI_MAX_TARGETS"
    fi

    workers="${WEBAPI_WORKERS:-1}"
    total=${#targets[@]}

    if [ "$workers" -gt 1 ]; then
        f_webapi_say "${YELLOW}[*] Running $total targets with $workers workers${NC}"
        for t in "${targets[@]}"; do
            while [ "$(jobs -rp | wc -l)" -ge "$workers" ]; do
                sleep 0.3
            done
            i=$((i + 1))
            f_webapi_say "${YELLOW}[$i/$total]${NC} $t"
            ( f_webapi_run_scan "$t" ) &
        done
        wait || rc=1
    else
        for t in "${targets[@]}"; do
            i=$((i + 1))
            f_webapi_say "${YELLOW}[$i/$total]${NC} $t"
            f_webapi_run_scan "$t" || rc=1
        done
    fi
    return "$rc"
}