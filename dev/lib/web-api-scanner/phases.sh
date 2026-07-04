# Phase tiers, filtering, and consent

WEBAPI_TIER="${WEBAPI_TIER:-}"
WEBAPI_PHASES="${WEBAPI_PHASES:-}"
WEBAPI_SKIP_PHASES="${WEBAPI_SKIP_PHASES:-}"
WEBAPI_QUICK="${WEBAPI_QUICK:-0}"

f_webapi_tier_rank(){
    case "$1" in
        passive) echo 1 ;;
        standard) echo 2 ;;
        intrusive) echo 3 ;;
        exploit) echo 4 ;;
        *) echo 0 ;;
    esac
}

f_webapi_resolve_tier(){
    if [ -n "$WEBAPI_TIER" ]; then
        f_webapi_tier_sets_passive_flag
        return 0
    fi
    if [ "$WEBAPI_PASSIVE" = "1" ]; then
        WEBAPI_TIER=passive
        return 0
    fi
    if [ "$WEBAPI_QUICK" = "1" ]; then
        WEBAPI_TIER=standard
        return 0
    fi
    WEBAPI_TIER=intrusive
}

f_webapi_tier_sets_passive_flag(){
    [ "$WEBAPI_TIER" = "passive" ] && WEBAPI_PASSIVE=1 || WEBAPI_PASSIVE=0
}

f_webapi_phase_list_contains(){
    local list="$1" item="$2"
    echo ",${list}," | grep -q ",${item},"
}

f_webapi_should_skip_phase_explicit(){
    local phase="$1"
    f_webapi_phase_list_contains "$WEBAPI_SKIP_PHASES" "$phase" && return 0
    if [ -n "$WEBAPI_PHASES" ] && ! f_webapi_phase_list_contains "$WEBAPI_PHASES" "$phase"; then
        return 0
    fi
    return 1
}

f_webapi_tech_is_detected(){
    local tech="$1"
    [ "${WEBAPI_TECH_SCORE[$tech]:-0}" -ge "${WEBAPI_TECH_MIN_SCORE:-3}" ]
}

f_webapi_build_phase_plan(){
    local -n _out=$1
    local phase_file="${WEBAPI_ROOT}/data/web-api-phases.tsv"
    local phase min_tier skip_waf tech_req cur_rank min_rank
    _out=()

    f_webapi_resolve_tier
    f_webapi_tier_sets_passive_flag
    cur_rank=$(f_webapi_tier_rank "$WEBAPI_TIER")

    while IFS=$'\t' read -r phase min_tier skip_waf tech_req; do
        [[ "$phase" =~ ^# ]] && continue
        [ -n "$phase" ] && [ -n "$min_tier" ] || continue
        f_webapi_should_skip_phase_explicit "$phase" && continue
        min_rank=$(f_webapi_tier_rank "$min_tier")
        [ "$cur_rank" -ge "$min_rank" ] || continue
        [ "$skip_waf" = "1" ] && [ "${WEBAPI_WAF_PRESENT:-0}" = "1" ] && {
            f_webapi_log "Skip phase $phase (WAF/CDN present)"
            continue
        }
        if [ -n "${tech_req:-}" ]; then
            f_webapi_tech_is_detected "$tech_req" || continue
        fi
        _out+=("$phase")
    done < "$phase_file"
}

f_webapi_require_active_consent(){
    f_webapi_resolve_tier
    case "$WEBAPI_TIER" in
        passive) return 0 ;;
        standard)
            [ "$WEBAPI_I_UNDERSTAND" = "1" ] && return 0
            [ "$WEBAPI_QUICK" = "1" ] && return 0
            ;;
        intrusive|exploit)
            [ "$WEBAPI_I_UNDERSTAND" = "1" ] && return 0
            ;;
    esac
    if [ -t 0 ] && [ -t 1 ]; then
        echo -e "${YELLOW}Tier '${WEBAPI_TIER}' runs Metasploit modules against the target. Authorized testing only.${NC}"
        echo -n "Continue? (y/n): "
        read -r ans
        [[ "$ans" =~ ^[Yy] ]] || { echo "Aborted."; exit 1; }
        return 0
    fi
    echo -e "${RED}[!] Active scan requires --passive, --quick, or --i-understand (tier=${WEBAPI_TIER})${NC}"
    exit 1
}