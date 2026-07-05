#!/usr/bin/env bash

# by ibrahimsql - WAF Detection Tool
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Standalone scanner: writes only under $HOME/data/waf-detection_*/ (or --output-dir).
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

if ! declare -f f_banner >/dev/null 2>&1; then
    WAF_DETECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    DISCOVER_SOURCE_ONLY=1 source "${WAF_DETECT_ROOT}/../discover.sh"
fi

WAF_DETECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/waf-detect/common.sh
source "${WAF_DETECT_ROOT}/lib/waf-detect/common.sh"
# shellcheck source=lib/waf-detect/probe.sh
source "${WAF_DETECT_ROOT}/lib/waf-detect/probe.sh"

f_terminate(){
    echo
    echo -e "${YELLOW}[!] Interrupted — saving partial reports.${NC}"
    if [ -n "${OUTPUT_DIR:-}" ] && [ -d "${OUTPUT_DIR:-}" ]; then
        f_waf_generate_reports 2>/dev/null || true
    fi
    echo
    exit 130
}

trap f_terminate SIGHUP SIGINT SIGTERM

f_waf_interactive_menu(){
    while true; do
        clear
        f_banner
        echo -e "${BLUE}WAF Detection${NC} originally by ${YELLOW}ibrahimsql${NC}"
        echo
        echo "1. Single target"
        echo "2. Multiple targets from file"
        echo "3. Previous menu"
        echo
        echo -n "Choice: "
        read -r CHOICE

        WAF_URL=""
        WAF_FILE=""

        case "$CHOICE" in
            1)
                echo -n "Target (URL or hostname): "
                read -r WAF_URL
                [ -n "$WAF_URL" ] || { f_error; continue; }
                ;;
            2)
                echo -n "Path to targets file: "
                read -r WAF_FILE
                [ -n "$WAF_FILE" ] && [ -f "$WAF_FILE" ] || { f_error; continue; }
                ;;
            3) f_dev; return 0 ;;
            *) f_error; continue ;;
        esac

        echo
        echo "Probe mode:"
        echo "1. Active (wafw00f + triggers)"
        echo "2. Passive (no attack triggers)"
        echo -n "Choice [1]: "
        read -r MODE_CHOICE
        case "$MODE_CHOICE" in
            2) WAF_PASSIVE=1 ;;
            *) WAF_PASSIVE=0 ;;
        esac

        f_waf_setup_output
        f_waf_require_active_consent
        f_waf_say "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
        if [ "$WAF_PASSIVE" = "1" ]; then
            f_waf_say "${GREEN}[*] Passive mode: normal GET + header signatures only (no wafw00f)${NC}"
        fi
        f_waf_run_scan || true
        f_waf_say "${YELLOW}[*] Reports: report.txt, report.md, findings.json, waf_results.tsv${NC}"
        echo -n "Press Enter..."
        read -r _
    done
}

f_waf_main(){
    f_waf_parse_cli "$@"

    if [ "$WAF_USE_MENU" = "1" ]; then
        f_waf_interactive_menu
        return 0
    fi

    if [ "$WAF_CLI_INVOKED" = "0" ] && [ $# -eq 0 ] && [ -t 0 ]; then
        f_waf_interactive_menu
        return 0
    fi

    if [ -z "$WAF_URL" ] && [ -z "$WAF_FILE" ]; then
        f_waf_usage
        exit 1
    fi

    f_waf_setup_output
    f_waf_require_active_consent

    if [ "$WAF_QUIET" != "1" ]; then
        clear
        f_banner
        echo -e "${BLUE}WAF Detection${NC}"
        echo -e "${YELLOW}Authorized security testing only. Active mode sends benign WAF triggers.${NC}"
        if [ "$WAF_PASSIVE" = "1" ]; then
            echo -e "${GREEN}[*] Passive mode: normal GET + header signatures only (no wafw00f)${NC}"
        fi
        echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
    else
        f_waf_log "CLI scan passive=$WAF_PASSIVE"
    fi

    f_waf_run_scan || exit $?

    if [ "$WAF_QUIET" != "1" ]; then
        echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
        echo -e "${YELLOW}[*] Results: waf_results.tsv${NC}"
        echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
        echo
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    f_waf_main "$@"
fi