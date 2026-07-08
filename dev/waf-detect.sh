#!/usr/bin/env bash

# by ibrahimsql - WAF Detection Tool
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Dev menu scanner: writes under $HOME/data/waf-detection_*/.
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

WAF_DETECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/menu.sh
source "${WAF_DETECT_ROOT}/lib/menu.sh"
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
        f_dev_read_choice CHOICE
        f_dev_menu_validate "$CHOICE"

        WAF_URL=""
        WAF_FILE=""

        case "$CHOICE" in
            1)
                f_dev_read_required WAF_URL "Target (URL or hostname): " "No target provided."
                ;;
            2)
                f_dev_read_file WAF_FILE "Path to targets file: " "Input file not found."
                ;;
            3) f_dev_previous ;;
            *) f_dev_die "Invalid choice or entry." ;;
        esac

        echo "Probe mode:"
        echo "1. Active (wafw00f + triggers)"
        echo "2. Passive (no attack triggers)"
        echo
        echo -n "Choice: "
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

f_waf_main "$@"