#!/usr/bin/env bash

# by ibrahimsql - Metasploit Web and API Security Scanner
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Dev menu scanner: writes under $HOME/data/web-api-scan_*/.
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

WEBAPI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/web-api-scanner/common.sh
source "${WEBAPI_ROOT}/lib/web-api-scanner/common.sh"
# shellcheck source=lib/web-api-scanner/phases.sh
source "${WEBAPI_ROOT}/lib/web-api-scanner/phases.sh"
# shellcheck source=lib/web-api-scanner/waf.sh
source "${WEBAPI_ROOT}/lib/web-api-scanner/waf.sh"
# shellcheck source=lib/web-api-scanner/targets.sh
source "${WEBAPI_ROOT}/lib/web-api-scanner/targets.sh"
# shellcheck source=lib/web-api-scanner/msf.sh
source "${WEBAPI_ROOT}/lib/web-api-scanner/msf.sh"
# shellcheck source=lib/web-api-scanner/probe.sh
source "${WEBAPI_ROOT}/lib/web-api-scanner/probe.sh"

f_terminate(){
    echo
    echo -e "${YELLOW}[!] Interrupted — saving partial reports.${NC}"
    if [ -n "${OUTPUT_DIR:-}" ] && [ -d "${OUTPUT_DIR:-}" ]; then
        f_webapi_generate_reports 2>/dev/null || true
    fi
    echo
    exit 130
}

trap f_terminate SIGHUP SIGINT SIGTERM

f_webapi_interactive_menu(){
    while true; do
        clear
        f_banner
        echo -e "${BLUE}Web and API Security${NC} originally by ${YELLOW}ibrahimsql${NC}"
        echo
        echo "1. Scan a URL"
        echo "2. Previous menu"
        echo
        echo -n "Choice: "
        read -r CHOICE

        case "$CHOICE" in
            1)
                echo
                echo -n "Target URL or hostname: "
                read -r WEBAPI_URL
                [ -n "$WEBAPI_URL" ] || { f_invalid; continue; }
                echo
                echo "Scan tier:"
                echo "1. Passive (MSF recon only — recommended)"
                echo "2. Quick/standard (recon + tech scanners)"
                echo "3. Intrusive (+ SQLi + auth brute)"
                echo "4. Exploit (+ exploit checks)"
                echo -n "Choice [1]: "
                read -r TIER_CHOICE
                case "$TIER_CHOICE" in
                    2) WEBAPI_TIER=standard; WEBAPI_QUICK=1 ;;
                    3) WEBAPI_TIER=intrusive ;;
                    4) WEBAPI_TIER=exploit ;;
                    *) WEBAPI_TIER=passive; WEBAPI_PASSIVE=1 ;;
                esac
                f_webapi_setup_output
                f_webapi_require_active_consent
                f_webapi_say "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
                f_webapi_say "${GREEN}[*] Tier: ${WEBAPI_TIER}${NC}"
                f_webapi_run_all || true
                f_webapi_say "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
                echo -n "Press Enter..."
                read -r _
                ;;
            2) f_dev ;;
            *) f_invalid; continue ;;
        esac
    done
}

f_webapi_main(){
    f_webapi_parse_cli "$@"

    if [ "$WEBAPI_USE_MENU" = "1" ]; then
        f_webapi_interactive_menu
        return 0
    fi

    if [ "$WEBAPI_CLI_INVOKED" = "0" ] && [ $# -eq 0 ] && [ -t 0 ]; then
        f_webapi_interactive_menu
        return 0
    fi

    if [ -z "$WEBAPI_URL" ] && [ -z "$WEBAPI_FILE" ]; then
        f_webapi_usage
        exit 1
    fi

    f_webapi_setup_output
    f_webapi_require_active_consent
    f_webapi_resolve_tier

    if [ "$WEBAPI_QUIET" != "1" ]; then
        clear
        f_banner
        echo -e "${BLUE}Web and API Security Scanner${NC}"
        echo -e "${YELLOW}Authorized security testing only.${NC}"
        echo -e "${GREEN}[*] Tier: ${WEBAPI_TIER}${NC}"
        if [ "$WEBAPI_DRY_RUN" = "1" ]; then
            echo -e "${YELLOW}[*] Dry-run: building session plan without msfconsole${NC}"
        fi
        echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
    else
        f_webapi_log "CLI scan tier=$WEBAPI_TIER dry_run=$WEBAPI_DRY_RUN"
    fi

    f_webapi_run_all || exit $?

    if [ "$WEBAPI_QUIET" != "1" ]; then
        echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
        echo -e "${YELLOW}[*] MSF sessions: ${OUTPUT_DIR}/msf_engine/session_*.rc${NC}"
        echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
        echo
    fi
}

f_webapi_main "$@"