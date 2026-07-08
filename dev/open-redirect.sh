#!/usr/bin/env bash

# by ibrahimsql - Open Redirect Scanner
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Dev menu scanner: writes under $HOME/data/openredirect-scan_*/.
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

OPEN_REDIRECT_SCANNER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/menu.sh
source "${OPEN_REDIRECT_SCANNER_ROOT}/lib/menu.sh"
# shellcheck source=lib/open-redirect-scanner/common.sh
source "${OPEN_REDIRECT_SCANNER_ROOT}/lib/open-redirect-scanner/common.sh"

f_terminate(){
    echo
    echo -e "${RED}[!] Terminating.${NC}"
    echo
    exit 1
}

trap f_terminate SIGHUP SIGINT SIGTERM

f_openredirect_run_scans(){
    local rc=0
    f_openredirect_run_engine || rc=$?
    f_openredirect_generate_reports
    return "$rc"
}

f_openredirect_interactive_menu(){
    while true; do
        clear
        f_banner
        echo -e "${BLUE}Open Redirect Scanner${NC} originally by ${YELLOW}ibrahimsql${NC}"
        echo
        echo "1. Scan a single URL"
        echo "2. Scan a domain"
        echo "3. Scan multiple URLs from a file"
        echo "4. Advanced options (wordlist, crawl, rate limits)"
        echo "5. Scan URLs from prior Discover scan dir"
        echo "6. Previous menu"
        echo
        echo -n "Choice: "
        f_dev_read_choice CHOICE
        f_dev_menu_validate "$CHOICE"

        OPEN_REDIRECT_URL=""
        OPEN_REDIRECT_DOMAIN=""
        OPEN_REDIRECT_FILE=""
        OPEN_REDIRECT_WORDLIST=""
        OPEN_REDIRECT_SCAN_DIR=""
        OPEN_REDIRECT_CRAWL=0
        OPEN_REDIRECT_DELAY=0
        OPEN_REDIRECT_RPS=0
        OPEN_REDIRECT_MAX_REQUESTS=0
        OPEN_REDIRECT_NO_CONFIRM=0

        case "$CHOICE" in
            1)
                f_dev_read_required OPEN_REDIRECT_URL "Target URL or domain: " "No target provided."
                OPEN_REDIRECT_URL=$(f_openredirect_normalize_url "$OPEN_REDIRECT_URL")
                ;;
            2)
                f_dev_read_required OPEN_REDIRECT_DOMAIN "Domain name: " "No domain provided."
                OPEN_REDIRECT_DOMAIN=$(f_openredirect_normalize_domain "$OPEN_REDIRECT_DOMAIN")
                ;;
            3)
                f_dev_read_file OPEN_REDIRECT_FILE "Path to URL list file: " "Input file not found."
                ;;
            4)
                f_dev_read_required OPEN_REDIRECT_URL "Target URL or domain: " "No target provided."
                OPEN_REDIRECT_URL=$(f_openredirect_normalize_url "$OPEN_REDIRECT_URL")
                echo -n "Custom parameter wordlist (optional): "
                read -r OPEN_REDIRECT_WORDLIST
                OPEN_REDIRECT_WORDLIST=$(f_dev_trim "$OPEN_REDIRECT_WORDLIST")
                OPEN_REDIRECT_WORDLIST="${OPEN_REDIRECT_WORDLIST/#\~/$HOME}"
                if [ -n "$OPEN_REDIRECT_WORDLIST" ] && [ ! -f "$OPEN_REDIRECT_WORDLIST" ]; then
                    f_dev_die "Input file not found."
                fi
                echo -n "Crawl links from target? (y/n) [n]: "
                read -r CRAWL_IN
                [[ "$CRAWL_IN" =~ ^[Yy] ]] && OPEN_REDIRECT_CRAWL=1
                echo -n "Max requests (0=unlimited) [0]: "
                read -r OPEN_REDIRECT_MAX_REQUESTS
                OPEN_REDIRECT_MAX_REQUESTS="${OPEN_REDIRECT_MAX_REQUESTS:-0}"
                echo -n "Delay between requests in seconds [0]: "
                read -r OPEN_REDIRECT_DELAY
                OPEN_REDIRECT_DELAY="${OPEN_REDIRECT_DELAY:-0}"
                ;;
            5)
                f_dev_read_dir OPEN_REDIRECT_SCAN_DIR "Prior scan output dir (e.g. ~/data/api-scan_*): " "Scan directory not found."
                echo -n "Also seed with a single URL (optional): "
                read -r OPEN_REDIRECT_URL
                OPEN_REDIRECT_URL=$(f_dev_trim "$OPEN_REDIRECT_URL")
                if [ -n "$OPEN_REDIRECT_URL" ]; then
                    OPEN_REDIRECT_URL=$(f_openredirect_normalize_url "$OPEN_REDIRECT_URL")
                fi
                ;;
            6) f_dev_previous ;;
            *) f_dev_die "Invalid choice or entry." ;;
        esac

        echo "Scan mode:"
        echo "1. Quick"
        echo "2. Full"
        f_dev_read_scan_mode OPEN_REDIRECT_SCAN_MODE

        echo -n "Canary host [${OPEN_REDIRECT_CANARY_HOST}]: "
        read -r CANARY_IN
        [ -n "$CANARY_IN" ] && OPEN_REDIRECT_CANARY_HOST="$CANARY_IN"

        f_openredirect_setup_output
        echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
        echo -e "${YELLOW}[*] Mode: $OPEN_REDIRECT_SCAN_MODE | Canary: $OPEN_REDIRECT_CANARY_HOST${NC}"
        f_openredirect_run_scans || true
        echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
        echo -n "Press Enter..."
        read -r _
    done
}

f_openredirect_main(){
    f_openredirect_parse_cli "$@"

    if [ "$OPEN_REDIRECT_USE_MENU" = "1" ]; then
        f_openredirect_interactive_menu
        return 0
    fi

    if [ "$OPEN_REDIRECT_CLI_INVOKED" = "0" ] && [ $# -eq 0 ] && [ -t 0 ]; then
        f_openredirect_interactive_menu
        return 0
    fi

    if ! f_openredirect_has_target; then
        f_openredirect_usage
        exit 1
    fi

    if [ -n "$OPEN_REDIRECT_URL" ]; then
        OPEN_REDIRECT_URL=$(f_openredirect_normalize_url "$OPEN_REDIRECT_URL")
    fi
    if [ -n "$OPEN_REDIRECT_DOMAIN" ]; then
        OPEN_REDIRECT_DOMAIN=$(f_openredirect_normalize_domain "$OPEN_REDIRECT_DOMAIN")
    fi

    f_openredirect_setup_output

    clear
    f_banner
    echo -e "${BLUE}Open Redirect Scanner${NC}"
    echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
    echo -e "${YELLOW}[*] Mode: $OPEN_REDIRECT_SCAN_MODE | Canary: $OPEN_REDIRECT_CANARY_HOST${NC}"

    f_openredirect_run_scans || exit $?

    echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
    echo -e "${YELLOW}[*] Findings: findings_registry.tsv${NC}"
    echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
    echo
}

f_openredirect_main "$@"