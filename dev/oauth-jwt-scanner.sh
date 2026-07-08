#!/usr/bin/env bash

# by ibrahimsql - OAuth/JWT Security Scanner
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Dev menu scanner: writes under $HOME/data/oauth-jwt-scan_*/.
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

OAUTH_JWT_SCANNER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/oauth-jwt-scanner/common.sh
source "${OAUTH_JWT_SCANNER_ROOT}/lib/oauth-jwt-scanner/common.sh"
# shellcheck source=lib/oauth-jwt-scanner/oauth.sh
source "${OAUTH_JWT_SCANNER_ROOT}/lib/oauth-jwt-scanner/oauth.sh"
# shellcheck source=lib/oauth-jwt-scanner/jwt.sh
source "${OAUTH_JWT_SCANNER_ROOT}/lib/oauth-jwt-scanner/jwt.sh"

f_terminate(){
    echo
    echo -e "${RED}[!] Terminating.${NC}"
    echo
    exit 1
}

trap f_terminate SIGHUP SIGINT SIGTERM

f_oauth_jwt_run_scans(){
    local rc=0
    case "$OAUTH_JWT_SCAN_TYPES" in
        oauth)
            [ -n "$OAUTH_JWT_TARGET" ] || { echo -e "${RED}[!] --target required${NC}"; exit 1; }
            f_oauth_analyze "$OAUTH_JWT_TARGET" "$OUTPUT_DIR"
            ;;
        jwt)
            f_jwt_security "$OAUTH_JWT_TOKEN" "$OUTPUT_DIR" || rc=1
            ;;
        all)
            [ -n "$OAUTH_JWT_TARGET" ] || { echo -e "${RED}[!] --target required for --all${NC}"; exit 1; }
            f_oauth_analyze "$OAUTH_JWT_TARGET" "$OUTPUT_DIR"
            f_jwt_security "$OAUTH_JWT_TOKEN" "$OUTPUT_DIR" || rc=1
            ;;
        *)
            echo -e "${RED}[!] Unknown scan type${NC}"
            f_oauth_jwt_usage
            exit 1
            ;;
    esac
    f_oauth_jwt_generate_reports
    return "$rc"
}

f_oauth_jwt_interactive_menu(){
    while true; do
        clear
        f_banner
        echo -e "${BLUE}OAuth/JWT Security Scanner${NC} originally by ${YELLOW}ibrahimsql${NC}"
        echo
        echo "1. OAuth Configuration/Security Test"
        echo "2. JWT Security Test"
        echo "3. Combined (OAuth + JWT)"
        echo "4. Previous menu"
        echo
        echo -n "Choice: "
        read -r CHOICE

        case "$CHOICE" in
            1) OAUTH_JWT_SCAN_TYPES="oauth" ;;
            2) OAUTH_JWT_SCAN_TYPES="jwt" ;;
            3) OAUTH_JWT_SCAN_TYPES="all" ;;
            4) f_dev ;;
            *) f_invalid; continue ;;
        esac

        echo
        echo "Scan mode:"
        echo "1. Quick"
        echo "2. Full"
        echo -n "Choice [2]: "
        read -r MODE_CHOICE
        case "$MODE_CHOICE" in
            1) OAUTH_JWT_SCAN_MODE="quick" ;;
            *) OAUTH_JWT_SCAN_MODE="full" ;;
        esac

        if [ "$OAUTH_JWT_SCAN_TYPES" != "jwt" ]; then
            echo -n "Target URL: "
            read -r OAUTH_JWT_TARGET
            [[ "$OAUTH_JWT_TARGET" =~ ^https?:// ]] || { f_invalid; continue; }
        fi

        if [ "$OAUTH_JWT_SCAN_TYPES" != "oauth" ]; then
            echo -n "JWT token (leave blank to use jwt_found.txt from api-scanner dir): "
            read -r OAUTH_JWT_TOKEN
            if [ -z "$OAUTH_JWT_TOKEN" ]; then
                echo -n "API scanner output dir (optional): "
                read -r OAUTH_JWT_API_SCAN_DIR
            fi
        fi

        echo -n "JWT live-test endpoint (optional): "
        read -r OAUTH_JWT_ENDPOINT

        f_oauth_jwt_setup_output
        echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
        f_oauth_jwt_run_scans || true
        echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
        echo -n "Press Enter..."
        read -r _
    done
}

f_oauth_jwt_main(){
    f_oauth_jwt_parse_cli "$@"

    if [ "$OAUTH_JWT_USE_MENU" = "1" ]; then
        f_oauth_jwt_interactive_menu
        return 0
    fi

    if [ "$OAUTH_JWT_CLI_INVOKED" = "0" ] && [ $# -eq 0 ] && [ -t 0 ]; then
        f_oauth_jwt_interactive_menu
        return 0
    fi

    if [ -z "$OAUTH_JWT_SCAN_TYPES" ]; then
        f_oauth_jwt_usage
        exit 1
    fi

    f_oauth_jwt_setup_output

    clear
    f_banner
    echo -e "${BLUE}OAuth/JWT Security Scanner${NC}"
    echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
    echo -e "${YELLOW}[*] Mode: $OAUTH_JWT_SCAN_MODE | Scan: $OAUTH_JWT_SCAN_TYPES${NC}"

    f_oauth_jwt_run_scans || exit $?

    echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
    echo -e "${YELLOW}[*] Findings: findings_registry.tsv${NC}"
    echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
    echo
}

f_oauth_jwt_main "$@"