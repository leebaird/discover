#!/usr/bin/env bash

# by ibrahimsql - Sensitive Information Scanner
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Dev menu scanner: writes under $HOME/data/sensitive-scan_*/.
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

SENSITIVE_SCANNER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/sensitive-scanner/common.sh
source "${SENSITIVE_SCANNER_ROOT}/lib/sensitive-scanner/common.sh"
# shellcheck source=lib/sensitive-scanner/files.sh
source "${SENSITIVE_SCANNER_ROOT}/lib/sensitive-scanner/files.sh"
# shellcheck source=lib/sensitive-scanner/web.sh
source "${SENSITIVE_SCANNER_ROOT}/lib/sensitive-scanner/web.sh"

f_terminate(){
    echo
    echo -e "${YELLOW}[!] Interrupted — saving partial reports.${NC}"
    if [ -n "${OUTPUT_DIR:-}" ] && [ -d "${OUTPUT_DIR:-}" ]; then
        f_sensitive_generate_reports 2>/dev/null || true
    fi
    echo
    exit 130
}

trap f_terminate SIGHUP SIGINT SIGTERM

f_sensitive_run_scans(){
    local rc=0
    case "$SENSITIVE_SCAN_TYPES" in
        files)
            f_sensitive_scan_files || rc=1
            ;;
        web)
            [ -n "$SENSITIVE_URL" ] || { echo -e "${RED}[!] --url required${NC}"; return 1; }
            f_sensitive_scan_web "$SENSITIVE_URL" || rc=1
            ;;
        all)
            [ -n "$SENSITIVE_URL" ] || { echo -e "${RED}[!] --url required for --all${NC}"; return 1; }
            f_sensitive_scan_files || rc=1
            f_sensitive_scan_web "$SENSITIVE_URL" || rc=1
            ;;
        *)
            echo -e "${RED}[!] Unknown scan type${NC}"
            f_sensitive_usage
            return 1
            ;;
    esac
    f_sensitive_generate_reports
    return "$rc"
}

f_sensitive_interactive_menu(){
    while true; do
        clear
        f_banner
        echo -e "${BLUE}Sensitive Information Scanner${NC} originally by ${YELLOW}ibrahimsql${NC}"
        echo
        echo "1. File or folder"
        echo "2. URL"
        echo "3. File/folder + prior scan dir"
        echo "4. URL + prior scan dir (api-scanner output)"
        echo "5. Previous menu"
        echo
        echo -n "Choice: "
        read -r CHOICE

        SENSITIVE_PATH=""
        SENSITIVE_URL=""
        SENSITIVE_SCAN_DIR=""

        case "$CHOICE" in
            1)
                echo -n "Path to file or folder: "
                read -r SENSITIVE_PATH
                [ -e "$SENSITIVE_PATH" ] || { f_invalid; continue; }
                SENSITIVE_SCAN_TYPES="files"
                ;;
            2)
                echo -n "URL (https://target.com): "
                read -r SENSITIVE_URL
                [[ "$SENSITIVE_URL" =~ ^https?:// ]] || { f_invalid; continue; }
                SENSITIVE_SCAN_TYPES="web"
                ;;
            3)
                echo -n "Path to file or folder: "
                read -r SENSITIVE_PATH
                [ -e "$SENSITIVE_PATH" ] || { f_invalid; continue; }
                echo -n "Prior scan dir (optional): "
                read -r SENSITIVE_SCAN_DIR
                SENSITIVE_SCAN_TYPES="files"
                ;;
            4)
                echo -n "URL: "
                read -r SENSITIVE_URL
                [[ "$SENSITIVE_URL" =~ ^https?:// ]] || { f_invalid; continue; }
                echo -n "Prior scan dir (e.g. ~/data/api-scan_*): "
                read -r SENSITIVE_SCAN_DIR
                [ -n "$SENSITIVE_SCAN_DIR" ] && [ -d "$SENSITIVE_SCAN_DIR" ] || { f_invalid; continue; }
                SENSITIVE_SCAN_TYPES="all"
                ;;
            5) f_dev ;;
            *) f_invalid; continue ;;
        esac

        echo
        echo "Scan mode:"
        echo "1. Quick"
        echo "2. Full"
        echo -n "Choice [2]: "
        read -r MODE_CHOICE
        case "$MODE_CHOICE" in
            1) SENSITIVE_SCAN_MODE="quick" ;;
            *) SENSITIVE_SCAN_MODE="full" ;;
        esac

        f_sensitive_setup_output
        echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
        echo -e "${YELLOW}[*] Mode: $SENSITIVE_SCAN_MODE | Scan: $SENSITIVE_SCAN_TYPES${NC}"
        f_sensitive_run_scans || true
        echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
        echo -n "Press Enter..."
        read -r _
    done
}

f_sensitive_main(){
    f_sensitive_parse_cli "$@"

    if [ "$SENSITIVE_USE_MENU" = "1" ]; then
        f_sensitive_interactive_menu
        return 0
    fi

    if [ "$SENSITIVE_CLI_INVOKED" = "0" ] && [ $# -eq 0 ] && [ -t 0 ]; then
        f_sensitive_interactive_menu
        return 0
    fi

    if [ -z "$SENSITIVE_SCAN_TYPES" ]; then
        f_sensitive_usage
        exit 1
    fi

    if [ "$SENSITIVE_SCAN_TYPES" = "files" ] || [ "$SENSITIVE_SCAN_TYPES" = "all" ]; then
        if [ -z "$SENSITIVE_PATH" ] && [ -z "$SENSITIVE_SCAN_DIR" ]; then
            echo -e "${RED}[!] --path or --scan-dir required for file scan${NC}"
            exit 1
        fi
    fi

    f_sensitive_setup_output

    if [ "$SENSITIVE_QUIET" != "1" ]; then
        clear
        f_banner
        echo -e "${BLUE}Sensitive Information Scanner${NC}"
        echo -e "${YELLOW}Authorized security testing only. Findings may contain live secrets.${NC}"
        echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
        echo -e "${YELLOW}[*] Mode: $SENSITIVE_SCAN_MODE | Scan: $SENSITIVE_SCAN_TYPES${NC}"
    else
        f_sensitive_log "CLI scan mode=$SENSITIVE_SCAN_MODE types=$SENSITIVE_SCAN_TYPES"
    fi

    f_sensitive_run_scans || exit $?

    if [ "$SENSITIVE_QUIET" != "1" ]; then
        echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
        echo -e "${YELLOW}[*] Findings: findings_registry.tsv${NC}"
        echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
        echo
    fi
}

f_sensitive_main "$@"