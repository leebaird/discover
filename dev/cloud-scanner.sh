#!/usr/bin/env bash

# by ibrahimsql - Cloud Security Scanner
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Standalone scanner: writes only under $HOME/data/cloud-scan_*/ (or --output-dir).
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

if ! declare -f f_banner >/dev/null 2>&1; then
    _CLOUD_SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    DISCOVER_SOURCE_ONLY=1 source "${_CLOUD_SCANNER_DIR}/../discover.sh"
fi

_CLOUD_SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/cloud-scanner/common.sh
source "${_CLOUD_SCANNER_DIR}/lib/cloud-scanner/common.sh"
# shellcheck source=lib/cloud-scanner/aws.sh
source "${_CLOUD_SCANNER_DIR}/lib/cloud-scanner/aws.sh"
# shellcheck source=lib/cloud-scanner/azure.sh
source "${_CLOUD_SCANNER_DIR}/lib/cloud-scanner/azure.sh"
# shellcheck source=lib/cloud-scanner/gcp.sh
source "${_CLOUD_SCANNER_DIR}/lib/cloud-scanner/gcp.sh"

###############################################################################################################################

f_terminate(){
    echo
    echo -e "${RED}[!] Terminating.${NC}"
    echo
    exit 1
}

trap f_terminate SIGHUP SIGINT SIGTERM

###############################################################################################################################

f_cloud_run_providers(){
    local failed=0

    if [ -z "$CLOUD_PROVIDERS" ] || [[ "$CLOUD_PROVIDERS" == *aws* ]]; then
        f_aws_security_check || failed=1
    fi
    if [ -z "$CLOUD_PROVIDERS" ] || [[ "$CLOUD_PROVIDERS" == *azure* ]]; then
        f_azure_security_check || failed=1
    fi
    if [ -z "$CLOUD_PROVIDERS" ] || [[ "$CLOUD_PROVIDERS" == *gcp* ]]; then
        f_gcp_security_check || failed=1
    fi

    f_cloud_generate_reports
    echo
    echo -e "${YELLOW}[*] Results: ${OUTPUT_DIR}/${NC}"
    echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
    echo -e "${YELLOW}[*] Findings: findings_registry.tsv${NC}"
    echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
    echo

    return "$failed"
}

f_cloud_interactive_menu(){
    while true; do
        clear
        f_banner
        echo -e "${BLUE}Cloud Security Scanner${NC} | ${YELLOW}by ibrahimsql${NC}"
        echo
        echo "1. AWS (Amazon Web Services)"
        echo "2. Azure (Microsoft Azure)"
        echo "3. GCP (Google Cloud Platform)"
        echo "4. All providers"
        echo "5. Previous menu"
        echo
        echo -n "Choice: "
        read -r CHOICE

        case "$CHOICE" in
            1) CLOUD_PROVIDERS="aws" ;;
            2) CLOUD_PROVIDERS="azure" ;;
            3) CLOUD_PROVIDERS="gcp" ;;
            4) CLOUD_PROVIDERS="" ;;
            5) f_dev ;;
            *) f_invalid; continue ;;
        esac

        echo
        echo "Scan mode:"
        echo "1. Quick (exposure-focused)"
        echo "2. Full (comprehensive)"
        echo -n "Choice [2]: "
        read -r MODE_CHOICE
        case "$MODE_CHOICE" in
            1) CLOUD_SCAN_MODE="quick" ;;
            *) CLOUD_SCAN_MODE="full" ;;
        esac

        f_cloud_setup_output
        f_cloud_run_providers || {
            echo -e "${YELLOW}[*] One or more provider checks failed. Fix credentials and retry.${NC}"
            echo
            echo -n "Press Enter to return to menu..."
            read -r _
            continue
        }
        return 0
    done
}

f_cloud_main(){
    f_cloud_parse_cli "$@"

    if [ "$CLOUD_CLI_PROVIDERS" = "1" ] || [ -n "$CLOUD_RESUME_DIR" ]; then
        f_cloud_setup_output
        f_cloud_run_providers
        return $?
    fi

    f_cloud_interactive_menu
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    f_cloud_main "$@"
fi