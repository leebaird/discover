#!/usr/bin/env bash

# by ibrahimsql - Cloud Security Scanner
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Dev menu scanner: writes under $HOME/data/cloud-scan_*/.
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

_CLOUD_SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/menu.sh
source "${_CLOUD_SCANNER_DIR}/lib/menu.sh"
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
    local ran=0

    if [ -z "$CLOUD_PROVIDERS" ] || [[ "$CLOUD_PROVIDERS" == *aws* ]]; then
        if f_aws_security_check; then
            ran=1
        else
            failed=1
        fi
    fi
    if [ -z "$CLOUD_PROVIDERS" ] || [[ "$CLOUD_PROVIDERS" == *azure* ]]; then
        if f_azure_security_check; then
            ran=1
        else
            failed=1
        fi
    fi
    if [ -z "$CLOUD_PROVIDERS" ] || [[ "$CLOUD_PROVIDERS" == *gcp* ]]; then
        if f_gcp_security_check; then
            ran=1
        else
            failed=1
        fi
    fi

    if [ "$ran" -eq 0 ]; then
        return 1
    fi

    f_cloud_generate_reports
    echo
    echo -e "${YELLOW}[*] Results: ${OUTPUT_DIR}/${NC}"
    echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
    echo -e "${YELLOW}[*] Findings: findings_registry.tsv${NC}"
    echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
    echo

    if [ "$failed" -ne 0 ]; then
        echo -e "${YELLOW}[!] One or more provider checks failed.${NC}"
        echo
    fi

    return 0
}

f_cloud_interactive_menu(){
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
    f_dev_read_choice CHOICE
    f_dev_menu_validate "$CHOICE"

    case "$CHOICE" in
        1) CLOUD_PROVIDERS="aws" ;;
        2) CLOUD_PROVIDERS="azure" ;;
        3) CLOUD_PROVIDERS="gcp" ;;
        4) CLOUD_PROVIDERS="" ;;
        5) f_dev_previous ;;
        *) f_dev_die "Invalid choice or entry." ;;
    esac

    echo "Scan mode:"
    echo "1. Quick (exposure-focused)"
    echo "2. Full (comprehensive)"
    f_dev_read_scan_mode CLOUD_SCAN_MODE

    f_cloud_setup_output
    if ! f_cloud_run_providers; then
        rm -rf "$OUTPUT_DIR" 2>/dev/null
        echo
        sleep 2
        exit 3
    fi
    return 0
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

f_cloud_main "$@"