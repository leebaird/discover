#!/usr/bin/env bash

# by ibrahimsql - Container Security Scanner
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Standalone scanner: writes only under $HOME/data/container-scan_*/ (or --output-dir).
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

if ! declare -f f_banner >/dev/null 2>&1; then
    CONTAINER_SCANNER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    DISCOVER_SOURCE_ONLY=1 source "${CONTAINER_SCANNER_ROOT}/../discover.sh"
fi

CONTAINER_SCANNER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/container-scanner/common.sh
source "${CONTAINER_SCANNER_ROOT}/lib/container-scanner/common.sh"
# shellcheck source=lib/container-scanner/docker.sh
source "${CONTAINER_SCANNER_ROOT}/lib/container-scanner/docker.sh"
# shellcheck source=lib/container-scanner/k8s.sh
source "${CONTAINER_SCANNER_ROOT}/lib/container-scanner/k8s.sh"

###############################################################################################################################

f_terminate(){
    echo
    echo -e "${RED}[!] Terminating.${NC}"
    echo
    exit 1
}

trap f_terminate SIGHUP SIGINT SIGTERM

###############################################################################################################################

f_container_run_scans(){
    case "$CONTAINER_SCAN_TYPES" in
        docker-images)
            f_scan_docker_images "$OUTPUT_DIR"
            ;;
        docker-containers)
            f_scan_docker_containers "$OUTPUT_DIR"
            ;;
        kubernetes)
            f_scan_kubernetes "$OUTPUT_DIR"
            ;;
        all)
            f_scan_docker_images "$OUTPUT_DIR"
            f_scan_docker_containers "$OUTPUT_DIR"
            f_scan_kubernetes "$OUTPUT_DIR"
            ;;
        *)
            echo -e "${RED}[!] Unknown scan type: $CONTAINER_SCAN_TYPES${NC}"
            f_container_usage
            exit 1
            ;;
    esac

    f_container_generate_reports
}

f_container_interactive_menu(){
    while true; do
        clear
        f_banner
        echo -e "${BLUE}Container Security Scanner${NC}"
        echo
        echo "1. Docker images"
        echo "2. Docker containers"
        echo "3. Kubernetes"
        echo "4. All scans"
        echo "5. Previous menu"
        echo
        echo -n "Choice: "
        read -r CHOICE

        case "$CHOICE" in
            1) CONTAINER_SCAN_TYPES="docker-images" ;;
            2) CONTAINER_SCAN_TYPES="docker-containers" ;;
            3) CONTAINER_SCAN_TYPES="kubernetes" ;;
            4) CONTAINER_SCAN_TYPES="all" ;;
            5) f_dev; return 0 ;;
            *) f_error; continue ;;
        esac

        echo
        echo "Scan mode:"
        echo "1. Quick (high-severity / running workloads)"
        echo "2. Full (comprehensive)"
        echo -n "Choice [2]: "
        read -r MODE_CHOICE
        case "$MODE_CHOICE" in
            1) CONTAINER_SCAN_MODE="quick" ;;
            *) CONTAINER_SCAN_MODE="full" ;;
        esac

        f_container_setup_output
        f_container_check_deps
        echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
        echo -e "${YELLOW}[*] Mode: $CONTAINER_SCAN_MODE${NC}"
        f_container_run_scans
        echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
        echo -e "${YELLOW}[*] Legacy: container_security_report.txt${NC}"
        echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
        echo
        echo -n "Press Enter to return to menu..."
        read -r _
    done
}

f_container_main(){
    f_container_parse_cli "$@"

    if [ "$CONTAINER_USE_MENU" = "1" ]; then
        f_container_interactive_menu
        return 0
    fi

    f_container_setup_output
    f_container_check_deps
    clear
    f_banner
    echo -e "${BLUE}Container Security Scanner${NC}"
    echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
    echo -e "${YELLOW}[*] Mode: $CONTAINER_SCAN_MODE | Scan: $CONTAINER_SCAN_TYPES${NC}"
    f_container_run_scans
    echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
    echo -e "${YELLOW}[*] Findings: findings_registry.tsv${NC}"
    echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
    echo
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    f_container_main "$@"
fi