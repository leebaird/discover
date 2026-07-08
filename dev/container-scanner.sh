#!/usr/bin/env bash

# by ibrahimsql - Container Security Scanner
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Dev menu scanner: writes under $HOME/data/container-scan_*/.
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

CONTAINER_SCANNER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/menu.sh
source "${CONTAINER_SCANNER_ROOT}/lib/menu.sh"
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
    local k8s_warn=0

    case "$CONTAINER_SCAN_TYPES" in
        docker-images|docker-containers|all)
            f_container_docker_available || return 1
            ;;
    esac
    case "$CONTAINER_SCAN_TYPES" in
        kubernetes)
            f_container_k8s_available || return 1
            ;;
    esac

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
            if f_container_k8s_available; then
                f_scan_kubernetes "$OUTPUT_DIR"
            else
                k8s_warn=1
            fi
            ;;
        *)
            echo -e "${RED}[!] Unknown scan type: $CONTAINER_SCAN_TYPES${NC}"
            f_container_usage
            return 1
            ;;
    esac

    f_container_generate_reports
    echo
    echo -e "${YELLOW}[*] Results: ${OUTPUT_DIR}/${NC}"
    echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
    echo -e "${YELLOW}[*] Findings: findings_registry.tsv${NC}"
    echo -e "${YELLOW}[*] Scan log: ${OUTPUT_DIR}/scan.log${NC}"
    echo

    if [ "$k8s_warn" -eq 1 ]; then
        echo -e "${YELLOW}[!] Kubernetes scan was skipped (no cluster connection).${NC}"
        echo
    fi

    return 0
}

f_container_interactive_menu(){
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
    f_dev_read_choice CHOICE
    f_dev_menu_validate "$CHOICE"

    case "$CHOICE" in
        1) CONTAINER_SCAN_TYPES="docker-images" ;;
        2) CONTAINER_SCAN_TYPES="docker-containers" ;;
        3) CONTAINER_SCAN_TYPES="kubernetes" ;;
        4) CONTAINER_SCAN_TYPES="all" ;;
        5) f_dev_previous ;;
        *) f_dev_die "Invalid choice or entry." ;;
    esac

    echo "Scan mode:"
    echo "1. Quick (high-severity / running workloads)"
    echo "2. Full (comprehensive)"
    f_dev_read_scan_mode CONTAINER_SCAN_MODE

    f_container_setup_output
    echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
    echo -e "${YELLOW}[*] Mode: $CONTAINER_SCAN_MODE | Scan: $CONTAINER_SCAN_TYPES${NC}"
    if ! f_container_run_scans; then
        rm -rf "$OUTPUT_DIR" 2>/dev/null
        echo
        sleep 2
        exit 3
    fi
    return 0
}

f_container_main(){
    f_container_parse_cli "$@"

    if [ "$CONTAINER_CLI_INVOKED" = "1" ] || [ -n "$CONTAINER_RESUME_DIR" ]; then
        f_container_setup_output
        clear
        f_banner
        echo -e "${BLUE}Container Security Scanner${NC}"
        echo -e "${YELLOW}[*] Output: $OUTPUT_DIR${NC}"
        echo -e "${YELLOW}[*] Mode: $CONTAINER_SCAN_MODE | Scan: $CONTAINER_SCAN_TYPES${NC}"
        if ! f_container_run_scans; then
            rm -rf "$OUTPUT_DIR" 2>/dev/null
            echo
            sleep 2
            exit 3
        fi
        return 0
    fi

    f_container_interactive_menu
}

f_container_main "$@"