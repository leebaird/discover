# Container Scanner shared library — sourced by dev/container-scanner.sh
#
# Output policy: all artifacts live under $HOME/data/container-scan_*/ (or --output-dir).
# Never writes to Discover recon report paths ($NAME, pages/*.htm, report.sh).

CONTAINER_SCANNER_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONTAINER_SCAN_MODE="${CONTAINER_SCAN_MODE:-full}"
CONTAINER_SCAN_TYPES="${CONTAINER_SCAN_TYPES:-all}"
CONTAINER_OUTPUT_DIR="${CONTAINER_OUTPUT_DIR:-}"
CONTAINER_RESUME_DIR="${CONTAINER_RESUME_DIR:-}"
CONTAINER_DOCKERFILE_ROOT="${CONTAINER_DOCKERFILE_ROOT:-}"
CONTAINER_INCLUDE_NS="${CONTAINER_INCLUDE_NS:-}"
CONTAINER_EXCLUDE_NS="${CONTAINER_EXCLUDE_NS:-kube-system,kube-public,kube-node-lease}"
CONTAINER_TRIVY_JOBS="${CONTAINER_TRIVY_JOBS:-4}"
CONTAINER_USE_MENU="${CONTAINER_USE_MENU:-0}"

CONTAINER_SCAN_LOG=""
CONTAINER_CHECKPOINT_DIR=""
CONTAINER_FINDINGS_FILE=""
CONTAINER_IMAGE_CHECKPOINT_DIR=""

# Wildcard RBAC: verbs, resources, and apiGroups must all be "*" within the same rule
_CONTAINER_RBAC_JQ_DEF='def rule_is_wildcard: ((.verbs//[])|index("*")!=null) and ((.resources//[])|index("*")!=null) and ((.apiGroups//[])|index("*")!=null); def has_wildcard_rule: any(.rules[]?; rule_is_wildcard);'

# Deprecated Kubernetes API versions (extend as needed)
_CONTAINER_DEPRECATED_API_VERSIONS=(
    "extensions/v1beta1"
    "networking.k8s.io/v1beta1"
    "policy/v1beta1"
    "batch/v1beta1"
    "apps/v1beta1"
    "apps/v1beta2"
)

# Dangerous capability names in pods
_CONTAINER_DANGEROUS_CAPS=(SYS_ADMIN NET_ADMIN ALL SYS_PTRACE DAC_READ_SEARCH)

f_container_now(){
    date -Iseconds
}

f_container_slug(){
    local s
    s=$(echo "$1" | tr -c 'A-Za-z0-9._-' '_' | sed 's/^_\+//;s/_$//')
    [ -n "$s" ] || s="unknown"
    echo "$s"
}

f_container_image_file_id(){
    local image="$1" hash
    hash=$(printf '%s' "$image" | sha256sum | awk '{print substr($1,1,12)}')
    echo "${hash}_$(printf '%s' "$image" | tr '/:' '_')"
}

f_container_jq_count(){
    local file="$1" filter="$2"
    [ -s "$file" ] || { echo 0; return; }
    jq -r "$filter" "$file" 2>/dev/null || echo 0
}

f_container_trivy_json_valid(){
    local file="$1"
    [ -s "$file" ] && jq -e '.Results | type == "array"' "$file" >/dev/null 2>&1
}

# Unified risk score from severity-weighted issue counts (1–10)
f_container_risk_score(){
    local crit="${1:-0}" high="${2:-0}" med="${3:-0}" low="${4:-0}"
    local total=$((crit + high + med + low))
    [ "$total" -eq 0 ] && { echo 0; return; }
    local score=$(( (crit * 10 + high * 7 + med * 4 + low * 1) / total ))
    [ "$score" -gt 10 ] && score=10
    [ "$score" -lt 1 ] && score=1
    echo "$score"
}

f_container_init_scan(){
    local resuming="${1:-0}"
    CONTAINER_SCAN_LOG="${OUTPUT_DIR}/scan.log"
    CONTAINER_CHECKPOINT_DIR="${OUTPUT_DIR}/.checkpoint"
    CONTAINER_IMAGE_CHECKPOINT_DIR="${CONTAINER_CHECKPOINT_DIR}/images"
    CONTAINER_FINDINGS_FILE="${OUTPUT_DIR}/findings_registry.tsv"

    mkdir -p "$CONTAINER_CHECKPOINT_DIR" "$CONTAINER_IMAGE_CHECKPOINT_DIR"
    touch "$CONTAINER_SCAN_LOG"

    if [ "$resuming" = "1" ] && [ -s "$CONTAINER_FINDINGS_FILE" ]; then
        :
    else
        printf '%s\n' 'severity	domain	resource	check	detail	evidence' > "$CONTAINER_FINDINGS_FILE"
    fi

    {
        echo "=== Container scan started $(f_container_now) ==="
        echo "Mode: $CONTAINER_SCAN_MODE"
        echo "Scan types: $CONTAINER_SCAN_TYPES"
        echo "Output: $OUTPUT_DIR"
    } >> "$CONTAINER_SCAN_LOG"
}

f_container_log(){
    echo "[$(f_container_now)] $*" >> "$CONTAINER_SCAN_LOG"
}

f_container_should_run_phase(){
    local phase="$1"
    [ -f "${CONTAINER_CHECKPOINT_DIR}/${phase}.done" ] && return 1
    return 0
}

f_container_mark_phase(){
    touch "${CONTAINER_CHECKPOINT_DIR}/$1.done"
    f_container_log "Phase completed: $1"
}

f_container_image_scanned(){
    local image_id="$1"
    [ -f "${CONTAINER_IMAGE_CHECKPOINT_DIR}/${image_id}.done" ]
}

f_container_mark_image_scanned(){
    touch "${CONTAINER_IMAGE_CHECKPOINT_DIR}/$1.done"
}

f_container_record_finding(){
    local severity="$1" domain="$2" resource="$3" check="$4" detail="$5" evidence="$6"
    local lockfile="${OUTPUT_DIR}/.findings.lock"
    (
        flock -x 9
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$severity" "$domain" "$resource" "$check" "$detail" "$evidence" >> "$CONTAINER_FINDINGS_FILE"
        echo "[$(f_container_now)] FINDING [$severity] $domain/$resource — $check: $detail" >> "$CONTAINER_SCAN_LOG"
    ) 9>"$lockfile"
}

f_container_count_findings(){
    local severity="${1:-}" domain="${2:-}"
    awk -F'\t' -v sev="$severity" -v dom="$domain" '
        NR > 1 {
            if (sev != "" && $1 != sev) next
            if (dom != "" && $2 != dom) next
            n++
        }
        END { print n + 0 }
    ' "$CONTAINER_FINDINGS_FILE"
}

f_container_ns_should_scan(){
    local ns="$1" inc exc item
    if [ -n "$CONTAINER_INCLUDE_NS" ]; then
        IFS=',' read -ra _inc <<< "$CONTAINER_INCLUDE_NS"
        for item in "${_inc[@]}"; do
            item="${item#"${item%%[![:space:]]*}"}"
            item="${item%"${item##*[![:space:]]}"}"
            [ "$ns" = "$item" ] && return 0
        done
        return 1
    fi
    IFS=',' read -ra _exc <<< "$CONTAINER_EXCLUDE_NS"
    for item in "${_exc[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [ -n "$item" ] && [ "$ns" = "$item" ] && return 1
    done
    return 0
}

f_container_k8s_version_thresholds(){
    local eol=33 current=35
    if command -v curl >/dev/null 2>&1; then
        local api_json
        api_json=$(curl -fsS --max-time 5 "https://endoflife.date/api/v1/products/kubernetes/" 2>/dev/null) || api_json=""
        if [ -n "$api_json" ]; then
            local latest_eol latest_supported
            latest_eol=$(echo "$api_json" | jq -r '[.result.releases[] | select(.isEol == true) | .name | ltrimstr("1.") | tonumber] | max // empty' 2>/dev/null)
            latest_supported=$(echo "$api_json" | jq -r '[.result.releases[] | select(.isEol == false) | .name | ltrimstr("1.") | tonumber] | max // empty' 2>/dev/null)
            [ -n "$latest_eol" ] && eol="$latest_eol"
            [ -n "$latest_supported" ] && current="$latest_supported"
            f_container_log "K8s version policy from endoflife.date: EOL<=${eol} current>=${current}"
        fi
    fi
    echo "$eol $current"
}

f_container_check_deps(){
    local need_docker=0 need_kubectl=0 need_trivy=0
    local missing=()

    case "$CONTAINER_SCAN_TYPES" in
        docker-images|docker-containers|all) need_docker=1; need_trivy=1 ;;
    esac
    case "$CONTAINER_SCAN_TYPES" in
        kubernetes|all) need_kubectl=1 ;;
    esac

    command -v jq >/dev/null 2>&1 || missing+=("jq")
    command -v numfmt >/dev/null 2>&1 || missing+=("numfmt")

    if [ "$need_docker" -eq 1 ] && ! command -v docker >/dev/null 2>&1; then missing+=("docker"); fi
    if [ "$need_kubectl" -eq 1 ] && ! command -v kubectl >/dev/null 2>&1; then missing+=("kubectl"); fi
    if [ "$need_trivy" -eq 1 ] && ! command -v trivy >/dev/null 2>&1; then missing+=("trivy"); fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo
        echo -e "${RED}[!] Missing required tools: ${missing[*]}${NC}"
        echo -e "${YELLOW}[*] Install dependencies (Discover Update installs trivy, jq, etc.) and retry.${NC}"
        echo
        exit 1
    fi
    : "$need_docker" "$need_kubectl" "$need_trivy"
}

f_container_setup_output(){
    if [ -n "$CONTAINER_RESUME_DIR" ]; then
        OUTPUT_DIR="$CONTAINER_RESUME_DIR"
        [ -d "$OUTPUT_DIR" ] || { echo -e "${RED}[!] Resume directory not found: $OUTPUT_DIR${NC}"; exit 1; }
        f_container_init_scan 1
        return 0
    fi

    if [ -n "$CONTAINER_OUTPUT_DIR" ]; then
        OUTPUT_DIR="$CONTAINER_OUTPUT_DIR"
    else
        OUTPUT_DIR="$HOME/data/container-scan_$(date +%Y%m%d-%H%M)"
    fi
    mkdir -p "$OUTPUT_DIR" || { echo -e "${RED}[!] Cannot create $OUTPUT_DIR${NC}"; exit 1; }
    f_container_init_scan 0
}

f_container_write_findings_json(){
    local stamp="$1"
    local json_file="${OUTPUT_DIR}/findings.json"
    local findings crit high warn info total

    crit=$(f_container_count_findings critical)
    high=$(f_container_count_findings high)
    warn=$(f_container_count_findings warning)
    info=$(f_container_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$CONTAINER_FINDINGS_FILE")

    if [ "$total" -gt 0 ]; then
        findings=$(tail -n +2 "$CONTAINER_FINDINGS_FILE" | jq -R -s '
            split("\n")
            | map(select(length > 0))
            | map(split("\t"))
            | map({
                severity: .[0],
                domain: .[1],
                resource: .[2],
                check: .[3],
                detail: .[4],
                evidence: (if length > 5 then .[5] else "" end)
            })
        ')
    else
        findings='[]'
    fi

    jq -n \
        --arg scanner "container-scanner" \
        --arg generated "$stamp" \
        --arg mode "$CONTAINER_SCAN_MODE" \
        --arg scan_types "$CONTAINER_SCAN_TYPES" \
        --arg output_dir "$OUTPUT_DIR" \
        --argjson critical "$crit" \
        --argjson high "$high" \
        --argjson warning "$warn" \
        --argjson info "$info" \
        --argjson total "$total" \
        --argjson findings "$findings" \
        '{
            scanner: $scanner,
            generated: $generated,
            mode: $mode,
            scan_types: $scan_types,
            output_dir: $output_dir,
            summary: {
                critical: $critical,
                high: $high,
                warning: $warning,
                info: $info,
                total: $total
            },
            findings: $findings
        }' > "$json_file"
}

f_container_generate_reports(){
    local stamp
    stamp=$(f_container_now)
    local crit high warn info total
    crit=$(f_container_count_findings critical)
    high=$(f_container_count_findings high)
    warn=$(f_container_count_findings warning)
    info=$(f_container_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$CONTAINER_FINDINGS_FILE")

    cat > "${OUTPUT_DIR}/report.txt" <<EOF
Container Security Scanner Report
=================================
Generated: $stamp
Mode:      $CONTAINER_SCAN_MODE
Scan:      $CONTAINER_SCAN_TYPES
Output:    $OUTPUT_DIR

Finding counts
--------------
Critical: $crit
High:     $high
Warning:  $warn
Info:     $info
Total:    $total

Detailed findings
-----------------
EOF

    awk -F'\t' 'NR > 1 {
        printf "  [%s] %s — %s\n", $1, $2, $3
        printf "    Check: %s\n", $4
        printf "    Detail: %s\n", $5
        if ($6 != "") printf "    Evidence: %s\n", $6
        printf "\n"
    }' "$CONTAINER_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.txt"

    cat > "${OUTPUT_DIR}/report.md" <<EOF
# Container Security Scanner Report

| Field | Value |
|-------|-------|
| Generated | $stamp |
| Mode | $CONTAINER_SCAN_MODE |
| Scan types | $CONTAINER_SCAN_TYPES |
| Output | \`$OUTPUT_DIR\` |

## Summary

| Severity | Count |
|----------|------:|
| Critical | $crit |
| High | $high |
| Warning | $warn |
| Info | $info |
| **Total** | **$total** |

## Findings

EOF

    awk -F'\t' 'NR > 1 {
        printf "### [%s] %s — %s\n", $1, $3, $4
        printf "- **Domain:** %s\n", $2
        printf "- **Detail:** %s\n", $5
        if ($6 != "") printf "- **Evidence:** \`%s\`\n", $6
        printf "\n"
    }' "$CONTAINER_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.md"

    # Legacy consolidated report (enriched)
    f_container_generate_legacy_report "$stamp" > "${OUTPUT_DIR}/container_security_report.txt"

    echo "Scan log: \`${CONTAINER_SCAN_LOG}\`" >> "${OUTPUT_DIR}/report.md"
    echo "Findings JSON: \`findings.json\`" >> "${OUTPUT_DIR}/report.md"
    echo "Legacy report: \`container_security_report.txt\`" >> "${OUTPUT_DIR}/report.md"

    f_container_write_findings_json "$stamp"
    f_container_log "Reports written. Findings: $total (findings.json)"
}

f_container_generate_legacy_report(){
    local stamp="$1"
    {
        echo "Container Security Scan Report"
        echo "=============================="
        echo "Generated: $stamp"
        echo "Mode: $CONTAINER_SCAN_MODE"
        echo "Output: $OUTPUT_DIR"
        echo
        echo "Finding Summary: critical=$(f_container_count_findings critical) high=$(f_container_count_findings high) warning=$(f_container_count_findings warning) info=$(f_container_count_findings info)"
        echo
        echo "1. Docker Image Analysis"
        echo "----------------------"
        if [ -f "$OUTPUT_DIR/docker/image_list.txt" ]; then
            echo "Total Docker Images: $(wc -l < "$OUTPUT_DIR/docker/image_list.txt")"
            if [ -f "$OUTPUT_DIR/docker/vulnerable_images.txt" ] && [ -s "$OUTPUT_DIR/docker/vulnerable_images.txt" ]; then
                echo "WARNING: Images with HIGH or CRITICAL vulnerabilities:"
                cat "$OUTPUT_DIR/docker/vulnerable_images.txt"
            else
                echo "No images with HIGH or CRITICAL vulnerabilities detected."
            fi
            if [ -f "$OUTPUT_DIR/docker/trivy_failed_images.txt" ] && [ -s "$OUTPUT_DIR/docker/trivy_failed_images.txt" ]; then
                echo "WARNING: Trivy scan failures:"
                cat "$OUTPUT_DIR/docker/trivy_failed_images.txt"
                echo "(see docker/trivy_errors.log)"
            fi
            if [ -f "$OUTPUT_DIR/docker/dockerfile_risk_scores.txt" ] && [ -s "$OUTPUT_DIR/docker/dockerfile_risk_scores.txt" ]; then
                echo "Top risky Dockerfiles:"
                sort -t'|' -k2,2nr "$OUTPUT_DIR/docker/dockerfile_risk_scores.txt" | head -5
            fi
        else
            echo "No Docker image scan performed."
        fi
        echo
        echo "2. Docker Container Analysis"
        echo "--------------------------"
        if [ -f "$OUTPUT_DIR/docker/container_list.txt" ]; then
            echo "Total Docker Containers: $(wc -l < "$OUTPUT_DIR/docker/container_list.txt")"
            if [ -f "$OUTPUT_DIR/docker/privileged_containers.txt" ] && [ -s "$OUTPUT_DIR/docker/privileged_containers.txt" ]; then
                echo "CRITICAL: Privileged containers:"
                cat "$OUTPUT_DIR/docker/privileged_containers.txt"
            fi
            if [ -f "$OUTPUT_DIR/docker/container_risk_scores.txt" ] && [ -s "$OUTPUT_DIR/docker/container_risk_scores.txt" ]; then
                echo "Top risky containers:"
                sort -t'|' -k3,3nr "$OUTPUT_DIR/docker/container_risk_scores.txt" | head -5
            fi
        else
            echo "No Docker container scan performed."
        fi
        echo
        echo "3. Kubernetes Analysis"
        echo "--------------------"
        if [ -f "$OUTPUT_DIR/kubernetes/resources/namespace_list.txt" ] && [ -s "$OUTPUT_DIR/kubernetes/resources/namespace_list.txt" ]; then
            echo "Namespaces scanned: $(wc -l < "$OUTPUT_DIR/kubernetes/resources/namespace_list.txt")"
            if [ -f "$OUTPUT_DIR/kubernetes/cluster/version_issues.txt" ] && [ -s "$OUTPUT_DIR/kubernetes/cluster/version_issues.txt" ]; then
                echo "Kubernetes version issues:"
                cat "$OUTPUT_DIR/kubernetes/cluster/version_issues.txt"
            fi
            for vuln_file in privileged_pods hostnetwork_pods hostpath_volumes root_pods insecure_capabilities deprecated_apis; do
                if [ -f "$OUTPUT_DIR/kubernetes/vulnerabilities/${vuln_file}.txt" ] && [ -s "$OUTPUT_DIR/kubernetes/vulnerabilities/${vuln_file}.txt" ]; then
                    echo "WARNING: ${vuln_file}:"
                    head -20 "$OUTPUT_DIR/kubernetes/vulnerabilities/${vuln_file}.txt" | sed 's/^/  /'
                fi
            done
            if [ -f "$OUTPUT_DIR/kubernetes/namespace_security_scores.txt" ] && [ -s "$OUTPUT_DIR/kubernetes/namespace_security_scores.txt" ]; then
                echo "Namespace security scores (lowest first):"
                sort -t'|' -k2,2n "$OUTPUT_DIR/kubernetes/namespace_security_scores.txt" | head -10
            fi
            if [ -f "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/permissive_cluster_roles.txt" ] && [ -s "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/permissive_cluster_roles.txt" ]; then
                echo "CRITICAL: Permissive cluster roles:"
                cat "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/permissive_cluster_roles.txt" | sed 's/^/  /'
            fi
        else
            echo "No Kubernetes scan performed or cluster unreachable."
        fi
        echo
        echo "See report.txt, report.md, and findings.json for structured findings."
    }
}

f_container_usage(){
    cat <<EOF
Usage: container-scanner.sh [options] [scan-type]

Scan types:
  docker-images       Scan local Docker images with Trivy
  docker-containers   Audit Docker container configurations
  kubernetes          Audit Kubernetes cluster security
  all                 All scans (default)

Options:
  --quick             High-severity / running workloads only
  --full              All checks (default)
  --output-dir DIR    Use specific output directory
  --resume DIR        Resume scan using existing output directory
  --dockerfile-root DIR   Root path for Dockerfile discovery
  --include-ns LIST   Comma-separated namespaces to scan (overrides exclude)
  --exclude-ns LIST   Comma-separated namespaces to skip (default: kube-system,...)
  --trivy-jobs N      Parallel Trivy workers (default: 4)
  --menu              Interactive scan menu (default: run scan-type directly)
  -h, --help          Show this help

Environment:
  CONTAINER_SCAN_MODE=quick|full
  CONTAINER_OUTPUT_DIR, CONTAINER_DOCKERFILE_ROOT
  CONTAINER_INCLUDE_NS, CONTAINER_EXCLUDE_NS, CONTAINER_TRIVY_JOBS
EOF
}

f_container_parse_cli(){
    CONTAINER_SCAN_TYPES="all"
    CONTAINER_OUTPUT_DIR=""
    CONTAINER_RESUME_DIR=""
    CONTAINER_DOCKERFILE_ROOT=""
    CONTAINER_INCLUDE_NS=""
    CONTAINER_EXCLUDE_NS="kube-system,kube-public,kube-node-lease"

    while [ $# -gt 0 ]; do
        case "$1" in
            --quick) CONTAINER_SCAN_MODE="quick"; shift ;;
            --full) CONTAINER_SCAN_MODE="full"; shift ;;
            --output-dir) CONTAINER_OUTPUT_DIR="$2"; shift 2 ;;
            --resume) CONTAINER_RESUME_DIR="$2"; shift 2 ;;
            --dockerfile-root) CONTAINER_DOCKERFILE_ROOT="$2"; shift 2 ;;
            --include-ns) CONTAINER_INCLUDE_NS="$2"; shift 2 ;;
            --exclude-ns) CONTAINER_EXCLUDE_NS="$2"; shift 2 ;;
            --trivy-jobs) CONTAINER_TRIVY_JOBS="$2"; shift 2 ;;
            --menu) CONTAINER_USE_MENU=1; shift ;;
            -h|--help) f_container_usage; exit 0 ;;
            docker-images|docker-containers|kubernetes|all)
                CONTAINER_SCAN_TYPES="$1"; shift ;;
            *)
                echo "Unknown option: $1"
                f_container_usage
                exit 1
                ;;
        esac
    done
}

f_container_scan_one_image(){
    local image="$1"
    local image_name trivy_json trivy_args=() scan_ok=true
    image_name=$(f_container_image_file_id "$image")
    trivy_json="$OUTPUT_DIR/docker/images/${image_name}.json"

    if f_container_image_scanned "$image_name"; then
        f_container_log "Skipping already-scanned image: $image"
        return 0
    fi

    if [ "$CONTAINER_SCAN_MODE" = "quick" ]; then
        trivy_args+=(--severity HIGH,CRITICAL)
    fi

    if ! trivy image --format json --scanners vuln,config,secret "${trivy_args[@]}" "$image" > "$trivy_json" 2>>"$OUTPUT_DIR/docker/trivy_errors.log"; then
        scan_ok=false
    elif ! f_container_trivy_json_valid "$trivy_json"; then
        scan_ok=false
    fi

    if [ "$scan_ok" = false ]; then
        grep -qxF "$image" "$OUTPUT_DIR/docker/trivy_failed_images.txt" 2>/dev/null || echo "$image" >> "$OUTPUT_DIR/docker/trivy_failed_images.txt"
        f_container_record_finding warning docker-image "$image" trivy_scan_failed \
            "Trivy scan failed or produced invalid JSON" "docker/trivy_errors.log"
        return 1
    fi

    if [ "$CONTAINER_SCAN_MODE" = "full" ]; then
        trivy image --format json --list-all-pkgs "$image" > "$OUTPUT_DIR/docker/images/${image_name}_sbom.json" 2>>"$OUTPUT_DIR/docker/trivy_errors.log" || true
    fi

    f_container_mark_image_scanned "$image_name"
    return 0
}