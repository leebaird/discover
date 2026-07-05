# Cloud Scanner shared library — sourced by dev/cloud-scanner.sh
#
# Output policy: all artifacts live under \$HOME/data/cloud-scan_*/ (or --output-dir).
# Never writes to Discover recon report paths (\$NAME, pages/*.htm, report.sh).

CLOUD_SCANNER_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLOUD_SCAN_MODE="${CLOUD_SCAN_MODE:-full}"
CLOUD_PROVIDERS="${CLOUD_PROVIDERS:-}"
CLOUD_RESUME_DIR=""

# Sensitive ingress ports for security-group / NSG highlighting
CLOUD_SENSITIVE_PORTS=(22 3389 3306 5432 6379 9200 27017 8080 8443)

f_cloud_init_scan(){
    local resuming="${1:-0}"
    CLOUD_SCAN_LOG="${OUTPUT_DIR}/scan.log"
    CLOUD_CHECKPOINT_DIR="${OUTPUT_DIR}/.checkpoint"
    CLOUD_FINDINGS_FILE="${OUTPUT_DIR}/findings_registry.tsv"
    CLOUD_POLICY_CACHE="${OUTPUT_DIR}/.policy_cache"

    mkdir -p "$CLOUD_CHECKPOINT_DIR" "$CLOUD_POLICY_CACHE"
    touch "$CLOUD_SCAN_LOG"

    if [ "$resuming" = "1" ] && [ -s "$CLOUD_FINDINGS_FILE" ]; then
        :
    else
        printf '%s\n' 'severity	provider	service	resource	check	detail	evidence' > "$CLOUD_FINDINGS_FILE"
    fi

    {
        echo "=== Cloud scan started $(date -Iseconds) ==="
        echo "Mode: $CLOUD_SCAN_MODE"
        echo "Providers: ${CLOUD_PROVIDERS:-all}"
        echo "Output: $OUTPUT_DIR"
    } >> "$CLOUD_SCAN_LOG"
}

f_cloud_log(){
    echo "[$(date -Iseconds)] $*" >> "$CLOUD_SCAN_LOG"
}

f_cloud_should_run_phase(){
    local phase="$1"
    [ -f "${CLOUD_CHECKPOINT_DIR}/${phase}.done" ] && return 1
    return 0
}

f_cloud_mark_phase(){
    touch "${CLOUD_CHECKPOINT_DIR}/$1.done"
    f_cloud_log "Phase completed: $1"
}

f_cloud_record_finding(){
    local severity="$1" provider="$2" service="$3" resource="$4" check="$5" detail="$6" evidence="$7"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$severity" "$provider" "$service" "$resource" "$check" "$detail" "$evidence" >> "$CLOUD_FINDINGS_FILE"
    f_cloud_log "FINDING [$severity] $provider/$service $resource — $check: $detail"
}

f_cloud_count_findings(){
    local severity="${1:-}" provider="${2:-}"
    awk -F'\t' -v sev="$severity" -v prov="$provider" '
        NR > 1 {
            if (sev != "" && $1 != sev) next
            if (prov != "" && $2 != prov) next
            n++
        }
        END { print n + 0 }
    ' "$CLOUD_FINDINGS_FILE"
}

f_cloud_port_sensitive(){
    local port="$1"
    local p
    for p in "${CLOUD_SENSITIVE_PORTS[@]}"; do
        [ "$port" = "$p" ] && return 0
    done
    return 1
}

# Cache IAM policy version JSON by ARN basename
f_cloud_cache_policy_version(){
    local policy_arn="$1" outdir="$2"
    local base version_file default_version
    base=$(basename "$policy_arn")
    version_file="${outdir}/${base}_default.json"
    [ -s "$version_file" ] && { echo "$version_file"; return 0; }

    aws iam get-policy --policy-arn "$policy_arn" > "${outdir}/${base}.json" 2>>"$CLOUD_SCAN_LOG" || return 1
    default_version=$(jq -r '.Policy.DefaultVersionId // empty' "${outdir}/${base}.json" 2>/dev/null)
    [ -n "$default_version" ] || return 1
    aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$default_version" \
        > "$version_file" 2>>"$CLOUD_SCAN_LOG" || return 1
    echo "$version_file"
}

f_cloud_policy_is_admin_document(){
    local version_file="$1"
    jq -e '
        .PolicyVersion.Document.Statement[]?
        | select(.Effect == "Allow")
        | select(
            (.Action == "*" or ((.Action | type) == "array" and (.Action | index("*") != null)))
            and (.Resource == "*" or ((.Resource | type) == "array" and (.Resource | index("*") != null)))
          )
    ' "$version_file" &>/dev/null
}

f_cloud_aws_s3_policy_jq(){
    local policy_file="$1"
    local jq_filter="$2"
    jq -e "(.Policy | fromjson? // .) | $jq_filter" "$policy_file" &>/dev/null
}

f_cloud_aws_bucket_cloudtrail_logged(){
    local bucket="$1"
    local trail selectors_file
    while read -r trail; do
        [ -z "$trail" ] && continue
        selectors_file="$OUTPUT_DIR/aws/cloudtrail/${trail}_selectors.json"
        [ -f "$selectors_file" ] || continue
        if jq -e --arg bucket "$bucket" '
            .EventSelectors[]?
            | .DataResources[]?
            | select(.Type == "AWS::S3::Object")
            | .Values[]?
            | select(test("arn:aws:s3:::" + $bucket + "(/|$)"))
        ' "$selectors_file" &>/dev/null; then
            return 0
        fi
    done < <(jq -r '.Trails[].Name' "$OUTPUT_DIR/aws/cloudtrail/trails.json" 2>/dev/null)
    return 1
}

f_cloud_aws_wait_credential_report(){
    local csv_out="$1"
    local max_wait="${2:-120}"
    local elapsed=0 interval=3

    aws iam generate-credential-report >>"$CLOUD_SCAN_LOG" 2>&1 || true
    while [ "$elapsed" -lt "$max_wait" ]; do
        if aws iam get-credential-report --query 'Content' --output text 2>>"$CLOUD_SCAN_LOG" | base64 -d > "$csv_out" 2>/dev/null; then
            if [ -s "$csv_out" ] && ! grep -q '<Error>' "$csv_out" 2>/dev/null; then
                return 0
            fi
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
        f_cloud_log "Waiting for IAM credential report (${elapsed}s)..."
    done
    return 1
}

f_cloud_write_findings_json(){
    local stamp="$1"
    local json_file="${OUTPUT_DIR}/findings.json"
    local findings crit high warn info total

    crit=$(f_cloud_count_findings critical)
    high=$(f_cloud_count_findings high)
    warn=$(f_cloud_count_findings warning)
    info=$(f_cloud_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$CLOUD_FINDINGS_FILE")

    if [ "$total" -gt 0 ]; then
        findings=$(tail -n +2 "$CLOUD_FINDINGS_FILE" | jq -R -s '
            split("\n")
            | map(select(length > 0))
            | map(split("\t"))
            | map({
                severity: .[0],
                provider: .[1],
                service: .[2],
                resource: .[3],
                check: .[4],
                detail: .[5],
                evidence: (if length > 6 then .[6] else "" end)
            })
        ')
    else
        findings='[]'
    fi

    jq -n \
        --arg scanner "cloud-scanner" \
        --arg generated "$stamp" \
        --arg mode "$CLOUD_SCAN_MODE" \
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

f_cloud_generate_reports(){
    local stamp
    stamp=$(date -Iseconds)
    local crit high warn info total
    crit=$(f_cloud_count_findings critical)
    high=$(f_cloud_count_findings high)
    warn=$(f_cloud_count_findings warning)
    info=$(f_cloud_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$CLOUD_FINDINGS_FILE")

    cat > "${OUTPUT_DIR}/report.txt" <<EOF
Cloud Security Scanner Report
=============================
Generated: $stamp
Mode:      $CLOUD_SCAN_MODE
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
        printf "  [%s] %s / %s — %s\n", $1, $2, $3, $4
        printf "    Check: %s\n", $5
        printf "    Detail: %s\n", $6
        if ($7 != "") printf "    Evidence: %s\n", $7
        printf "\n"
    }' "$CLOUD_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.txt"

    cat > "${OUTPUT_DIR}/report.md" <<EOF
# Cloud Security Scanner Report

| Field | Value |
|-------|-------|
| Generated | $stamp |
| Mode | $CLOUD_SCAN_MODE |
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
        printf "### [%s] %s — %s (%s)\n", $1, $4, $5, $3
        printf "- **Provider:** %s\n", $2
        printf "- **Detail:** %s\n", $6
        if ($7 != "") printf "- **Evidence:** \`%s\`\n", $7
        printf "\n"
    }' "$CLOUD_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.md"

    echo "Scan log: \`${CLOUD_SCAN_LOG}\`" >> "${OUTPUT_DIR}/report.md"
    echo "Findings JSON: \`findings.json\`" >> "${OUTPUT_DIR}/report.md"

    f_cloud_write_findings_json "$stamp"
    f_cloud_log "Reports written. Findings: $total (findings.json)"
}

f_cloud_usage(){
    cat <<EOF
Usage: cloud-scanner.sh [options]

Options:
  --aws                 Run AWS checks only
  --azure               Run Azure checks only
  --gcp                 Run GCP checks only
  --quick               High-severity / exposure checks only
  --full                All checks (default)
  --output-dir DIR      Use specific output directory
  --resume DIR          Resume scan using existing output directory
  -h, --help            Show this help

Interactive menu runs when no provider flags are set and stdin is a TTY.

Environment: CLOUD_SCAN_MODE=quick|full
EOF
}

f_cloud_parse_cli(){
    CLOUD_PROVIDERS=""
    CLOUD_CLI_PROVIDERS=0
    CLOUD_OUTPUT_DIR=""
    CLOUD_RESUME_DIR=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --aws) CLOUD_PROVIDERS="${CLOUD_PROVIDERS} aws"; CLOUD_CLI_PROVIDERS=1; shift ;;
            --azure) CLOUD_PROVIDERS="${CLOUD_PROVIDERS} azure"; CLOUD_CLI_PROVIDERS=1; shift ;;
            --gcp) CLOUD_PROVIDERS="${CLOUD_PROVIDERS} gcp"; CLOUD_CLI_PROVIDERS=1; shift ;;
            --quick) CLOUD_SCAN_MODE="quick"; shift ;;
            --full) CLOUD_SCAN_MODE="full"; shift ;;
            --output-dir) CLOUD_OUTPUT_DIR="$2"; shift 2 ;;
            --resume) CLOUD_RESUME_DIR="$2"; shift 2 ;;
            -h|--help) f_cloud_usage; exit 0 ;;
            *) echo "Unknown option: $1"; f_cloud_usage; exit 1 ;;
        esac
    done

    CLOUD_PROVIDERS="${CLOUD_PROVIDERS# }"
}

f_cloud_setup_output(){
    if [ -n "$CLOUD_RESUME_DIR" ]; then
        OUTPUT_DIR="$CLOUD_RESUME_DIR"
        [ -d "$OUTPUT_DIR" ] || { echo -e "${RED}[!] Resume directory not found: $OUTPUT_DIR${NC}"; exit 1; }
        f_cloud_init_scan 1
        return 0
    fi

    if [ -n "$CLOUD_OUTPUT_DIR" ]; then
        OUTPUT_DIR="$CLOUD_OUTPUT_DIR"
    else
        OUTPUT_DIR="$HOME/data/cloud-scan_$(date +%Y%m%d-%H%M)"
    fi
    mkdir -p "$OUTPUT_DIR" || { echo -e "${RED}[!] Cannot create $OUTPUT_DIR${NC}"; exit 1; }
    # Isolated from Discover recon \$NAME / report.sh — scanner-owned directory only.
    f_cloud_init_scan 0
}