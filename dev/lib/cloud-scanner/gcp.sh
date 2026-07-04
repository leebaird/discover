# GCP cloud security checks — sourced by dev/cloud-scanner.sh

f_gcp_auth_check(){
    if ! gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>>"$CLOUD_SCAN_LOG" | grep -q .; then
        echo -e "${RED}[!] GCP authentication failed. Run 'gcloud auth login' and retry.${NC}"
        return 1
    fi
    return 0
}

f_gcp_phase_projects(){
    f_cloud_should_run_phase gcp_projects || return 0
    echo -e "${BLUE}[*] Gathering GCP project context.${NC}"
    mkdir -p "$OUTPUT_DIR/gcp"

    gcloud projects list --format=json > "$OUTPUT_DIR/gcp/projects.json" 2>>"$CLOUD_SCAN_LOG" || true
    f_cloud_mark_phase gcp_projects
}

f_gcp_scan_project(){
    local project="$1"
    [ -z "$project" ] && return 0

    echo -e "${YELLOW}[*] Scanning GCP project: $project${NC}"
    mkdir -p "$OUTPUT_DIR/gcp/projects/$project/iam"

    gcloud storage buckets list --project="$project" --format=json \
        > "$OUTPUT_DIR/gcp/projects/$project/buckets.json" 2>>"$CLOUD_SCAN_LOG" || true

    jq -r '.[]?.name' "$OUTPUT_DIR/gcp/projects/$project/buckets.json" 2>/dev/null | while read -r bucket; do
        [ -z "$bucket" ] && continue
        local short="${bucket##*/}"
        gcloud storage buckets get-iam-policy "$bucket" --format=json \
            > "$OUTPUT_DIR/gcp/projects/$project/iam/${short}-iam.json" 2>>"$CLOUD_SCAN_LOG" || true
        if jq -e '
            .bindings[]?
            | select(.members[]? == "allUsers" or .members[]? == "allAuthenticatedUsers")
        ' "$OUTPUT_DIR/gcp/projects/$project/iam/${short}-iam.json" &>/dev/null; then
            f_cloud_record_finding high gcp storage "$short" public-iam \
                "Bucket IAM grants allUsers or allAuthenticatedUsers" \
                "$OUTPUT_DIR/gcp/projects/$project/iam/${short}-iam.json"
        fi
    done

    gcloud compute firewall-rules list --project="$project" --format=json \
        > "$OUTPUT_DIR/gcp/projects/$project/firewall_rules.json" 2>>"$CLOUD_SCAN_LOG" || true

    jq -r '
        .[]? as $rule
        | select($rule.disabled != true and $rule.direction == "INGRESS")
        | select($rule.sourceRanges[]? == "0.0.0.0/0")
        | $rule.name + "\t" + (($rule.allowed[]?.ports[]?) // "all")
    ' "$OUTPUT_DIR/gcp/projects/$project/firewall_rules.json" 2>/dev/null | while IFS=$'\t' read -r rule port; do
        [ -z "$rule" ] && continue
        local sev=warning
        f_cloud_port_sensitive "$port" && sev=high
        f_cloud_record_finding "$sev" gcp network "$rule" firewall-ingress-open \
            "Ingress firewall allows 0.0.0.0/0 on port ${port:-all}" \
            "$OUTPUT_DIR/gcp/projects/$project/firewall_rules.json"
    done

    gcloud projects get-iam-policy "$project" --format=json \
        > "$OUTPUT_DIR/gcp/projects/$project/iam_policy.json" 2>>"$CLOUD_SCAN_LOG" || true
    jq -r '
        .bindings[]?
        | select(.role == "roles/owner" or .role == "roles/editor")
        | .role + ": " + (.members | join(", "))
    ' "$OUTPUT_DIR/gcp/projects/$project/iam_policy.json" 2>/dev/null | while read -r binding; do
        [ -z "$binding" ] && continue
        f_cloud_record_finding warning gcp iam "$project" sensitive-role \
            "$binding" "$OUTPUT_DIR/gcp/projects/$project/iam_policy.json"
    done

    if [ "$CLOUD_SCAN_MODE" = "full" ]; then
        gcloud compute instances list --project="$project" --format=json \
            > "$OUTPUT_DIR/gcp/projects/$project/instances.json" 2>>"$CLOUD_SCAN_LOG" || true
        jq -r '.[]? | select(.networkInterfaces[]?.accessConfigs[]?.natIP != null) | .name' \
            "$OUTPUT_DIR/gcp/projects/$project/instances.json" 2>/dev/null | while read -r inst; do
            [ -z "$inst" ] && continue
            f_cloud_record_finding info gcp compute "$inst" external-ip \
                "Instance has external IP" "$OUTPUT_DIR/gcp/projects/$project/instances.json"
        done
    fi
}

f_gcp_phase_resources(){
    f_cloud_should_run_phase gcp_resources || return 0
    echo -e "${BLUE}[*] Checking GCP resources.${NC}"

    local active_project projects=()
    active_project=$(gcloud config get-value project 2>/dev/null)
    echo "${active_project:-}" > "$OUTPUT_DIR/gcp/active_project.txt"

    if [ "$CLOUD_SCAN_MODE" = "full" ] && [ -s "$OUTPUT_DIR/gcp/projects.json" ]; then
        mapfile -t projects < <(jq -r '.[].projectId' "$OUTPUT_DIR/gcp/projects.json" 2>/dev/null)
    elif [ -n "$active_project" ]; then
        projects=("$active_project")
    fi

    if [ ${#projects[@]} -eq 0 ]; then
        f_cloud_record_finding warning gcp project "" no-active-project \
            "No active GCP project; set with gcloud config set project PROJECT_ID" ""
        f_cloud_mark_phase gcp_resources
        return 0
    fi

    local proj
    for proj in "${projects[@]}"; do
        f_gcp_scan_project "$proj"
    done

    f_cloud_mark_phase gcp_resources
}

f_gcp_security_check(){
    echo
    echo -e "${BLUE}[*] Performing GCP security checks (mode: $CLOUD_SCAN_MODE).${NC}"
    mkdir -p "$OUTPUT_DIR/gcp"

    f_gcp_auth_check || return 1
    f_gcp_phase_projects
    f_gcp_phase_resources

    echo -e "${YELLOW}[*] GCP checks complete.${NC}"
    return 0
}