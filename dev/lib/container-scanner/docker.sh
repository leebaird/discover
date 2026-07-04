# Container Scanner — Docker images, containers, Dockerfiles
# Sourced by dev/container-scanner.sh

f_container_dockerfile_root(){
    echo "${CONTAINER_DOCKERFILE_ROOT:-${DISCOVER:-$CONTAINER_SCANNER_ROOT/..}}"
}

f_scan_docker_images(){
    local OUTPUT_DIR="$1"

    f_container_should_run_phase docker-images || { f_container_log "Skipping docker-images (checkpoint)"; return 0; }

    echo -e "${BLUE}[*] Starting comprehensive Docker image security scan.${NC}"
    mkdir -p "$OUTPUT_DIR/docker/images" "$OUTPUT_DIR/docker/vulnerabilities" "$OUTPUT_DIR/docker/dockerfile_analysis"

    # List all Docker images with additional metadata
    echo -e "${BLUE}[*] Collecting Docker image inventory.${NC}"
    docker images --format "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedAt}}" > "$OUTPUT_DIR/docker/image_inventory.tsv"
    docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>" > "$OUTPUT_DIR/docker/image_list.txt"

    if [ "$CONTAINER_SCAN_MODE" = "quick" ] && [ -s "$OUTPUT_DIR/docker/running_images_quick.txt" ]; then
        :
    elif [ "$CONTAINER_SCAN_MODE" = "quick" ]; then
        docker ps --format "{{.Image}}" 2>/dev/null | sort -u > "$OUTPUT_DIR/docker/running_images_quick.txt" || : > "$OUTPUT_DIR/docker/running_images_quick.txt"
        if [ -s "$OUTPUT_DIR/docker/running_images_quick.txt" ]; then
            comm -12 <(sort "$OUTPUT_DIR/docker/image_list.txt") <(sort "$OUTPUT_DIR/docker/running_images_quick.txt") > "$OUTPUT_DIR/docker/image_list_quick.txt" || cp "$OUTPUT_DIR/docker/running_images_quick.txt" "$OUTPUT_DIR/docker/image_list_quick.txt"
            mv "$OUTPUT_DIR/docker/image_list_quick.txt" "$OUTPUT_DIR/docker/image_list.txt"
            echo -e "${YELLOW}[*] Quick mode: scanning $(wc -l < "$OUTPUT_DIR/docker/image_list.txt") images used by running containers${NC}"
        fi
    fi

    # Check if there are any images
    if [ ! -s "$OUTPUT_DIR/docker/image_list.txt" ]; then
        echo -e "${YELLOW}[!] No Docker images found.${NC}"
        return
    fi

    # Count total images for progress reporting
    TOTAL_IMAGES=$(wc -l < "$OUTPUT_DIR/docker/image_list.txt")
    echo -e "${YELLOW}[*] Found $TOTAL_IMAGES Docker images to analyze${NC}"

    # Create summary file
    echo "Docker Image Security Summary" > "$OUTPUT_DIR/docker/image_security_summary.txt"
    echo "===========================" >> "$OUTPUT_DIR/docker/image_security_summary.txt"
    echo "Analysis Date: $(f_container_now)" >> "$OUTPUT_DIR/docker/image_security_summary.txt"
    echo "" >> "$OUTPUT_DIR/docker/image_security_summary.txt"

    # Initialize vulnerability counters
    CRITICAL_COUNT=0
    HIGH_COUNT=0
    MEDIUM_COUNT=0
    LOW_COUNT=0
    TRIVY_FAILED_COUNT=0
    : > "$OUTPUT_DIR/docker/vulnerable_images.txt"
    : > "$OUTPUT_DIR/docker/image_risk_scores.txt"
    : > "$OUTPUT_DIR/docker/trivy_failed_images.txt"

    # Scan images (parallel Trivy with per-image checkpoint)
    echo -e "${BLUE}[*] Scanning images for vulnerabilities and misconfigurations (jobs: $CONTAINER_TRIVY_JOBS).${NC}"

    f_container_process_image(){
        local image="$1" OUTPUT_DIR="$2"
        local image_name trivy_json CRITICAL_COUNT_IMG HIGH_COUNT_IMG MEDIUM_COUNT_IMG LOW_COUNT_IMG
        local SECRETS_COUNT MISCONFIGS_COUNT RISK_SCORE IMAGE_ID IMAGE_CREATED IMAGE_SIZE IMAGE_LAYERS PARENT_IMAGE

        image_name=$(f_container_image_file_id "$image")
        trivy_json="$OUTPUT_DIR/docker/images/${image_name}.json"

        if f_container_image_scanned "$image_name" && f_container_trivy_json_valid "$trivy_json"; then
            f_container_log "Using cached Trivy results: $image"
        else
            f_container_scan_one_image "$image" || true
        fi

        IMAGE_ID=$(docker inspect --format '{{.Id}}' "$image" 2>/dev/null | cut -d':' -f2 | cut -c1-12)
        IMAGE_CREATED=$(docker inspect --format '{{.Created}}' "$image" 2>/dev/null)
        IMAGE_SIZE=$(docker inspect --format '{{.Size}}' "$image" 2>/dev/null | numfmt --to=iec-i 2>/dev/null || echo unknown)
        IMAGE_LAYERS=$(docker inspect --format '{{len .RootFS.Layers}}' "$image" 2>/dev/null)
        PARENT_IMAGE=$(docker history --format "{{.CreatedBy}}" "$image" 2>/dev/null | grep -i "FROM" | head -1)

        CRITICAL_COUNT_IMG=$(f_container_jq_count "$trivy_json" '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length')
        HIGH_COUNT_IMG=$(f_container_jq_count "$trivy_json" '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length')
        MEDIUM_COUNT_IMG=$(f_container_jq_count "$trivy_json" '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length')
        LOW_COUNT_IMG=$(f_container_jq_count "$trivy_json" '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length')
        SECRETS_COUNT=$(f_container_jq_count "$trivy_json" '[.Results[]?.Secrets[]?] | length')
        MISCONFIGS_COUNT=$(f_container_jq_count "$trivy_json" '[.Results[]?.Misconfigurations[]?] | length')
        RISK_SCORE=$(f_container_risk_score "$CRITICAL_COUNT_IMG" "$HIGH_COUNT_IMG" "$MEDIUM_COUNT_IMG" "$LOW_COUNT_IMG")

        {
            echo "Security Profile for Image: $image"
            echo "Image ID: $IMAGE_ID | Risk: $RISK_SCORE/10"
            echo "Critical: $CRITICAL_COUNT_IMG High: $HIGH_COUNT_IMG Medium: $MEDIUM_COUNT_IMG Low: $LOW_COUNT_IMG"
            echo "Secrets: $SECRETS_COUNT Misconfigs: $MISCONFIGS_COUNT"
            echo "Evidence: docker/images/${image_name}.json"
        } > "$OUTPUT_DIR/docker/vulnerabilities/${image_name}_profile.txt"

        if [ "$CRITICAL_COUNT_IMG" -gt 0 ]; then
            f_container_record_finding critical docker-image "$image" trivy_critical_vulns \
                "Found $CRITICAL_COUNT_IMG CRITICAL vulnerabilities" "docker/images/${image_name}.json"
        fi
        if [ "$HIGH_COUNT_IMG" -gt 0 ]; then
            f_container_record_finding high docker-image "$image" trivy_high_vulns \
                "Found $HIGH_COUNT_IMG HIGH vulnerabilities" "docker/images/${image_name}.json"
        fi
        if [ "$SECRETS_COUNT" -gt 0 ]; then
            f_container_record_finding critical docker-image "$image" trivy_secrets \
                "Found $SECRETS_COUNT potential secrets in image" "docker/images/${image_name}.json"
        fi
        if [ "$MISCONFIGS_COUNT" -gt 0 ]; then
            f_container_record_finding warning docker-image "$image" trivy_misconfig \
                "Found $MISCONFIGS_COUNT misconfigurations" "docker/images/${image_name}.json"
        fi

        echo "$CRITICAL_COUNT_IMG $HIGH_COUNT_IMG $MEDIUM_COUNT_IMG $LOW_COUNT_IMG"
        if [ "$CRITICAL_COUNT_IMG" -gt 0 ] || [ "$HIGH_COUNT_IMG" -gt 0 ]; then
            echo "$image: Critical: $CRITICAL_COUNT_IMG, High: $HIGH_COUNT_IMG, Medium: $MEDIUM_COUNT_IMG, Low: $LOW_COUNT_IMG"
        fi
        echo "$image|$RISK_SCORE|$CRITICAL_COUNT_IMG|$HIGH_COUNT_IMG|$MEDIUM_COUNT_IMG|$LOW_COUNT_IMG|$SECRETS_COUNT|$MISCONFIGS_COUNT"
    }

    COUNTER=0
    _active_jobs=0
    while read -r image; do
        ((COUNTER++))
        echo -e "${BLUE}[*] [$COUNTER/$TOTAL_IMAGES] Queue image: $image${NC}"
        (
            f_container_process_image "$image" "$OUTPUT_DIR" > "$OUTPUT_DIR/docker/images/.result_${COUNTER}.tmp"
        ) &
        _active_jobs=$((_active_jobs + 1))
        if [ "$_active_jobs" -ge "$CONTAINER_TRIVY_JOBS" ]; then
            wait -n 2>/dev/null || wait
            _active_jobs=$((_active_jobs - 1))
        fi
    done < "$OUTPUT_DIR/docker/image_list.txt"
    wait

    for rf in "$OUTPUT_DIR"/docker/images/.result_*.tmp; do
        [ -f "$rf" ] || continue
        read -r c h m l < <(head -1 "$rf")
        CRITICAL_COUNT=$((CRITICAL_COUNT + c))
        HIGH_COUNT=$((HIGH_COUNT + h))
        MEDIUM_COUNT=$((MEDIUM_COUNT + m))
        LOW_COUNT=$((LOW_COUNT + l))
        sed -n '2p' "$rf" >> "$OUTPUT_DIR/docker/vulnerable_images.txt" 2>/dev/null || true
        sed -n '3p' "$rf" >> "$OUTPUT_DIR/docker/image_risk_scores.txt" 2>/dev/null || true
        rm -f "$rf"
    done
    TRIVY_FAILED_COUNT=$(wc -l < "$OUTPUT_DIR/docker/trivy_failed_images.txt" 2>/dev/null || echo 0)

    # Update summary file with totals
    {
        echo "VULNERABILITY SUMMARY ACROSS ALL IMAGES:"
        echo "Critical: $CRITICAL_COUNT"
        echo "High: $HIGH_COUNT"
        echo "Medium: $MEDIUM_COUNT"
        echo "Low: $LOW_COUNT"
        echo
        echo "Images with critical/high vulnerabilities: $(wc -l < "$OUTPUT_DIR/docker/vulnerable_images.txt" 2>/dev/null || echo 0)"
        echo "Trivy scan failures (invalid/empty results): $TRIVY_FAILED_COUNT"
        echo

        if [ "$TRIVY_FAILED_COUNT" -gt 0 ]; then
            echo "TRIVY SCAN FAILURES:"
            cat "$OUTPUT_DIR/docker/trivy_failed_images.txt"
            echo "(see docker/trivy_errors.log for details)"
            echo
        fi

        if [ -s "$OUTPUT_DIR/docker/vulnerable_images.txt" ]; then
            echo "VULNERABLE IMAGES (Ordered by Risk):"
            sort -t'|' -k2,2nr "$OUTPUT_DIR/docker/image_risk_scores.txt" | awk -F'|' '{print $1 " (Risk: " $2 "/10, Critical: " $3 ", High: " $4 ")"}' | head -10
        fi
    } >> "$OUTPUT_DIR/docker/image_security_summary.txt"

    # Analyze Dockerfile security
    echo -e "${BLUE}[*] Looking for Dockerfiles.${NC}"
    local dockerfile_root="${CONTAINER_DOCKERFILE_ROOT:-${DISCOVER:-$CONTAINER_SCANNER_ROOT/..}}"
    find "$dockerfile_root" \( -path "*/.git/*" -o -path "*/node_modules/*" -o -path "*/vendor/*" \) -prune -o -name "Dockerfile" -type f -print 2>/dev/null > "$OUTPUT_DIR/docker/dockerfile_list.txt" || : > "$OUTPUT_DIR/docker/dockerfile_list.txt"

    if [ -s "$OUTPUT_DIR/docker/dockerfile_list.txt" ]; then
        DOCKERFILE_COUNT=$(wc -l < "$OUTPUT_DIR/docker/dockerfile_list.txt")
        echo -e "${YELLOW}[*] Found $DOCKERFILE_COUNT Dockerfiles to analyze${NC}"
        echo -e "${BLUE}[*] Performing advanced Dockerfile security analysis.${NC}"

        DOCKERFILE_ISSUES_COUNT=0

        while read -r dockerfile; do
            echo -e "${BLUE}[*] Analyzing Dockerfile: $dockerfile${NC}"
            dockerfile_name=$(echo "$dockerfile" | tr './' '_')

            # Check for security issues in Dockerfile with advanced analysis
            {
                echo "Dockerfile Security Analysis: $dockerfile"
                echo "=================================="
                echo "Scan Date: $(f_container_now)"
                echo

                # Initialize issue counters
                CRITICAL_ISSUES=0
                HIGH_ISSUES=0
                MEDIUM_ISSUES=0

                # Check for root user
                if ! grep -q "USER " "$dockerfile" || grep -q "USER root" "$dockerfile"; then
                    echo "WARNING: Dockerfile runs as root user or doesn't specify a user"
                    ((HIGH_ISSUES++))
                fi

                # Check for latest tag
                if grep -q "FROM.*:latest" "$dockerfile"; then
                    echo "WARNING: Dockerfile uses 'latest' tag which is not recommended for production"
                    ((MEDIUM_ISSUES++))
                fi

                # Check for sensitive data
                if grep -Ei "(password|token|key|secret|credential)" "$dockerfile"; then
                    echo "CRITICAL: Dockerfile may contain hardcoded secrets:"
                    grep -Ei "(password|token|key|secret|credential)" "$dockerfile" | sed 's/^/  /'
                    ((CRITICAL_ISSUES++))
                fi

                # Check for COPY vs ADD (ADD can extract archives automatically)
                if grep -q "ADD " "$dockerfile"; then
                    echo "INFO: Using ADD instead of COPY may introduce security risks if archives are extracted"
                    ((MEDIUM_ISSUES++))
                fi

                # Check for package update and upgrade in the same RUN
                if grep -q "apt-get update" "$dockerfile" && ! grep -q "apt-get update.*apt-get upgrade" "$dockerfile"; then
                    echo "WARNING: apt-get update without upgrade may lead to outdated packages"
                    ((MEDIUM_ISSUES++))
                fi

                # Check for package upgrades that don't clean cache
                if grep -q "apt-get .*upgrade" "$dockerfile" && ! grep -q "apt-get .*upgrade.*rm -rf /var/lib/apt/lists/" "$dockerfile"; then
                    echo "WARNING: Package cache not cleaned after install/upgrade (increases image size)"
                    ((MEDIUM_ISSUES++))
                fi

                # Check for unsafe curl usage 
                if grep -q "curl .*| sh" "$dockerfile" || grep -q "wget .*| sh" "$dockerfile"; then
                    echo "CRITICAL: Unsafe practice - piping curl/wget output to shell"
                    ((CRITICAL_ISSUES++))
                fi

                # Check for healthcheck
                if ! grep -q "HEALTHCHECK" "$dockerfile"; then
                    echo "INFO: No HEALTHCHECK instruction found (recommended for production)"
                    ((MEDIUM_ISSUES++))
                fi

                # Check for multi-stage builds
                if [ "$(grep -c "^FROM" "$dockerfile")" -ge 2 ]; then
                    echo "GOOD PRACTICE: Using multi-stage builds to reduce image size"
                fi

                # Check for exposed ports without specific binding
                if grep -q "EXPOSE" "$dockerfile"; then
                    echo "INFO: Exposed ports found - ensure they're properly secured in production"
                fi

                # Check for proper handling of signals (SIGTERM)
                if ! grep -q "STOPSIGNAL" "$dockerfile"; then
                    echo "INFO: No STOPSIGNAL instruction (might not gracefully handle container stopping)"
                fi

                # Check for run-as-non-root comment
                if ! grep -q "#.*run as non root" "$dockerfile" && ! grep -q "USER [^r][^o][^o][^t]" "$dockerfile"; then
                    echo "WARNING: No explicit intention to run as non-root"
                    ((MEDIUM_ISSUES++))
                fi

                # Check for suspicious download/execution patterns
                if grep -Ei "(curl|wget).*\.(sh|bash|zsh|py|pl)" "$dockerfile"; then
                    echo "WARNING: Downloading and potentially executing scripts from internet:"
                    grep -Ei "(curl|wget).*\.(sh|bash|zsh|py|pl)" "$dockerfile" | sed 's/^/  /'
                    ((HIGH_ISSUES++))
                fi

                # Generate summary
                echo
                echo "ISSUES SUMMARY:"
                echo "Critical issues: $CRITICAL_ISSUES"
                echo "High-risk issues: $HIGH_ISSUES"
                echo "Medium-risk issues: $MEDIUM_ISSUES"

                TOTAL_ISSUES=$((CRITICAL_ISSUES + HIGH_ISSUES + MEDIUM_ISSUES))
                if [ "$TOTAL_ISSUES" -gt 0 ]; then
                    DOCKERFILE_RISK_SCORE=$(( (CRITICAL_ISSUES * 10 + HIGH_ISSUES * 5 + MEDIUM_ISSUES * 2) / TOTAL_ISSUES ))
                    if [ "$DOCKERFILE_RISK_SCORE" -gt 10 ]; then
                        DOCKERFILE_RISK_SCORE=10
                    fi
                else
                    DOCKERFILE_RISK_SCORE=0
                fi

                echo "Dockerfile Risk Score: $DOCKERFILE_RISK_SCORE/10"

                # Add recommendations
                echo
                echo "RECOMMENDATIONS:"
                if [ "$CRITICAL_ISSUES" -gt 0 ] || [ "$HIGH_ISSUES" -gt 0 ]; then
                    echo "- Remove all secrets, tokens and credentials from Dockerfile"
                    echo "- Avoid running containers as root - use 'USER nonroot' or similar"
                    echo "- Never pipe curl/wget directly to shell - download first, verify, then execute"
                fi
                if [ "$MEDIUM_ISSUES" -gt 0 ]; then
                    echo "- Use specific version tags instead of 'latest'"
                    echo "- Add a HEALTHCHECK to ensure container availability"
                    echo "- Clean package cache after installations to reduce image size"
                    echo "- Use COPY instead of ADD when possible"
                fi
                echo "- Consider multi-stage builds to minimize attack surface"
                echo "- Implement principle of least privilege for all operations"

                echo
            } > "$OUTPUT_DIR/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt"

            trivy config --format json "$dockerfile" > "$OUTPUT_DIR/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_trivy.json" 2>>"$OUTPUT_DIR/docker/trivy_errors.log" || true
            if [ -s "$OUTPUT_DIR/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_trivy.json" ]; then
                _df_mis=$(f_container_jq_count "$OUTPUT_DIR/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_trivy.json" '[.Results[]?.Misconfigurations[]?] | length')
                if [ "$_df_mis" -gt 0 ]; then
                    f_container_record_finding warning dockerfile "$dockerfile" trivy_config                         "Trivy reported $_df_mis Dockerfile misconfigurations" "docker/dockerfile_analysis/dockerfile_${dockerfile_name}_trivy.json"
                fi
            fi

            _df_crit=$(grep "^Critical issues:" "$OUTPUT_DIR/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt" | awk '{print $3}')
            _df_high=$(grep "^High-risk issues:" "$OUTPUT_DIR/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt" | awk '{print $3}')
            if [ "${_df_crit:-0}" -gt 0 ]; then
                f_container_record_finding critical dockerfile "$dockerfile" dockerfile_static_analysis \
                    "Critical Dockerfile issues: $_df_crit" "docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt"
            elif [ "${_df_high:-0}" -gt 0 ]; then
                f_container_record_finding high dockerfile "$dockerfile" dockerfile_static_analysis \
                    "High-risk Dockerfile issues: $_df_high" "docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt"
            fi

            # Extract risk score for summary
            DOCKERFILE_RISK_SCORE=$(grep "Dockerfile Risk Score:" "$OUTPUT_DIR/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt" | awk '{print $4}' | cut -d'/' -f1)
            ISSUES_COUNT=$(grep "Critical issues:" "$OUTPUT_DIR/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt" -A2 | awk '{sum+=$3} END {print sum}')

            if [ "$ISSUES_COUNT" -gt 0 ]; then
                echo "$dockerfile|$DOCKERFILE_RISK_SCORE|$ISSUES_COUNT" >> "$OUTPUT_DIR/docker/dockerfile_risk_scores.txt"
                ((DOCKERFILE_ISSUES_COUNT++))
            fi
        done < "$OUTPUT_DIR/docker/dockerfile_list.txt"

        # Add Dockerfile analysis to summary
        {
            echo
            echo "DOCKERFILE SECURITY ANALYSIS:"
            echo "Total Dockerfiles analyzed: $DOCKERFILE_COUNT"
            echo "Dockerfiles with security issues: $DOCKERFILE_ISSUES_COUNT"
            echo

            if [ -s "$OUTPUT_DIR/docker/dockerfile_risk_scores.txt" ]; then
                echo "TOP RISKY DOCKERFILES:"
                sort -t'|' -k2,2nr "$OUTPUT_DIR/docker/dockerfile_risk_scores.txt" | awk -F'|' '{print $1 " (Risk: " $2 "/10, Issues: " $3 ")"}' | head -5
            fi
        } >> "$OUTPUT_DIR/docker/image_security_summary.txt"
    fi

    echo
    f_container_mark_phase docker-images
    echo -e "${YELLOW}[*] Docker image analysis complete.${NC}"
    echo -e "${YELLOW}[*] Results saved to $OUTPUT_DIR/docker/image_security_summary.txt${NC}"
    echo
}

f_scan_docker_containers(){
    local OUTPUT_DIR="$1"

    f_container_should_run_phase docker-containers || { f_container_log "Skipping docker-containers (checkpoint)"; return 0; }

    echo -e "${BLUE}[*] Starting comprehensive Docker container security audit.${NC}"
    mkdir -p "$OUTPUT_DIR/docker/containers" "$OUTPUT_DIR/docker/container_reports" "$OUTPUT_DIR/docker/runtime_analysis"

    # List all Docker containers with additional metadata
    echo -e "${BLUE}[*] Gathering container inventory.${NC}"
    docker ps -a --format "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Command}}" > "$OUTPUT_DIR/docker/container_inventory.tsv"
    if [ "$CONTAINER_SCAN_MODE" = "quick" ]; then
        docker ps --format "{{.ID}} {{.Image}} {{.Names}}" > "$OUTPUT_DIR/docker/container_list.txt"
    else
        docker ps -a --format "{{.ID}} {{.Image}} {{.Names}}" > "$OUTPUT_DIR/docker/container_list.txt"
    fi

    # Get running containers in a separate list
    docker ps --format "{{.ID}} {{.Image}} {{.Names}}" > "$OUTPUT_DIR/docker/running_containers.txt"

    # Check if there are any containers
    if [ ! -s "$OUTPUT_DIR/docker/container_list.txt" ]; then
        echo -e "${YELLOW}[!] No Docker containers found.${NC}"
        return
    fi

    # Count total containers
    TOTAL_CONTAINERS=$(wc -l < "$OUTPUT_DIR/docker/container_list.txt")
    RUNNING_CONTAINERS=$(wc -l < "$OUTPUT_DIR/docker/running_containers.txt" 2>/dev/null || echo 0)

    echo -e "${YELLOW}[*] Found $TOTAL_CONTAINERS containers ($RUNNING_CONTAINERS running)${NC}"

    # Create summary file
    echo "Docker Container Security Summary" > "$OUTPUT_DIR/docker/container_security_summary.txt"
    echo "================================" >> "$OUTPUT_DIR/docker/container_security_summary.txt"
    echo "Analysis Date: $(f_container_now)" >> "$OUTPUT_DIR/docker/container_security_summary.txt"
    echo "Total Containers: $TOTAL_CONTAINERS" >> "$OUTPUT_DIR/docker/container_security_summary.txt"
    echo "Running Containers: $RUNNING_CONTAINERS" >> "$OUTPUT_DIR/docker/container_security_summary.txt"
    echo "" >> "$OUTPUT_DIR/docker/container_security_summary.txt"

    # Initialize risk counters
    CRITICAL_CONTAINERS=0
    HIGH_RISK_CONTAINERS=0
    MEDIUM_RISK_CONTAINERS=0

    # Analyze each container
    echo -e "${BLUE}[*] Performing deep security analysis of container configurations.${NC}"

    # Create detailed issue tracking files
    touch "$OUTPUT_DIR/docker/privileged_containers.txt"
    touch "$OUTPUT_DIR/docker/root_containers.txt"
    touch "$OUTPUT_DIR/docker/sensitive_mount_containers.txt"
    touch "$OUTPUT_DIR/docker/network_sensitive_containers.txt"
    touch "$OUTPUT_DIR/docker/capability_containers.txt"
    touch "$OUTPUT_DIR/docker/no_health_check_containers.txt"

    COUNTER=0
    while read -r container_info; do
        ((COUNTER++))
        container_id=$(echo "$container_info" | awk '{print $1}')
        container_image=$(echo "$container_info" | awk '{print $2}')
        container_name=$(echo "$container_info" | awk '{print $3}')
        local container_safe="${container_id:0:12}"
        [ -n "$container_name" ] && container_safe="$(f_container_slug "$container_name")_${container_id:0:12}"

        echo -e "${BLUE}[*] [$COUNTER/$TOTAL_CONTAINERS] Analyzing container: $container_name ($container_id)${NC}"

        # Get container details
        docker inspect "$container_id" > "$OUTPUT_DIR/docker/containers/${container_safe}_inspect.json" 2>/dev/null

        # Extract container status
        local inspect_file="$OUTPUT_DIR/docker/containers/${container_safe}_inspect.json"
        CONTAINER_STATUS=$(jq -r '.[0].State.Status' "$inspect_file" 2>/dev/null)
        CONTAINER_CREATED=$(jq -r '.[0].Created' "$inspect_file" 2>/dev/null)
        CONTAINER_PLATFORM=$(jq -r '.[0].Platform' "$inspect_file" 2>/dev/null)

        # Initialize security issue counter for this container
        CRITICAL_ISSUES=0
        HIGH_ISSUES=0
        MEDIUM_ISSUES=0

        # Prepare container security report
        {
            echo "Container Security Analysis: $container_name"
            echo "====================================="
            echo "Analysis Date: $(f_container_now)"
            echo
            echo "CONTAINER DETAILS:"
            echo "Container ID: $container_id"
            echo "Image: $container_image"
            echo "Status: $CONTAINER_STATUS"
            echo "Created: $CONTAINER_CREATED"
            echo "Platform: $CONTAINER_PLATFORM"
            echo
            echo "SECURITY FINDINGS:"

            # Check if container is running in privileged mode
            privileged=$(jq -r '.[0].HostConfig.Privileged' "$inspect_file")
            if [ "$privileged" = "true" ]; then
                echo "CRITICAL: Container is running in privileged mode (full access to host devices)"
                echo "$container_name" >> "$OUTPUT_DIR/docker/privileged_containers.txt"
                f_container_record_finding critical docker-container "$container_name" privileged_mode "Container runs privileged" "docker/containers/${container_safe}_inspect.json"
                ((CRITICAL_ISSUES++))
            fi

            # Check for user running container (root vs non-root)
            user=$(jq -r '.[0].Config.User' "$inspect_file")
            if [ -z "$user" ] || [ "$user" = "0" ] || [ "$user" = "root" ]; then
                echo "HIGH-RISK: Container is running as root user"
                echo "$container_name" >> "$OUTPUT_DIR/docker/root_containers.txt"
                f_container_record_finding high docker-container "$container_name" root_user "Container runs as root" "docker/containers/${container_safe}_inspect.json"
                ((HIGH_ISSUES++))
            else
                echo "GOOD PRACTICE: Container is running as non-root user: $user"
            fi

            # Check for additional Linux capabilities
            caps_add=$(jq -r '.[0].HostConfig.CapAdd[]' "$inspect_file" 2>/dev/null)
            if [ -n "$caps_add" ]; then
                echo "HIGH-RISK: Container has additional Linux capabilities:"
                echo "$caps_add" | sed 's/^/  /' 

                # Check for particularly dangerous capabilities
                if echo "$caps_add" | grep -q "SYS_ADMIN\|NET_ADMIN\|ALL"; then
                    echo "CRITICAL: Container has highly privileged capabilities that can lead to host compromise"
                    ((CRITICAL_ISSUES++))
                else
                    ((HIGH_ISSUES++))
                fi

                echo "$container_name: $caps_add" >> "$OUTPUT_DIR/docker/capability_containers.txt"
            fi

            # Check for sensitive env variables
            sensitive_env=$(jq -r '.[0].Config.Env[]' "$inspect_file" 2>/dev/null | grep -Ei "(password|token|key|secret|credential|api_key|apikey|access_key|auth)")
            if [ -n "$sensitive_env" ]; then
                echo "CRITICAL: Container has sensitive environment variables (potential secret exposure):"
                echo "$sensitive_env" | sed 's/^/  /' | cut -d'=' -f1
                ((CRITICAL_ISSUES++))
            fi

            # Check for mounted sensitive directories
            sensitive_mounts=$(jq -r '.[0].Mounts[] | select(.Source | test("/etc|/var/run|/var/lib|/usr|/root|/.ssh|/.aws|/.kube|/docker.sock"))' "$inspect_file" 2>/dev/null)
            if [ -n "$sensitive_mounts" ]; then
                echo "HIGH-RISK: Container has sensitive host directories mounted:"
                jq -r '.[0].Mounts[] | select(.Source | test("/etc|/var/run|/var/lib|/usr|/root|/.ssh|/.aws|/.kube|/docker.sock")) | .Source + " -> " + .Destination' "$inspect_file" 2>/dev/null | sed 's/^/  /'
                echo "$container_name" >> "$OUTPUT_DIR/docker/sensitive_mount_containers.txt"

                # Check specifically for docker.sock which is especially dangerous
                if jq -r '.[0].Mounts[].Source' "$inspect_file" 2>/dev/null | grep -q "/var/run/docker.sock"; then
                    echo "CRITICAL: Container has docker.sock mounted - this allows complete control of the host Docker daemon!"
                    ((CRITICAL_ISSUES++))
                else
                    ((HIGH_ISSUES++))
                fi
            fi

            # Check for network mode
            network_mode=$(jq -r '.[0].HostConfig.NetworkMode' "$inspect_file")
            if [ "$network_mode" = "host" ]; then
                echo "HIGH-RISK: Container is using host network mode (no network isolation)"
                echo "$container_name" >> "$OUTPUT_DIR/docker/network_sensitive_containers.txt"
                ((HIGH_ISSUES++))
            fi

            # Check for PID mode
            pid_mode=$(jq -r '.[0].HostConfig.PidMode' "$inspect_file")
            if [ "$pid_mode" = "host" ]; then
                echo "HIGH-RISK: Container is using host PID mode (can see all processes on host)"
                echo "$container_name" >> "$OUTPUT_DIR/docker/network_sensitive_containers.txt"
                ((HIGH_ISSUES++))
            fi

            # Check for IPC mode
            ipc_mode=$(jq -r '.[0].HostConfig.IpcMode' "$inspect_file")
            if [ "$ipc_mode" = "host" ]; then
                echo "MEDIUM-RISK: Container is using host IPC mode (shared memory with host)"
                echo "$container_name" >> "$OUTPUT_DIR/docker/network_sensitive_containers.txt"
                ((MEDIUM_ISSUES++))
            fi

            # Check for port bindings (especially sensitive ports)
            port_bindings=$(jq -r '.[0].HostConfig.PortBindings | keys[]' "$inspect_file" 2>/dev/null)
            if [ -n "$port_bindings" ]; then
                echo "INFO: Container exposes the following ports:"
                jq -r '.[0].HostConfig.PortBindings | to_entries[] | .key + " -> " + (.value[0].HostPort // "ephemeral")' "$inspect_file" 2>/dev/null | sed 's/^/  /'

                # Check for sensitive ports
                if echo "$port_bindings" | grep -qE '22/|3306/|5432/|27017/|6379/|9200/|8080/|443/|80/'; then
                    echo "MEDIUM-RISK: Container exposes sensitive ports that may require additional security measures"
                    ((MEDIUM_ISSUES++))
                fi
            fi

            # Check read-only filesystem
            readonly_fs=$(jq -r '.[0].HostConfig.ReadonlyRootfs' "$inspect_file")
            if [ "$readonly_fs" = "true" ]; then
                echo "GOOD PRACTICE: Container uses read-only root filesystem"
            else
                echo "MEDIUM-RISK: Container does not use read-only root filesystem"
                ((MEDIUM_ISSUES++))
            fi

            # Check for health checks
            health_check=$(jq -r '.[0].Config.Healthcheck' "$inspect_file" 2>/dev/null)
            if [ "$health_check" = "null" ] || [ -z "$health_check" ]; then
                echo "MEDIUM-RISK: Container does not have a health check defined"
                echo "$container_name" >> "$OUTPUT_DIR/docker/no_health_check_containers.txt"
                ((MEDIUM_ISSUES++))
            else
                echo "GOOD PRACTICE: Container has health check defined"
            fi

            # Check for restart policy
            restart_policy=$(jq -r '.[0].HostConfig.RestartPolicy.Name' "$inspect_file")
            if [ "$restart_policy" = "no" ] || [ -z "$restart_policy" ]; then
                echo "INFO: Container has no restart policy defined"
            else
                echo "GOOD PRACTICE: Container has restart policy: $restart_policy"
            fi

            # Check for security options
            security_opts=$(jq -r '.[0].HostConfig.SecurityOpt[]' "$inspect_file" 2>/dev/null)
            if [ -n "$security_opts" ]; then
                echo "GOOD PRACTICE: Container uses security options:"
                echo "$security_opts" | sed 's/^/  /'
            else
                echo "MEDIUM-RISK: Container does not use any security options (e.g., seccomp, apparmor)"
                ((MEDIUM_ISSUES++))
            fi

            # Check for AppArmor profile
            apparmor_profile=$(jq -r '.[0].AppArmorProfile' "$inspect_file" 2>/dev/null)
            if [ -z "$apparmor_profile" ] || [ "$apparmor_profile" = "unconfined" ]; then
                echo "MEDIUM-RISK: Container does not use AppArmor confinement"
                ((MEDIUM_ISSUES++))
            else
                echo "GOOD PRACTICE: Container uses AppArmor profile: $apparmor_profile"
            fi

            # Check for Seccomp profile
            seccomp_profile=$(jq -r '.[0].HostConfig.SecurityOpt[] | select(startswith("seccomp"))' "$inspect_file" 2>/dev/null)
            if [ -z "$seccomp_profile" ]; then
                echo "MEDIUM-RISK: Container does not use custom Seccomp profile"
                ((MEDIUM_ISSUES++))
            else
                echo "GOOD PRACTICE: Container uses Seccomp profile"
            fi

            # Check for memory limits
            memory_limit=$(jq -r '.[0].HostConfig.Memory' "$inspect_file")
            if [ "$memory_limit" = "0" ]; then
                echo "MEDIUM-RISK: Container has no memory limits set (potential DoS vector)"
                ((MEDIUM_ISSUES++))
            else
                mem_human=$(echo "$memory_limit" | numfmt --to=iec-i)
                echo "GOOD PRACTICE: Container has memory limit: $mem_human"
            fi

            # Check for CPU limits
            cpu_limit=$(jq -r '.[0].HostConfig.CpuShares' "$inspect_file")
            if [ "$cpu_limit" = "0" ]; then
                echo "INFO: Container has no CPU limits set"
            else
                echo "GOOD PRACTICE: Container has CPU limits set: $cpu_limit shares"
            fi

            # Look for common vulnerable software patterns in commands/entrypoint
            cmd=$(jq -r '.[0].Config.Cmd[]' "$inspect_file" 2>/dev/null)
            entrypoint=$(jq -r '.[0].Config.Entrypoint[]' "$inspect_file" 2>/dev/null)

            # Check running commands for potential issues
            if echo "$cmd $entrypoint" | grep -qiE 'telnet|ftp|eval|exec|nc -l|netcat -l'; then
                echo "HIGH-RISK: Container command/entrypoint contains potentially unsafe operations"
                echo "Command: $cmd"
                echo "Entrypoint: $entrypoint"
                ((HIGH_ISSUES++))
            fi

            # Check for tmpfs mounts (good security practice)
            tmpfs_mounts=$(jq -r '.[0].HostConfig.Tmpfs' "$inspect_file" 2>/dev/null)
            if [ -n "$tmpfs_mounts" ] && [ "$tmpfs_mounts" != "null" ]; then
                echo "GOOD PRACTICE: Container uses tmpfs mounts for sensitive temporary data"
            fi

            # Generate risk score (weighted calculation)
            # Scale: 1-10, with 10 being highest risk
            CONTAINER_RISK_SCORE=$(f_container_risk_score "$CRITICAL_ISSUES" "$HIGH_ISSUES" "$MEDIUM_ISSUES" 0)
            if [ "$CONTAINER_RISK_SCORE" -gt 10 ]; then
                CONTAINER_RISK_SCORE=10
            fi

            echo
            echo "ISSUES SUMMARY:"
            echo "Critical issues: $CRITICAL_ISSUES"
            echo "High-risk issues: $HIGH_ISSUES"
            echo "Medium-risk issues: $MEDIUM_ISSUES"
            echo "Container Risk Score: $CONTAINER_RISK_SCORE/10"

            # Add recommendations
            echo
            echo "RECOMMENDATIONS:"

            if [ "$CRITICAL_ISSUES" -gt 0 ] || [ "$HIGH_ISSUES" -gt 0 ]; then
                if [ "$privileged" = "true" ]; then
                    echo "- Avoid running containers in privileged mode - use specific capabilities instead"
                fi
                if [ -z "$user" ] || [ "$user" = "0" ] || [ "$user" = "root" ]; then
                    echo "- Run container as non-root user by adding USER instruction to Dockerfile"
                fi
                if [ -n "$sensitive_mounts" ]; then
                    echo "- Avoid mounting sensitive host directories. Use volumes or bind mounts to specific required paths"
                fi
                if [ "$network_mode" = "host" ]; then
                    echo "- Use bridge network instead of host network mode"
                fi
                if [ -n "$sensitive_env" ]; then
                    echo "- Use Docker secrets or a secure vault solution instead of environment variables for sensitive data"
                fi
                if [ -n "$caps_add" ]; then
                    echo "- Remove unnecessary capabilities and use only those specifically required"
                fi
            fi

            if [ "$MEDIUM_ISSUES" -gt 0 ]; then
                if [ "$readonly_fs" != "true" ]; then
                    echo "- Use read-only root filesystem (--read-only flag) where possible"
                fi
                if [ "$health_check" = "null" ] || [ -z "$health_check" ]; then
                    echo "- Add a HEALTHCHECK instruction to ensure container health monitoring"
                fi
                if [ -z "$security_opts" ]; then
                    echo "- Implement security options like seccomp and apparmor profiles"
                fi
                if [ "$memory_limit" = "0" ]; then
                    echo "- Set memory limits to prevent resource exhaustion attacks"
                fi
            fi

            echo "- Implement least privilege principle for all container configurations"
            echo "- Regularly update base images and scan for vulnerabilities"
            echo
            echo "For full container inspection details, see: $OUTPUT_DIR/docker/containers/${container_name}_inspect.json"

        } > "$OUTPUT_DIR/docker/container_reports/${container_safe}_security_analysis.txt"

        # Update global counters based on risk level
        if [ "$CRITICAL_ISSUES" -gt 0 ]; then
            ((CRITICAL_CONTAINERS++))
        elif [ "$HIGH_ISSUES" -gt 0 ]; then
            ((HIGH_RISK_CONTAINERS++))
        elif [ "$MEDIUM_ISSUES" -gt 0 ]; then
            ((MEDIUM_RISK_CONTAINERS++))
        fi

        # Generate machine-readable risk data
        echo "$container_name|$container_id|$CONTAINER_RISK_SCORE|$CRITICAL_ISSUES|$HIGH_ISSUES|$MEDIUM_ISSUES" >> "$OUTPUT_DIR/docker/container_risk_scores.txt"

        # If container is running, perform additional runtime checks
        if [ "$CONTAINER_SCAN_MODE" = "full" ] && docker ps -q --filter "id=$container_id" | grep -q .; then
            echo -e "${BLUE}[*] Performing runtime analysis of container: $container_name${NC}"

            # Create directory for runtime analysis
            mkdir -p "$OUTPUT_DIR/docker/runtime_analysis/$container_safe"

            # Get process list
            docker top "$container_id" aux > "$OUTPUT_DIR/docker/runtime_analysis/$container_safe/processes.txt" 2>/dev/null

            # Get network information
            docker exec "$container_id" netstat -tulpn > "$OUTPUT_DIR/docker/runtime_analysis/$container_safe/netstat.txt" 2>/dev/null || true

            # Check for listening ports inside container
            docker exec "$container_id" netstat -tulpn | grep LISTEN > "$OUTPUT_DIR/docker/runtime_analysis/$container_safe/listening_ports.txt" 2>/dev/null || true

            # Get environment variables in running container
            docker exec "$container_id" env > "$OUTPUT_DIR/docker/runtime_analysis/$container_safe/environment.txt" 2>/dev/null || true

            # Check for setuid/setgid binaries
            docker exec "$container_id" find / -perm /6000 -type f 2>/dev/null > "$OUTPUT_DIR/docker/runtime_analysis/$container_safe/setuid_setgid_binaries.txt" || true

            echo -e "${YELLOW}[*] Runtime analysis complete for container: $container_name${NC}"
        fi
    done < "$OUTPUT_DIR/docker/container_list.txt"

    # Update summary with risk breakdown
    {
        echo "CONTAINER SECURITY RISK SUMMARY:"
        echo "Critical risk containers: $CRITICAL_CONTAINERS"
        echo "High risk containers: $HIGH_RISK_CONTAINERS"
        echo "Medium risk containers: $MEDIUM_RISK_CONTAINERS"
        echo "Low risk containers: $(( TOTAL_CONTAINERS - CRITICAL_CONTAINERS - HIGH_RISK_CONTAINERS - MEDIUM_RISK_CONTAINERS ))"
        echo

        # List top risky containers
        if [ -s "$OUTPUT_DIR/docker/container_risk_scores.txt" ]; then
            echo "TOP RISKY CONTAINERS:"
            sort -t'|' -k3,3nr "$OUTPUT_DIR/docker/container_risk_scores.txt" | head -5 | \
                awk -F'|' '{print $1 " (" $2 "): Risk Score " $3 "/10, Critical: " $4 ", High: " $5 ", Medium: " $6}'
        fi

        echo
        echo "SECURITY ISSUE BREAKDOWN:"
        echo "Privileged containers: $(wc -l < "$OUTPUT_DIR/docker/privileged_containers.txt" 2>/dev/null || echo 0)"
        echo "Root user containers: $(wc -l < "$OUTPUT_DIR/docker/root_containers.txt" 2>/dev/null || echo 0)"
        echo "Sensitive mount containers: $(wc -l < "$OUTPUT_DIR/docker/sensitive_mount_containers.txt" 2>/dev/null || echo 0)"
        echo "Host network mode containers: $(wc -l < "$OUTPUT_DIR/docker/network_sensitive_containers.txt" 2>/dev/null || echo 0)"
        echo "Containers with added capabilities: $(wc -l < "$OUTPUT_DIR/docker/capability_containers.txt" 2>/dev/null || echo 0)"
        echo "Containers without health checks: $(wc -l < "$OUTPUT_DIR/docker/no_health_check_containers.txt" 2>/dev/null || echo 0)"
    } >> "$OUTPUT_DIR/docker/container_security_summary.txt"

    echo
    f_container_mark_phase docker-containers
    echo -e "${YELLOW}[*] Container security analysis complete.${NC}"
    echo -e "${YELLOW}[*] Results saved to $OUTPUT_DIR/docker/container_security_summary.txt${NC}"
    echo
}