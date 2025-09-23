#!/usr/bin/env bash

# by ibrahimsql - Container Security Scanner

clear
f_banner

# Variables
DATESTAMP=$(date +%F)
TIMESTAMP=$(date +%T)

# Function to terminate script
f_terminate(){
    echo
    echo -e "${RED}[!] Terminating.${NC}"
    echo
    exit 1
}

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

###############################################################################################################################

# Check for required tools
f_check_requirements(){
    MISSING_TOOLS=()

    # Check for Docker
    if ! command -v docker &> /dev/null; then
        MISSING_TOOLS+=("docker")
    fi

    # Check for kubectl
    if ! command -v kubectl &> /dev/null; then
        MISSING_TOOLS+=("kubectl")
    fi

    # Check for trivy
    if ! command -v trivy &> /dev/null; then
        MISSING_TOOLS+=("trivy")
    fi

    # If there are missing tools, inform the user
    if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] The following tools are required but not installed:${NC}"
        for tool in "${MISSING_TOOLS[@]}"; do
            echo "  - $tool"
        done
        echo
        echo -e "${YELLOW}[!] Would you like to install the missing tools? (y/n)${NC}"
        read -r INSTALL_CHOICE

        if [[ "$INSTALL_CHOICE" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[*] Installing missing tools.${NC}"

            for tool in "${MISSING_TOOLS[@]}"; do
                case "$tool" in
                    "docker")
                        echo -e "${BLUE}[*] Installing Docker.${NC}"
                        sudo apt-get update && sudo apt-get install -y docker.io
                        sudo systemctl enable docker
                        sudo systemctl start docker
                        sudo usermod -aG docker "$USER"
                        ;;
                    "kubectl")
                        echo -e "${BLUE}[*] Installing kubectl.${NC}"
                        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
                        chmod +x kubectl
                        sudo mv kubectl /usr/local/bin/
                        ;;
                    "trivy")
                        echo -e "${BLUE}[*] Installing Trivy.${NC}"
                        sudo apt-get install -y wget apt-transport-https gnupg lsb-release
                        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
                        echo deb https://aquasecurity.github.io/trivy-repo/deb "$(lsb_release -sc)" main | sudo tee -a /etc/apt/sources.list.d/trivy.list
                        sudo apt-get update && sudo apt-get install -y trivy
                        ;;
                esac
            done

            echo
            echo -e "${YELLOW}[*] Installation complete. You may need to log out and back in for Docker permissions to take effect.${NC}"
            echo
            exit
        else
            echo
            echo -e "${RED}[!] Cannot proceed without required tools.${NC}"
            echo
            exit 1
        fi
    fi
}

###############################################################################################################################

# Function to scan Docker images
f_scan_docker_images(){
    local output_dir="$1"

    echo -e "${BLUE}[*] Starting comprehensive Docker image security scan.${NC}"
    mkdir -p "$output_dir/docker/images" "$output_dir/docker/vulnerabilities" "$output_dir/docker/dockerfile_analysis"

    # List all Docker images with additional metadata
    echo -e "${BLUE}[*] Collecting Docker image inventory.${NC}"
    docker images --format "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedAt}}" > "$output_dir/docker/image_inventory.tsv"
    docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>" > "$output_dir/docker/image_list.txt"

    # Check if there are any images
    if [ ! -s "$output_dir/docker/image_list.txt" ]; then
        echo -e "${YELLOW}[!] No Docker images found.${NC}"
        return
    fi

    # Count total images for progress reporting
    TOTAL_IMAGES=$(wc -l < "$output_dir/docker/image_list.txt")
    echo -e "${YELLOW}[*] Found $TOTAL_IMAGES Docker images to analyze${NC}"

    # Create summary file
    echo "Docker Image Security Summary" > "$output_dir/docker/image_security_summary.txt"
    echo "===========================" >> "$output_dir/docker/image_security_summary.txt"
    echo "Analysis Date: $DATESTAMP $TIMESTAMP" >> "$output_dir/docker/image_security_summary.txt"
    echo "" >> "$output_dir/docker/image_security_summary.txt"

    # Initialize vulnerability counters
    CRITICAL_COUNT=0
    HIGH_COUNT=0
    MEDIUM_COUNT=0
    LOW_COUNT=0

    # Scan each image with Trivy for vulnerabilities
    echo -e "${BLUE}[*] Scanning images for vulnerabilities and misconfigurations.${NC}"
    COUNTER=0
    while read -r image; do
        ((COUNTER++))
        echo -e "${BLUE}[*] [$COUNTER/$TOTAL_IMAGES] Scanning image: $image${NC}"
        image_name=$(echo "$image" | tr '/:' '_')

        # Run comprehensive Trivy scan with all security checks
        trivy image --format json --security-checks vuln,config,secret "$image" > "$output_dir/docker/images/$image_name.json" 2>/dev/null

        # Run additional scan for SBOM (Software Bill of Materials)
        trivy image --format json --list-all-pkgs "$image" > "$output_dir/docker/images/${image_name}_sbom.json" 2>/dev/null

        # Extract metadata to create image profile
        IMAGE_ID=$(docker inspect --format '{{.Id}}' "$image" 2>/dev/null | cut -d':' -f2 | cut -c1-12)
        IMAGE_CREATED=$(docker inspect --format '{{.Created}}' "$image" 2>/dev/null)
        IMAGE_SIZE=$(docker inspect --format '{{.Size}}' "$image" 2>/dev/null | numfmt --to=iec-i)
        IMAGE_LAYERS=$(docker inspect --format '{{len .RootFS.Layers}}' "$image" 2>/dev/null)
        PARENT_IMAGE=$(docker history --format "{{.CreatedBy}}" "$image" | grep -i "FROM" | head -1)

        # Extract vulnerabilities by severity
        CRITICAL_VULNS=$(jq -r '.Results[] | select(.Vulnerabilities != null) | .Vulnerabilities[] | select(.Severity == "CRITICAL")' "$output_dir/docker/images/$image_name.json" 2>/dev/null)
        HIGH_VULNS=$(jq -r '.Results[] | select(.Vulnerabilities != null) | .Vulnerabilities[] | select(.Severity == "HIGH")' "$output_dir/docker/images/$image_name.json" 2>/dev/null)
        MEDIUM_VULNS=$(jq -r '.Results[] | select(.Vulnerabilities != null) | .Vulnerabilities[] | select(.Severity == "MEDIUM")' "$output_dir/docker/images/$image_name.json" 2>/dev/null)
        LOW_VULNS=$(jq -r '.Results[] | select(.Vulnerabilities != null) | .Vulnerabilities[] | select(.Severity == "LOW")' "$output_dir/docker/images/$image_name.json" 2>/dev/null)

        # Count vulnerabilities
        CRITICAL_COUNT_IMG=$(echo "$CRITICAL_VULNS" | grep -v '^$' | wc -l)
        HIGH_COUNT_IMG=$(echo "$HIGH_VULNS" | grep -v '^$' | wc -l)
        MEDIUM_COUNT_IMG=$(echo "$MEDIUM_VULNS" | grep -v '^$' | wc -l)
        LOW_COUNT_IMG=$(echo "$LOW_VULNS" | grep -v '^$' | wc -l)

        # Update global counters
        CRITICAL_COUNT=$((CRITICAL_COUNT + CRITICAL_COUNT_IMG))
        HIGH_COUNT=$((HIGH_COUNT + HIGH_COUNT_IMG))
        MEDIUM_COUNT=$((MEDIUM_COUNT + MEDIUM_COUNT_IMG))
        LOW_COUNT=$((LOW_COUNT + LOW_COUNT_IMG))

        # Check for secrets or sensitive data
        SECRETS=$(jq -r '.Results[] | select(.Secrets != null) | .Secrets[]' "$output_dir/docker/images/$image_name.json" 2>/dev/null)
        SECRETS_COUNT=$(echo "$SECRETS" | grep -v '^$' | wc -l)

        # Check for misconfigurations
        MISCONFIGS=$(jq -r '.Results[] | select(.Misconfigurations != null) | .Misconfigurations[]' "$output_dir/docker/images/$image_name.json" 2>/dev/null)
        MISCONFIGS_COUNT=$(echo "$MISCONFIGS" | grep -v '^$' | wc -l)

        # Create detailed image security profile
        {
            echo "Security Profile for Image: $image"
            echo "=================================="
            echo "Image ID: $IMAGE_ID"
            echo "Created: $IMAGE_CREATED"
            echo "Size: $IMAGE_SIZE"
            echo "Layers: $IMAGE_LAYERS"
            echo "Based on: $PARENT_IMAGE"
            echo
            echo "VULNERABILITY SUMMARY:"
            echo "- Critical: $CRITICAL_COUNT_IMG"
            echo "- High: $HIGH_COUNT_IMG"
            echo "- Medium: $MEDIUM_COUNT_IMG"
            echo "- Low: $LOW_COUNT_IMG"
            echo

            if [ "$SECRETS_COUNT" -gt 0 ]; then
                echo "SECRETS FOUND: $SECRETS_COUNT potential secrets/credentials detected!"
            fi
            if [ "$MISCONFIGS_COUNT" -gt 0 ]; then
                echo "MISCONFIGURATIONS FOUND: $MISCONFIGS_COUNT security misconfigurations detected!"
            fi

            echo

            # Extract OS and package information
            OS_INFO=$(jq -r '.Results[] | select(.Type == "os-pkgs") | .Target' "$output_dir/docker/images/$image_name.json" 2>/dev/null)
            echo "OS: $OS_INFO"

            # List top 10 critical/high vulnerabilities
            if [ "$CRITICAL_COUNT_IMG" -gt 0 ] || [ "$HIGH_COUNT_IMG" -gt 0 ]; then
                echo
                echo "TOP CRITICAL/HIGH VULNERABILITIES:"
                jq -r '.Results[] | select(.Vulnerabilities != null) | .Vulnerabilities[] | select(.Severity == "CRITICAL" or .Severity == "HIGH") | "["+.Severity+"] "+.VulnerabilityID+" - "+.PkgName+" "+.InstalledVersion+" (Fixed: "+(.FixedVersion // "Not Available")+") - "+.Title' "$output_dir/docker/images/$image_name.json" 2>/dev/null | head -10
            fi

            # Extract any secrets found (without revealing actual secrets)
            if [ "$SECRETS_COUNT" -gt 0 ]; then
                echo
                echo "SECRETS DETECTED:"
                jq -r '.Results[] | select(.Secrets != null) | .Secrets[] | "- Found in "+.RuleID+" ("+.Category+")"' "$output_dir/docker/images/$image_name.json" 2>/dev/null
            fi

            # Extract misconfigurations
            if [ "$MISCONFIGS_COUNT" -gt 0 ]; then
                echo
                echo "SECURITY MISCONFIGURATIONS:"
                jq -r '.Results[] | select(.Misconfigurations != null) | .Misconfigurations[] | "["+.Severity+"] "+.ID+" - "+.Title' "$output_dir/docker/images/$image_name.json" 2>/dev/null
            fi

            echo
            echo "For full details, see: $output_dir/docker/images/$image_name.json"
        } > "$output_dir/docker/vulnerabilities/${image_name}_profile.txt"

        # Add to summary list
        if [ "$CRITICAL_COUNT_IMG" -gt 0 ] || [ "$HIGH_COUNT_IMG" -gt 0 ]; then
            echo "$image: Critical: $CRITICAL_COUNT_IMG, High: $HIGH_COUNT_IMG, Medium: $MEDIUM_COUNT_IMG, Low: $LOW_COUNT_IMG" >> "$output_dir/docker/vulnerable_images.txt"
        fi

        # Create machine-readable risk score (1-10)
        RISK_SCORE=$(( (CRITICAL_COUNT_IMG * 10 + HIGH_COUNT_IMG * 5 + MEDIUM_COUNT_IMG * 2 + LOW_COUNT_IMG) / (CRITICAL_COUNT_IMG + HIGH_COUNT_IMG + MEDIUM_COUNT_IMG + LOW_COUNT_IMG + 1) ))
        if [ "$RISK_SCORE" -gt 10 ]; then
            RISK_SCORE=10
        fi
        echo "$image|$RISK_SCORE|$CRITICAL_COUNT_IMG|$HIGH_COUNT_IMG|$MEDIUM_COUNT_IMG|$LOW_COUNT_IMG|$SECRETS_COUNT|$MISCONFIGS_COUNT" >> "$output_dir/docker/image_risk_scores.txt"

        echo -e "${YELLOW}[*] Image scan complete: $image (Risk Score: $RISK_SCORE/10)${NC}"
    done < "$output_dir/docker/image_list.txt"

    # Update summary file with totals
    {
        echo "VULNERABILITY SUMMARY ACROSS ALL IMAGES:"
        echo "Critical: $CRITICAL_COUNT"
        echo "High: $HIGH_COUNT"
        echo "Medium: $MEDIUM_COUNT"
        echo "Low: $LOW_COUNT"
        echo
        echo "Images with critical/high vulnerabilities: $(wc -l < "$output_dir/docker/vulnerable_images.txt" 2>/dev/null || echo 0)"
        echo

        if [ -s "$output_dir/docker/vulnerable_images.txt" ]; then
            echo "VULNERABLE IMAGES (Ordered by Risk):"
            sort -t'|' -k2,2nr "$output_dir/docker/image_risk_scores.txt" | awk -F'|' '{print $1 " (Risk: " $2 "/10, Critical: " $3 ", High: " $4 ")"}' | head -10
        fi
    } >> "$output_dir/docker/image_security_summary.txt"

    # Analyze Dockerfile security
    echo -e "${BLUE}[*] Looking for Dockerfiles.${NC}"
    find . -name "Dockerfile" -type f > "$output_dir/docker/dockerfile_list.txt" 2>/dev/null

    if [ -s "$output_dir/docker/dockerfile_list.txt" ]; then
        DOCKERFILE_COUNT=$(wc -l < "$output_dir/docker/dockerfile_list.txt")
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
                echo "Scan Date: $DATESTAMP $TIMESTAMP"
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
                if [ "$(grep -c "FROM" "$dockerfile")" -eq 1 ] && grep -q "COPY --from=" "$dockerfile"; then
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
            } > "$output_dir/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt"

            # Extract risk score for summary
            DOCKERFILE_RISK_SCORE=$(grep "Dockerfile Risk Score:" "$output_dir/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt" | awk '{print $4}' | cut -d'/' -f1)
            ISSUES_COUNT=$(grep "Critical issues:" "$output_dir/docker/dockerfile_analysis/dockerfile_${dockerfile_name}_analysis.txt" -A2 | awk '{sum+=$3} END {print sum}')

            if [ "$ISSUES_COUNT" -gt 0 ]; then
                echo "$dockerfile|$DOCKERFILE_RISK_SCORE|$ISSUES_COUNT" >> "$output_dir/docker/dockerfile_risk_scores.txt"
                ((DOCKERFILE_ISSUES_COUNT++))
            fi
        done < "$output_dir/docker/dockerfile_list.txt"

        # Add Dockerfile analysis to summary
        {
            echo
            echo "DOCKERFILE SECURITY ANALYSIS:"
            echo "Total Dockerfiles analyzed: $DOCKERFILE_COUNT"
            echo "Dockerfiles with security issues: $DOCKERFILE_ISSUES_COUNT"
            echo

            if [ -s "$output_dir/docker/dockerfile_risk_scores.txt" ]; then
                echo "TOP RISKY DOCKERFILES:"
                sort -t'|' -k2,2nr "$output_dir/docker/dockerfile_risk_scores.txt" | awk -F'|' '{print $1 " (Risk: " $2 "/10, Issues: " $3 ")"}' | head -5
            fi
        } >> "$output_dir/docker/image_security_summary.txt"
    fi

    echo -e "${YELLOW}[*] Docker image analysis complete! Results saved to $output_dir/docker/image_security_summary.txt${NC}"
}

###############################################################################################################################

# Function to scan Docker containers
f_scan_docker_containers(){
    local output_dir="$1"

    echo -e "${BLUE}[*] Starting comprehensive Docker container security audit.${NC}"
    mkdir -p "$output_dir/docker/containers" "$output_dir/docker/container_reports" "$output_dir/docker/runtime_analysis"

    # List all Docker containers with additional metadata
    echo -e "${BLUE}[*] Gathering container inventory.${NC}"
    docker ps -a --format "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Command}}" > "$output_dir/docker/container_inventory.tsv"
    docker ps -a --format "{{.ID}} {{.Image}} {{.Names}}" > "$output_dir/docker/container_list.txt"

    # Get running containers in a separate list
    docker ps --format "{{.ID}} {{.Image}} {{.Names}}" > "$output_dir/docker/running_containers.txt"

    # Check if there are any containers
    if [ ! -s "$output_dir/docker/container_list.txt" ]; then
        echo -e "${YELLOW}[!] No Docker containers found.${NC}"
        return
    fi

    # Count total containers
    TOTAL_CONTAINERS=$(wc -l < "$output_dir/docker/container_list.txt")
    RUNNING_CONTAINERS=$(wc -l < "$output_dir/docker/running_containers.txt" 2>/dev/null || echo 0)

    echo -e "${YELLOW}[*] Found $TOTAL_CONTAINERS containers ($RUNNING_CONTAINERS running)${NC}"

    # Create summary file
    echo "Docker Container Security Summary" > "$output_dir/docker/container_security_summary.txt"
    echo "================================" >> "$output_dir/docker/container_security_summary.txt"
    echo "Analysis Date: $DATESTAMP $TIMESTAMP" >> "$output_dir/docker/container_security_summary.txt"
    echo "Total Containers: $TOTAL_CONTAINERS" >> "$output_dir/docker/container_security_summary.txt"
    echo "Running Containers: $RUNNING_CONTAINERS" >> "$output_dir/docker/container_security_summary.txt"
    echo "" >> "$output_dir/docker/container_security_summary.txt"

    # Initialize risk counters
    CRITICAL_CONTAINERS=0
    HIGH_RISK_CONTAINERS=0
    MEDIUM_RISK_CONTAINERS=0

    # Analyze each container
    echo -e "${BLUE}[*] Performing deep security analysis of container configurations.${NC}"

    # Create detailed issue tracking files
    touch "$output_dir/docker/privileged_containers.txt"
    touch "$output_dir/docker/root_containers.txt"
    touch "$output_dir/docker/sensitive_mount_containers.txt"
    touch "$output_dir/docker/network_sensitive_containers.txt"
    touch "$output_dir/docker/capability_containers.txt"
    touch "$output_dir/docker/no_health_check_containers.txt"

    COUNTER=0
    while read -r container_info; do
        ((COUNTER++))
        container_id=$(echo "$container_info" | awk '{print $1}')
        container_image=$(echo "$container_info" | awk '{print $2}')
        container_name=$(echo "$container_info" | awk '{print $3}')

        echo -e "${BLUE}[*] [$COUNTER/$TOTAL_CONTAINERS] Analyzing container: $container_name ($container_id)${NC}"

        # Get container details
        docker inspect "$container_id" > "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null

        # Extract container status
        CONTAINER_STATUS=$(jq -r '.[0].State.Status' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
        CONTAINER_CREATED=$(jq -r '.[0].Created' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
        CONTAINER_PLATFORM=$(jq -r '.[0].Platform' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)

        # Initialize security issue counter for this container
        CRITICAL_ISSUES=0
        HIGH_ISSUES=0
        MEDIUM_ISSUES=0

        # Prepare container security report
        {
            echo "Container Security Analysis: $container_name"
            echo "====================================="
            echo "Analysis Date: $DATESTAMP $TIMESTAMP"
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
            privileged=$(jq -r '.[0].HostConfig.Privileged' "$output_dir/docker/containers/${container_name}_inspect.json")
            if [ "$privileged" = "true" ]; then
                echo "CRITICAL: Container is running in privileged mode (full access to host devices)"
                echo "$container_name" >> "$output_dir/docker/privileged_containers.txt"
                ((CRITICAL_ISSUES++))
            fi

            # Check for user running container (root vs non-root)
            user=$(jq -r '.[0].Config.User' "$output_dir/docker/containers/${container_name}_inspect.json")
            if [ -z "$user" ] || [ "$user" = "0" ] || [ "$user" = "root" ]; then
                echo "HIGH-RISK: Container is running as root user"
                echo "$container_name" >> "$output_dir/docker/root_containers.txt"
                ((HIGH_ISSUES++))
            else
                echo "GOOD PRACTICE: Container is running as non-root user: $user"
            fi

            # Check for additional Linux capabilities
            caps_add=$(jq -r '.[0].HostConfig.CapAdd[]' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
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

                echo "$container_name: $caps_add" >> "$output_dir/docker/capability_containers.txt"
            fi

            # Check for sensitive env variables
            sensitive_env=$(jq -r '.[0].Config.Env[]' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null | grep -Ei "(password|token|key|secret|credential|api_key|apikey|access_key|auth)")
            if [ -n "$sensitive_env" ]; then
                echo "CRITICAL: Container has sensitive environment variables (potential secret exposure):"
                echo "$sensitive_env" | sed 's/^/  /' | cut -d'=' -f1
                ((CRITICAL_ISSUES++))
            fi

            # Check for mounted sensitive directories
            sensitive_mounts=$(jq -r '.[0].Mounts[] | select(.Source | test("/etc|/var/run|/var/lib|/usr|/root|/.ssh|/.aws|/.kube|/docker.sock"))' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
            if [ -n "$sensitive_mounts" ]; then
                echo "HIGH-RISK: Container has sensitive host directories mounted:"
                jq -r '.[0].Mounts[] | select(.Source | test("/etc|/var/run|/var/lib|/usr|/root|/.ssh|/.aws|/.kube|/docker.sock")) | .Source + " -> " + .Destination' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null | sed 's/^/  /'
                echo "$container_name" >> "$output_dir/docker/sensitive_mount_containers.txt"

                # Check specifically for docker.sock which is especially dangerous
                if jq -r '.[0].Mounts[].Source' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null | grep -q "/var/run/docker.sock"; then
                    echo "CRITICAL: Container has docker.sock mounted - this allows complete control of the host Docker daemon!"
                    ((CRITICAL_ISSUES++))
                else
                    ((HIGH_ISSUES++))
                fi
            fi

            # Check for network mode
            network_mode=$(jq -r '.[0].HostConfig.NetworkMode' "$output_dir/docker/containers/${container_name}_inspect.json")
            if [ "$network_mode" = "host" ]; then
                echo "HIGH-RISK: Container is using host network mode (no network isolation)"
                echo "$container_name" >> "$output_dir/docker/network_sensitive_containers.txt"
                ((HIGH_ISSUES++))
            fi

            # Check for PID mode
            pid_mode=$(jq -r '.[0].HostConfig.PidMode' "$output_dir/docker/containers/${container_name}_inspect.json")
            if [ "$pid_mode" = "host" ]; then
                echo "HIGH-RISK: Container is using host PID mode (can see all processes on host)"
                echo "$container_name" >> "$output_dir/docker/network_sensitive_containers.txt"
                ((HIGH_ISSUES++))
            fi

            # Check for IPC mode
            ipc_mode=$(jq -r '.[0].HostConfig.IpcMode' "$output_dir/docker/containers/${container_name}_inspect.json")
            if [ "$ipc_mode" = "host" ]; then
                echo "MEDIUM-RISK: Container is using host IPC mode (shared memory with host)"
                echo "$container_name" >> "$output_dir/docker/network_sensitive_containers.txt"
                ((MEDIUM_ISSUES++))
            fi

            # Check for port bindings (especially sensitive ports)
            port_bindings=$(jq -r '.[0].HostConfig.PortBindings | keys[]' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
            if [ -n "$port_bindings" ]; then
                echo "INFO: Container exposes the following ports:"
                jq -r '.[0].HostConfig.PortBindings | to_entries[] | .key + " -> " + (.value[0].HostPort // "ephemeral")' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null | sed 's/^/  /'

                # Check for sensitive ports
                if echo "$port_bindings" | grep -qE '22/|3306/|5432/|27017/|6379/|9200/|8080/|443/|80/'; then
                    echo "MEDIUM-RISK: Container exposes sensitive ports that may require additional security measures"
                    ((MEDIUM_ISSUES++))
                fi
            fi

            # Check read-only filesystem
            readonly_fs=$(jq -r '.[0].HostConfig.ReadonlyRootfs' "$output_dir/docker/containers/${container_name}_inspect.json")
            if [ "$readonly_fs" = "true" ]; then
                echo "GOOD PRACTICE: Container uses read-only root filesystem"
            else
                echo "MEDIUM-RISK: Container does not use read-only root filesystem"
                ((MEDIUM_ISSUES++))
            fi

            # Check for health checks
            health_check=$(jq -r '.[0].Config.Healthcheck' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
            if [ "$health_check" = "null" ] || [ -z "$health_check" ]; then
                echo "MEDIUM-RISK: Container does not have a health check defined"
                echo "$container_name" >> "$output_dir/docker/no_health_check_containers.txt"
                ((MEDIUM_ISSUES++))
            else
                echo "GOOD PRACTICE: Container has health check defined"
            fi

            # Check for restart policy
            restart_policy=$(jq -r '.[0].HostConfig.RestartPolicy.Name' "$output_dir/docker/containers/${container_name}_inspect.json")
            if [ "$restart_policy" = "no" ] || [ -z "$restart_policy" ]; then
                echo "INFO: Container has no restart policy defined"
            else
                echo "GOOD PRACTICE: Container has restart policy: $restart_policy"
            fi

            # Check for security options
            security_opts=$(jq -r '.[0].HostConfig.SecurityOpt[]' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
            if [ -n "$security_opts" ]; then
                echo "GOOD PRACTICE: Container uses security options:"
                echo "$security_opts" | sed 's/^/  /'
            else
                echo "MEDIUM-RISK: Container does not use any security options (e.g., seccomp, apparmor)"
                ((MEDIUM_ISSUES++))
            fi

            # Check for AppArmor profile
            apparmor_profile=$(jq -r '.[0].AppArmorProfile' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
            if [ -z "$apparmor_profile" ] || [ "$apparmor_profile" = "unconfined" ]; then
                echo "MEDIUM-RISK: Container does not use AppArmor confinement"
                ((MEDIUM_ISSUES++))
            else
                echo "GOOD PRACTICE: Container uses AppArmor profile: $apparmor_profile"
            fi

            # Check for Seccomp profile
            seccomp_profile=$(jq -r '.[0].HostConfig.SecurityOpt[] | select(startswith("seccomp"))' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
            if [ -z "$seccomp_profile" ]; then
                echo "MEDIUM-RISK: Container does not use custom Seccomp profile"
                ((MEDIUM_ISSUES++))
            else
                echo "GOOD PRACTICE: Container uses Seccomp profile"
            fi

            # Check for memory limits
            memory_limit=$(jq -r '.[0].HostConfig.Memory' "$output_dir/docker/containers/${container_name}_inspect.json")
            if [ "$memory_limit" = "0" ]; then
                echo "MEDIUM-RISK: Container has no memory limits set (potential DoS vector)"
                ((MEDIUM_ISSUES++))
            else
                mem_human=$(echo "$memory_limit" | numfmt --to=iec-i)
                echo "GOOD PRACTICE: Container has memory limit: $mem_human"
            fi

            # Check for CPU limits
            cpu_limit=$(jq -r '.[0].HostConfig.CpuShares' "$output_dir/docker/containers/${container_name}_inspect.json")
            if [ "$cpu_limit" = "0" ]; then
                echo "INFO: Container has no CPU limits set"
            else
                echo "GOOD PRACTICE: Container has CPU limits set: $cpu_limit shares"
            fi

            # Look for common vulnerable software patterns in commands/entrypoint
            cmd=$(jq -r '.[0].Config.Cmd[]' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
            entrypoint=$(jq -r '.[0].Config.Entrypoint[]' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)

            # Check running commands for potential issues
            if echo "$cmd $entrypoint" | grep -qiE 'telnet|ftp|eval|exec|nc -l|netcat -l'; then
                echo "HIGH-RISK: Container command/entrypoint contains potentially unsafe operations"
                echo "Command: $cmd"
                echo "Entrypoint: $entrypoint"
                ((HIGH_ISSUES++))
            fi

            # Check for tmpfs mounts (good security practice)
            tmpfs_mounts=$(jq -r '.[0].HostConfig.Tmpfs' "$output_dir/docker/containers/${container_name}_inspect.json" 2>/dev/null)
            if [ -n "$tmpfs_mounts" ] && [ "$tmpfs_mounts" != "null" ]; then
                echo "GOOD PRACTICE: Container uses tmpfs mounts for sensitive temporary data"
            fi

            # Generate risk score (weighted calculation)
            # Scale: 1-10, with 10 being highest risk
            CONTAINER_RISK_SCORE=$(( (CRITICAL_ISSUES * 10 + HIGH_ISSUES * 5 + MEDIUM_ISSUES * 2) ))
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
            echo "For full container inspection details, see: $output_dir/docker/containers/${container_name}_inspect.json"

        } > "$output_dir/docker/container_reports/${container_name}_security_analysis.txt"

        # Update global counters based on risk level
        if [ "$CRITICAL_ISSUES" -gt 0 ]; then
            ((CRITICAL_CONTAINERS++))
        elif [ "$HIGH_ISSUES" -gt 0 ]; then
            ((HIGH_RISK_CONTAINERS++))
        elif [ "$MEDIUM_ISSUES" -gt 0 ]; then
            ((MEDIUM_RISK_CONTAINERS++))
        fi

        # Generate machine-readable risk data
        echo "$container_name|$container_id|$CONTAINER_RISK_SCORE|$CRITICAL_ISSUES|$HIGH_ISSUES|$MEDIUM_ISSUES" >> "$output_dir/docker/container_risk_scores.txt"

        # If container is running, perform additional runtime checks
        if docker ps -q | grep -q "$container_id"; then
            echo -e "${BLUE}[*] Performing runtime analysis of container: $container_name${NC}"

            # Create directory for runtime analysis
            mkdir -p "$output_dir/docker/runtime_analysis/$container_name"

            # Get process list
            docker top "$container_id" aux > "$output_dir/docker/runtime_analysis/$container_name/processes.txt" 2>/dev/null

            # Get network information
            docker exec "$container_id" netstat -tulpn > "$output_dir/docker/runtime_analysis/$container_name/netstat.txt" 2>/dev/null || true

            # Check for listening ports inside container
            docker exec "$container_id" netstat -tulpn | grep LISTEN > "$output_dir/docker/runtime_analysis/$container_name/listening_ports.txt" 2>/dev/null || true

            # Get environment variables in running container
            docker exec "$container_id" env > "$output_dir/docker/runtime_analysis/$container_name/environment.txt" 2>/dev/null || true

            # Check for setuid/setgid binaries
            docker exec "$container_id" find / -perm /6000 -type f 2>/dev/null > "$output_dir/docker/runtime_analysis/$container_name/setuid_setgid_binaries.txt" || true

            echo -e "${YELLOW}[*] Runtime analysis complete for container: $container_name${NC}"
        fi
    done < "$output_dir/docker/container_list.txt"

    # Update summary with risk breakdown
    {
        echo "CONTAINER SECURITY RISK SUMMARY:"
        echo "Critical risk containers: $CRITICAL_CONTAINERS"
        echo "High risk containers: $HIGH_RISK_CONTAINERS"
        echo "Medium risk containers: $MEDIUM_RISK_CONTAINERS"
        echo "Low risk containers: $(( TOTAL_CONTAINERS - CRITICAL_CONTAINERS - HIGH_RISK_CONTAINERS - MEDIUM_RISK_CONTAINERS ))"
        echo

        # List top risky containers
        if [ -s "$output_dir/docker/container_risk_scores.txt" ]; then
            echo "TOP RISKY CONTAINERS:"
            sort -t'|' -k3,3nr "$output_dir/docker/container_risk_scores.txt" | head -5 | \
                awk -F'|' '{print $1 " (" $2 "): Risk Score " $3 "/10, Critical: " $4 ", High: " $5 ", Medium: " $6}'
        fi

        echo
        echo "SECURITY ISSUE BREAKDOWN:"
        echo "Privileged containers: $(wc -l < "$output_dir/docker/privileged_containers.txt" 2>/dev/null || echo 0)"
        echo "Root user containers: $(wc -l < "$output_dir/docker/root_containers.txt" 2>/dev/null || echo 0)"
        echo "Sensitive mount containers: $(wc -l < "$output_dir/docker/sensitive_mount_containers.txt" 2>/dev/null || echo 0)"
        echo "Host network mode containers: $(wc -l < "$output_dir/docker/network_sensitive_containers.txt" 2>/dev/null || echo 0)"
        echo "Containers with added capabilities: $(wc -l < "$output_dir/docker/capability_containers.txt" 2>/dev/null || echo 0)"
        echo "Containers without health checks: $(wc -l < "$output_dir/docker/no_health_check_containers.txt" 2>/dev/null || echo 0)"
    } >> "$output_dir/docker/container_security_summary.txt"

    echo -e "${YELLOW}[*] Container security analysis complete! Results saved to $output_dir/docker/container_security_summary.txt${NC}"
}

###############################################################################################################################

# Function to scan Kubernetes resources
f_scan_kubernetes(){
    local output_dir="$1"

    echo -e "${BLUE}[*] Starting comprehensive Kubernetes security audit.${NC}"
    mkdir -p "$output_dir/kubernetes/cluster" "$output_dir/kubernetes/resources" "$output_dir/kubernetes/vulnerabilities" "$output_dir/kubernetes/security_reports" "$output_dir/kubernetes/rbac" "$output_dir/kubernetes/workloads" "$output_dir/kubernetes/network"

    # Initialize summary file
    echo "Kubernetes Security Audit Report" > "$output_dir/kubernetes/kubernetes_security_summary.txt"
    echo "==============================" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"
    echo "Analysis Date: $DATESTAMP $TIMESTAMP" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"
    echo "" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"

    # Check if kubectl can connect to a cluster
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${YELLOW}[!] Cannot connect to Kubernetes cluster. Skipping Kubernetes scan.${NC}"
        echo "ERROR: Could not connect to Kubernetes cluster. Scan aborted." >> "$output_dir/kubernetes/kubernetes_security_summary.txt"
        return
    fi

    # Get cluster info
    echo -e "${BLUE}[*] Gathering Kubernetes cluster information.${NC}"
    kubectl cluster-info > "$output_dir/kubernetes/cluster/cluster_info.txt" 2>/dev/null
    kubectl version --output=json > "$output_dir/kubernetes/cluster/version.json" 2>/dev/null

    # Extract important cluster metadata
    SERVER_VERSION=$(jq -r '.serverVersion.gitVersion' "$output_dir/kubernetes/cluster/version.json" 2>/dev/null)

    # Check Kubernetes version for known vulnerabilities
    echo -e "${BLUE}[*] Checking Kubernetes version for known vulnerabilities.${NC}"
    MAJOR_VERSION=$(echo "$SERVER_VERSION" | cut -d'.' -f1 | tr -d 'v')
    MINOR_VERSION=$(echo "$SERVER_VERSION" | cut -d'.' -f2)

    K8S_VERSION_ISSUES=0
    if [ "$MAJOR_VERSION" -lt 1 ] || ([ "$MAJOR_VERSION" -eq 1 ] && [ "$MINOR_VERSION" -lt 19 ]); then
        echo -e "${RED}[!] WARNING: Kubernetes version $SERVER_VERSION is outdated and may have known security vulnerabilities${NC}"
        echo "CRITICAL: Kubernetes version $SERVER_VERSION is outdated (current stable is 1.26+)" >> "$output_dir/kubernetes/cluster/version_issues.txt"
        K8S_VERSION_ISSUES=1
    elif [ "$MAJOR_VERSION" -eq 1 ] && [ "$MINOR_VERSION" -lt 24 ]; then
        echo -e "${YELLOW}[!] WARNING: Kubernetes version $SERVER_VERSION is not the latest. Consider upgrading.${NC}"
        echo "WARNING: Kubernetes version $SERVER_VERSION is not the latest. Consider upgrading to 1.26+" >> "$output_dir/kubernetes/cluster/version_issues.txt"
        K8S_VERSION_ISSUES=1
    else
        echo -e "${YELLOW}[*] Kubernetes version $SERVER_VERSION is recent${NC}"
    fi

    # Add version info to summary
    echo "CLUSTER INFORMATION:" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"
    echo "Kubernetes Version: $SERVER_VERSION" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"

    if [ "$K8S_VERSION_ISSUES" -eq 1 ]; then
        echo "Version Status: Outdated - see version_issues.txt for details" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"
    else
        echo "Version Status: Current" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"
    fi

    echo "" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"

    # Collect node information
    echo -e "${BLUE}[*] Gathering node information.${NC}"
    kubectl get nodes -o wide > "$output_dir/kubernetes/cluster/nodes_info.txt" 2>/dev/null
    kubectl get nodes -o json > "$output_dir/kubernetes/cluster/nodes.json" 2>/dev/null

    # Count and analyze nodes
    NODE_COUNT=$(jq -r '.items | length' "$output_dir/kubernetes/cluster/nodes.json" 2>/dev/null)
    echo "Node Count: $NODE_COUNT" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"

    # Check node versions for consistency
    echo -e "${BLUE}[*] Checking for node version consistency.${NC}"
    kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\n"}{end}' > "$output_dir/kubernetes/cluster/node_versions.txt" 2>/dev/null

    NODE_VERSION_COUNT=$(awk '{print $2}' "$output_dir/kubernetes/cluster/node_versions.txt" | sort | uniq | wc -l)
    if [ "$NODE_VERSION_COUNT" -gt 1 ]; then
        echo -e "${YELLOW}[!] Multiple Kubernetes versions detected across nodes. This could lead to unexpected behavior${NC}"
        echo "WARNING: Cluster has nodes running $NODE_VERSION_COUNT different Kubernetes versions" >> "$output_dir/kubernetes/cluster/node_issues.txt"
        echo "Node Version Consistency: INCONSISTENT ($NODE_VERSION_COUNT versions)" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"
    else
        echo -e "${YELLOW}[*] All nodes running the same Kubernetes version${NC}"
        echo "Node Version Consistency: CONSISTENT" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"
    fi

    echo "" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"

    # Get and analyze all namespaces
    echo -e "${BLUE}[*] Enumerating and analyzing Kubernetes namespaces.${NC}"
    kubectl get namespaces -o json > "$output_dir/kubernetes/resources/namespaces.json" 2>/dev/null
    kubectl get namespaces > "$output_dir/kubernetes/resources/namespaces.txt" 2>/dev/null

    # Save namespaces in a list
    jq -r '.items[].metadata.name' "$output_dir/kubernetes/resources/namespaces.json" > "$output_dir/kubernetes/resources/namespace_list.txt" 2>/dev/null

    # Count namespaces
    NAMESPACE_COUNT=$(wc -l < "$output_dir/kubernetes/resources/namespace_list.txt")
    echo -e "${YELLOW}[*] Found $NAMESPACE_COUNT namespaces${NC}"
    echo "Namespace Count: $NAMESPACE_COUNT" >> "$output_dir/kubernetes/kubernetes_security_summary.txt"

    # Initialize resource counters for various types
    TOTAL_DEPLOYMENTS=0
    TOTAL_PODS=0
    TOTAL_PRIVILEGED_PODS=0
    TOTAL_HOSTNETWORK_PODS=0
    TOTAL_HOSTPATH_PODS=0
    TOTAL_ROOT_PODS=0
    TOTAL_SERVICES=0
    TOTAL_INGRESSES=0
    TOTAL_SECRETS=0
    TOTAL_CONFIGMAPS=0

    # Initialize map files for tracking issues
    touch "$output_dir/kubernetes/vulnerabilities/privileged_pods.txt"
    touch "$output_dir/kubernetes/vulnerabilities/hostnetwork_pods.txt"
    touch "$output_dir/kubernetes/vulnerabilities/hostpath_volumes.txt"
    touch "$output_dir/kubernetes/vulnerabilities/root_pods.txt"
    touch "$output_dir/kubernetes/vulnerabilities/no_resource_limits.txt"
    touch "$output_dir/kubernetes/vulnerabilities/deprecated_apis.txt"
    touch "$output_dir/kubernetes/vulnerabilities/insecure_capabilities.txt"
    touch "$output_dir/kubernetes/vulnerabilities/secrets_as_env.txt"

    # For each namespace, get and analyze all resources
    echo -e "${BLUE}[*] Starting detailed namespace analysis.${NC}"
    NAMESPACE_COUNTER=0

    while read -r namespace; do
        ((NAMESPACE_COUNTER++))
        echo -e "${BLUE}[*] Analyzing namespace [$NAMESPACE_COUNTER/$NAMESPACE_COUNT]: $namespace${NC}"
        mkdir -p "$output_dir/kubernetes/workloads/$namespace" "$output_dir/kubernetes/network/$namespace" "$output_dir/kubernetes/security_reports/$namespace"

        # Create namespace summary file
        echo "Security Analysis for Namespace: $namespace" > "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "=================================" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

        # Get all resource types in namespace
        echo -e "${BLUE}[*] Collecting all resources in namespace: $namespace${NC}"
        kubectl api-resources --verbs=list --namespaced -o name | xargs -n 1 kubectl get --show-kind --ignore-not-found -n "$namespace" > "$output_dir/kubernetes/resources/$namespace-all_resources.txt" 2>/dev/null

        # Get workload resources
        kubectl get deployments,statefulsets,daemonsets,replicasets,pods -n "$namespace" -o json > "$output_dir/kubernetes/workloads/$namespace/workloads.json" 2>/dev/null

        # Get network resources
        kubectl get services,ingresses,networkpolicies -n "$namespace" -o json > "$output_dir/kubernetes/network/$namespace/network.json" 2>/dev/null

        # Get secrets and config resources
        kubectl get secrets,configmaps -n "$namespace" -o json > "$output_dir/kubernetes/workloads/$namespace/configs.json" 2>/dev/null

        # Get specific counts
        DEPLOYMENT_COUNT=$(kubectl get deployments -n "$namespace" 2>/dev/null | grep -v NAME | wc -l)
        POD_COUNT=$(kubectl get pods -n "$namespace" 2>/dev/null | grep -v NAME | wc -l)
        SERVICE_COUNT=$(kubectl get services -n "$namespace" 2>/dev/null | grep -v NAME | wc -l)
        INGRESS_COUNT=$(kubectl get ingresses -n "$namespace" 2>/dev/null | grep -v NAME | wc -l 2>/dev/null || echo 0)
        SECRET_COUNT=$(kubectl get secrets -n "$namespace" 2>/dev/null | grep -v NAME | wc -l)
        CONFIGMAP_COUNT=$(kubectl get configmaps -n "$namespace" 2>/dev/null | grep -v NAME | wc -l)

        # Update total counters
        TOTAL_DEPLOYMENTS=$((TOTAL_DEPLOYMENTS + DEPLOYMENT_COUNT))
        TOTAL_PODS=$((TOTAL_PODS + POD_COUNT))
        TOTAL_SERVICES=$((TOTAL_SERVICES + SERVICE_COUNT))
        TOTAL_INGRESSES=$((TOTAL_INGRESSES + INGRESS_COUNT))
        TOTAL_SECRETS=$((TOTAL_SECRETS + SECRET_COUNT))
        TOTAL_CONFIGMAPS=$((TOTAL_CONFIGMAPS + CONFIGMAP_COUNT))

        # Add to namespace summary
        echo "Resource Counts:" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Deployments: $DEPLOYMENT_COUNT" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Pods: $POD_COUNT" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Services: $SERVICE_COUNT" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Ingresses: $INGRESS_COUNT" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Secrets: $SECRET_COUNT" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "- ConfigMaps: $CONFIGMAP_COUNT" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

        # Security Analysis
        echo -e "${BLUE}[*] Performing security analysis for namespace: $namespace${NC}"

        # Check pods for security issues
        if [ "$POD_COUNT" -gt 0 ]; then
            echo "POD SECURITY ANALYSIS:" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

            # Check for privileged containers
            PRIV_PODS=$(kubectl get pods -n "$namespace" -o json | jq -r '.items[] | select(any(.spec.containers[]; .securityContext.privileged == true)) | .metadata.name' 2>/dev/null)
            if [ -n "$PRIV_PODS" ]; then
                PRIV_POD_COUNT=$(echo "$PRIV_PODS" | wc -l)
                echo "WARNING: Found $PRIV_POD_COUNT pods with privileged containers" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
                echo "$PRIV_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$output_dir/kubernetes/vulnerabilities/privileged_pods.txt"
                done
                TOTAL_PRIVILEGED_PODS=$((TOTAL_PRIVILEGED_PODS + PRIV_POD_COUNT))
            else
                echo "GOOD: No privileged containers found" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for hostNetwork
            HOSTNET_PODS=$(kubectl get pods -n "$namespace" -o json | jq -r '.items[] | select(.spec.hostNetwork == true) | .metadata.name' 2>/dev/null)
            if [ -n "$HOSTNET_PODS" ]; then
                HOSTNET_POD_COUNT=$(echo "$HOSTNET_PODS" | wc -l)
                echo "WARNING: Found $HOSTNET_POD_COUNT pods using host network" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
                echo "$HOSTNET_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$output_dir/kubernetes/vulnerabilities/hostnetwork_pods.txt"
                done
                TOTAL_HOSTNETWORK_PODS=$((TOTAL_HOSTNETWORK_PODS + HOSTNET_POD_COUNT))
            else
                echo "GOOD: No pods using host network" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for hostPath volumes
            HOSTPATH_PODS=$(kubectl get pods -n "$namespace" -o json | jq -r '.items[] | select(any(.spec.volumes[]; .hostPath != null)) | .metadata.name' 2>/dev/null)
            if [ -n "$HOSTPATH_PODS" ]; then
                HOSTPATH_POD_COUNT=$(echo "$HOSTPATH_PODS" | wc -l)
                echo "WARNING: Found $HOSTPATH_POD_COUNT pods using hostPath volumes" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
                echo "$HOSTPATH_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$output_dir/kubernetes/vulnerabilities/hostpath_volumes.txt"
                done
                TOTAL_HOSTPATH_PODS=$((TOTAL_HOSTPATH_PODS + HOSTPATH_POD_COUNT))
            else
                echo "GOOD: No pods using hostPath volumes" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for root containers
            ROOT_PODS=$(kubectl get pods -n "$namespace" -o json | jq -r '.items[] | select(any(.spec.containers[]; .securityContext.runAsNonRoot != true and (.securityContext.runAsUser == null or .securityContext.runAsUser == 0))) | .metadata.name' 2>/dev/null)
            if [ -n "$ROOT_PODS" ]; then
                ROOT_POD_COUNT=$(echo "$ROOT_PODS" | wc -l)
                echo "WARNING: Found $ROOT_POD_COUNT pods running as root" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
                echo "$ROOT_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$output_dir/kubernetes/vulnerabilities/root_pods.txt"
                done
                TOTAL_ROOT_PODS=$((TOTAL_ROOT_PODS + ROOT_POD_COUNT))
            else
                echo "GOOD: No pods running as root" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for missing resource limits
            NOLIMIT_PODS=$(kubectl get pods -n "$namespace" -o json | jq -r '.items[] | select(any(.spec.containers[]; .resources.limits == null or .resources.limits.cpu == null or .resources.limits.memory == null)) | .metadata.name' 2>/dev/null)
            if [ -n "$NOLIMIT_PODS" ]; then
                NOLIMIT_POD_COUNT=$(echo "$NOLIMIT_PODS" | wc -l)
                echo "WARNING: Found $NOLIMIT_POD_COUNT pods without complete resource limits" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
                echo "$NOLIMIT_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$output_dir/kubernetes/vulnerabilities/no_resource_limits.txt"
                done
            else
                echo "GOOD: All pods have resource limits defined" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            fi

            echo "" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        # Network Security Analysis 
        if [ "$SERVICE_COUNT" -gt 0 ] || [ "$INGRESS_COUNT" -gt 0 ]; then
            echo "NETWORK SECURITY ANALYSIS:" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

            # Check for NodePort services
            NODEPORT_SERVICES=$(kubectl get services -n "$namespace" -o json | jq -r '.items[] | select(.spec.type == "NodePort") | .metadata.name' 2>/dev/null)
            if [ -n "$NODEPORT_SERVICES" ]; then
                NODEPORT_COUNT=$(echo "$NODEPORT_SERVICES" | wc -l)
                echo "INFO: Found $NODEPORT_COUNT NodePort services (ensure these are properly secured)" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for LoadBalancer services
            LB_SERVICES=$(kubectl get services -n "$namespace" -o json | jq -r '.items[] | select(.spec.type == "LoadBalancer") | .metadata.name' 2>/dev/null)
            if [ -n "$LB_SERVICES" ]; then
                LB_COUNT=$(echo "$LB_SERVICES" | wc -l)
                echo "INFO: Found $LB_COUNT LoadBalancer services (ensure these are properly secured)" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for Network Policies
            NP_COUNT=$(kubectl get networkpolicies -n "$namespace" 2>/dev/null | grep -v NAME | wc -l)
            if [ "$NP_COUNT" -eq 0 ]; then
                echo "WARNING: No NetworkPolicies found in namespace. Consider implementing network segmentation." >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            else
                echo "GOOD: Found $NP_COUNT NetworkPolicies" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            fi

            echo "" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        # Secrets analysis
        if [ "$SECRET_COUNT" -gt 0 ]; then
            echo "SECRETS ANALYSIS:" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

            # Check for secrets mounted as environment variables (less secure than volumes)
            SECRET_ENV_PODS=$(kubectl get pods -n "$namespace" -o json | jq -r '.items[] | select(any(.spec.containers[]; any(.env[]; .valueFrom.secretKeyRef != null))) | .metadata.name' 2>/dev/null)
            if [ -n "$SECRET_ENV_PODS" ]; then
                SECRET_ENV_COUNT=$(echo "$SECRET_ENV_PODS" | wc -l)
                echo "INFO: Found $SECRET_ENV_COUNT pods using secrets as environment variables" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
                echo "$SECRET_ENV_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$output_dir/kubernetes/vulnerabilities/secrets_as_env.txt"
                done
            fi

            # List any default-token secrets that might be automatically mounted
            DEFAULT_TOKEN=$(kubectl get secrets -n "$namespace" | grep -c "default-token")
            if [ "$DEFAULT_TOKEN" -gt 0 ]; then
                echo "INFO: Found default-token secrets that are auto-mounted in pods" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
            fi

            echo "" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        # Check RBAC permissions in namespace
        echo "RBAC ANALYSIS:" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

        # Get roles and role bindings
        kubectl get roles,rolebindings -n "$namespace" -o json > "$output_dir/kubernetes/rbac/$namespace-rbac.json" 2>/dev/null

        # Check for permissive roles
        PERMISSIVE_ROLES=$(jq -r '.items[] | select(.kind == "Role") | select(any(.rules[]; .resources[] == "*" and .verbs[] == "*")) | .metadata.name' "$output_dir/kubernetes/rbac/$namespace-rbac.json" 2>/dev/null)
        if [ -n "$PERMISSIVE_ROLES" ]; then
            PERMISSIVE_ROLE_COUNT=$(echo "$PERMISSIVE_ROLES" | wc -l)
            echo "WARNING: Found $PERMISSIVE_ROLE_COUNT overly permissive roles with wildcard resources and verbs" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        else
            echo "GOOD: No overly permissive roles found" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        # Check service accounts with elevated permissions
        SA_WITH_BINDINGS=$(jq -r '.items[] | select(.kind == "RoleBinding") | select(.subjects[] | select(.kind == "ServiceAccount")) | .metadata.name' "$output_dir/kubernetes/rbac/$namespace-rbac.json" 2>/dev/null)
        if [ -n "$SA_WITH_BINDINGS" ]; then
            SA_BINDING_COUNT=$(echo "$SA_WITH_BINDINGS" | wc -l)
            echo "INFO: Found $SA_BINDING_COUNT role bindings to service accounts" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        echo "" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

        # Summarize namespace security posture
        echo "NAMESPACE SECURITY SCORE:" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

        # Initialize score (10 = most secure)
        SECURITY_SCORE=10

        # Deduct points for security issues
        if [ -n "$PRIV_PODS" ]; then SECURITY_SCORE=$((SECURITY_SCORE - 2)); fi
        if [ -n "$HOSTNET_PODS" ]; then SECURITY_SCORE=$((SECURITY_SCORE - 2)); fi
        if [ -n "$HOSTPATH_PODS" ]; then SECURITY_SCORE=$((SECURITY_SCORE - 2)); fi
        if [ -n "$ROOT_PODS" ]; then SECURITY_SCORE=$((SECURITY_SCORE - 1)); fi
        if [ "$NP_COUNT" -eq 0 ] && [ "$POD_COUNT" -gt 0 ]; then SECURITY_SCORE=$((SECURITY_SCORE - 1)); fi
        if [ -n "$PERMISSIVE_ROLES" ]; then SECURITY_SCORE=$((SECURITY_SCORE - 2)); fi

        # Ensure score doesn't go below 1
        if [ "$SECURITY_SCORE" -lt 1 ]; then SECURITY_SCORE=1; fi

        # Record the score
        echo "Security Score: $SECURITY_SCORE/10" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "$namespace|$SECURITY_SCORE|$POD_COUNT" >> "$output_dir/kubernetes/namespace_security_scores.txt"

        # Add recommendations
        echo "" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "SECURITY RECOMMENDATIONS:" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

        if [ -n "$PRIV_PODS" ]; then
            echo "- Avoid using privileged containers when possible" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$HOSTNET_PODS" ]; then
            echo "- Avoid using host network namespace" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$HOSTPATH_PODS" ]; then
            echo "- Avoid using hostPath volumes, prefer PersistentVolumes instead" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$ROOT_PODS" ]; then
            echo "- Run containers as non-root users with runAsNonRoot: true" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$NOLIMIT_PODS" ]; then
            echo "- Set resource limits for all containers to prevent resource exhaustion attacks" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ "$NP_COUNT" -eq 0 ] && [ "$POD_COUNT" -gt 0 ]; then
            echo "- Implement NetworkPolicies to enforce network segmentation" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$PERMISSIVE_ROLES" ]; then
            echo "- Refine RBAC roles to use least privilege principle instead of wildcard permissions" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        fi

        echo "- Implement Pod Security Policies or Pod Security Standards" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Use Secret management solutions instead of Kubernetes Secrets for sensitive data" >> "$output_dir/kubernetes/security_reports/$namespace/summary.txt"

        echo -e "${YELLOW}[*] Completed security analysis for namespace: $namespace${NC}"
    done < "$output_dir/kubernetes/resources/namespace_list.txt"

    # Check cluster-wide RBAC
    echo -e "${BLUE}[*] Analyzing cluster-wide RBAC settings.${NC}"
    mkdir -p "$output_dir/kubernetes/rbac/cluster-wide"

    # Get cluster roles and bindings
    kubectl get clusterroles,clusterrolebindings -o json > "$output_dir/kubernetes/rbac/cluster-roles.json" 2>/dev/null

    # Check for overly permissive cluster roles
    echo -e "${BLUE}[*] Checking for overly permissive cluster roles.${NC}"
    jq -r '.items[] | select(.kind == "ClusterRole") | select(any(.rules[]; .resources[] == "*" and .verbs[] == "*")) | .metadata.name' "$output_dir/kubernetes/rbac/cluster-roles.json" > "$output_dir/kubernetes/rbac/cluster-wide/permissive_cluster_roles.txt" 2>/dev/null

    PERMISSIVE_CLUSTER_ROLES=$(wc -l < "$output_dir/kubernetes/rbac/cluster-wide/permissive_cluster_roles.txt" 2>/dev/null || echo 0)
    if [ "$PERMISSIVE_CLUSTER_ROLES" -gt 0 ]; then
        echo -e "${RED}[!] WARNING: Found $PERMISSIVE_CLUSTER_ROLES overly permissive cluster roles${NC}"
    fi

    # Check for dangerous subjects in cluster role bindings
    echo -e "${BLUE}[*] Checking for dangerous cluster role bindings.${NC}"
    jq -r '.items[] | select(.kind == "ClusterRoleBinding") | select(.roleRef.name == "cluster-admin") | .subjects[] | select(.kind == "Group" and .name == "system:authenticated") | "CRITICAL: cluster-admin bound to system:authenticated"' "$output_dir/kubernetes/rbac/cluster-roles.json" > "$output_dir/kubernetes/rbac/cluster-wide/dangerous_bindings.txt" 2>/dev/null

    if [ -s "$output_dir/kubernetes/rbac/cluster-wide/dangerous_bindings.txt" ]; then
        echo -e "${RED}[!] CRITICAL: Found dangerous cluster role bindings that grant admin to all authenticated users!${NC}"
    fi

    # Generate cluster-wide RBAC summary
    {
        echo "CLUSTER-WIDE RBAC ANALYSIS"
        echo "========================="
        echo "Overly permissive cluster roles: $PERMISSIVE_CLUSTER_ROLES"

        if [ -s "$output_dir/kubernetes/rbac/cluster-wide/dangerous_bindings.txt" ]; then
            echo "CRITICAL: Found dangerous cluster role bindings (see dangerous_bindings.txt)"
        else
            echo "GOOD: No dangerous cluster role bindings found"
        fi

        echo
        echo "RECOMMENDATIONS:"
        echo "- Avoid using wildcards (*) in cluster role rules"
        echo "- Never bind cluster-admin role to broad groups like system:authenticated"
        echo "- Apply least privilege principle to all RBAC configurations"
        echo "- Regularly audit cluster role bindings"
    } > "$output_dir/kubernetes/rbac/cluster-wide/rbac_summary.txt"

    # Create comprehensive Kubernetes security summary
    echo -e "${BLUE}[*] Generating comprehensive Kubernetes security report.${NC}"

    # Add resource stats to summary
    {
        echo "RESOURCE STATISTICS:"
        echo "Total Namespaces: $NAMESPACE_COUNT"
        echo "Total Deployments: $TOTAL_DEPLOYMENTS"
        echo "Total Pods: $TOTAL_PODS"
        echo "Total Services: $TOTAL_SERVICES"
        echo "Total Ingresses: $TOTAL_INGRESSES"
        echo "Total Secrets: $TOTAL_SECRETS"
        echo "Total ConfigMaps: $TOTAL_CONFIGMAPS"
        echo

        echo "SECURITY ISSUES SUMMARY:"
        echo "Privileged Pods: $TOTAL_PRIVILEGED_PODS"
        echo "Pods with Host Network: $TOTAL_HOSTNETWORK_PODS"
        echo "Pods with Host Path Volumes: $TOTAL_HOSTPATH_PODS"
        echo "Pods Running as Root: $TOTAL_ROOT_PODS"
        echo "Overly Permissive Cluster Roles: $PERMISSIVE_CLUSTER_ROLES"
        echo

        echo "NAMESPACE SECURITY SCORES (Highest Risk First):"
        if [ -f "$output_dir/kubernetes/namespace_security_scores.txt" ]; then
            sort -t'|' -k2,2n "$output_dir/kubernetes/namespace_security_scores.txt" | head -10 | \
                awk -F'|' '{print $1 ": " $2 "/10 (" $3 " pods)"}'  
        fi
        echo

        echo "TOP SECURITY RECOMMENDATIONS:"
        echo "1. Implement Pod Security Standards to enforce security best practices"
        echo "2. Use NetworkPolicies in all namespaces to restrict pod-to-pod traffic"
        echo "3. Avoid running containers as root or with privileged access"
        echo "4. Implement strict RBAC policies using least privilege principle"
        echo "5. Use tools like Trivy or Kubesec to scan workloads regularly"
        echo "6. Keep Kubernetes updated to latest stable version"
        echo "7. Use external secret management solutions instead of Kubernetes Secrets"
        echo "8. Implement resource quotas and limits on all namespaces"
        echo "9. Use image scanning and admission controllers to prevent vulnerable images"
        echo "10. Enable audit logging and implement monitoring/alerting"
    } >> "$output_dir/kubernetes/kubernetes_security_summary.txt"

    echo -e "${YELLOW}[*] Kubernetes security audit complete! Results are in $output_dir/kubernetes/kubernetes_security_summary.txt${NC}"
}

###############################################################################################################################

# Function to generate a comprehensive report
f_generate_report(){
    local output_dir="$1"

    echo -e "${BLUE}[*] Generating container security report.${NC}"
    {
        echo "Container Security Scan Report"
        echo "=============================="
        echo "Date: $DATESTAMP $TIMESTAMP"
        echo
        echo "1. Docker Image Analysis"
        echo "----------------------"

        if [ -f "$output_dir/docker/image_list.txt" ]; then
            echo "Total Docker Images: $(wc -l < "$output_dir/docker/image_list.txt")"

            if [ -f "$output_dir/docker/vulnerable_images.txt" ] && [ -s "$output_dir/docker/vulnerable_images.txt" ]; then
                echo "WARNING: The following images have HIGH or CRITICAL vulnerabilities:"
                cat "$output_dir/docker/vulnerable_images.txt"
            else
                echo "No images with HIGH or CRITICAL vulnerabilities detected."
            fi
        else
            echo "No Docker images found."
        fi

        echo
        echo "2. Docker Container Analysis"
        echo "--------------------------"

        if [ -f "$output_dir/docker/container_list.txt" ]; then
            echo "Total Docker Containers: $(wc -l < "$output_dir/docker/container_list.txt")"

            if [ -f "$output_dir/docker/privileged_containers.txt" ] && [ -s "$output_dir/docker/privileged_containers.txt" ]; then
                echo "CRITICAL: The following containers are running in privileged mode:"
                cat "$output_dir/docker/privileged_containers.txt"
            else
                echo "No containers running in privileged mode detected."
            fi
        else
            echo "No Docker containers found."
        fi

        echo
        echo "3. Dockerfile Analysis"
        echo "--------------------"

        if [ -f "$output_dir/docker/dockerfile_list.txt" ]; then
            echo "Total Dockerfiles: $(wc -l < "$output_dir/docker/dockerfile_list.txt")"

            # List Dockerfiles with issues
            for df_analysis in "$output_dir"/docker/dockerfile_*.txt; do
                if grep -q "WARNING\|CRITICAL" "$df_analysis"; then
                    echo "Issues found in $(basename "$df_analysis" | sed 's/dockerfile_//' | sed 's/.txt//'):"
                    grep "WARNING\|CRITICAL" "$df_analysis" | sed 's/^/  /'
                    echo
                fi
            done
        else
            echo "No Dockerfiles found."
        fi

        echo
        echo "4. Kubernetes Analysis"
        echo "--------------------"

        if [ -f "$output_dir/kubernetes/namespace_list.txt" ]; then
            echo "Total Kubernetes Namespaces: $(wc -l < "$output_dir/kubernetes/namespace_list.txt")"

            # List insecure pods across all namespaces
            insecure_pods_found=false
            while read -r namespace; do
                if [ -f "$output_dir/kubernetes/$namespace/insecure_pods.txt" ] && [ -s "$output_dir/kubernetes/$namespace/insecure_pods.txt" ]; then
                    echo "CRITICAL: Insecure pods in namespace $namespace:"
                    cat "$output_dir/kubernetes/$namespace/insecure_pods.txt" | sed 's/^/  /'
                    insecure_pods_found=true
                fi

                if [ -f "$output_dir/kubernetes/$namespace/root_pods.txt" ] && [ -s "$output_dir/kubernetes/$namespace/root_pods.txt" ]; then
                    echo "WARNING: Pods running as root in namespace $namespace:"
                    cat "$output_dir/kubernetes/$namespace/root_pods.txt" | sed 's/^/  /'
                    insecure_pods_found=true
                fi

                if [ -f "$output_dir/kubernetes/$namespace/sensitive_mount_pods.txt" ] && [ -s "$output_dir/kubernetes/$namespace/sensitive_mount_pods.txt" ]; then
                    echo "WARNING: Pods with sensitive host mounts in namespace $namespace:"
                    cat "$output_dir/kubernetes/$namespace/sensitive_mount_pods.txt" | sed 's/^/  /'
                    insecure_pods_found=true
                fi
            done < "$output_dir/kubernetes/namespace_list.txt"

            if [ "$insecure_pods_found" = false ]; then
                echo "No insecure Kubernetes pod configurations detected."
            fi

            # Check for permissive RBAC roles
            if [ -f "$output_dir/kubernetes/permissive_roles.txt" ] && [ -s "$output_dir/kubernetes/permissive_roles.txt" ]; then
                echo "CRITICAL: The following cluster roles have overly permissive permissions:"
                cat "$output_dir/kubernetes/permissive_roles.txt" | sed 's/^/  /'
            else
                echo "No overly permissive RBAC roles detected."
            fi
        else
            echo "No Kubernetes resources found or unable to connect to Kubernetes cluster."
        fi

    } > "$output_dir/container_security_report.txt"

    echo -e "${YELLOW}[*] Container security scan complete. Results saved to $output_dir/container_security_report.txt${NC}"
}

###############################################################################################################################

# Main function
f_container_main(){
    f_check_requirements

    echo -e "${BLUE}Container Security Scanner${NC}"

    # Parse scan type parameter
    local scan_type="$1"

    case "$scan_type" in
        "docker-images")
            echo -e "${BLUE}[*] Starting Docker image scan.${NC}"
            f_scan_docker_images "$NAME"
            f_generate_report "$NAME"
            ;;
        "docker-containers")
            echo -e "${BLUE}[*] Starting Docker container scan.${NC}"
            f_scan_docker_containers "$NAME"
            f_generate_report "$NAME"
            ;;
        "kubernetes")
            echo -e "${BLUE}[*] Starting Kubernetes scan.${NC}"
            f_scan_kubernetes "$NAME"
            f_generate_report "$NAME"
            ;;
        "all" | *)
            # Default to full scan if parameter is not recognized
            echo -e "${BLUE}[*] Starting comprehensive container security scan.${NC}"
            f_scan_docker_images "$NAME"
            f_scan_docker_containers "$NAME"
            f_scan_kubernetes "$NAME"
            f_generate_report "$NAME"
            ;;
    esac

    echo -e "${YELLOW}[*] Container security scan complete.${NC}"
    echo
}

# Run the script
f_container_main
