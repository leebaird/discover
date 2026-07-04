# Container Scanner — Kubernetes cluster audit
# Sourced by dev/container-scanner.sh

f_scan_kubernetes(){
    local OUTPUT_DIR="$1"

    f_container_should_run_phase kubernetes || { f_container_log "Skipping kubernetes (checkpoint)"; return 0; }

    echo -e "${BLUE}[*] Starting comprehensive Kubernetes security audit.${NC}"
    mkdir -p "$OUTPUT_DIR/kubernetes/cluster" "$OUTPUT_DIR/kubernetes/resources" "$OUTPUT_DIR/kubernetes/vulnerabilities" "$OUTPUT_DIR/kubernetes/security_reports" "$OUTPUT_DIR/kubernetes/rbac" "$OUTPUT_DIR/kubernetes/workloads" "$OUTPUT_DIR/kubernetes/network"

    # Initialize summary file
    echo "Kubernetes Security Audit Report" > "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"
    echo "==============================" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"
    echo "Analysis Date: $(f_container_now)" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"
    echo "" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"

    # Check if kubectl can connect to a cluster
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${YELLOW}[!] Cannot connect to Kubernetes cluster. Skipping Kubernetes scan.${NC}"
        echo "ERROR: Could not connect to Kubernetes cluster. Scan aborted." >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"
        return
    fi

    # Get cluster info
    echo -e "${BLUE}[*] Gathering Kubernetes cluster information.${NC}"
    kubectl cluster-info > "$OUTPUT_DIR/kubernetes/cluster/cluster_info.txt" 2>/dev/null
    kubectl version --output=json > "$OUTPUT_DIR/kubernetes/cluster/version.json" 2>/dev/null

    # Extract important cluster metadata
    SERVER_VERSION=$(jq -r '.serverVersion.gitVersion' "$OUTPUT_DIR/kubernetes/cluster/version.json" 2>/dev/null)

    # Check Kubernetes version for known vulnerabilities
    echo -e "${BLUE}[*] Checking Kubernetes version for known vulnerabilities.${NC}"
    MAJOR_VERSION=$(echo "$SERVER_VERSION" | cut -d'.' -f1 | tr -d 'v')
    MINOR_VERSION=$(echo "$SERVER_VERSION" | cut -d'.' -f2)

    # Version policy (refresh periodically): https://kubernetes.io/releases/
    # As of 2026-07, 1.33 and below are EOL; 1.34–1.36 are in the supported window.
    read -r K8S_EOL_MINOR K8S_CURRENT_MINOR <<< "$(f_container_k8s_version_thresholds)"
    K8S_VERSION_ISSUES=0
    if [ "$MAJOR_VERSION" -lt 1 ] || ([ "$MAJOR_VERSION" -eq 1 ] && [ "$MINOR_VERSION" -le "$K8S_EOL_MINOR" ]); then
        echo -e "${RED}[!] WARNING: Kubernetes version $SERVER_VERSION is end-of-life (no security patches)${NC}"
        echo "CRITICAL: Kubernetes version $SERVER_VERSION is end-of-life. Upgrade to 1.34+ (current stable: 1.${K8S_CURRENT_MINOR}+)." >> "$OUTPUT_DIR/kubernetes/cluster/version_issues.txt"
        K8S_VERSION_ISSUES=1
        f_container_record_finding critical kubernetes "cluster/$SERVER_VERSION" k8s_version_eol \
            "Kubernetes version is end-of-life (no security patches)" "kubernetes/cluster/version_issues.txt"
    elif [ "$MAJOR_VERSION" -eq 1 ] && [ "$MINOR_VERSION" -lt "$K8S_CURRENT_MINOR" ]; then
        echo -e "${YELLOW}[!] WARNING: Kubernetes version $SERVER_VERSION is supported but not current. Consider upgrading.${NC}"
        echo "WARNING: Kubernetes version $SERVER_VERSION is supported but not current. Consider upgrading to 1.${K8S_CURRENT_MINOR}+." >> "$OUTPUT_DIR/kubernetes/cluster/version_issues.txt"
        K8S_VERSION_ISSUES=1
        f_container_record_finding warning kubernetes "cluster/$SERVER_VERSION" k8s_version_outdated \
            "Kubernetes version is supported but not current" "kubernetes/cluster/version_issues.txt"
    else
        echo -e "${YELLOW}[*] Kubernetes version $SERVER_VERSION is current${NC}"
    fi

    # Add version info to summary
    echo "CLUSTER INFORMATION:" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"
    echo "Kubernetes Version: $SERVER_VERSION" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"

    if [ "$K8S_VERSION_ISSUES" -eq 1 ]; then
        echo "Version Status: Outdated - see version_issues.txt for details" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"
    else
        echo "Version Status: Current" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"
    fi

    echo "" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"

    # Collect node information
    echo -e "${BLUE}[*] Gathering node information.${NC}"
    kubectl get nodes -o wide > "$OUTPUT_DIR/kubernetes/cluster/nodes_info.txt" 2>/dev/null
    kubectl get nodes -o json > "$OUTPUT_DIR/kubernetes/cluster/nodes.json" 2>/dev/null

    # Count and analyze nodes
    NODE_COUNT=$(jq -r '.items | length' "$OUTPUT_DIR/kubernetes/cluster/nodes.json" 2>/dev/null)
    echo "Node Count: $NODE_COUNT" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"

    # Check node versions for consistency
    echo -e "${BLUE}[*] Checking for node version consistency.${NC}"
    kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\n"}{end}' > "$OUTPUT_DIR/kubernetes/cluster/node_versions.txt" 2>/dev/null

    NODE_VERSION_COUNT=$(awk '{print $2}' "$OUTPUT_DIR/kubernetes/cluster/node_versions.txt" | sort | uniq | wc -l)
    if [ "$NODE_VERSION_COUNT" -gt 1 ]; then
        echo -e "${YELLOW}[!] Multiple Kubernetes versions detected across nodes. This could lead to unexpected behavior${NC}"
        echo "WARNING: Cluster has nodes running $NODE_VERSION_COUNT different Kubernetes versions" >> "$OUTPUT_DIR/kubernetes/cluster/node_issues.txt"
        echo "Node Version Consistency: INCONSISTENT ($NODE_VERSION_COUNT versions)" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"
    else
        echo -e "${YELLOW}[*] All nodes running the same Kubernetes version${NC}"
        echo "Node Version Consistency: CONSISTENT" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"
    fi

    echo "" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"

    # Get and analyze all namespaces
    echo -e "${BLUE}[*] Enumerating and analyzing Kubernetes namespaces.${NC}"
    kubectl get namespaces -o json > "$OUTPUT_DIR/kubernetes/resources/namespaces.json" 2>/dev/null
    kubectl get namespaces > "$OUTPUT_DIR/kubernetes/resources/namespaces.txt" 2>/dev/null

    # Save namespaces in a list
    jq -r '.items[].metadata.name' "$OUTPUT_DIR/kubernetes/resources/namespaces.json" > "$OUTPUT_DIR/kubernetes/resources/namespace_list_all.txt" 2>/dev/null
    : > "$OUTPUT_DIR/kubernetes/resources/namespace_list.txt"
    while read -r _ns; do
        f_container_ns_should_scan "$_ns" && echo "$_ns" >> "$OUTPUT_DIR/kubernetes/resources/namespace_list.txt"
    done < "$OUTPUT_DIR/kubernetes/resources/namespace_list_all.txt"

    # Count namespaces
    NAMESPACE_COUNT=$(wc -l < "$OUTPUT_DIR/kubernetes/resources/namespace_list.txt")
    echo -e "${YELLOW}[*] Found $NAMESPACE_COUNT namespaces${NC}"
    echo "Namespace Count: $NAMESPACE_COUNT" >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"

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
    touch "$OUTPUT_DIR/kubernetes/vulnerabilities/privileged_pods.txt"
    touch "$OUTPUT_DIR/kubernetes/vulnerabilities/hostnetwork_pods.txt"
    touch "$OUTPUT_DIR/kubernetes/vulnerabilities/hostpath_volumes.txt"
    touch "$OUTPUT_DIR/kubernetes/vulnerabilities/root_pods.txt"
    touch "$OUTPUT_DIR/kubernetes/vulnerabilities/no_resource_limits.txt"
    touch "$OUTPUT_DIR/kubernetes/vulnerabilities/deprecated_apis.txt"
    touch "$OUTPUT_DIR/kubernetes/vulnerabilities/insecure_capabilities.txt"
    touch "$OUTPUT_DIR/kubernetes/vulnerabilities/secrets_as_env.txt"

    # Fetch cluster roles once for namespace RBAC cross-checks and cluster-wide analysis
    mkdir -p "$OUTPUT_DIR/kubernetes/rbac/cluster-wide"
    kubectl get clusterroles,clusterrolebindings -o json > "$OUTPUT_DIR/kubernetes/rbac/cluster-roles.json" 2>/dev/null

    # For each namespace, get and analyze all resources
    echo -e "${BLUE}[*] Starting detailed namespace analysis.${NC}"
    NAMESPACE_COUNTER=0

    while read -r namespace; do
        f_container_ns_should_scan "$namespace" || continue
        ((NAMESPACE_COUNTER++))
        echo -e "${BLUE}[*] Analyzing namespace [$NAMESPACE_COUNTER/$NAMESPACE_COUNT]: $namespace${NC}"
        mkdir -p "$OUTPUT_DIR/kubernetes/workloads/$namespace" "$OUTPUT_DIR/kubernetes/network/$namespace" "$OUTPUT_DIR/kubernetes/security_reports/$namespace"
        NP_COUNT=0

        # Create namespace summary file
        echo "Security Analysis for Namespace: $namespace" > "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "=================================" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

        # Get all resource types in namespace (full mode only)
        if [ "$CONTAINER_SCAN_MODE" = "full" ]; then
        echo -e "${BLUE}[*] Collecting all resources in namespace: $namespace${NC}"
        kubectl api-resources --verbs=list --namespaced -o name | xargs -r -n 1 kubectl get --show-kind --ignore-not-found -n "$namespace" > "$OUTPUT_DIR/kubernetes/resources/$namespace-all_resources.txt" 2>/dev/null
        fi

        # Get workload resources
        kubectl get deployments,statefulsets,daemonsets,replicasets,pods -n "$namespace" -o json > "$OUTPUT_DIR/kubernetes/workloads/$namespace/workloads.json" 2>/dev/null

        # Derive pod list once from cached workloads (avoids repeated kubectl get pods)
        local pods_json="$OUTPUT_DIR/kubernetes/workloads/$namespace/pods.json"
        jq '{apiVersion: "v1", kind: "List", items: [.items[]? | select(.kind == "Pod")]}' \
            "$OUTPUT_DIR/kubernetes/workloads/$namespace/workloads.json" > "$pods_json" 2>/dev/null

        # Get network resources
        local network_json="$OUTPUT_DIR/kubernetes/network/$namespace/network.json"
        kubectl get services,ingresses,networkpolicies -n "$namespace" -o json > "$network_json" 2>/dev/null

        # Get secrets and config resources
        kubectl get secrets,configmaps -n "$namespace" -o json > "$OUTPUT_DIR/kubernetes/workloads/$namespace/configs.json" 2>/dev/null

        # Get specific counts (pods/services from cached JSON where possible)
        DEPLOYMENT_COUNT=$(jq '[.items[]? | select(.kind == "Deployment")] | length' "$OUTPUT_DIR/kubernetes/workloads/$namespace/workloads.json" 2>/dev/null || echo 0)
        POD_COUNT=$(jq '.items | length' "$pods_json" 2>/dev/null || echo 0)
        SERVICE_COUNT=$(jq '[.items[]? | select(.kind == "Service")] | length' "$network_json" 2>/dev/null || echo 0)
        INGRESS_COUNT=$(jq '[.items[]? | select(.kind == "Ingress")] | length' "$network_json" 2>/dev/null || echo 0)
        SECRET_COUNT=$(jq '[.items[]? | select(.kind == "Secret")] | length' "$OUTPUT_DIR/kubernetes/workloads/$namespace/configs.json" 2>/dev/null || echo 0)
        CONFIGMAP_COUNT=$(jq '[.items[]? | select(.kind == "ConfigMap")] | length' "$OUTPUT_DIR/kubernetes/workloads/$namespace/configs.json" 2>/dev/null || echo 0)

        # Update total counters
        TOTAL_DEPLOYMENTS=$((TOTAL_DEPLOYMENTS + DEPLOYMENT_COUNT))
        TOTAL_PODS=$((TOTAL_PODS + POD_COUNT))
        TOTAL_SERVICES=$((TOTAL_SERVICES + SERVICE_COUNT))
        TOTAL_INGRESSES=$((TOTAL_INGRESSES + INGRESS_COUNT))
        TOTAL_SECRETS=$((TOTAL_SECRETS + SECRET_COUNT))
        TOTAL_CONFIGMAPS=$((TOTAL_CONFIGMAPS + CONFIGMAP_COUNT))

        # Add to namespace summary
        echo "Resource Counts:" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Deployments: $DEPLOYMENT_COUNT" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Pods: $POD_COUNT" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Services: $SERVICE_COUNT" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Ingresses: $INGRESS_COUNT" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Secrets: $SECRET_COUNT" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "- ConfigMaps: $CONFIGMAP_COUNT" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

        # Pod Security Standards (PSS) label check
        PSS_ENFORCE=$(jq -r --arg ns "$namespace" '.items[] | select(.metadata.name == $ns) | .metadata.labels["pod-security.kubernetes.io/enforce"] // "unset"' "$OUTPUT_DIR/kubernetes/resources/namespaces.json" 2>/dev/null)
        echo "PSS enforce label: $PSS_ENFORCE" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        if [ "$POD_COUNT" -gt 0 ] && { [ -z "$PSS_ENFORCE" ] || [ "$PSS_ENFORCE" = "unset" ] || [ "$PSS_ENFORCE" = "privileged" ]; }; then
            f_container_record_finding warning kubernetes "namespace/$namespace" pss_not_enforced                 "Namespace lacks restrictive PSS enforce label (current: ${PSS_ENFORCE:-unset})" "kubernetes/security_reports/$namespace/summary.txt"
            echo "WARNING: Namespace should enforce Pod Security Standards (current: ${PSS_ENFORCE:-unset})" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi


        # Security Analysis
        echo -e "${BLUE}[*] Performing security analysis for namespace: $namespace${NC}"

        # Check pods for security issues
        if [ "$POD_COUNT" -gt 0 ]; then
            echo "POD SECURITY ANALYSIS:" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

            # Check for privileged containers
            PRIV_PODS=$(jq -r '.items[] | select(any(.spec.containers[]?; .securityContext.privileged == true)) | .metadata.name' "$pods_json" 2>/dev/null)
            if [ -n "$PRIV_PODS" ]; then
                PRIV_POD_COUNT=$(echo "$PRIV_PODS" | wc -l)
                echo "WARNING: Found $PRIV_POD_COUNT pods with privileged containers" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
                echo "$PRIV_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$OUTPUT_DIR/kubernetes/vulnerabilities/privileged_pods.txt"
                    f_container_record_finding critical kubernetes "$namespace/$pod" privileged_pod "Pod runs privileged container" "kubernetes/workloads/$namespace/pods.json"
                done
                TOTAL_PRIVILEGED_PODS=$((TOTAL_PRIVILEGED_PODS + PRIV_POD_COUNT))
            else
                echo "GOOD: No privileged containers found" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for hostNetwork
            HOSTNET_PODS=$(jq -r '.items[] | select(.spec.hostNetwork == true) | .metadata.name' "$pods_json" 2>/dev/null)
            if [ -n "$HOSTNET_PODS" ]; then
                HOSTNET_POD_COUNT=$(echo "$HOSTNET_PODS" | wc -l)
                echo "WARNING: Found $HOSTNET_POD_COUNT pods using host network" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
                echo "$HOSTNET_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$OUTPUT_DIR/kubernetes/vulnerabilities/hostnetwork_pods.txt"
                    f_container_record_finding high kubernetes "$namespace/$pod" host_network "Pod uses hostNetwork" "kubernetes/workloads/$namespace/pods.json"
                done
                TOTAL_HOSTNETWORK_PODS=$((TOTAL_HOSTNETWORK_PODS + HOSTNET_POD_COUNT))
            else
                echo "GOOD: No pods using host network" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for hostPath volumes
            HOSTPATH_PODS=$(jq -r '.items[] | select(any(.spec.volumes[]?; .hostPath != null)) | .metadata.name' "$pods_json" 2>/dev/null)
            if [ -n "$HOSTPATH_PODS" ]; then
                HOSTPATH_POD_COUNT=$(echo "$HOSTPATH_PODS" | wc -l)
                echo "WARNING: Found $HOSTPATH_POD_COUNT pods using hostPath volumes" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
                echo "$HOSTPATH_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$OUTPUT_DIR/kubernetes/vulnerabilities/hostpath_volumes.txt"
                done
                TOTAL_HOSTPATH_PODS=$((TOTAL_HOSTPATH_PODS + HOSTPATH_POD_COUNT))
            else
                echo "GOOD: No pods using hostPath volumes" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for root containers
            ROOT_PODS=$(jq -r '.items[] | select(any(.spec.containers[]?; .securityContext.runAsNonRoot != true and (.securityContext.runAsUser == null or .securityContext.runAsUser == 0))) | .metadata.name' "$pods_json" 2>/dev/null)
            if [ -n "$ROOT_PODS" ]; then
                ROOT_POD_COUNT=$(echo "$ROOT_PODS" | wc -l)
                echo "WARNING: Found $ROOT_POD_COUNT pods running as root" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
                echo "$ROOT_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$OUTPUT_DIR/kubernetes/vulnerabilities/root_pods.txt"
                    f_container_record_finding high kubernetes "$namespace/$pod" root_pod "Pod may run as root" "kubernetes/workloads/$namespace/pods.json"
                done
                TOTAL_ROOT_PODS=$((TOTAL_ROOT_PODS + ROOT_POD_COUNT))
            else
                echo "GOOD: No pods running as root" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Check for missing resource limits
            NOLIMIT_PODS=$(jq -r '.items[] | select(any(.spec.containers[]?; .resources.limits == null or .resources.limits.cpu == null or .resources.limits.memory == null)) | .metadata.name' "$pods_json" 2>/dev/null)
            if [ -n "$NOLIMIT_PODS" ]; then
                NOLIMIT_POD_COUNT=$(echo "$NOLIMIT_PODS" | wc -l)
                echo "WARNING: Found $NOLIMIT_POD_COUNT pods without complete resource limits" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
                echo "$NOLIMIT_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$OUTPUT_DIR/kubernetes/vulnerabilities/no_resource_limits.txt"
                done
            else
                echo "GOOD: All pods have resource limits defined" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Dangerous Linux capabilities
            INSECURE_CAP_PODS=$(jq -r '.items[] | select(any(.spec.containers[]?; (.securityContext.capabilities.add // []) | any(. == "SYS_ADMIN" or . == "NET_ADMIN" or . == "ALL" or . == "SYS_PTRACE" or . == "DAC_READ_SEARCH"))) | .metadata.name' "$pods_json" 2>/dev/null)
            if [ -n "$INSECURE_CAP_PODS" ]; then
                echo "$INSECURE_CAP_PODS" | while read -r pod; do
                    caps=$(jq -r --arg p "$pod" '.items[] | select(.metadata.name == $p) | [.spec.containers[]?.securityContext.capabilities.add[]?] | join(",")' "$pods_json" 2>/dev/null)
                    echo "$namespace/$pod ($caps)" >> "$OUTPUT_DIR/kubernetes/vulnerabilities/insecure_capabilities.txt"
                    f_container_record_finding high kubernetes "$namespace/$pod" dangerous_capabilities                         "Pod adds dangerous capabilities: $caps" "kubernetes/workloads/$namespace/pods.json"
                done
                echo "WARNING: Pods with dangerous added capabilities detected" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
            fi

            # Deprecated API versions in cached workloads
            for _api in "${_CONTAINER_DEPRECATED_API_VERSIONS[@]}"; do
                _hits=$(jq -r --arg api "$_api" '[.items[]? | select(.apiVersion == $api) | .kind + "/" + .metadata.name] | .[]' "$OUTPUT_DIR/kubernetes/workloads/$namespace/workloads.json" 2>/dev/null)
                if [ -n "$_hits" ]; then
                    echo "$_hits" | while read -r hit; do
                        echo "$namespace/$hit ($_api)" >> "$OUTPUT_DIR/kubernetes/vulnerabilities/deprecated_apis.txt"
                        f_container_record_finding warning kubernetes "$namespace/$hit" deprecated_api_version                             "Resource uses deprecated API $_api" "kubernetes/workloads/$namespace/workloads.json"
                    done
                fi
            done


            echo "" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        # Network Security Analysis
        NP_COUNT=$(jq '[.items[]? | select(.kind == "NetworkPolicy")] | length' "$network_json" 2>/dev/null || echo 0)
        if [ "$SERVICE_COUNT" -gt 0 ] || [ "$INGRESS_COUNT" -gt 0 ] || [ "$POD_COUNT" -gt 0 ]; then
            echo "NETWORK SECURITY ANALYSIS:" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

            if [ "$SERVICE_COUNT" -gt 0 ] || [ "$INGRESS_COUNT" -gt 0 ]; then
                # Check for NodePort services
                NODEPORT_SERVICES=$(jq -r '.items[] | select(.kind == "Service") | select(.spec.type == "NodePort") | .metadata.name' "$network_json" 2>/dev/null)
                if [ -n "$NODEPORT_SERVICES" ]; then
                    NODEPORT_COUNT=$(echo "$NODEPORT_SERVICES" | wc -l)
                    echo "INFO: Found $NODEPORT_COUNT NodePort services (ensure these are properly secured)" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
                fi

                # Check for LoadBalancer services
                LB_SERVICES=$(jq -r '.items[] | select(.kind == "Service") | select(.spec.type == "LoadBalancer") | .metadata.name' "$network_json" 2>/dev/null)
                if [ -n "$LB_SERVICES" ]; then
                    LB_COUNT=$(echo "$LB_SERVICES" | wc -l)
                    echo "INFO: Found $LB_COUNT LoadBalancer services (ensure these are properly secured)" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
                fi
            fi

            if [ "$NP_COUNT" -eq 0 ] && [ "$POD_COUNT" -gt 0 ]; then
                f_container_record_finding warning kubernetes "namespace/$namespace" missing_network_policy "No NetworkPolicies in namespace with pods" "kubernetes/network/$namespace/network.json"
                echo "WARNING: No NetworkPolicies found in namespace. Consider implementing network segmentation." >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
            elif [ "$NP_COUNT" -gt 0 ]; then
                echo "GOOD: Found $NP_COUNT NetworkPolicies" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
            fi

            echo "" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        # Secrets analysis
        if [ "$SECRET_COUNT" -gt 0 ]; then
            echo "SECRETS ANALYSIS:" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

            # Check for secrets mounted as environment variables (less secure than volumes)
            SECRET_ENV_PODS=$(jq -r '.items[] | select(any(.spec.containers[]?; any(.env[]?; .valueFrom.secretKeyRef != null))) | .metadata.name' "$pods_json" 2>/dev/null)
            if [ -n "$SECRET_ENV_PODS" ]; then
                SECRET_ENV_COUNT=$(echo "$SECRET_ENV_PODS" | wc -l)
                echo "INFO: Found $SECRET_ENV_COUNT pods using secrets as environment variables" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
                echo "$SECRET_ENV_PODS" | while read -r pod; do
                    echo "$namespace/$pod" >> "$OUTPUT_DIR/kubernetes/vulnerabilities/secrets_as_env.txt"
                done
            fi

            # List any default-token secrets that might be automatically mounted
            DEFAULT_TOKEN=$(kubectl get secrets -n "$namespace" | grep -c "default-token")
            if [ "$DEFAULT_TOKEN" -gt 0 ]; then
                echo "INFO: Found default-token secrets that are auto-mounted in pods" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
            fi

            echo "" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        # Check RBAC permissions in namespace
        echo "RBAC ANALYSIS:" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

        # Get roles and role bindings
        kubectl get roles,rolebindings -n "$namespace" -o json > "$OUTPUT_DIR/kubernetes/rbac/$namespace-rbac.json" 2>/dev/null

        # Check for permissive roles and ClusterRoles bound in this namespace
        PERMISSIVE_ROLES=$(jq -r --slurpfile cr "$OUTPUT_DIR/kubernetes/rbac/cluster-roles.json" "$_CONTAINER_RBAC_JQ_DEF" '
            (.items[] | select(.kind == "Role") | select(has_wildcard_rule) | "Role/\(.metadata.name)"),
            (.items[] | select(.kind == "RoleBinding") | .roleRef as $ref | select($ref.kind == "ClusterRole") |
             $cr[0].items[]? | select(.kind == "ClusterRole" and .metadata.name == $ref.name) |
             select(has_wildcard_rule) | "ClusterRole/\($ref.name)")
        ' "$OUTPUT_DIR/kubernetes/rbac/$namespace-rbac.json" 2>/dev/null)
        if [ -n "$PERMISSIVE_ROLES" ]; then
            echo "$PERMISSIVE_ROLES" | while read -r role; do
                f_container_record_finding high kubernetes "namespace/$namespace" permissive_rbac "Overly permissive $role" "kubernetes/rbac/$namespace-rbac.json"
            done
            PERMISSIVE_ROLE_COUNT=$(echo "$PERMISSIVE_ROLES" | wc -l)
            echo "WARNING: Found $PERMISSIVE_ROLE_COUNT overly permissive roles (wildcard apiGroups/resources/verbs)" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        else
            echo "GOOD: No overly permissive roles found" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        # Check service accounts with elevated permissions
        SA_WITH_BINDINGS=$(jq -r '.items[] | select(.kind == "RoleBinding") | select(.subjects[] | select(.kind == "ServiceAccount")) | .metadata.name' "$OUTPUT_DIR/kubernetes/rbac/$namespace-rbac.json" 2>/dev/null)
        if [ -n "$SA_WITH_BINDINGS" ]; then
            SA_BINDING_COUNT=$(echo "$SA_WITH_BINDINGS" | wc -l)
            echo "INFO: Found $SA_BINDING_COUNT role bindings to service accounts" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        echo "" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

        # Summarize namespace security posture
        echo "NAMESPACE SECURITY SCORE:" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

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
        echo "Security Score: $SECURITY_SCORE/10" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "$namespace|$SECURITY_SCORE|$POD_COUNT" >> "$OUTPUT_DIR/kubernetes/namespace_security_scores.txt"

        # Add recommendations
        echo "" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "SECURITY RECOMMENDATIONS:" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

        if [ -n "$PRIV_PODS" ]; then
            echo "- Avoid using privileged containers when possible" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$HOSTNET_PODS" ]; then
            echo "- Avoid using host network namespace" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$HOSTPATH_PODS" ]; then
            echo "- Avoid using hostPath volumes, prefer PersistentVolumes instead" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$ROOT_PODS" ]; then
            echo "- Run containers as non-root users with runAsNonRoot: true" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$NOLIMIT_PODS" ]; then
            echo "- Set resource limits for all containers to prevent resource exhaustion attacks" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ "$NP_COUNT" -eq 0 ] && [ "$POD_COUNT" -gt 0 ]; then
            echo "- Implement NetworkPolicies to enforce network segmentation" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        if [ -n "$PERMISSIVE_ROLES" ]; then
            echo "- Refine RBAC roles to use least privilege principle instead of wildcard permissions" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        fi

        echo "- Enforce Pod Security Standards (PSS) via namespace labels or admission policy" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"
        echo "- Use Secret management solutions instead of Kubernetes Secrets for sensitive data" >> "$OUTPUT_DIR/kubernetes/security_reports/$namespace/summary.txt"

        echo -e "${YELLOW}[*] Completed security analysis for namespace: $namespace${NC}"
    done < "$OUTPUT_DIR/kubernetes/resources/namespace_list.txt"

    # Check cluster-wide RBAC (cluster-roles.json fetched before namespace loop)
    echo -e "${BLUE}[*] Analyzing cluster-wide RBAC settings.${NC}"

    # Check for overly permissive cluster roles
    echo -e "${BLUE}[*] Checking for overly permissive cluster roles.${NC}"
    jq -r "$_CONTAINER_RBAC_JQ_DEF" '.items[] | select(.kind == "ClusterRole") | select(has_wildcard_rule) | .metadata.name' \
        "$OUTPUT_DIR/kubernetes/rbac/cluster-roles.json" > "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/permissive_cluster_roles.txt" 2>/dev/null

    PERMISSIVE_CLUSTER_ROLES=$(wc -l < "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/permissive_cluster_roles.txt" 2>/dev/null || echo 0)
    if [ "$PERMISSIVE_CLUSTER_ROLES" -gt 0 ]; then
        while read -r cr; do
            [ -n "$cr" ] && f_container_record_finding critical kubernetes "clusterrole/$cr" permissive_cluster_role "ClusterRole has wildcard rules" "kubernetes/rbac/cluster-wide/permissive_cluster_roles.txt"
        done < "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/permissive_cluster_roles.txt"
        echo -e "${RED}[!] WARNING: Found $PERMISSIVE_CLUSTER_ROLES overly permissive cluster roles${NC}"
    fi

    # Check for dangerous subjects in cluster role bindings
    echo -e "${BLUE}[*] Checking for dangerous cluster role bindings.${NC}"
    jq -r '.items[] | select(.kind == "ClusterRoleBinding") | select(.roleRef.name == "cluster-admin") | .subjects[] | select(.kind == "Group" and .name == "system:authenticated") | "CRITICAL: cluster-admin bound to system:authenticated"' "$OUTPUT_DIR/kubernetes/rbac/cluster-roles.json" > "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/dangerous_bindings.txt" 2>/dev/null

    if [ -s "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/dangerous_bindings.txt" ]; then
        f_container_record_finding critical kubernetes "cluster/rbac" dangerous_cluster_binding "cluster-admin bound to system:authenticated" "kubernetes/rbac/cluster-wide/dangerous_bindings.txt"
        echo -e "${RED}[!] CRITICAL: Found dangerous cluster role bindings that grant admin to all authenticated users!${NC}"
    fi

    # Generate cluster-wide RBAC summary
    {
        echo "CLUSTER-WIDE RBAC ANALYSIS"
        echo "========================="
        echo "Overly permissive cluster roles: $PERMISSIVE_CLUSTER_ROLES"

        if [ -s "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/dangerous_bindings.txt" ]; then
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
    } > "$OUTPUT_DIR/kubernetes/rbac/cluster-wide/rbac_summary.txt"

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
        if [ -f "$OUTPUT_DIR/kubernetes/namespace_security_scores.txt" ]; then
            sort -t'|' -k2,2n "$OUTPUT_DIR/kubernetes/namespace_security_scores.txt" | head -10 | \
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
    } >> "$OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt"

    f_container_mark_phase kubernetes
    echo -e "${YELLOW}[*] Kubernetes security audit complete! Results are in $OUTPUT_DIR/kubernetes/kubernetes_security_summary.txt${NC}"
}