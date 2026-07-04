# Azure cloud security checks — sourced by dev/cloud-scanner.sh

f_azure_auth_check(){
    if ! az account show > "$OUTPUT_DIR/azure/subscription_info.json" 2>>"$CLOUD_SCAN_LOG"; then
        echo -e "${RED}[!] Azure authentication failed. Run 'az login' and retry.${NC}"
        return 1
    fi
    local sub_name
    sub_name=$(jq -r '.name' "$OUTPUT_DIR/azure/subscription_info.json" 2>/dev/null)
    echo -e "${YELLOW}[*] Azure subscription: $sub_name${NC}"
    return 0
}

f_azure_phase_storage(){
    f_cloud_should_run_phase azure_storage || return 0
    echo -e "${BLUE}[*] Checking Azure storage accounts.${NC}"
    mkdir -p "$OUTPUT_DIR/azure"

    az storage account list > "$OUTPUT_DIR/azure/storage_accounts.json" 2>>"$CLOUD_SCAN_LOG" || true
    jq -r '.[] | select(.allowBlobPublicAccess == true) | .name' \
        "$OUTPUT_DIR/azure/storage_accounts.json" 2>/dev/null | while read -r name; do
        [ -z "$name" ] && continue
        f_cloud_record_finding high azure storage "$name" public-blob-access \
            "allowBlobPublicAccess is true" "$OUTPUT_DIR/azure/storage_accounts.json"
    done

    if [ "$CLOUD_SCAN_MODE" = "full" ]; then
        jq -r '.[] | select(.publicNetworkAccess == "Enabled") | .name' \
            "$OUTPUT_DIR/azure/storage_accounts.json" 2>/dev/null | while read -r name; do
            [ -z "$name" ] && continue
            f_cloud_record_finding warning azure storage "$name" public-network \
                "publicNetworkAccess Enabled" "$OUTPUT_DIR/azure/storage_accounts.json"
        done
    fi

    f_cloud_mark_phase azure_storage
}

f_azure_phase_nsg(){
    f_cloud_should_run_phase azure_nsg || return 0
    echo -e "${BLUE}[*] Checking Network Security Groups.${NC}"

    az network nsg list > "$OUTPUT_DIR/azure/network_security_groups.json" 2>>"$CLOUD_SCAN_LOG" || true

    jq -r '
        .[]? as $nsg
        | $nsg.securityRules[]? as $rule
        | select($rule.access == "Allow" and $rule.direction == "Inbound")
        | select($rule.sourceAddressPrefix == "*" or $rule.sourceAddressPrefix == "Internet" or ($rule.sourceAddressPrefixes[]? == "*"))
        | $nsg.name + "\t" + $rule.name + "\t" + ($rule.destinationPortRange // "all") + "\t" + ($rule.sourceAddressPrefix // "prefixes")
    ' "$OUTPUT_DIR/azure/network_security_groups.json" 2>/dev/null > "$OUTPUT_DIR/azure/permissive_nsg_rules.tsv"

    while IFS=$'\t' read -r nsg rule port src; do
        [ -z "$nsg" ] && continue
        local sev=warning
        if [ "$port" != "all" ] && [ "$port" != "*" ] && f_cloud_port_sensitive "${port%%-*}"; then
            sev=high
        fi
        f_cloud_record_finding "$sev" azure network "$nsg" nsg-inbound-open \
            "Inbound rule $rule allows $src on port $port" \
            "$OUTPUT_DIR/azure/network_security_groups.json"
    done < "$OUTPUT_DIR/azure/permissive_nsg_rules.tsv"

    f_cloud_mark_phase azure_nsg
}

f_azure_phase_compute(){
    f_cloud_should_run_phase azure_compute || return 0
    echo -e "${BLUE}[*] Checking virtual machines.${NC}"

    az vm list > "$OUTPUT_DIR/azure/vms.json" 2>>"$CLOUD_SCAN_LOG" || true
    mapfile -t vm_ids < <(jq -r '.[].id' "$OUTPUT_DIR/azure/vms.json" 2>/dev/null)

    if [ "${#vm_ids[@]}" -gt 0 ] && [ "$CLOUD_SCAN_MODE" = "full" ]; then
        az vm encryption show --ids "${vm_ids[@]}" > "$OUTPUT_DIR/azure/vm_encryption.json" 2>>"$CLOUD_SCAN_LOG" || true
        jq -r '
            .[]? | select(.disks[]?.statuses[]?.code != "EncryptionState/encrypted") | .id
        ' "$OUTPUT_DIR/azure/vm_encryption.json" 2>/dev/null | while read -r vm_id; do
            [ -z "$vm_id" ] && continue
            f_cloud_record_finding warning azure compute "$vm_id" disk-encryption \
                "VM disk encryption not fully enabled" "$OUTPUT_DIR/azure/vm_encryption.json"
        done
    else
        : > "$OUTPUT_DIR/azure/vm_encryption.json"
    fi

    f_cloud_mark_phase azure_compute
}

f_azure_phase_keyvault(){
    [ "$CLOUD_SCAN_MODE" = "full" ] || { f_cloud_mark_phase azure_keyvault; return 0; }
    f_cloud_should_run_phase azure_keyvault || return 0
    echo -e "${BLUE}[*] Checking Key Vaults.${NC}"

    az keyvault list > "$OUTPUT_DIR/azure/keyvaults.json" 2>>"$CLOUD_SCAN_LOG" || true
    jq -c '.[]?' "$OUTPUT_DIR/azure/keyvaults.json" 2>/dev/null | while read -r kv; do
        local name pub soft
        name=$(echo "$kv" | jq -r '.name')
        pub=$(echo "$kv" | jq -r '.properties.publicNetworkAccess // "unknown"')
        soft=$(echo "$kv" | jq -r '.properties.enableSoftDelete // false')
        if [ "$pub" = "Enabled" ]; then
            f_cloud_record_finding warning azure keyvault "$name" public-network \
                "Key Vault public network access enabled" "$OUTPUT_DIR/azure/keyvaults.json"
        fi
        if [ "$soft" != "true" ]; then
            f_cloud_record_finding warning azure keyvault "$name" soft-delete \
                "Soft delete not enabled" "$OUTPUT_DIR/azure/keyvaults.json"
        fi
    done

    f_cloud_mark_phase azure_keyvault
}

f_azure_security_check(){
    echo
    echo -e "${BLUE}[*] Performing Azure security checks (mode: $CLOUD_SCAN_MODE).${NC}"
    mkdir -p "$OUTPUT_DIR/azure"

    f_azure_auth_check || return 1
    az group list > "$OUTPUT_DIR/azure/resource_groups.json" 2>>"$CLOUD_SCAN_LOG" || true
    f_azure_phase_storage
    f_azure_phase_nsg
    f_azure_phase_compute
    f_azure_phase_keyvault

    echo -e "${YELLOW}[*] Azure checks complete.${NC}"
    return 0
}