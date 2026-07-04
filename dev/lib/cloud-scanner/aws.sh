# AWS cloud security checks — sourced by dev/cloud-scanner.sh

f_aws_auth_check(){
    if ! aws sts get-caller-identity > "$OUTPUT_DIR/aws/account_info.json" 2>>"$CLOUD_SCAN_LOG"; then
        echo -e "${RED}[!] AWS authentication failed. Configure credentials (aws configure / env vars / SSO) and retry.${NC}"
        return 1
    fi
    local account_id user_arn
    account_id=$(jq -r '.Account' "$OUTPUT_DIR/aws/account_info.json" 2>/dev/null)
    user_arn=$(jq -r '.Arn' "$OUTPUT_DIR/aws/account_info.json" 2>/dev/null)
    echo -e "${YELLOW}[*] AWS Account ID: $account_id${NC}"
    echo -e "${YELLOW}[*] AWS User ARN: $user_arn${NC}"
    return 0
}

f_aws_bucket_has_public_signal(){
    local bucket="$1"
    local policy_file="$OUTPUT_DIR/aws/buckets/$bucket/policy.json"
    local pab_file="$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json"
    local acl_file="$OUTPUT_DIR/aws/buckets/$bucket/acl.json"

    if [ -s "$policy_file" ]; then
        if f_cloud_aws_s3_policy_jq "$policy_file" '.Statement[]? | select(.Effect == "Allow" and (.Principal == "*" or .Principal.AWS == "*" or (.Principal.AWS? | type == "string" and . == "*")))' || \
           f_cloud_aws_s3_policy_jq "$policy_file" '.Statement[]? | select(.Effect == "Allow" and (.Principal.AWS? | type == "array" and index("*") != null))'; then
            return 0
        fi
    fi
    if [ -s "$acl_file" ]; then
        if jq -e '.Grants[] | select(.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" or .Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")' "$acl_file" &>/dev/null; then
            return 0
        fi
    fi
    if [ -s "$pab_file" ]; then
        if jq -e '.PublicAccessBlockConfiguration | .BlockPublicAcls == false or .BlockPublicPolicy == false or .IgnorePublicAcls == false or .RestrictPublicBuckets == false' "$pab_file" &>/dev/null; then
            return 0
        fi
    elif [ ! -s "$pab_file" ]; then
        return 0
    fi
    return 1
}

f_aws_phase_account(){
    f_cloud_should_run_phase aws_account || return 0
    echo -e "${BLUE}[*] Gathering AWS account context.${NC}"
    mkdir -p "$OUTPUT_DIR/aws"

    aws ec2 describe-regions --query "Regions[].RegionName" --output json > "$OUTPUT_DIR/aws/regions.json" 2>>"$CLOUD_SCAN_LOG" || true
    aws organizations describe-organization > "$OUTPUT_DIR/aws/organization.json" 2>>"$CLOUD_SCAN_LOG" || true

    # Account-level S3 public access block
    if aws s3control get-public-access-block --account-id "$(jq -r '.Account' "$OUTPUT_DIR/aws/account_info.json")" \
        > "$OUTPUT_DIR/aws/account_s3_public_access_block.json" 2>>"$CLOUD_SCAN_LOG"; then
        if jq -e '.PublicAccessBlockConfiguration | .BlockPublicAcls == false or .BlockPublicPolicy == false' \
            "$OUTPUT_DIR/aws/account_s3_public_access_block.json" &>/dev/null; then
            f_cloud_record_finding warning aws s3 account account-s3-pab \
                "Account-level S3 Block Public Access not fully enabled" \
                "$OUTPUT_DIR/aws/account_s3_public_access_block.json"
        fi
    else
        f_cloud_record_finding warning aws s3 account account-s3-pab-missing \
            "Account-level S3 Block Public Access not configured" \
            "$OUTPUT_DIR/aws/account_s3_public_access_block.json"
    fi

    f_cloud_mark_phase aws_account
}

f_aws_phase_s3(){
    f_cloud_should_run_phase aws_s3 || return 0
    echo -e "${BLUE}[*] Auditing S3 buckets.${NC}"
    mkdir -p "$OUTPUT_DIR/aws/buckets" "$OUTPUT_DIR/aws/cloudtrail"

    aws s3api list-buckets > "$OUTPUT_DIR/aws/s3_buckets.json" 2>>"$CLOUD_SCAN_LOG" || return 0
    local total
    total=$(jq '.Buckets | length' "$OUTPUT_DIR/aws/s3_buckets.json" 2>/dev/null || echo 0)
    echo -e "${YELLOW}[*] Found $total S3 buckets${NC}"

    jq -r '.Buckets[].Name' "$OUTPUT_DIR/aws/s3_buckets.json" 2>/dev/null > "$OUTPUT_DIR/aws/bucket_names.txt" || : > "$OUTPUT_DIR/aws/bucket_names.txt"
    [ -s "$OUTPUT_DIR/aws/bucket_names.txt" ] || { f_cloud_mark_phase aws_s3; return 0; }

    # Cache CloudTrail selectors once
    aws cloudtrail list-trails > "$OUTPUT_DIR/aws/cloudtrail/trails.json" 2>>"$CLOUD_SCAN_LOG" || true
    if [ -s "$OUTPUT_DIR/aws/cloudtrail/trails.json" ]; then
        while read -r trail; do
            [ -z "$trail" ] && continue
            aws cloudtrail get-event-selectors --trail-name "$trail" \
                > "$OUTPUT_DIR/aws/cloudtrail/${trail}_selectors.json" 2>>"$CLOUD_SCAN_LOG" || true
        done < <(jq -r '.Trails[].Name' "$OUTPUT_DIR/aws/cloudtrail/trails.json" 2>/dev/null)
    fi

    local bucket current=0 count
    count=$(wc -l < "$OUTPUT_DIR/aws/bucket_names.txt")
    while read -r bucket; do
        ((current++))
        echo -ne "${BLUE}[*] S3 bucket ($((current * 100 / count))%): $bucket${NC}\r"
        mkdir -p "$OUTPUT_DIR/aws/buckets/$bucket"

        aws s3api get-bucket-policy --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/policy.json" 2>>"$CLOUD_SCAN_LOG" || true
        aws s3api get-bucket-acl --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/acl.json" 2>>"$CLOUD_SCAN_LOG" || true
        aws s3api get-public-access-block --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json" 2>>"$CLOUD_SCAN_LOG" || true

        local policy_file="$OUTPUT_DIR/aws/buckets/$bucket/policy.json"
        if [ -s "$policy_file" ]; then
            if f_cloud_aws_s3_policy_jq "$policy_file" '.Statement[]? | select(.Effect == "Allow" and (.Principal == "*" or .Principal.AWS == "*" or (.Principal.AWS? | type == "string" and . == "*")))' || \
               f_cloud_aws_s3_policy_jq "$policy_file" '.Statement[]? | select(.Effect == "Allow" and (.Principal.AWS? | type == "array" and index("*") != null))'; then
                f_cloud_record_finding high aws s3 "$bucket" wildcard-principal \
                    "Bucket policy allows wildcard Principal" "$policy_file"
            fi
            if f_aws_bucket_has_public_signal "$bucket"; then
                if ! f_cloud_aws_s3_policy_jq "$policy_file" '.Statement[]? | select(.Effect == "Deny" and .Condition.Bool."aws:SecureTransport" == "false")'; then
                    f_cloud_record_finding warning aws s3 "$bucket" secure-transport \
                        "Public-exposure bucket lacks aws:SecureTransport deny" "$policy_file"
                fi
            fi
        fi

        if [ -s "$OUTPUT_DIR/aws/buckets/$bucket/acl.json" ]; then
            if jq -e '.Grants[] | select(.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers")' "$OUTPUT_DIR/aws/buckets/$bucket/acl.json" &>/dev/null; then
                f_cloud_record_finding high aws s3 "$bucket" public-acl \
                    "ACL grants AllUsers" "$OUTPUT_DIR/aws/buckets/$bucket/acl.json"
            fi
            if jq -e '.Grants[] | select(.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")' "$OUTPUT_DIR/aws/buckets/$bucket/acl.json" &>/dev/null; then
                f_cloud_record_finding high aws s3 "$bucket" authenticated-acl \
                    "ACL grants AuthenticatedUsers" "$OUTPUT_DIR/aws/buckets/$bucket/acl.json"
            fi
        fi

        if [ ! -s "$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json" ]; then
            f_cloud_record_finding high aws s3 "$bucket" no-pab \
                "No public access block configuration" ""
        else
            if jq -e '.PublicAccessBlockConfiguration.BlockPublicAcls == false' "$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json" &>/dev/null; then
                f_cloud_record_finding high aws s3 "$bucket" pab-block-acls \
                    "BlockPublicAcls disabled" "$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json"
            fi
        fi

        if [ "$CLOUD_SCAN_MODE" = "full" ]; then
            local enc_result=0
            aws s3api get-bucket-encryption --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/encryption.json" 2>>"$CLOUD_SCAN_LOG" || enc_result=$?
            if [ "$enc_result" -ne 0 ]; then
                f_cloud_record_finding warning aws s3 "$bucket" no-encryption \
                    "No default encryption configured" ""
            elif jq -e '.ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm == "AES256"' \
                "$OUTPUT_DIR/aws/buckets/$bucket/encryption.json" &>/dev/null; then
                f_cloud_record_finding info aws s3 "$bucket" sse-s3 \
                    "Using SSE-S3 (AES256); CMK may be required for regulated data" \
                    "$OUTPUT_DIR/aws/buckets/$bucket/encryption.json"
            fi

            aws s3api get-bucket-versioning --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/versioning.json" 2>>"$CLOUD_SCAN_LOG" || true
            if ! jq -e '.Status == "Enabled"' "$OUTPUT_DIR/aws/buckets/$bucket/versioning.json" &>/dev/null; then
                f_cloud_record_finding info aws s3 "$bucket" versioning \
                    "Versioning not enabled" "$OUTPUT_DIR/aws/buckets/$bucket/versioning.json"
            fi

            aws s3api get-bucket-logging --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/logging.json" 2>>"$CLOUD_SCAN_LOG" || true
            if ! jq -e '.LoggingEnabled' "$OUTPUT_DIR/aws/buckets/$bucket/logging.json" &>/dev/null; then
                f_cloud_record_finding info aws s3 "$bucket" logging \
                    "Access logging not enabled" "$OUTPUT_DIR/aws/buckets/$bucket/logging.json"
            fi

            if ! f_cloud_aws_bucket_cloudtrail_logged "$bucket"; then
                f_cloud_record_finding info aws s3 "$bucket" cloudtrail-objects \
                    "No CloudTrail object-level logging for bucket" "$OUTPUT_DIR/aws/cloudtrail/trails.json"
            fi
        fi
    done < "$OUTPUT_DIR/aws/bucket_names.txt"
    echo ""

    f_cloud_mark_phase aws_s3
}

f_aws_analyze_sg_file(){
    local sg_file="$1" region="$2"
    jq -r --arg region "$region" '
        .SecurityGroups[]? as $sg
        | $sg.IpPermissions[]? as $perm
        | $perm.IpRanges[]? as $range
        | select($range.CidrIp == "0.0.0.0/0")
        | ($perm.FromPort // "all") as $fp
        | ($perm.ToPort // "all") as $tp
        | $sg.GroupId + "\t" + $sg.GroupName + "\t" + $region + "\t" + ($fp|tostring) + "-" + ($tp|tostring) + "\t" + $range.CidrIp
    ' "$sg_file" 2>/dev/null
    jq -r --arg region "$region" '
        .SecurityGroups[]? as $sg
        | $sg.IpPermissions[]? as $perm
        | $perm.Ipv6Ranges[]? as $range
        | select($range.CidrIpv6 == "::/0")
        | ($perm.FromPort // "all") as $fp
        | ($perm.ToPort // "all") as $tp
        | $sg.GroupId + "\t" + $sg.GroupName + "\t" + $region + "\t" + ($fp|tostring) + "-" + ($tp|tostring) + "\t" + $range.CidrIpv6
    ' "$sg_file" 2>/dev/null
}

f_aws_phase_ec2(){
    f_cloud_should_run_phase aws_ec2 || return 0
    echo -e "${BLUE}[*] Checking EC2 and security groups.${NC}"
    mkdir -p "$OUTPUT_DIR/aws/ec2"

    local regions=()
    if [ "$CLOUD_SCAN_MODE" = "full" ] && [ -s "$OUTPUT_DIR/aws/regions.json" ]; then
        mapfile -t regions < <(jq -r '.[]' "$OUTPUT_DIR/aws/regions.json" 2>/dev/null)
    else
        regions=("$AWS_DEFAULT_REGION")
        [ -n "${regions[0]}" ] || regions=("us-east-1")
    fi

    : > "$OUTPUT_DIR/aws/overly_permissive_sgs.tsv"
    local region sg_file
    for region in "${regions[@]}"; do
        [ -z "$region" ] && continue
        sg_file="$OUTPUT_DIR/aws/ec2/security_groups_${region}.json"
        aws ec2 describe-security-groups --region "$region" > "$sg_file" 2>>"$CLOUD_SCAN_LOG" || continue
        f_aws_analyze_sg_file "$sg_file" "$region" >> "$OUTPUT_DIR/aws/overly_permissive_sgs.tsv" || true

        if [ "$CLOUD_SCAN_MODE" = "full" ]; then
            aws ec2 describe-instances --region "$region" > "$OUTPUT_DIR/aws/ec2/instances_${region}.json" 2>>"$CLOUD_SCAN_LOG" || true
        fi
    done

    while IFS=$'\t' read -r gid gname reg ports cidr; do
        [ -z "$gid" ] && continue
        local sev=warning
        local from_port="${ports%%-*}"
        if [ "$from_port" != "all" ] && [ "$from_port" = "$ports" ] && f_cloud_port_sensitive "$from_port"; then
            sev=high
        elif [[ "$ports" == *"-"* ]]; then
            local to_port="${ports##*-}"
            if f_cloud_port_sensitive "$from_port" || f_cloud_port_sensitive "$to_port"; then
                sev=high
            fi
        fi
        f_cloud_record_finding "$sev" aws ec2 "$gid" ingress-open \
            "Ingress $ports open to $cidr in $reg ($gname)" \
            "$OUTPUT_DIR/aws/ec2/security_groups_${reg}.json"
    done < "$OUTPUT_DIR/aws/overly_permissive_sgs.tsv"

    f_cloud_mark_phase aws_ec2
}

f_aws_iam_check_user_admin(){
    local user="$1"
    local policy_dir="$OUTPUT_DIR/aws/iam/policies"
    local seen_admin=0

    aws iam list-attached-user-policies --user-name "$user" > "$OUTPUT_DIR/aws/iam/users/${user}_attached.json" 2>>"$CLOUD_SCAN_LOG" || true
    while read -r policy_arn; do
        [ -z "$policy_arn" ] && continue
        if [[ "$policy_arn" == *":policy/AdministratorAccess" ]] || [[ "$policy_arn" == *":policy/PowerUserAccess" ]]; then
            f_cloud_record_finding high aws iam "$user" admin-policy \
                "Attached policy: $policy_arn" "$OUTPUT_DIR/aws/iam/users/${user}_attached.json"
            seen_admin=1
            break
        fi
        local version_file
        version_file=$(f_cloud_cache_policy_version "$policy_arn" "$policy_dir" 2>/dev/null) || continue
        if f_cloud_policy_is_admin_document "$version_file"; then
            f_cloud_record_finding high aws iam "$user" admin-document \
                "Policy document allows */* on $policy_arn" "$version_file"
            seen_admin=1
            break
        fi
    done < <(jq -r '.AttachedPolicies[]?.PolicyArn' "$OUTPUT_DIR/aws/iam/users/${user}_attached.json" 2>/dev/null)

    if [ "$seen_admin" -eq 0 ]; then
        aws iam list-user-policies --user-name "$user" > "$OUTPUT_DIR/aws/iam/users/${user}_inline_list.json" 2>>"$CLOUD_SCAN_LOG" || true
        while read -r inline_name; do
            [ -z "$inline_name" ] && continue
            aws iam get-user-policy --user-name "$user" --policy-name "$inline_name" \
                > "$OUTPUT_DIR/aws/iam/users/${user}_inline_${inline_name}.json" 2>>"$CLOUD_SCAN_LOG" || continue
            if jq -e '
                .PolicyDocument.Statement[]?
                | select(.Effect == "Allow")
                | select(
                    (.Action == "*" or ((.Action | type) == "array" and (.Action | index("*") != null)))
                    and (.Resource == "*" or ((.Resource | type) == "array" and (.Resource | index("*") != null)))
                  )
            ' "$OUTPUT_DIR/aws/iam/users/${user}_inline_${inline_name}.json" &>/dev/null; then
                f_cloud_record_finding high aws iam "$user" inline-admin \
                    "Inline policy $inline_name allows */*" \
                    "$OUTPUT_DIR/aws/iam/users/${user}_inline_${inline_name}.json"
                break
            fi
        done < <(jq -r '.PolicyNames[]?' "$OUTPUT_DIR/aws/iam/users/${user}_inline_list.json" 2>/dev/null)
    fi

    aws iam list-groups-for-user --user-name "$user" > "$OUTPUT_DIR/aws/iam/users/${user}_groups.json" 2>>"$CLOUD_SCAN_LOG" || true
    while read -r group; do
        [ -z "$group" ] && continue
        aws iam list-attached-group-policies --group-name "$group" > "$OUTPUT_DIR/aws/iam/groups/${group}_policies.json" 2>>"$CLOUD_SCAN_LOG" || true
        while read -r gpol; do
            [ -z "$gpol" ] && continue
            if [[ "$gpol" == *":policy/AdministratorAccess" ]] || [[ "$gpol" == *":policy/PowerUserAccess" ]]; then
                f_cloud_record_finding high aws iam "$user" group-admin \
                    "Admin via group $group ($gpol)" "$OUTPUT_DIR/aws/iam/groups/${group}_policies.json"
                return 0
            fi
        done < <(jq -r '.AttachedPolicies[]?.PolicyArn' "$OUTPUT_DIR/aws/iam/groups/${group}_policies.json" 2>/dev/null)
    done < <(jq -r '.Groups[]?.GroupName' "$OUTPUT_DIR/aws/iam/users/${user}_groups.json" 2>/dev/null)
}

f_aws_iam_check_role_admin(){
    local role="$1"
    local policy_dir="$OUTPUT_DIR/aws/iam/policies"

    aws iam list-attached-role-policies --role-name "$role" > "$OUTPUT_DIR/aws/iam/roles/${role}_attached.json" 2>>"$CLOUD_SCAN_LOG" || true
    while read -r policy_arn; do
        [ -z "$policy_arn" ] && continue
        if [[ "$policy_arn" == *":policy/AdministratorAccess" ]]; then
            f_cloud_record_finding high aws iam "$role" role-admin \
                "Role has AdministratorAccess" "$OUTPUT_DIR/aws/iam/roles/${role}_attached.json"
            return 0
        fi
        local version_file
        version_file=$(f_cloud_cache_policy_version "$policy_arn" "$policy_dir" 2>/dev/null) || continue
        if f_cloud_policy_is_admin_document "$version_file"; then
            f_cloud_record_finding high aws iam "$role" role-admin-document \
                "Role policy allows */* ($policy_arn)" "$version_file"
            return 0
        fi
    done < <(jq -r '.AttachedPolicies[]?.PolicyArn' "$OUTPUT_DIR/aws/iam/roles/${role}_attached.json" 2>/dev/null)
}

f_aws_phase_iam(){
    f_cloud_should_run_phase aws_iam || return 0
    echo -e "${BLUE}[*] Auditing IAM.${NC}"
    mkdir -p "$OUTPUT_DIR/aws/iam/users" "$OUTPUT_DIR/aws/iam/roles" "$OUTPUT_DIR/aws/iam/policies" "$OUTPUT_DIR/aws/iam/groups"

    aws iam list-users > "$OUTPUT_DIR/aws/iam/users.json" 2>>"$CLOUD_SCAN_LOG" || true
    aws iam list-roles > "$OUTPUT_DIR/aws/iam/roles.json" 2>>"$CLOUD_SCAN_LOG" || true
    aws iam list-policies --scope Local > "$OUTPUT_DIR/aws/iam/custom_policies.json" 2>>"$CLOUD_SCAN_LOG" || true

    if aws iam get-account-password-policy > "$OUTPUT_DIR/aws/iam/password_policy.json" 2>>"$CLOUD_SCAN_LOG"; then
        local min_length reuse max_age
        min_length=$(jq -r '.PasswordPolicy.MinimumPasswordLength // 0' "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null)
        if [[ "$min_length" =~ ^[0-9]+$ ]] && [ "$min_length" -lt 14 ]; then
            f_cloud_record_finding warning aws iam account password-length \
                "Minimum password length $min_length (recommended 14)" \
                "$OUTPUT_DIR/aws/iam/password_policy.json"
        fi
        reuse=$(jq -r '.PasswordPolicy.PasswordReusePrevention // 0' "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null)
        if [[ "$reuse" =~ ^[0-9]+$ ]] && [ "$reuse" -lt 24 ]; then
            f_cloud_record_finding warning aws iam account password-reuse \
                "Password reuse prevention $reuse (recommended 24)" \
                "$OUTPUT_DIR/aws/iam/password_policy.json"
        fi
    else
        f_cloud_record_finding critical aws iam account no-password-policy \
            "No account password policy defined" ""
    fi

    local cred_csv="$OUTPUT_DIR/aws/iam/credential_report.csv"
    if f_cloud_aws_wait_credential_report "$cred_csv"; then
        if awk -F',' '$1=="root" && $8=="false"' "$cred_csv" | grep -q .; then
            f_cloud_record_finding critical aws iam root root-no-mfa \
                "Root account MFA not enabled" "$cred_csv"
        fi
        if awk -F',' '$1=="root" && ($9=="true" || $12=="true")' "$cred_csv" | grep -q .; then
            f_cloud_record_finding critical aws iam root root-access-keys \
                "Root account has active access keys" "$cred_csv"
        fi

        awk -F',' 'NR>1 && $1!="root" && $8=="false" && ($4=="true" || $9=="true" || $12=="true")' \
            "$cred_csv" > "$OUTPUT_DIR/aws/iam/users_without_mfa.csv"
        while IFS=',' read -r user _a _b _c _d _e _f _g _h _i _j _k _l _m _n; do
            [ "$user" = "user" ] && continue
            f_cloud_record_finding high aws iam "$user" no-mfa \
                "Console or API access without MFA" "$OUTPUT_DIR/aws/iam/users_without_mfa.csv"
        done < "$OUTPUT_DIR/aws/iam/users_without_mfa.csv"

        if [ "$CLOUD_SCAN_MODE" = "full" ]; then
            local current_date user
            current_date=$(date +%s)
            while IFS=',' read -r user _arn _uct password_enabled _plu password_last_changed _pnr _mfa access_key_1_active access_key_1_last_rotated _ak1u access_key_2_active access_key_2_last_rotated _ak2u _rest; do
                [ "$user" = "user" ] || [ "$user" = "root" ] && continue
                if [ "$access_key_1_active" = "true" ] && [ "$access_key_1_last_rotated" != "N/A" ]; then
                    local age
                    age=$(( (current_date - $(date -d "$access_key_1_last_rotated" +%s 2>/dev/null || echo 0)) / 86400 ))
                    [ "$age" -gt 90 ] && f_cloud_record_finding warning aws iam "$user" stale-key-1 \
                        "Access key 1 is ${age} days old" "$cred_csv"
                fi
                if [ "$access_key_1_active" = "true" ] && [ "$access_key_1_last_rotated" = "N/A" ]; then
                    f_cloud_record_finding warning aws iam "$user" unused-key-1 \
                        "Access key 1 active but never rotated/used" "$cred_csv"
                fi
                if [ "$password_enabled" = "true" ] && [ "$password_last_changed" != "N/A" ]; then
                    local page
                    page=$(( (current_date - $(date -d "$password_last_changed" +%s 2>/dev/null || echo 0)) / 86400 ))
                    [ "$page" -gt 90 ] && f_cloud_record_finding warning aws iam "$user" stale-password \
                        "Password is ${page} days old" "$cred_csv"
                fi
            done < "$cred_csv"
        fi
    else
        f_cloud_record_finding warning aws iam account credential-report \
            "IAM credential report unavailable" "$cred_csv"
    fi

    if [ "$CLOUD_SCAN_MODE" = "full" ]; then
        while read -r user; do
            [ -z "$user" ] && continue
            f_aws_iam_check_user_admin "$user"
        done < <(jq -r '.Users[]?.UserName' "$OUTPUT_DIR/aws/iam/users.json" 2>/dev/null)
        while read -r role; do
            [[ "$role" == AWS-* ]] && continue
            [ -z "$role" ] && continue
            f_aws_iam_check_role_admin "$role"
        done < <(jq -r '.Roles[]?.RoleName' "$OUTPUT_DIR/aws/iam/roles.json" 2>/dev/null)

        while read -r policy_arn; do
            [ -z "$policy_arn" ] && continue
            local version_file
            version_file=$(f_cloud_cache_policy_version "$policy_arn" "$OUTPUT_DIR/aws/iam/policies" 2>/dev/null) || continue
            if f_cloud_policy_is_admin_document "$version_file"; then
                f_cloud_record_finding warning aws iam "$policy_arn" permissive-custom-policy \
                    "Custom policy allows */*" "$version_file"
            fi
        done < <(jq -r '.Policies[]?.Arn' "$OUTPUT_DIR/aws/iam/custom_policies.json" 2>/dev/null)

        aws accessanalyzer list-analyzers > "$OUTPUT_DIR/aws/iam/analyzers.json" 2>>"$CLOUD_SCAN_LOG" || true
        while read -r analyzer_arn; do
            [ -z "$analyzer_arn" ] && continue
            local aid findings_file active
            aid=$(basename "$analyzer_arn")
            findings_file="$OUTPUT_DIR/aws/iam/analyzer_${aid}_findings.json"
            aws accessanalyzer list-findings --analyzer-arn "$analyzer_arn" > "$findings_file" 2>>"$CLOUD_SCAN_LOG" || true
            active=$(jq -r '[.findings[]? | select(.status == "ACTIVE")] | length' "$findings_file" 2>/dev/null || echo 0)
            [ "$active" -gt 0 ] && f_cloud_record_finding warning aws iam "$aid" access-analyzer \
                "$active active Access Analyzer findings" "$findings_file"
        done < <(jq -r '.analyzers[]?.arn' "$OUTPUT_DIR/aws/iam/analyzers.json" 2>/dev/null)
    fi

    f_cloud_mark_phase aws_iam
}

f_aws_phase_cloudtrail(){
    f_cloud_should_run_phase aws_cloudtrail || return 0
    echo -e "${BLUE}[*] Checking CloudTrail.${NC}"

    aws cloudtrail describe-trails > "$OUTPUT_DIR/aws/cloudtrail.json" 2>>"$CLOUD_SCAN_LOG" || true
    jq -r '.trailList[]? | select(.KmsKeyId == null or .IsMultiRegionTrail == false) | .Name' \
        "$OUTPUT_DIR/aws/cloudtrail.json" 2>/dev/null | while read -r trail; do
        [ -z "$trail" ] && continue
        f_cloud_record_finding warning aws cloudtrail "$trail" trail-config \
            "Trail missing KMS encryption or not multi-region" "$OUTPUT_DIR/aws/cloudtrail.json"
    done

    f_cloud_mark_phase aws_cloudtrail
}

f_aws_phase_extras(){
    [ "$CLOUD_SCAN_MODE" = "full" ] || { f_cloud_mark_phase aws_extras; return 0; }
    f_cloud_should_run_phase aws_extras || return 0
    echo -e "${BLUE}[*] Running extended AWS exposure checks.${NC}"
    mkdir -p "$OUTPUT_DIR/aws/extras"

    # Public EBS snapshots
    aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all \
        > "$OUTPUT_DIR/aws/extras/public_snapshots.json" 2>>"$CLOUD_SCAN_LOG" || true
    jq -r '.Snapshots[]? | .SnapshotId + " (" + .Description + ")"' \
        "$OUTPUT_DIR/aws/extras/public_snapshots.json" 2>/dev/null | while read -r snap; do
        [ -z "$snap" ] && continue
        f_cloud_record_finding high aws ec2 "$snap" public-snapshot \
            "EBS snapshot publicly restorable" "$OUTPUT_DIR/aws/extras/public_snapshots.json"
    done

    # Lambda function URLs (auth none)
    aws lambda list-functions > "$OUTPUT_DIR/aws/extras/lambda_functions.json" 2>>"$CLOUD_SCAN_LOG" || true
    jq -r '.Functions[]?.FunctionName' "$OUTPUT_DIR/aws/extras/lambda_functions.json" 2>/dev/null | while read -r fn; do
        [ -z "$fn" ] && continue
        aws lambda get-function-url-config --function-name "$fn" \
            > "$OUTPUT_DIR/aws/extras/lambda_${fn}_url.json" 2>>"$CLOUD_SCAN_LOG" || continue
        if jq -e '.AuthType == "NONE"' "$OUTPUT_DIR/aws/extras/lambda_${fn}_url.json" &>/dev/null; then
            f_cloud_record_finding high aws lambda "$fn" public-url \
                "Lambda function URL with AuthType NONE" "$OUTPUT_DIR/aws/extras/lambda_${fn}_url.json"
        fi
    done

    # GuardDuty
    aws guardduty list-detectors > "$OUTPUT_DIR/aws/extras/guardduty.json" 2>>"$CLOUD_SCAN_LOG" || true
    local gd_count
    gd_count=$(jq -r '.DetectorIds | length' "$OUTPUT_DIR/aws/extras/guardduty.json" 2>/dev/null || echo 0)
    [ "$gd_count" -eq 0 ] && f_cloud_record_finding info aws guardduty account not-enabled \
        "GuardDuty not enabled" "$OUTPUT_DIR/aws/extras/guardduty.json"

    # AWS Config
    aws configservice describe-configuration-recorders > "$OUTPUT_DIR/aws/extras/config.json" 2>>"$CLOUD_SCAN_LOG" || true
    local cfg_count
    cfg_count=$(jq -r '.ConfigurationRecorders | length' "$OUTPUT_DIR/aws/extras/config.json" 2>/dev/null || echo 0)
    [ "$cfg_count" -eq 0 ] && f_cloud_record_finding info aws config account not-enabled \
        "AWS Config recorder not configured" "$OUTPUT_DIR/aws/extras/config.json"

    f_cloud_mark_phase aws_extras
}

f_aws_security_check(){
    echo
    echo -e "${BLUE}[*] Performing AWS security checks (mode: $CLOUD_SCAN_MODE).${NC}"
    mkdir -p "$OUTPUT_DIR/aws"

    f_aws_auth_check || return 1
    f_aws_phase_account
    f_aws_phase_s3
    f_aws_phase_ec2
    f_aws_phase_iam
    f_aws_phase_cloudtrail
    f_aws_phase_extras

    echo -e "${YELLOW}[*] AWS checks complete.${NC}"
    return 0
}