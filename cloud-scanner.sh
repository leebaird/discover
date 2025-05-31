#!/usr/bin/env bash

# by ibrahimsql - Cloud Security Scanner

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

# AWS Security Check Function
f_aws_security_check(){
    # Check for AWS CLI
    if ! command -v aws &> /dev/null; then
        echo
        echo -e "${YELLOW}Installing AWS CLI.${NC}"
        sudo apt update
        sudo apt install -y awscli
        echo
    fi

    local OUTPUT_DIR="$1"

    echo
    echo -e "${BLUE}[*] Performing comprehensive AWS security checks.${NC}"
    mkdir -p "$OUTPUT_DIR/aws/policies" "$OUTPUT_DIR/aws/acls" "$OUTPUT_DIR/aws/encryption" "$OUTPUT_DIR/aws/security" "$OUTPUT_DIR/aws/iam" "$OUTPUT_DIR/aws/monitoring" "$OUTPUT_DIR/aws/networking" "$OUTPUT_DIR/aws/compliance"

    # Check if AWS is configured and get available regions
    if ! aws configure list &> /dev/null; then
        echo -e "${YELLOW}[!] AWS CLI is not configured. Running aws configure.${NC}"
        aws configure
    fi

    # Get AWS Account information
    echo -e "${BLUE}[*] Getting AWS Account information.${NC}"
    aws sts get-caller-identity > "$OUTPUT_DIR/aws/account_info.json" 2>/dev/null

    if [ $? -ne 0 ]; then
        echo
        echo -e "${RED}[!] Failed to authenticate with AWS. Please check your credentials.${NC}"
        echo
        exit 1
    fi

    # Get AWS regions and set default region if not specified
    aws ec2 describe-regions --query "Regions[].RegionName" --output json > "$OUTPUT_DIR/aws/regions.json" 2>/dev/null
    REGIONS=$(jq -r '.[]' "$OUTPUT_DIR/aws/regions.json" 2>/dev/null) # Lee: This variable is not used

    # Display account info
    ACCOUNT_ID=$(jq -r '.Account' "$OUTPUT_DIR/aws/account_info.json" 2>/dev/null)
    USER_ARN=$(jq -r '.Arn' "$OUTPUT_DIR/aws/account_info.json" 2>/dev/null)
    echo -e "${YELLOW}[*] AWS Account ID: $ACCOUNT_ID${NC}"
    echo -e "${YELLOW}[*] AWS User ARN: $USER_ARN${NC}"

    # Get organization details if available
    echo -e "${BLUE}[*] Checking AWS Organization details.${NC}"
    aws organizations describe-organization > "$OUTPUT_DIR/aws/organization.json" 2>/dev/null

    # Get list of all AWS services being used
    echo -e "${BLUE}[*] Getting list of AWS services in use.${NC}"
    aws service-quotas list-services --query "Services[].ServiceName" --output json > "$OUTPUT_DIR/aws/services_in_use.json" 2>/dev/null

    # S3 Bucket Security Checks (Enhanced)
    echo -e "${BLUE}[*] Performing comprehensive S3 bucket security audit.${NC}"
    aws s3api list-buckets > "$OUTPUT_DIR/aws/s3_buckets.json" 2>/dev/null

    # Count total buckets
    TOTAL_BUCKETS=$(jq '.Buckets | length' "$OUTPUT_DIR/aws/s3_buckets.json" 2>/dev/null || echo "0")
    echo -e "${YELLOW}[*] Found $TOTAL_BUCKETS S3 buckets${NC}"

    # Initialize counters for statistics
    PUBLIC_COUNT=0
    UNENCRYPTED_COUNT=0
    LOGGING_DISABLED_COUNT=0
    VERSIONING_DISABLED_COUNT=0
    MFA_DELETE_DISABLED_COUNT=0
    SECURE_TRANSPORT_DISABLED_COUNT=0

    # Create summary files (Lee: should touch be used here to create this files?)
    > "$OUTPUT_DIR/aws/s3_security_issues.txt"
    > "$OUTPUT_DIR/aws/public_buckets.txt"
    > "$OUTPUT_DIR/aws/unencrypted_buckets.txt"
    > "$OUTPUT_DIR/aws/s3_compliance_issues.txt"

    # Extract bucket names
    bucket_names=$(jq -r '.Buckets[].Name' "$OUTPUT_DIR/aws/s3_buckets.json" 2>/dev/null)

    if [ -n "$bucket_names" ]; then
        echo "$bucket_names" > "$OUTPUT_DIR/aws/bucket_names.txt"
        BUCKET_COUNT=$(echo "$bucket_names" | wc -l)
        CURRENT=0

        while read -r bucket; do
            ((CURRENT++))
            PERCENTAGE=$((CURRENT * 100 / BUCKET_COUNT))

            # Show progress
            echo -ne "${BLUE}[*] Analyzing S3 bucket ($PERCENTAGE%): $bucket${NC}\r"

            # Create bucket-specific directory
            mkdir -p "$OUTPUT_DIR/aws/buckets/$bucket"

            # 1. Check bucket policy
            aws s3api get-bucket-policy --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/policy.json" 2>/dev/null

            # Check for policy issues
            if [ -s "$OUTPUT_DIR/aws/buckets/$bucket/policy.json" ]; then
                # Check for Allow * in the policy
                if jq -e '.Statement[] | select(.Effect == "Allow" and (.Principal == "*" or .Principal.AWS == "*"))' "$OUTPUT_DIR/aws/buckets/$bucket/policy.json" &>/dev/null; then
                    echo "$bucket: Contains wildcard Principal in Allow statement" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                    echo "$bucket: Contains wildcard Principal in Allow statement" >> "$OUTPUT_DIR/aws/public_buckets.txt"
                    ((PUBLIC_COUNT++))
                fi

                # Check for missing condition for secure transport
                if ! jq -e '.Statement[] | select(.Condition.Bool."aws:SecureTransport" == "false")' "$OUTPUT_DIR/aws/buckets/$bucket/policy.json" &>/dev/null; then
                    echo "$bucket: Missing secure transport condition" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                    ((SECURE_TRANSPORT_DISABLED_COUNT++))
                fi
            fi

            # 2. Check bucket ACL
            aws s3api get-bucket-acl --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/acl.json" 2>/dev/null

            # Check for public ACLs
            if jq -e '.Grants[] | select(.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers")' "$OUTPUT_DIR/aws/buckets/$bucket/acl.json" &>/dev/null; then
                echo "$bucket: ACL grants access to All Users" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                echo "$bucket: ACL grants access to All Users" >> "$OUTPUT_DIR/aws/public_buckets.txt"
                ((PUBLIC_COUNT++))
            fi

            if jq -e '.Grants[] | select(.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")' "$OUTPUT_DIR/aws/buckets/$bucket/acl.json" &>/dev/null; then
                echo "$bucket: ACL grants access to Authenticated Users" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                echo "$bucket: ACL grants access to Authenticated Users" >> "$OUTPUT_DIR/aws/public_buckets.txt"
                ((PUBLIC_COUNT++))
            fi

            # 3. Check public access block settings
            aws s3api get-public-access-block --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json" 2>/dev/null

            # If get-public-access-block fails or has public settings enabled
            if [ $? -ne 0 ]; then
                echo "$bucket: No public access block settings" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                echo "$bucket: No public access block settings" >> "$OUTPUT_DIR/aws/public_buckets.txt"
                ((PUBLIC_COUNT++))
            else
                # Check each setting
                if jq -e '.PublicAccessBlockConfiguration.BlockPublicAcls == false' "$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json" &>/dev/null; then
                    echo "$bucket: BlockPublicAcls disabled" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                    echo "$bucket: BlockPublicAcls disabled" >> "$OUTPUT_DIR/aws/public_buckets.txt"
                    ((PUBLIC_COUNT++))
                fi

                if jq -e '.PublicAccessBlockConfiguration.BlockPublicPolicy == false' "$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json" &>/dev/null; then
                    echo "$bucket: BlockPublicPolicy disabled" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                    echo "$bucket: BlockPublicPolicy disabled" >> "$OUTPUT_DIR/aws/public_buckets.txt"
                    ((PUBLIC_COUNT++))
                fi

                if jq -e '.PublicAccessBlockConfiguration.IgnorePublicAcls == false' "$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json" &>/dev/null; then
                    echo "$bucket: IgnorePublicAcls disabled" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                    echo "$bucket: IgnorePublicAcls disabled" >> "$OUTPUT_DIR/aws/public_buckets.txt"
                    ((PUBLIC_COUNT++))
                fi

                if jq -e '.PublicAccessBlockConfiguration.RestrictPublicBuckets == false' "$OUTPUT_DIR/aws/buckets/$bucket/public_access_block.json" &>/dev/null; then
                    echo "$bucket: RestrictPublicBuckets disabled" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                    echo "$bucket: RestrictPublicBuckets disabled" >> "$OUTPUT_DIR/aws/public_buckets.txt"
                    ((PUBLIC_COUNT++))
                fi
            fi

            # 4. Check bucket encryption
            aws s3api get-bucket-encryption --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/encryption.json" 2>/dev/null

            if [ $? -ne 0 ]; then
                echo "$bucket: No default encryption configured" >> "$OUTPUT_DIR/aws/s3_security_issues.txt"
                echo "$bucket: No default encryption configured" >> "$OUTPUT_DIR/aws/unencrypted_buckets.txt"
                ((UNENCRYPTED_COUNT++))
            else
                # Check for weak encryption
                if jq -e '.ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm == "AES256"' "$OUTPUT_DIR/aws/buckets/$bucket/encryption.json" &>/dev/null; then
                    echo "$bucket: Using AES256 (S3-managed keys) instead of KMS" >> "$OUTPUT_DIR/aws/s3_compliance_issues.txt"
                fi
            fi

            # 5. Check bucket versioning
            aws s3api get-bucket-versioning --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/versioning.json" 2>/dev/null

            # Check if versioning is enabled
            if ! jq -e '.Status == "Enabled"' "$OUTPUT_DIR/aws/buckets/$bucket/versioning.json" &>/dev/null; then
                echo "$bucket: Versioning not enabled" >> "$OUTPUT_DIR/aws/s3_compliance_issues.txt"
                ((VERSIONING_DISABLED_COUNT++))
            fi

            # Check for MFA Delete
            if ! jq -e '.MFADelete == "Enabled"' "$OUTPUT_DIR/aws/buckets/$bucket/versioning.json" &>/dev/null; then
                echo "$bucket: MFA Delete not enabled" >> "$OUTPUT_DIR/aws/s3_compliance_issues.txt"
                ((MFA_DELETE_DISABLED_COUNT++))
            fi

            # 6. Check bucket logging
            aws s3api get-bucket-logging --bucket "$bucket" > "$OUTPUT_DIR/aws/buckets/$bucket/logging.json" 2>/dev/null

            # Check if logging is configured
            if ! jq -e '.LoggingEnabled' "$OUTPUT_DIR/aws/buckets/$bucket/logging.json" &>/dev/null; then
                echo "$bucket: Logging not enabled" >> "$OUTPUT_DIR/aws/s3_compliance_issues.txt"
                ((LOGGING_DISABLED_COUNT++))
            fi

            # 7. Check for object-level logging via CloudTrail
            aws cloudtrail list-trails > "$OUTPUT_DIR/aws/cloudtrail/trails.json" 2>/dev/null
            trail_names=$(jq -r '.Trails[].Name' "$OUTPUT_DIR/aws/cloudtrail/trails.json" 2>/dev/null)

            # Initialize flag to check if at least one trail logs this bucket
            BUCKET_S3_EVENTS_LOGGED=false

            if [ -n "$trail_names" ]; then
                while read -r trail; do
                    aws cloudtrail get-event-selectors --trail-name "$trail" > "$OUTPUT_DIR/aws/cloudtrail/${trail}_selectors.json" 2>/dev/null

                    # Check if this trail logs S3 object-level events for this bucket
                    if jq -e '.EventSelectors[] | select(.DataResources[] | select(.Type == "AWS::S3::Object" and (.Values | index("arn:aws:s3:::' "$bucket" '/*") != null)))' "$OUTPUT_DIR/aws/cloudtrail/${trail}_selectors.json" &>/dev/null; then
                        BUCKET_S3_EVENTS_LOGGED=true
                        break
                    fi
                done <<< "$trail_names"
            fi

            if [ "$BUCKET_S3_EVENTS_LOGGED" = false ]; then
                echo "$bucket: No CloudTrail object-level logging configured" >> "$OUTPUT_DIR/aws/s3_compliance_issues.txt"
            fi

        done < "$OUTPUT_DIR/aws/bucket_names.txt"
        echo -e "\n"
    fi

    # Print S3 security summary
    echo -e "${YELLOW}[*] S3 Security Summary:${NC}"
    echo -e "${YELLOW}[-] Buckets with public access issues: $PUBLIC_COUNT${NC}"
    echo -e "${YELLOW}[-] Buckets without default encryption: $UNENCRYPTED_COUNT${NC}"
    echo -e "${YELLOW}[-] Buckets without logging enabled: $LOGGING_DISABLED_COUNT${NC}"
    echo -e "${YELLOW}[-] Buckets without versioning: $VERSIONING_DISABLED_COUNT${NC}"
    echo -e "${YELLOW}[-] Buckets without MFA Delete: $MFA_DELETE_DISABLED_COUNT${NC}"
    echo -e "${YELLOW}[-] Buckets without secure transport enforcement: $SECURE_TRANSPORT_DISABLED_COUNT${NC}"

    # EC2 Security Checks
    echo -e "${BLUE}[*] Checking EC2 security configurations.${NC}"
    aws ec2 describe-instances > "$OUTPUT_DIR/aws/ec2_instances.json" 2>/dev/null

    # Security Group Checks
    echo -e "${BLUE}[*] Checking Security Group configurations.${NC}"
    aws ec2 describe-security-groups > "$OUTPUT_DIR/aws/security_groups.json" 2>/dev/null

    # Check for overly permissive security groups (0.0.0.0/0)
    jq -r '.SecurityGroups[] | select(.IpPermissions[].IpRanges[].CidrIp == "0.0.0.0/0") | .GroupId + ": " + .GroupName' "$OUTPUT_DIR/aws/security_groups.json" > "$OUTPUT_DIR/aws/overly_permissive_sgs.txt" 2>/dev/null

    # Enhanced IAM Security Checks
    mkdir -p "$OUTPUT_DIR/aws/iam/users" "$OUTPUT_DIR/aws/iam/roles" "$OUTPUT_DIR/aws/iam/policies" "$OUTPUT_DIR/aws/iam/groups"
    echo -e "${BLUE}[*] Performing comprehensive IAM security audit.${NC}"

    # Get all IAM users, roles, policies and groups
    echo -e "${BLUE}[*] Retrieving IAM users, roles, policies and groups.${NC}"
    aws iam list-users > "$OUTPUT_DIR/aws/iam/users.json" 2>/dev/null
    aws iam list-roles > "$OUTPUT_DIR/aws/iam/roles.json" 2>/dev/null
    aws iam list-groups > "$OUTPUT_DIR/aws/iam/groups.json" 2>/dev/null
    aws iam list-policies --scope All > "$OUTPUT_DIR/aws/iam/all_policies.json" 2>/dev/null
    aws iam list-policies --scope Local > "$OUTPUT_DIR/aws/iam/custom_policies.json" 2>/dev/null
    aws iam list-policies --scope AWS > "$OUTPUT_DIR/aws/iam/aws_managed_policies.json" 2>/dev/null

    # Get account password policy
    echo -e "${BLUE}[*] Checking password policy.${NC}"
    aws iam get-account-password-policy > "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null
    PASSWORD_POLICY_RESULT=$?

    # Check for weak password policy
    if [ $PASSWORD_POLICY_RESULT -ne 0 ]; then
        echo -e "${RED}[!] No password policy defined!${NC}"
        echo "CRITICAL: No password policy defined" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
    else
        # Check minimum password length
        MIN_LENGTH=$(jq -r '.PasswordPolicy.MinimumPasswordLength' "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null)
        if [ "$MIN_LENGTH" -lt 14 ]; then
            echo -e "${YELLOW}[!] Weak password policy: Minimum length $MIN_LENGTH (recommended: 14)${NC}"
            echo "WARNING: Weak password policy - Minimum length $MIN_LENGTH (recommended: 14)" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
        fi

        # Check password reuse prevention
        REUSE_PREVENTION=$(jq -r '.PasswordPolicy.PasswordReusePrevention // 0' "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null)
        if [ "$REUSE_PREVENTION" -lt 24 ]; then
            echo -e "${YELLOW}[!] Weak password policy: Password reuse prevention $REUSE_PREVENTION (recommended: 24)${NC}"
            echo "WARNING: Weak password policy - Reuse prevention $REUSE_PREVENTION (recommended: 24)" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
        fi

        # Check password expiration
        MAX_AGE=$(jq -r '.PasswordPolicy.MaxPasswordAge // 0' "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null)
        if [ "$MAX_AGE" -eq 0 ] || [ "$MAX_AGE" -gt 90 ]; then
            echo -e "${YELLOW}[!] Weak password policy: Password expiration not enforced or too long ($MAX_AGE days)${NC}"
            echo "WARNING: Weak password policy - Expiration too long or not enforced ($MAX_AGE days)" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
        fi

        # Check for complexity requirements
        REQUIRE_UPPERCASE=$(jq -r '.PasswordPolicy.RequireUppercaseCharacters' "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null)
        REQUIRE_LOWERCASE=$(jq -r '.PasswordPolicy.RequireLowercaseCharacters' "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null)
        REQUIRE_NUMBERS=$(jq -r '.PasswordPolicy.RequireNumbers' "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null)
        REQUIRE_SYMBOLS=$(jq -r '.PasswordPolicy.RequireSymbols' "$OUTPUT_DIR/aws/iam/password_policy.json" 2>/dev/null)

        if [ "$REQUIRE_UPPERCASE" != "true" ] || [ "$REQUIRE_LOWERCASE" != "true" ] || [ "$REQUIRE_NUMBERS" != "true" ] || [ "$REQUIRE_SYMBOLS" != "true" ]; then
            echo -e "${YELLOW}[!] Weak password policy: Not all complexity requirements enforced${NC}"
            echo "WARNING: Weak password policy - Not all complexity requirements enforced" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
        fi
    fi

    # Check for users without MFA
    echo -e "${BLUE}[*] Checking for users without MFA.${NC}"
    aws iam generate-credential-report > /dev/null 2>&1
    sleep 2  # Wait for report generation
    aws iam get-credential-report --query 'Content' --output text | base64 -d > "$OUTPUT_DIR/aws/iam/credential_report.csv" 2>/dev/null

    # Parse credential report
    echo -e "${BLUE}[*] Analyzing credential report.${NC}"
    if [ -s "$OUTPUT_DIR/aws/iam/credential_report.csv" ]; then
        # Extract header line
        head -1 "$OUTPUT_DIR/aws/iam/credential_report.csv" > "$OUTPUT_DIR/aws/iam/credential_report_header.csv"

        # Check root account MFA
        grep "^root" "$OUTPUT_DIR/aws/iam/credential_report.csv" > "$OUTPUT_DIR/aws/iam/root_credentials.csv"
        if grep -q "^root.*,false," "$OUTPUT_DIR/aws/iam/credential_report.csv"; then
            echo -e "${RED}[!] CRITICAL: Root account does not have MFA enabled!${NC}"
            echo "CRITICAL: Root account does not have MFA enabled" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
        fi

        # Check root account access keys
        if grep -q "^root.*,true," "$OUTPUT_DIR/aws/iam/credential_report.csv"; then
            echo -e "${RED}[!] CRITICAL: Root account has access keys!${NC}"
            echo "CRITICAL: Root account has access keys" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
        fi

        # Check for IAM users without MFA
        grep -v "^root" "$OUTPUT_DIR/aws/iam/credential_report.csv" | grep ",false," > "$OUTPUT_DIR/aws/iam/users_without_mfa.csv"
        USERS_WITHOUT_MFA=$(wc -l < "$OUTPUT_DIR/aws/iam/users_without_mfa.csv")

        if [ "$USERS_WITHOUT_MFA" -gt 0 ]; then
            echo -e "${RED}[!] Found $USERS_WITHOUT_MFA IAM users without MFA${NC}"
            echo "WARNING: $USERS_WITHOUT_MFA IAM users without MFA enabled" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
            cat "$OUTPUT_DIR/aws/iam/credential_report_header.csv" "$OUTPUT_DIR/aws/iam/users_without_mfa.csv" > "$OUTPUT_DIR/aws/iam/users_without_mfa_with_header.csv"
        fi

        # Check for users with old credentials
        echo -e "${BLUE}[*] Checking for users with old credentials.${NC}"
        CURRENT_DATE=$(date +%s)

        while IFS=',' read -r user mfa access_key_1_active access_key_1_last_rotated access_key_2_active access_key_2_last_rotated password_enabled password_last_changed password_next_rotation mfa_active rest; do
            [ "$user" = "user" ] && continue  # Skip header

            # Skip root account
            [ "$user" = "root" ] && continue

            # Check for old access keys (> 90 days)
            if [ "$access_key_1_active" = "true" ] && [ "$access_key_1_last_rotated" != "N/A" ]; then
                ACCESS_KEY_1_DATE=$(date -d "$access_key_1_last_rotated" +%s 2>/dev/null)
                if [ -n "$ACCESS_KEY_1_DATE" ]; then
                    ACCESS_KEY_1_AGE=$(( (CURRENT_DATE - ACCESS_KEY_1_DATE) / 86400 ))
                    if [ "$ACCESS_KEY_1_AGE" -gt 90 ]; then
                        echo "$user: Access Key 1 is $ACCESS_KEY_1_AGE days old" >> "$OUTPUT_DIR/aws/iam/old_credentials.txt"
                    fi
                fi
            fi

            if [ "$access_key_2_active" = "true" ] && [ "$access_key_2_last_rotated" != "N/A" ]; then
                ACCESS_KEY_2_DATE=$(date -d "$access_key_2_last_rotated" +%s 2>/dev/null)
                if [ -n "$ACCESS_KEY_2_DATE" ]; then
                    ACCESS_KEY_2_AGE=$(( (CURRENT_DATE - ACCESS_KEY_2_DATE) / 86400 ))
                    if [ "$ACCESS_KEY_2_AGE" -gt 90 ]; then
                        echo "$user: Access Key 2 is $ACCESS_KEY_2_AGE days old" >> "$OUTPUT_DIR/aws/iam/old_credentials.txt"
                    fi
                fi
            fi

            # Check for old passwords (> 90 days)
            if [ "$password_enabled" = "true" ] && [ "$password_last_changed" != "N/A" ]; then
                PASSWORD_DATE=$(date -d "$password_last_changed" +%s 2>/dev/null)
                if [ -n "$PASSWORD_DATE" ]; then
                    PASSWORD_AGE=$(( (CURRENT_DATE - PASSWORD_DATE) / 86400 ))
                    if [ "$PASSWORD_AGE" -gt 90 ]; then
                        echo "$user: Password is $PASSWORD_AGE days old" >> "$OUTPUT_DIR/aws/iam/old_credentials.txt"
                    fi
                fi
            fi
        done < "$OUTPUT_DIR/aws/iam/credential_report.csv"

        if [ -f "$OUTPUT_DIR/aws/iam/old_credentials.txt" ]; then
            OLD_CREDENTIALS_COUNT=$(wc -l < "$OUTPUT_DIR/aws/iam/old_credentials.txt")
            echo -e "${YELLOW}[!] Found $OLD_CREDENTIALS_COUNT credentials older than 90 days${NC}"
            echo "WARNING: $OLD_CREDENTIALS_COUNT credentials older than 90 days" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
        fi
    fi

    # Check for users with Administrator access
    echo -e "${BLUE}[*] Checking for users with administrative privileges.${NC}"
    USER_NAMES=$(jq -r '.Users[].UserName' "$OUTPUT_DIR/aws/iam/users.json" 2>/dev/null)

    # Initialize admin counters
    ADMIN_USERS_COUNT=0

    if [ -n "$USER_NAMES" ]; then
        while read -r user; do
            echo -e "${BLUE}[*] Analyzing user policies: $user${NC}"

            # Get directly attached policies
            aws iam list-attached-user-policies --user-name "$user" > "$OUTPUT_DIR/aws/iam/users/${user}_attached_policies.json" 2>/dev/null

            # Get inline policies
            aws iam list-user-policies --user-name "$user" > "$OUTPUT_DIR/aws/iam/users/${user}_inline_policies.json" 2>/dev/null

            # Check for admin access in attached policies
            POLICY_ARNS=$(jq -r '.AttachedPolicies[].PolicyArn' "$OUTPUT_DIR/aws/iam/users/${user}_attached_policies.json" 2>/dev/null)

            if [ -n "$POLICY_ARNS" ]; then
                while read -r policy_arn; do
                    # Check if policy is AdministratorAccess or similar
                    if [[ "$policy_arn" == *AdministratorAccess* ]] || [[ "$policy_arn" == *FullAccess* ]]; then
                        echo "$user: Has administrative policy attached: $policy_arn" >> "$OUTPUT_DIR/aws/iam/admin_users.txt"
                        ((ADMIN_USERS_COUNT++))
                        break
                    else
                        # Get policy details
                        aws iam get-policy --policy-arn "$policy_arn" > "$OUTPUT_DIR/aws/iam/policies/$(basename "$policy_arn").json" 2>/dev/null

                        # Get policy version
                        DEFAULT_VERSION=$(jq -r '.Policy.DefaultVersionId' "$OUTPUT_DIR/aws/iam/policies/$(basename "$policy_arn").json" 2>/dev/null)

                        if [ -n "$DEFAULT_VERSION" ]; then
                            aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$DEFAULT_VERSION" > "$OUTPUT_DIR/aws/iam/policies/$(basename "$policy_arn")_${DEFAULT_VERSION}.json" 2>/dev/null

                            # Check for * Action and * Resource
                            if jq -e '.PolicyVersion.Document.Statement[] | select(.Effect == "Allow" and .Action == "*" and .Resource == "*")' "$OUTPUT_DIR/aws/iam/policies/$(basename "$policy_arn")_${DEFAULT_VERSION}.json" &>/dev/null; then
                                echo "$user: Has policy with full admin access: $policy_arn" >> "$OUTPUT_DIR/aws/iam/admin_users.txt"
                                ((ADMIN_USERS_COUNT++))
                                break
                            fi
                        fi
                    fi
                done <<< "$POLICY_ARNS"
            fi

            # Check user groups for admin access
            aws iam list-groups-for-user --user-name "$user" > "$OUTPUT_DIR/aws/iam/users/${user}_groups.json" 2>/dev/null
            GROUP_NAMES=$(jq -r '.Groups[].GroupName' "$OUTPUT_DIR/aws/iam/users/${user}_groups.json" 2>/dev/null)

            if [ -n "$GROUP_NAMES" ]; then
                while read -r group; do
                    # Check group policies
                    aws iam list-attached-group-policies --group-name "$group" > "$OUTPUT_DIR/aws/iam/groups/${group}_policies.json" 2>/dev/null
                    GROUP_POLICY_ARNS=$(jq -r '.AttachedPolicies[].PolicyArn' "$OUTPUT_DIR/aws/iam/groups/${group}_policies.json" 2>/dev/null)

                    if [ -n "$GROUP_POLICY_ARNS" ]; then
                        while read -r group_policy_arn; do
                            if [[ "$group_policy_arn" == *AdministratorAccess* ]] || [[ "$group_policy_arn" == *FullAccess* ]]; then
                                echo "$user: Has administrative access via group $group (policy: $group_policy_arn)" >> "$OUTPUT_DIR/aws/iam/admin_users.txt"
                                ((ADMIN_USERS_COUNT++))
                                break 2
                            fi
                        done <<< "$GROUP_POLICY_ARNS"
                    fi
                done <<< "$GROUP_NAMES"
            fi
        done <<< "$USER_NAMES"
    fi

    if [ -f "$OUTPUT_DIR/aws/iam/admin_users.txt" ]; then
        echo -e "${YELLOW}[!] Found $ADMIN_USERS_COUNT users with administrative privileges${NC}"
        echo "WARNING: $ADMIN_USERS_COUNT users with administrative privileges" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
    else
        echo -e "${YELLOW}[*] No users with administrative privileges found${NC}"
    fi

    # Analyze custom IAM policies for overly permissive settings
    echo -e "${BLUE}[*] Analyzing custom IAM policies for security issues.${NC}"
    CUSTOM_POLICY_ARNS=$(jq -r '.Policies[].Arn' "$OUTPUT_DIR/aws/iam/custom_policies.json" 2>/dev/null)

    if [ -n "$CUSTOM_POLICY_ARNS" ]; then
        OVERLY_PERMISSIVE_COUNT=0

        while read -r policy_arn; do
            # Get policy details
            aws iam get-policy --policy-arn "$policy_arn" > "$OUTPUT_DIR/aws/iam/policies/$(basename "$policy_arn").json" 2>/dev/null

            # Get policy version
            DEFAULT_VERSION=$(jq -r '.Policy.DefaultVersionId' "$OUTPUT_DIR/aws/iam/policies/$(basename "$policy_arn").json" 2>/dev/null)

            if [ -n "$DEFAULT_VERSION" ]; then
                aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$DEFAULT_VERSION" > "$OUTPUT_DIR/aws/iam/policies/$(basename "$policy_arn")_${DEFAULT_VERSION}.json" 2>/dev/null

                # Check for * Action and * Resource
                if jq -e '.PolicyVersion.Document.Statement[] | select(.Effect == "Allow" and (.Action == "*" or ((.Action | type) == "array" and (.Action | index("*") != null))) and (.Resource == "*" or ((.Resource | type) == "array" and (.Resource | index("*") != null))))' "$OUTPUT_DIR/aws/iam/policies/$(basename "$policy_arn")_${DEFAULT_VERSION}.json" &>/dev/null; then
                    echo "Policy $policy_arn: Overly permissive (Action: *, Resource: *)" >> "$OUTPUT_DIR/aws/iam/overly_permissive_policies.txt"
                    ((OVERLY_PERMISSIVE_COUNT++))
                fi
            fi
        done <<< "$CUSTOM_POLICY_ARNS"

        if [ "$OVERLY_PERMISSIVE_COUNT" -gt 0 ]; then
            echo -e "${RED}[!] Found $OVERLY_PERMISSIVE_COUNT overly permissive custom policies${NC}"
            echo "WARNING: $OVERLY_PERMISSIVE_COUNT overly permissive custom policies" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
        else
            echo -e "${YELLOW}[*] No overly permissive custom policies found${NC}"
        fi
    fi

    # Check for IAM access analyzer findings
    echo -e "${BLUE}[*] Checking IAM Access Analyzer findings.${NC}"

    # List analyzers
    aws accessanalyzer list-analyzers > "$OUTPUT_DIR/aws/iam/analyzers.json" 2>/dev/null
    ANALYZER_ARNS=$(jq -r '.analyzers[].arn' "$OUTPUT_DIR/aws/iam/analyzers.json" 2>/dev/null)

    if [ -n "$ANALYZER_ARNS" ]; then
        while read -r analyzer_arn; do
            ANALYZER_ID=$(basename "$analyzer_arn")
            aws accessanalyzer list-findings --analyzer-arn "$analyzer_arn" > "$OUTPUT_DIR/aws/iam/analyzer_${ANALYZER_ID}_findings.json" 2>/dev/null

            # Count by status
            ACTIVE_FINDINGS=$(jq -r '.findings[] | select(.status == "ACTIVE") | .id' "$OUTPUT_DIR/aws/iam/analyzer_${ANALYZER_ID}_findings.json" 2>/dev/null | wc -l)

            if [ "$ACTIVE_FINDINGS" -gt 0 ]; then
                echo -e "${RED}[!] Found $ACTIVE_FINDINGS active findings in Access Analyzer ${ANALYZER_ID}${NC}"
                echo "WARNING: $ACTIVE_FINDINGS active findings in Access Analyzer $ANALYZER_ID" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"

                # Extract finding details
                jq -r '.findings[] | select(.status == "ACTIVE") | "Resource: " + .resource + ", Type: " + .resourceType + ", External Principal: " + (.principal | tostring)' "$OUTPUT_DIR/aws/iam/analyzer_${ANALYZER_ID}_findings.json" >> "$OUTPUT_DIR/aws/iam/access_analyzer_findings.txt"
            else
                echo -e "${YELLOW}[*] No active findings in Access Analyzer ${ANALYZER_ID}${NC}"
            fi
        done <<< "$ANALYZER_ARNS"
    else
        echo -e "${YELLOW}[!] No IAM Access Analyzers configured${NC}"
        echo "WARNING: No IAM Access Analyzers configured" >> "$OUTPUT_DIR/aws/iam/security_issues.txt"
    fi

    # Summarize IAM findings
    echo -e "${YELLOW}[*] IAM Security Summary:${NC}"

    if [ -f "$OUTPUT_DIR/aws/iam/security_issues.txt" ]; then
        TOTAL_IAM_ISSUES=$(wc -l < "$OUTPUT_DIR/aws/iam/security_issues.txt")
        echo -e "${YELLOW}[-] Found $TOTAL_IAM_ISSUES IAM security issues${NC}"
        echo -e "${YELLOW}[-] Users without MFA: $USERS_WITHOUT_MFA${NC}"
        echo -e "${YELLOW}[-] Users with administrative access: $ADMIN_USERS_COUNT${NC}"
        echo -e "${YELLOW}[-] Overly permissive policies: $OVERLY_PERMISSIVE_COUNT${NC}"
    else
        echo -e "${YELLOW}[*] No IAM security issues found${NC}"
    fi

    # CloudTrail Checks
    echo -e "${BLUE}[*] Checking CloudTrail configurations.${NC}"
    aws cloudtrail describe-trails > "$OUTPUT_DIR/aws/cloudtrail.json" 2>/dev/null

    # Check for trails without encryption or multi-region disabled
    jq -r '.trailList[] | select(.KmsKeyId == null or .IsMultiRegionTrail == false) | .Name' "$OUTPUT_DIR/aws/cloudtrail.json" > "$OUTPUT_DIR/aws/vulnerable_trails.txt" 2>/dev/null

    # Generate Security Report
    echo -e "${BLUE}[*] Generating AWS security report.${NC}"
    {
        echo "AWS Cloud Security Report"
        echo "========================="
        echo "Date: $DATESTAMP $TIMESTAMP"
        echo

        echo "1. Account Information"
        echo "---------------------"
        jq -r '.Account + " (" + .Arn + ")"' "$OUTPUT_DIR/aws/account_info.json" 2>/dev/null
        echo

        echo "2. S3 Bucket Security"
        echo "--------------------"
        echo "Total S3 Buckets: $(jq -r '.Buckets | length' "$OUTPUT_DIR/aws/s3_buckets.json" 2>/dev/null)"

        if [ -f "$OUTPUT_DIR/aws/public_buckets.txt" ] && [ -s "$OUTPUT_DIR/aws/public_buckets.txt" ]; then
            echo "WARNING: The following buckets may have public access:"
            cat "$OUTPUT_DIR/aws/public_buckets.txt"
        else
            echo "No publicly accessible buckets detected."
        fi

        echo
        echo "3. Security Group Configurations"
        echo "-------------------------------"

        if [ -f "$OUTPUT_DIR/aws/overly_permissive_sgs.txt" ] && [ -s "$OUTPUT_DIR/aws/overly_permissive_sgs.txt" ]; then
            echo "WARNING: The following security groups allow access from anywhere (0.0.0.0/0):"
            cat "$OUTPUT_DIR/aws/overly_permissive_sgs.txt"
        else
            echo "No overly permissive security groups detected."
        fi

        echo
        echo "4. IAM Security"
        echo "--------------"
        echo "Total Users: $(jq -r '.Users | length' "$OUTPUT_DIR/aws/iam_users.json" 2>/dev/null)"
        echo "Total Roles: $(jq -r '.Roles | length' "$OUTPUT_DIR/aws/iam_roles.json" 2>/dev/null)"
        echo "Custom Policies: $(jq -r '.Policies | length' "$OUTPUT_DIR/aws/iam_custom_policies.json" 2>/dev/null)"

        if [ -f "$OUTPUT_DIR/aws/users_without_mfa.csv" ] && [ -s "$OUTPUT_DIR/aws/users_without_mfa.csv" ]; then
            echo "WARNING: The following users do not have MFA enabled:"
            awk -F',' '{print $1}' "$OUTPUT_DIR/aws/users_without_mfa.csv"
        else
            echo "All users have MFA enabled."
        fi

        echo
        echo "5. CloudTrail Audit Logging"
        echo "--------------------------"
        echo "Total CloudTrails: $(jq -r '.trailList | length' "$OUTPUT_DIR/aws/cloudtrail.json" 2>/dev/null)"

        if [ -f "$OUTPUT_DIR/aws/vulnerable_trails.txt" ] && [ -s "$OUTPUT_DIR/aws/vulnerable_trails.txt" ]; then
            echo "WARNING: The following trails have security issues (no encryption or multi-region disabled):"
            cat "$OUTPUT_DIR/aws/vulnerable_trails.txt"
        else
            echo "All trails have proper security configurations."
        fi
    } > "$OUTPUT_DIR/aws_security_report.txt"

    echo -e "${YELLOW}[*] AWS security check complete. Results saved to $OUTPUT_DIR/aws_security_report.txt${NC}"
}

###############################################################################################################################

# Azure Security Check Function
f_azure_security_check(){
    # Check for Azure CLI
    if ! command -v az &> /dev/null; then
        echo
        echo -e "${YELLOW}Installing Azure CLI.${NC}"
        sudo apt update
        sudo apt install -y azure-cli
        echo
    fi

    local OUTPUT_DIR="$1"

    echo
    echo -e "${BLUE}[*] Performing Azure security checks.${NC}"
    mkdir -p "$OUTPUT_DIR/azure"

    # Check if Azure CLI is logged in
    if ! az account show &> /dev/null; then
        echo -e "${YELLOW}[!] Azure CLI is not logged in. Running az login.${NC}"
        az login
    fi

    # Get Azure Subscription information
    echo -e "${BLUE}[*] Getting Azure Subscription information.${NC}"
    az account show > "$OUTPUT_DIR/azure/subscription_info.json" 2>/dev/null

    if [ $? -ne 0 ]; then
        echo
        echo -e "${RED}[!] Failed to authenticate with Azure. Please check your credentials.${NC}"
        echo
        exit 1
    fi

    # Get Resource Groups
    echo -e "${BLUE}[*] Getting Azure Resource Groups.${NC}"
    az group list > "$OUTPUT_DIR/azure/resource_groups.json" 2>/dev/null

    # Storage Account Security Checks
    echo -e "${BLUE}[*] Checking Storage Account security configurations.${NC}"
    az storage account list > "$OUTPUT_DIR/azure/storage_accounts.json" 2>/dev/null

    # Check for storage accounts with public access enabled
    jq -r '.[] | select(.allowBlobPublicAccess == true) | .name + ": Public blob access enabled"' "$OUTPUT_DIR/azure/storage_accounts.json" > "$OUTPUT_DIR/azure/public_storage_accounts.txt" 2>/dev/null

    # Network Security Group Checks
    echo -e "${BLUE}[*] Checking Network Security Group configurations.${NC}"
    az network nsg list > "$OUTPUT_DIR/azure/network_security_groups.json" 2>/dev/null

    # VM Security Checks
    echo -e "${BLUE}[*] Checking VM security configurations.${NC}"
    az vm list > "$OUTPUT_DIR/azure/vms.json" 2>/dev/null

    # Check for VMs without disk encryption
    az vm encryption show --ids $(az vm list --query "[].id" -o tsv) > "$OUTPUT_DIR/azure/vm_encryption.json" 2>/dev/null

    # Key Vault Checks
    echo -e "${BLUE}[*] Checking Key Vault configurations.${NC}"
    az keyvault list > "$OUTPUT_DIR/azure/keyvaults.json" 2>/dev/null

    # Generate Security Report
    echo -e "${BLUE}[*] Generating Azure security report.${NC}"
    {
        echo "Azure Cloud Security Report"
        echo "==========================="
        echo "Date: $DATESTAMP $TIMESTAMP"
        echo

        echo "1. Subscription Information"
        echo "-------------------------"
        jq -r '"\(.name) (\(.id))"' "$OUTPUT_DIR/azure/subscription_info.json" 2>/dev/null
        echo

        echo "2. Storage Account Security"
        echo "--------------------------"
        echo "Total Storage Accounts: $(jq -r '. | length' "$OUTPUT_DIR/azure/storage_accounts.json" 2>/dev/null)"

        if [ -f "$OUTPUT_DIR/azure/public_storage_accounts.txt" ] && [ -s "$OUTPUT_DIR/azure/public_storage_accounts.txt" ]; then
            echo "WARNING: The following storage accounts have public blob access enabled:"
            cat "$OUTPUT_DIR/azure/public_storage_accounts.txt"
        else
            echo "No storage accounts with public blob access detected."
        fi

        echo
        echo "3. Network Security Group Configurations"
        echo "---------------------------------------"
        echo "Total NSGs: $(jq -r '. | length' "$OUTPUT_DIR/azure/network_security_groups.json" 2>/dev/null)"
        echo

        echo "4. Virtual Machine Security"
        echo "-------------------------"
        echo "Total VMs: $(jq -r '. | length' "$OUTPUT_DIR/azure/vms.json" 2>/dev/null)"
        echo

        echo "5. Key Vault Security"
        echo "-------------------"
        echo "Total Key Vaults: $(jq -r '. | length' "$OUTPUT_DIR/azure/keyvaults.json" 2>/dev/null)"
    } > "$OUTPUT_DIR/azure_security_report.txt"

    echo -e "${YELLOW}[*] Azure security check complete. Results saved to $OUTPUT_DIR/azure_security_report.txt${NC}"
}

###############################################################################################################################

# Google Cloud Platform Security Check Function
f_gcp_security_check(){
    # Check for Google Cloud CLI
    if ! command -v gcloud &> /dev/null; then
        echo
        echo -e "${YELLOW}Installing Google Cloud CLI.${NC}"
        cd "$HOME/"
        curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz
        tar -xf google-cloud-cli-linux-x86_64.tar.gz
        rm google-cloud-cli-linux-x86_64.tar.gz
        ./google-cloud-sdk/install.sh
        echo
    fi

    local OUTPUT_DIR="$1"

    echo
    echo -e "${BLUE}[*] Performing Google Cloud Platform security checks.${NC}"
    mkdir -p "$OUTPUT_DIR/gcp"

    # Check if GCloud is configured
    if ! gcloud config list &> /dev/null; then
        echo -e "${YELLOW}[!] GCloud is not configured. Running gcloud init.${NC}"
        gcloud init
    fi

    # Get GCP Project information
    echo -e "${BLUE}[*] Getting GCP Project information.${NC}"
    gcloud projects list --format=json > "$OUTPUT_DIR/gcp/projects.json" 2>/dev/null

    if [ $? -ne 0 ]; then
        echo
        echo -e "${RED}[!] Failed to authenticate with GCP. Please check your credentials.${NC}"
        echo
        exit 1
    fi

    # Get active project
    active_project=$(gcloud config get-value project 2>/dev/null)
    echo "$active_project" > "$OUTPUT_DIR/gcp/active_project.txt"

    # Storage Bucket Security Checks
    echo -e "${BLUE}[*] Checking Storage Bucket security configurations.${NC}"
    gsutil ls -p "$active_project" > "$OUTPUT_DIR/gcp/buckets.txt" 2>/dev/null

    # Check bucket IAM permissions
    if [ -s "$OUTPUT_DIR/gcp/buckets.txt" ]; then
        while read -r bucket; do
            bucket_name=$(basename "$bucket")
            echo -e "${BLUE}[*] Analyzing bucket: $bucket_name${NC}"
            gsutil iam get "$bucket" > "$OUTPUT_DIR/gcp/iam/$bucket_name-iam.json" 2>/dev/null

            # Check for public access
            if grep -q "allUsers\|allAuthenticatedUsers" "$OUTPUT_DIR/gcp/iam/$bucket_name-iam.json" 2>/dev/null; then
                echo "$bucket_name: Public access detected" >> "$OUTPUT_DIR/gcp/public_buckets.txt"
            fi
        done < "$OUTPUT_DIR/gcp/buckets.txt"
    fi

    # Compute Instance Security Checks
    echo -e "${BLUE}[*] Checking Compute Instance security configurations.${NC}"
    gcloud compute instances list --format=json > "$OUTPUT_DIR/gcp/instances.json" 2>/dev/null

    # Firewall Rule Checks
    echo -e "${BLUE}[*] Checking Firewall Rule configurations.${NC}"
    gcloud compute firewall-rules list --format=json > "$OUTPUT_DIR/gcp/firewall_rules.json" 2>/dev/null

    # Check for overly permissive firewall rules
    jq -r '.[] | select(.sourceRanges[] == "0.0.0.0/0") | .name + ": Allows traffic from anywhere"' "$OUTPUT_DIR/gcp/firewall_rules.json" > "$OUTPUT_DIR/gcp/permissive_firewall_rules.txt" 2>/dev/null

    # IAM Checks
    echo -e "${BLUE}[*] Checking IAM configurations.${NC}"
    gcloud projects get-iam-policy "$active_project" --format=json > "$OUTPUT_DIR/gcp/iam_policy.json" 2>/dev/null

    # Check for roles with dangerous permissions
    jq -r '.bindings[] | select(.role == "roles/owner" or .role == "roles/editor") | .role + ": " + (.members | join(", "))' "$OUTPUT_DIR/gcp/iam_policy.json" > "$OUTPUT_DIR/gcp/sensitive_roles.txt" 2>/dev/null

    # Generate Security Report
    echo -e "${BLUE}[*] Generating GCP security report.${NC}"
    {
        echo "Google Cloud Platform Security Report"
        echo "===================================="
        echo "Date: $DATESTAMP $TIMESTAMP"
        echo

        echo "1. Project Information"
        echo "--------------------"
        echo "Active Project: $(cat "$OUTPUT_DIR/gcp/active_project.txt")"
        echo "Total Projects: $(jq -r '. | length' "$OUTPUT_DIR/gcp/projects.json" 2>/dev/null)"
        echo

        echo "2. Storage Bucket Security"
        echo "------------------------"

        if [ -f "$OUTPUT_DIR/gcp/buckets.txt" ]; then
            echo "Total Buckets: $(wc -l < "$OUTPUT_DIR/gcp/buckets.txt")"
            
            if [ -f "$OUTPUT_DIR/gcp/public_buckets.txt" ] && [ -s "$OUTPUT_DIR/gcp/public_buckets.txt" ]; then
                echo "WARNING: The following buckets have public access:"
                cat "$OUTPUT_DIR/gcp/public_buckets.txt"
            else
                echo "No buckets with public access detected."
            fi
        else
            echo "No storage buckets found."
        fi

        echo
        echo "3. Firewall Rule Configurations"
        echo "-----------------------------"
        echo "Total Firewall Rules: $(jq -r '. | length' "$OUTPUT_DIR/gcp/firewall_rules.json" 2>/dev/null)"

        if [ -f "$OUTPUT_DIR/gcp/permissive_firewall_rules.txt" ] && [ -s "$OUTPUT_DIR/gcp/permissive_firewall_rules.txt" ]; then
            echo "WARNING: The following firewall rules allow traffic from anywhere (0.0.0.0/0):"
            cat "$OUTPUT_DIR/gcp/permissive_firewall_rules.txt"
        else
            echo "No overly permissive firewall rules detected."
        fi

        echo
        echo "4. IAM Security"
        echo "-------------"

        if [ -f "$OUTPUT_DIR/gcp/sensitive_roles.txt" ] && [ -s "$OUTPUT_DIR/gcp/sensitive_roles.txt" ]; then
            echo "WARNING: The following sensitive roles have been assigned:"
            cat "$OUTPUT_DIR/gcp/sensitive_roles.txt"
        else
            echo "No sensitive role assignments detected."
        fi
    } > "$OUTPUT_DIR/gcp_security_report.txt"

    echo -e "${YELLOW}[*] GCP security check complete. Results saved to $OUTPUT_DIR/gcp_security_report.txt${NC}"
}

###############################################################################################################################

# Main function
f_cloud_main(){
    echo -e "${BLUE}Cloud Security Scanner${NC} | ${YELLOW}by ibrahimsql${NC}"
    echo
    echo "1. AWS (Amazon Web Services)"
    echo "2. Azure (Microsoft Azure)"
    echo "3. GCP (Google Cloud Platform)"
    echo "4. All providers"
    echo "5. Previous menu"
    echo
    echo -n "Choice: "
    read -r CHOICE

    case "$CHOICE" in
        1)
            f_aws_security_check "$NAME" ;;
        2)
            f_azure_security_check "$NAME" ;;
        3)
            f_gcp_security_check "$NAME" ;;
        4)
            f_aws_security_check "$NAME"
            f_azure_security_check "$NAME"
            f_gcp_security_check "$NAME"

            # Generate combined report
            echo -e "${BLUE}[*] Generating combined cloud security report.${NC}"
            {
                echo "Combined Cloud Security Report"
                echo "=============================="
                echo "Date: $DATESTAMP $TIMESTAMP"
                echo
                echo "This report contains security findings from multiple cloud providers."
                echo "Please refer to the individual reports for detailed information:"
                echo

                if [ -f "$NAME/aws_security_report.txt" ]; then
                    echo "[*] AWS Security Report: $NAME/aws_security_report.txt"
                fi

                if [ -f "$NAME/azure_security_report.txt" ]; then
                    echo "[*] Azure Security Report: $NAME/azure_security_report.txt"
                fi

                if [ -f "$NAME/gcp_security_report.txt" ]; then
                    echo "[*] GCP Security Report: $NAME/gcp_security_report.txt"
                fi

                echo
                echo "Summary of Critical Findings"
                echo "============================"
                echo
                echo "AWS Critical Issues:"

                if [ -f "$NAME/aws/public_buckets.txt" ] && [ -s "$NAME/aws/public_buckets.txt" ]; then
                    echo "[*] Public S3 Buckets Detected"
                fi

                if [ -f "$NAME/aws/overly_permissive_sgs.txt" ] && [ -s "$NAME/aws/overly_permissive_sgs.txt" ]; then
                    echo "[*] Overly Permissive Security Groups Detected"
                fi

                echo
                echo "Azure Critical Issues:"

                if [ -f "$NAME/azure/public_storage_accounts.txt" ] && [ -s "$NAME/azure/public_storage_accounts.txt" ]; then
                    echo "[*] Public Storage Accounts Detected"
                fi

                echo
                echo "GCP Critical Issues:"

                if [ -f "$NAME/gcp/public_buckets.txt" ] && [ -s "$NAME/gcp/public_buckets.txt" ]; then
                    echo "[*] Public GCP Buckets Detected"
                fi

                if [ -f "$NAME/gcp/permissive_firewall_rules.txt" ] && [ -s "$NAME/gcp/permissive_firewall_rules.txt" ]; then
                    echo "[*] Overly Permissive Firewall Rules Detected"
                fi
           } > "$NAME/combined_cloud_security_report.txt"

            echo -e "${YELLOW}[*] Combined security report generated: $NAME/combined_cloud_security_report.txt${NC}"
            ;;
        5)
            f_main ;;
        *)
            echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; clear && f_banner && f_cloud_main ;;
    esac
}

# Run the script
f_cloud_main
