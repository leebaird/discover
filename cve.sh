#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)
# Thanks to Aaron Stone

set -euo pipefail

# Check for a program
if ! command -v jq &> /dev/null; then
    echo
    echo "[!] jq is not installed."
    echo
    exit 1
fi

# Check if Firefox is running
if pgrep firefox > /dev/null; then
    echo
    echo "[!] Close Firefox before running script."
    echo
    exit 1
fi

clear
echo
echo
echo "Search for info and exploits on a CVE."
echo
echo -n "CVE: "
read -r cve
echo

# Check for no answer
if [ -z "$cve" ]; then
    echo
    echo "[!] No CVE entered."
    echo
    exit 1
fi

# Validate CVE format
if ! echo "$cve" | grep -Eq '^CVE-[0-9]{4}-[0-9]{4,7}$'; then
    echo
    echo "[!] Invalid format."
    echo
    exit 1
fi

# Make GET request and parse JSON response using jq
response=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve")

# Parse JSON response using jq
description=$(echo "$response" | jq -r '.vulnerabilities[0].cve.descriptions[0].value')
published=$(echo "$response" | jq -r '.vulnerabilities[0].cve.published')
last_modified=$(echo "$response" | jq -r '.vulnerabilities[0].cve.lastModified')
severity=$(echo "$response" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity')
cvss_version=$(echo "$response" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.version')
cvss_score=$(echo "$response" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore')
reference_url=$(echo "$response" | jq -r '.vulnerabilities[0].cve.references[0].url')

# Convert timestamps to desired format
published_formatted=$(date -d "$published" "+%Y-%m-%d")
last_modified_formatted=$(date -d "$last_modified" "+%Y-%m-%d")

# Output
echo "Description:    $description"
echo
echo "Published:      $published_formatted"
echo "Last modified:  $last_modified_formatted"
echo "Severity:       $severity"
echo "CVSS version:   $cvss_version"
echo "CVSS score:     $cvss_score"
echo "Reference:      $reference_url"

###############################################################################################################################

echo
echo "[*] seachsploit"
searchsploit "$cve"

###############################################################################################################################

xdg-open https://github.com/search?q="$cve"&type=repositories &
sleep 4
xdg-open https://www.google.com/search?q=%22"$cve"%22+AND+exploit &
sleep 4
xdg-open https://www.rapid7.com/db/?q="$cve"&type=nexpose &
sleep 4
xdg-open https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query="$cve"&search_type=all&isCpeNameSearch=false &
sleep 4
xdg-open https://www.tenable.com/plugins &
