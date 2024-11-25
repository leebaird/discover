#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

# Check if Firefox is running
if pgrep firefox > /dev/null; then
    echo
    echo "[!] Close Firefox before running script."
    echo
    exit 1
fi

echo
echo
echo "Search for info on a CVE."
echo
echo -n "CVE: "
read -r CVE
echo

# Check for a valid CVE
if [[ ! $CVE =~ ^CVE-[0-9]{4}-[0-9]{4,6}$ ]]; then
    echo
    echo "[!] Invalid format."
    echo
    exit 1
fi

urls=(
    "https://nvd.nist.gov/vuln/detail/$CVE"
    "https://www.cvedetails.com/cve/$CVE"
    "https://vulners.com/search?query=$CVE"
    "https://www.tenable.com/cve/$CVE"
    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=$CVE"
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=$CVE"
    "https://www.google.com/search?q=%22$CVE%22+AND+exploit"
    "https://www.rapid7.com/db/?q=$CVE&type=nexpose"
)

# Open each URL in a new tab
for url in "${urls[@]}"; do
    xdg-open "$url" &
    sleep 2
done
