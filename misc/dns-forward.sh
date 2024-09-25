#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

medium='=================================================================='

clear
echo
echo "DNS Forward"
echo
echo
echo "By Lee Baird"
echo
echo "Show IP addresses of subdomains."
echo
echo "Usage: target.com"
echo

echo -n "Domain: "
read -r domain

if [ -z "$domain" ]; then
    echo
    echo $medium
    echo
    echo "[!] Invalid choice."
    echo
    exit 1
fi

if [ ! -f /usr/share/dnsenum/dns.txt ]; then
    echo
    echo $medium
    echo
    echo "[!] Subdomain list not found at /usr/share/dnsenum/dns.txt"
    echo
    exit 1
fi

echo
echo $medium
echo

while IFS= read -r x; do
    if result=$(host "$x.$domain" | grep 'has address'); then
        echo "$result" | cut -d ' ' -f1,4 >> tmp
    else
        echo
        echo "[!] Failed to resolve $x.$domain"
        echo
        exit 1
    fi
done < /usr/share/dnsenum/dns.txt

column -t tmp | sort -u

rm tmp
