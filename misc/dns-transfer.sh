#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

medium='=================================================================='

clear
echo
echo "DNS Transfer"
echo
echo
echo "By Lee Baird"
echo
echo "Check for DNS zone transfer."
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
    echo
    exit 1
fi

echo
echo $medium
echo

# Perform DNS zone transfer check
for x in $(host -t ns "$domain" | cut -d ' ' -f4); do
    echo "[*] Checking name server: $x"

    # Check if the DNS zone transfer is successful
    if host -l "$domain" "$x" > /dev/null 2>&1; then
        host -l "$domain" "$x"
    else
        echo "[!] Failed or no zone transfer on $x."
        echo
        echo
        exit 1
    fi

    echo $medium
done

echo
echo
