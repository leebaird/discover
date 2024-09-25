#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

medium='=================================================================='

clear
echo
echo -n "Enter a domain: "
read -r domain

# Check for no answer
if [ -z "$domain" ]; then
    echo
    echo $medium
    echo
    echo "[!] Invalid choice."
    echo
    exit 1
fi

sslyze "$domain" --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers > tmp

grep 'X509v3 Subject Alternative Name:' tmp | sed 's/      X509v3 Subject Alternative Name:   //g; s/, DNS:/\n/g; s/www.//g; s/DNS://g' > tmp2

# Remove trailing whitespace from each line
sed 's/[ \t]*$//' tmp2 | sort -u > tmp3

echo
cat tmp3
rm tmp*
