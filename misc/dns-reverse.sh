#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

medium='=================================================================='

clear
echo
echo "DNS Reverse"
echo
echo
echo "By Lee Baird"
echo
echo "Perform a PTR DNS query on a Class C range and return FQDNs."
echo
echo "Usage: 192.168.1"
echo

echo -n "Class: "
read -r class

# Check if class is empty
if [ -z "$class" ]; then
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

# Perform PTR DNS query on each IP in the Class C range
for x in $(seq 1 254); do
    # Check if the host command returns a valid PTR record
    if result=$(host "$class.$x" | grep 'name pointer'); then
        echo "$result" | cut -d ' ' -f1,5
    else
        echo "[!] No PTR record for $class.$x"
    fi
done

echo
echo
