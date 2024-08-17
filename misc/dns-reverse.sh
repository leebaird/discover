#!/usr/bin/bash

# by Lee Baird (@discoverscripts)

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

read -p "Class: " class

if [ -z $class ]; then
    echo
    echo $medium
    echo
    echo "Invalid choice."
    echo
    echo
    exit 1
fi

echo
echo $medium
echo

for x in `seq 1 254`; do
    host $class.$x | grep 'name pointer' | cut -d ' ' -f1,5
done

echo
echo
