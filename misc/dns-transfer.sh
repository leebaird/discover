#!/usr/bin/bash

# by Lee Baird (@discoverscripts)

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

read -p "Domain: " domain

if [ -z $domain ]; then
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

for x in $(host -t ns $domain | cut -d ' ' -f4); do
    host -l $domain $x
done

echo
echo
