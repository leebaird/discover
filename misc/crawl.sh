#!/usr/bin/bash

# by Lee Baird (@discoverscripts)

medium='=================================================================='

clear
echo
echo "Crawl"
echo
echo
echo "By Lee Baird"
echo
echo "Find all of the subdomains linked to the homepage."
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

wget www.$domain

grep 'href=' index.html | cut -d '/' -f3 | grep $domain | egrep -v "(www.$domain|>)" | cut -d '"' -f1 | sort -u > tmp

if [ ! -s tmp ]; then
    echo 'No subdomains found.'
else
    echo $medium
    echo
    cat tmp | sed 's/\?.*//' | sort -u | column -t
fi

rm index.html tmp*

echo
echo
