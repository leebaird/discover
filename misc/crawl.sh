#!/usr/bin/bash

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
     echo "========================================"
     echo
     echo "Invalid choice."
     echo
     echo
     exit
fi

echo
echo "========================================"
echo

wget -q www.$domain

if [ ! -e index.html ]; then
     echo
     exit
fi

grep 'href=' index.html | cut -d '/' -f3 | grep $domain | egrep -v "(www.$domain|>)" | cut -d '"' -f1 | sort -u > tmp

if [ ! -s tmp ]; then
     echo 'No subdomains found.'
else
     cat tmp | sort -u | column -t 2>/dev/null
fi

rm index.html tmp*

echo
echo
