#!/bin/bash

clear
echo
echo Crawl
echo
echo
echo By Lee Baird
echo
echo "Returns a list of IP addresses to web servers that are linked from a given domain's home page."
echo
echo Usage: target.com
echo

read -p "Domain: " domain

if [ -z $domain ]; then
     echo
     echo "#########################"
     echo
     echo "Invalid choice."
     echo
     exit
fi

echo
echo "#########################"
echo

wget www.$domain

grep 'href=' index.html | cut -d '/' -f3 | grep $domain | cut -d '"' -f1 | sort -u > tmp

for x in $(cat tmp); do
     host $x | grep 'has address' | cut -d ' ' -f4 >> tmp2
done

cat tmp2 | sort -nu > $domain

rm index.html
rm tmp*

echo "#########################"
echo
cat $domain
echo
echo
