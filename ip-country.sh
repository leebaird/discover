#!/bin/bash

# Check for argument. If not given, print the usage
if [ -z "$1" ]; then
    echo
    echo "Usage: $0 <list of IPs>"
    exit 1
fi

while read i; do
    country=$(whois "$i" | grep -i country | head -n1)
    echo "$i $country" >> tmp
done < $1

cat tmp | sed 's/ # country is really world wide//gi; s/country:        //gi' | column -t | sort -k2 > ip-countries.txt
rm tmp
