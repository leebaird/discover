#!/bin/bash

echo
echo
echo "This will take about 100 sec."

for x in `seq 1 255`; do
     whois $x.0.0.0 | egrep '(CIDR|OrgName)' >> tmp
     echo >> tmp
done

egrep -v '(%|No address)' tmp > tmp2
cat -s tmp2 > netblocks.txt

rm tmp*

echo
echo

