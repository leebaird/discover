#!/bin/bash

clear
echo
echo "Netblocks"
echo
echo
echo "By Lee Baird"
echo
echo "This returns a list of Class A owners and takes about 100 sec."
echo

for x in `seq 1 255`; do
     whois $x.0.0.0 | egrep '(CIDR|OrgName)' >> tmp
     echo >> tmp
done

egrep -v '(%|No address)' tmp > tmp2
cat -s tmp2 > netblocks.txt

rm tmp*

echo
echo

