#!/bin/bash

clear

break="=================================================="

echo "Discover Report"
echo "${PWD##*/}"
date "+%A, %m-%d-%Y"
echo
cat report.txt | grep 'Start time'
cat report.txt | grep 'Finish time'
echo "Scanner IP - $(ifconfig | grep 'Bcast' | cut -d ':' -f2 | cut -d ' ' -f1)"
nmap -V | grep 'version' | cut -d ' ' -f1-3
echo
echo $break
echo

if [ -f script-ms08-067.txt ]; then
     echo "May be vulnerable to MS08-067."
     echo
     cat script-ms08-067.txt
     echo
     echo $break
     echo
fi

# Total number of...
host=`wc -l hosts.txt | cut -d ' ' -f1`
ports=`wc -l ports.txt | cut -d ' ' -f1`
banners=`wc -l banners.txt | cut -d ' ' -f1`
COUNT=0

if [ $host -eq 1 ]; then
     echo "1 host discovered."
     echo
     echo $break
     echo
     cat nmap.txt
     echo $break
     echo $break
     echo
     echo "Nmap Scripts"

     SCRIPTS="script-13 script-21 script-22 script-23 script-25 script-53 script-67 script-70 script-79 script-110 script-111 script-123 script-137 script-143 script-161 script-389 script-445 script-465 script-500 script-523 script-524 script-548 script-554 script-631 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-2202 script-2628 script-2947 script-3031 script-3260 script-3306 script-3389 script-3478 script-3632 script-4369 script-5019 script-5353 script-5666 script-5672 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8009 script-8081 script-8091 script-bitcoin script-9100 script-9160 script-9999 script-10000 script-11211 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-50000 script-hadoop script-apache-hbase script-http"

     for i in $SCRIPTS; do
          if [ -f "$i.txt" ]; then
               cat "$i.txt"
               echo $break
          fi
     done

     exit
fi

echo "Hosts Discovered ($host)"
echo
cat hosts.txt
echo

if [ ! -s ports.txt ]; then
     echo "No open ports found."
     echo
     exit
else
     ports=`wc -l ports.txt | cut -d ' ' -f1`
fi

echo $break
echo
echo "Open Ports ($ports)"
echo
echo "TCP Ports"
cat ports-tcp.txt
echo

if [ -s ports-udp.txt ]; then
     echo "UDP Ports"
     cat ports-udp.txt
     echo
fi

echo $break

if [ -f banners.txt ]; then
     banners=`wc -l banners.txt | cut -d ' ' -f1`
     echo
     echo "Banners ($banners)"
     echo
     cat banners.txt
     echo
     echo $break
fi

echo
echo "High Value Hosts by Port"
echo

HVPORTS="13 21 22 23 25 53 67 69 70 79 80 110 111 123 137 139 143 161 389 443 445 465 500 523 524 548 554 631 873 993 995 1050 1080 1099 1099 1158 1344 1352 1433 1434 1521 1604 1720 1723 2202 2628 2947 3031 3260 3306 3389 3478 3632 4369 5019 5353 5432 5666 5672 5850 5900 5984 6000 6001 6002 6003 6004 6005 6379 6481 6666 7210 7634 7777 8000 8009 8080 8081 8091 8222 8332 8333 8400 8443 9100 9160 9999 10000 11211 12345 17185 19150 27017 31337 35871 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $HVPORTS; do
     if [ -f $i.txt ]; then
          echo "Port $i"
          cat $i.txt
          echo
     fi
done

echo $break
echo
cat nmap.txt
echo $break
echo $break
echo
echo "Nmap Scripts"

SCRIPTS="script-13 script-21 script-22 script-23 script-25 script-53 script-67 script-70 script-79 script-110 script-111 script-123 script-137 script-143 script-161 script-389 script-445 script-465 script-500 script-523 script-524 script-548 script-554 script-631 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-2202 script-2628 script-2947 script-3031 script-3260 script-3306 script-3389 script-3478 script-3632 script-4369 script-5019 script-5353 script-5666 script-5672 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8009 script-8081 script-8091 script-bitcoin script-9100 script-9160 script-9999 script-10000 script-11211 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-50000 script-hadoop script-apache-hbase script-http"

for i in $SCRIPTS; do
     if [ -f "$i.txt" ]; then
          cat "$i.txt"
          echo $break
     fi
done
