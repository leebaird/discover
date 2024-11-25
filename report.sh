#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

END=$(date +%r\ %Z)
FILENAME="$NAME"/report.txt
host=$(wc -l "$NAME"/hosts.txt | cut -d ' ' -f1)

echo "Nmap Report" > "$FILENAME"
date +%A" - "%B" "%d", "%Y >> "$FILENAME"
echo >> "$FILENAME"
echo "Start time   $START" >> "$FILENAME"
echo "Finish time  $END" >> "$FILENAME"
echo "Scanner IP   $MYIP" >> "$FILENAME"
echo >> "$FILENAME"
echo "$MEDIUM" >> "$FILENAME"
echo >> "$FILENAME"

echo "Targets discovered ($host)" >> "$FILENAME"
echo >> "$FILENAME"
cat "$NAME"/hosts.txt >> "$FILENAME" 2>/dev/null
echo >> "$FILENAME"

if [ ! -s "$NAME"/ports.txt ]; then
    rm -rf "$NAME" tmp*
    echo
    echo "$MEDIUM"
    echo
    echo "[*] Scan complete."
    echo
    echo -e "${YELLOW}No hosts found with open ports.${NC}"
    echo
    exit
else
    PORTS=$(wc -l "$NAME"/ports.txt | cut -d ' ' -f1)
fi

echo "$MEDIUM" >> "$FILENAME"
echo >> "$FILENAME"
echo "Open ports ($PORTS)" >> "$FILENAME"
echo >> "$FILENAME"

if [ -s "$NAME"/ports-tcp.txt ]; then
    echo "TCP ports" >> "$FILENAME"
    cat "$NAME"/ports-tcp.txt >> "$FILENAME"
    echo >> "$FILENAME"
fi

if [ -s "$NAME"/ports-udp.txt ]; then
    echo "UDP ports" >> "$FILENAME"
    cat "$NAME"/ports-udp.txt >> "$FILENAME"
    echo >> "$FILENAME"
fi

echo "$MEDIUM" >> "$FILENAME"

if [ -f "$NAME"/banners.txt ]; then
    banners=$(wc -l "$NAME"/banners.txt | cut -d ' ' -f1)
    echo >> "$FILENAME"
    echo "Banners ($banners)" >> "$FILENAME"
    echo >> "$FILENAME"
    cat "$NAME"/banners.txt >> "$FILENAME"
    echo >> "$FILENAME"
    echo "$MEDIUM" >> "$FILENAME"
fi

echo >> "$FILENAME"
echo "High value targets by port" >> "$FILENAME"
echo >> "$FILENAME"

HVPORTS="13 19 21 22 23 25 37 53 67 69 70 79 80 102 110 111 119 123 135 137 139 143 161 389 407 433 443 445 465 500 502 512 513 514 523 524 548 554 563 587 623 631 636 771 831 873 902 993 995 998 1050 1080 1099 1158 1344 1352 1433 1434 1521 1604 1720 1723 1883 1900 1911 1962 2049 2202 2302 2362 2375 2628 2947 3000 3031 3050 3260 3306 3310 3389 3478 3500 3632 3671 4369 4800 5019 5040 5060 5353 5432 5560 5631 5632 5666 5672 5683 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6379 6481 6666 7210 7634 7777 8000 8009 8080 8081 8091 8140 8222 8332 8333 8400 8443 8834 9000 9084 9100 9160 9600 9999 10000 10809 11211 12000 12345 13364 17185 19150 27017 28784 30718 31337 35871 37777 44818 46824 47808 49152 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $HVPORTS; do
    if [ -f "$NAME"/"$i".txt ]; then
        echo "Port $i" >> "$FILENAME"
        cat "$NAME"/"$i".txt >> "$FILENAME"
        echo >> "$FILENAME"
    fi
done

echo "$MEDIUM" >> "$FILENAME"
echo >> "$FILENAME"
cat "$NAME"/nmap.txt >> "$FILENAME"
echo "$MEDIUM" >> "$FILENAME"
echo "$MEDIUM" >> "$FILENAME"
echo >> "$FILENAME"
echo "Nmap scripts" >> "$FILENAME"
echo >> "$FILENAME"

SCRIPTS="script-13 script-21 script-22 script-23 script-smtp script-37 script-53 script-67 script-70 script-79 script-102 script-110 script-111 script-nntp script-123 script-137 script-139 script-143 script-161 script-389 script-443 script-445 script-500 script-523 script-524 script-548 script-554 script-623 script-631 script-636 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-1883 script-1911 script-1962 script-2049 script-2202 script-2302 script-2375 script-2628 script-2947 script-3031 script-3260 script-3306 script-3310 script-3389 script-3478 script-3632 script-3671 script-4369 script-5019 script-5060 script-5353 script-5666 script-5672 script-5683 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8000 script-8009 script-8081 script-8091 script-8140 script-bitcoin script-9100 script-9160 script-9600 script-9999 script-10000 script-10809 script-11211 script-12000 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-44818 script-47808 script-49152 script-50000 script-hadoop script-apache-hbase"

for i in $SCRIPTS; do
    if [ -f "$NAME"/"$i.txt" ]; then
        cat "$NAME"/"$i.txt" >> "$FILENAME"
        echo "$MEDIUM" >> "$FILENAME"
        echo >> "$FILENAME"
    fi
done

if [ -f "$NAME"/script-smbvulns.txt ]; then
    echo "May be vulnerable to MS08-067." >> "$FILENAME"
    echo >> "$FILENAME"
    cat "$NAME"/script-smbvulns.txt >> "$FILENAME"
    echo >> "$FILENAME"
    echo "$MEDIUM" >> "$FILENAME"
    echo >> "$FILENAME"
fi

if [ -f "$NAME"/script-onesixtyone.txt ] || [ -f "$NAME"/script-smbclient.txt ] || [ -f "$NAME"/ike-scan.txt ]; then
    echo "Additional enumeration" >> "$FILENAME"

    if [ -f "$NAME"/script-onesixtyone.txt ]; then
        echo >> "$FILENAME"
        echo "- onesixtyone" >> "$FILENAME"
        cat "$NAME"/script-onesixtyone.txt >> "$FILENAME"
    fi

    if [ -f "$NAME"/script-smbclient.txt ]; then
        echo >> "$FILENAME"
        echo "- smbclient" >> "$FILENAME"
        cat "$NAME"/script-smbclient.txt >> "$FILENAME"
    fi

    if [ -f "$NAME"/script-ike-scan.txt ]; then
        echo >> "$FILENAME"
        echo "- ike-scan" >> "$FILENAME"
        cat "$NAME"/script-ike-scan.txt >> "$FILENAME"
    fi
fi

mv "$NAME" "$HOME"/data/

START=0
END=0

echo
echo "$MEDIUM"
echo
echo "[*] Scan complete."
echo
echo -e "The new report is located at ${YELLOW}$HOME/data/$NAME/report.txt${NC}"
