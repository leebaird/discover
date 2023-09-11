#!/bin/bash

# by Lee Baird (@discoverscripts)

echo
echo "Use a CVE to search for exploits."
echo
echo -n "CVE:  "
read cve

# Check for no answer
if [ -z $cve ]; then
     echo
     echo "[!] No CVE entered."
     echo
     exit 1
fi

xdg-open https://github.com/search?q=$cve&type=repositories &
sleep 4
xdg-open https://www.google.com/search?q=%22$cve%22+AND+exploit &
sleep 4
xdg-open https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=$cve&queryType=phrase&search_type=all&isCpeNameSearch=false &
sleep 4
xdg-open https://www.rapid7.com/db/?q=$cve&type=nexpose &
sleep 4
xdg-open https://www.tenable.com/plugins &

shorthand="$(echo $CVE | cut -d '-' -f2)-$(echo $CVE | cut -d '-' -f3)"

searchsploit $CVE

echo

msfconsole -x "search cve:$shorthand;exit" -q
