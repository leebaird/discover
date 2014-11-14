#!/bin/bash
clear

echo
echo
echo -n "Enter a domain: "
read domain

# Check for no response
if [ -z $domain ];then
     echo 
     echo "You did not enter a domain."
     exit
fi

echo
echo "You can following directions. Starting recon on $domain."
echo
read -p "Press <enter> to continue."

firefox &
sleep 4
firefox -new-tab http://www.intodns.com/$domain &
sleep 1
firefox -new-tab http://www.dnsstuff.com/tools#dnsReport|type=domain&&value=$domain &
sleep 1
firefox -new-tab http://mxtoolbox.com/SuperTool.aspx?action=dns%3a$domain&run=toolpage &
sleep 1
firefox -new-tab http://viewdns.info/dnsreport/?domain=$domain &
sleep 1
firefox -new-tab http://dnstools.fastnext.com/index.php?fDNSreport=$domain &












