#!/bin/bash

# Number of tests
total=8

###############################################################################################################################

clear
f_banner

echo -e "${BLUE}Uses recon-ng, Traceroute, wafw00f and Whatweb.${NC}"
echo
echo -e "${BLUE}[*] Acquire API keys for maximum results with recon-ng.${NC}"
echo
echo $medium
echo
echo "Usage"
echo
echo "Domain: target.com"
echo
echo $medium
echo
echo -n "Domain:  "
read domain

# Check for no answer
if [[ -z $domain ]]; then
     f_error
fi

if [ ! -d $home/data/$domain ]; then
     cp -R $discover/report/ $home/data/$domain
     sed -i "s/#COMPANY#/$company/" $home/data/$domain/index.htm
     sed -i "s/#DOMAIN#/$domain/" $home/data/$domain/index.htm
     sed -i "s/#DATE#/$rundate/" $home/data/$domain/index.htm
fi

echo
echo $medium
echo

###############################################################################################################################

echo "     Sub-domains          (1/$total)"
if [ -f /usr/share/dnsrecon/namelist.txt ]; then
     dnsrecon -d $domain -D /usr/share/dnsrecon/namelist.txt -f -t brt > tmp
fi

# PTF
if [ -f /pentest/intelligence-gathering/dnsrecon/namelist.txt ]; then
     dnsrecon -d $domain -D /pentest/intelligence-gathering/dnsrecon/namelist.txt -f -t brt > tmp
fi

grep $domain tmp | grep -v "$domain\." | egrep -v '(Performing|Records Found|xxx)' | sed 's/\[\*\] //g; s/^[ \t]*//' | awk '{print $2,$3}' | column -t | sort -u > sub-dnsrecon

egrep -v '(\[|.nat.|1.1.1.1|6.9.6.9|127.0.0.1)' sub-dnsrecon | tr '[A-Z]' '[a-z]' | column -t | sort -u | awk '$2 !~ /[a-z]/' > subdomains

if [ -e $home/data/$domain/data/subdomains.htm ]; then
     cat $home/data/$domain/data/subdomains.htm subdomains | grep -v "<" | grep -v "$domain\." | column -t | sort -u > subdomains-combined

     cp $discover/report/data/subdomains.htm $home/data/$domain/data/subdomains.htm
     cat subdomains-combined >> $home/data/$domain/data/subdomains.htm
     echo "</pre>" >> $home/data/$domain/data/subdomains.htm
fi

awk '{print $3}' records > tmp
awk '{print $2}' sub-dnsrecon >> tmp
grep -E '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}' tmp | egrep -v '(-|=|:|1.1.1.1|6.9.6.9|127.0.0.1)' | grep -v [a-z] | $sip > hosts

###############################################################################################################################

echo "     Zone Transfer        (2/$total)"
dnsrecon -d $domain -t axfr > tmp
egrep -v '(Checking for|Failed|filtered|No answer|NS Servers|Removing|reset|TCP Open|Testing NS)' tmp | sed 's/^....//g; /^$/d' > zonetransfer
echo

###############################################################################################################################

echo "Web Application Firewall  (3/$total)"
wafw00f -a http://www.$domain > tmp 2>/dev/null
sed '1,16d' tmp > waf
echo

###############################################################################################################################

echo "Traceroute"
echo "     UDP                  (4/$total)"
echo "UDP" > tmp
traceroute $domain | awk -F" " '{print $1,$2,$3}' >> tmp
echo >> tmp
echo "ICMP ECHO" >> tmp
echo "     ICMP ECHO            (5/$total)"
traceroute -I $domain | awk -F" " '{print $1,$2,$3}' >> tmp
echo >> tmp
echo "TCP SYN" >> tmp
echo "     TCP SYN              (6/$total)"
traceroute -T $domain | awk -F" " '{print $1,$2,$3}' >> tmp
grep -v 'traceroute' tmp > tmp2
# Remove blank lines from end of file
awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp2 > ztraceroute
echo

###############################################################################################################################

echo "Whatweb (~5 min)          (7/$total)"
grep -v '<' $home/data/$domain/data/subdomains.htm | awk '{print $1}' > tmp
whatweb -i tmp --color=never --no-errors > tmp2 2>/dev/null

# Find lines that start with http, and insert a line after
sort tmp2 | sed '/^http/a\ ' > tmp3
# Cleanup
cat tmp3 | sed 's/,/\n/g; s/\[200 OK\]/\n\[200 OK\]\n/g; s/\[301 Moved Permanently\]/\n\[301 Moved Permanently\]\n/g; s/\[302 Found\]/\n\[302 Found\]\n/g; s/\[404 Not Found\]/\n\[404 Not Found\]\n/g' | egrep -v '(Unassigned|UNITED STATES)' | sed 's/^[ \t]*//' | cat -s | more > whatweb

grep '@' whatweb | sed 's/Email//g; s/\[//g; s/\]//g' | tr '[A-Z]' '[a-z]' | grep "@$domain" | grep -v 'hosting' | cut -d ' ' -f2 | sort -u > emails

rm tmp*
# Remove all empty files
find . -type f -empty -exec rm "{}" \;
echo

###############################################################################################################################

echo "recon-ng                  (8/$total)"
echo "marketplace install all" > active.rc
echo "workspaces load $domain" >> active.rc
cat $discover/resource/recon-ng-active.rc >> active.rc
sed -i "s/yyy/$domain/g" active.rc

recon-ng -r $CWD/active.rc

###############################################################################################################################

echo "Summary" > zreport
echo $short >> zreport

echo > tmp

if [ -e emails ]; then
     emailcount=$(wc -l emails | cut -d ' ' -f1)
     echo "Emails        $emailcount" >> zreport
     echo "Emails ($emailcount)" >> tmp
     echo $short >> tmp
     cat emails >> tmp
     echo >> tmp
fi

if [ -e hosts ]; then
     hostcount=$(wc -l hosts | cut -d ' ' -f1)
     echo "Hosts         $hostcount" >> zreport
     echo "Hosts ($hostcount)" >> tmp
     echo $short >> tmp
     cat hosts >> tmp
     echo >> tmp
fi

if [ -e subdomains ]; then
     subdomaincount=$(wc -l subdomains | cut -d ' ' -f1)
     echo "Subdomains    $subdomaincount" >> zreport
     echo "Subdomains ($subdomaincount)" >> tmp
     echo $long >> tmp
     cat subdomains >> tmp
     echo >> tmp
fi

cat tmp >> zreport

echo "Web Application Firewall" >> zreport
echo $long >> zreport
cat waf >> zreport

echo >> zreport
echo "Traceroute" >> zreport
echo $long >> zreport
cat ztraceroute >> zreport

echo >> zreport
echo "Zone Transfer" >> zreport
echo $long >> zreport
cat zonetransfer >> zreport

echo >> zreport
echo "Whatweb" >> zreport
echo $long >> zreport
cat whatweb >> zreport

cat zreport >> $home/data/$domain/data/active-recon.htm
echo "</pre>" >> $home/data/$domain/data/active-recon.htm
cat ztraceroute >> $home/data/$domain/data/traceroute.htm
echo "</pre>" >> $home/data/$domain/data/traceroute.htm
cat waf >> $home/data/$domain/data/waf.htm
echo "</pre>" >> $home/data/$domain/data/waf.htm
cat whatweb >> $home/data/$domain/data/whatweb.htm
echo "</pre>" >> $home/data/$domain/data/whatweb.htm
cat zonetransfer >> $home/data/$domain/data/zonetransfer.htm
echo "</pre>" >> $home/data/$domain/data/zonetransfer.htm

if [[ -e $home/data/$domain/data/emails.htm && -e emails ]]; then
     cat $home/data/$domain/data/emails.htm emails | grep -v '<' | sort -u > tmp-new-emails
     cat $home/data/$domain/data/emails.htm | grep '<' > tmp-new-page
     mv tmp-new-page $home/data/$domain/data/emails.htm
     cat tmp-new-emails >> $home/data/$domain/data/emails.htm
     echo "</pre>" >> $home/data/$domain/data/emails.htm
fi

if [[ -e $home/data/$domain/data/hosts.htm && -e hosts ]]; then
     cat $home/data/$domain/data/hosts.htm hosts | grep -v '<' | $sip > tmp-new-hosts
     cat $home/data/$domain/data/hosts.htm | grep '<' > tmp-new-page
     mv tmp-new-page $home/data/$domain/data/hosts.htm
     cat tmp-new-hosts >> $home/data/$domain/data/hosts.htm
     echo "</pre>" >> $home/data/$domain/data/hosts.htm
fi

mv active.rc emails hosts sub* waf whatweb z* /tmp/subdomains-active $home/data/$domain/tools/active/ 2>/dev/null
rm tmp*

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The supporting data folder is located at ${YELLOW}$home/data/$domain/${NC}\n"

