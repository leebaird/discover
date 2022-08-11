#!/usr/bin/bash

# Number of tests
total=8

###############################################################################################################################

clear
f_banner

echo -e "${BLUE}Uses DNSRecon, recon-ng, Traceroute, wafw00f, and Whatweb.${NC}"
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
if [ -z $domain ]; then
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

echo "DNSRecon"
echo "     Sub-domains          (1/$total)"
dnsrecon -d $domain -D /usr/share/dnsrecon/namelist.txt -f -t brt > tmp

grep $domain tmp | grep -v "$domain\." | egrep -v '(Performing)' | awk '{print $3}' > tmp2
grep $domain tmp | grep -v "$domain\." | egrep -v '(Performing)' | awk '{print $4}' >> tmp2
cat tmp2 | sort -u > subdomains

###############################################################################################################################

echo "     Zone Transfer        (2/$total)"
dnsrecon -d $domain -t axfr > zonetransfer
echo

###############################################################################################################################

echo "Traceroute"
echo "     UDP                  (3/$total)"
echo "UDP" > tmp
traceroute $domain | awk -F" " '{print $1,$2,$3}' >> tmp
echo >> tmp
echo "ICMP ECHO" >> tmp
echo "     ICMP ECHO            (4/$total)"
traceroute -I $domain | awk -F" " '{print $1,$2,$3}' >> tmp
echo >> tmp
echo "TCP SYN" >> tmp
echo "     TCP SYN              (5/$total)"
traceroute -T $domain | awk -F" " '{print $1,$2,$3}' >> tmp
grep -v 'traceroute' tmp > tmp2
# Remove blank lines from end of file
awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp2 > traceroute
echo

###############################################################################################################################

echo "Web Application Firewall  (6/$total)"
wafw00f -a http://www.$domain > tmp 2>/dev/null
sed '1,16d' tmp > waf
echo

###############################################################################################################################

echo "Whatweb (~5 min)          (7/$total)      broken"
#grep -v '<' $home/data/$domain/data/subdomains.htm | awk '{print $1}' > tmp
#whatweb -i tmp --color=never --no-errors > tmp2 2>/dev/null
#whatweb -i subdomains --color=never --no-errors > tmp2 2>/dev/null

# Find lines that start with http, and insert a line after
#sort tmp2 | sed '/^http/a\ ' > tmp3
# Cleanup
#cat tmp3 | sed 's/,/\n/g; s/\[200 OK\]/\n\[200 OK\]\n/g; s/\[301 Moved Permanently\]/\n\[301 Moved Permanently\]\n/g; s/\[302 Found\]/\n\[302 Found\]\n/g; s/\[404 Not Found\]/\n\[404 Not Found\]\n/g' | egrep -v '(Unassigned|UNITED STATES)' | sed 's/^[ \t]*//' | cat -s | more > whatweb

#grep '@' whatweb | sed 's/Email//g; s/\[//g; s/\]//g' | tr '[A-Z]' '[a-z]' | grep "@$domain" | grep -v 'hosting' | cut -d ' ' -f2 | sort -u > emails

#rm tmp*
# Remove all empty files
#find . -type f -empty -exec rm "{}" \;
#echo

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

if [ -f subdomains ]; then
     subdomaincount=$(wc -l subdomains | cut -d ' ' -f1)
     echo "Subdomains    $subdomaincount" >> zreport
     echo "Subdomains ($subdomaincount)" >> tmp
     echo $long >> tmp
     cat subdomains >> tmp
     echo >> tmp
fi

echo >> zreport
echo "Traceroute" >> zreport
echo $long >> zreport
cat traceroute >> zreport

echo >> zreport
echo "Web Application Firewall" >> zreport
echo $long >> zreport
cat waf >> zreport

echo >> zreport
echo "Zone Transfer" >> zreport
echo $long >> zreport
cat zonetransfer >> zreport

cat zreport >> $home/data/$domain/data/active-recon.htm
echo "</pre>" >> $home/data/$domain/data/active-recon.htm
cat ztraceroute >> $home/data/$domain/data/traceroute.htm
echo "</pre>" >> $home/data/$domain/data/traceroute.htm
cat waf >> $home/data/$domain/data/waf.htm
echo "</pre>" >> $home/data/$domain/data/waf.htm
#cat whatweb >> $home/data/$domain/data/whatweb.htm
#echo "</pre>" >> $home/data/$domain/data/whatweb.htm
cat zonetransfer >> $home/data/$domain/data/zonetransfer.htm
echo "</pre>" >> $home/data/$domain/data/zonetransfer.htm

#if [[ -f $home/data/$domain/data/emails.htm && -f emails ]]; then
#     cat $home/data/$domain/data/emails.htm emails | grep -v '<' | sort -u > tmp-new-emails
#     cat $home/data/$domain/data/emails.htm | grep '<' > tmp-new-page
#     mv tmp-new-page $home/data/$domain/data/emails.htm
#     cat tmp-new-emails >> $home/data/$domain/data/emails.htm
#     echo "</pre>" >> $home/data/$domain/data/emails.htm
#fi

#if [[ -f $home/data/$domain/data/hosts.htm && -f hosts ]]; then
#     cat $home/data/$domain/data/hosts.htm hosts | grep -v '<' | $sip > tmp-new-hosts
#     cat $home/data/$domain/data/hosts.htm | grep '<' > tmp-new-page
#     mv tmp-new-page $home/data/$domain/data/hosts.htm
#     cat tmp-new-hosts >> $home/data/$domain/data/hosts.htm
#     echo "</pre>" >> $home/data/$domain/data/hosts.htm
#fi

mv active.rc subdomains traceroute waf whatweb zonetransfer /tmp/subdomains-active $home/data/$domain/tools/active/ 2>/dev/null
rm tmp*

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The supporting data folder is located at ${YELLOW}$home/data/$domain/${NC}\n"
