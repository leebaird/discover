#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

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
read -r domain

# Check for no answer
if [ -z $domain ]; then
    f_error
fi

if [ ! -d $HOME/data/$domain ]; then
    cp -R $discover/report/ $HOME/data/$domain
    sed -i "s/#COMPANY#/$company/" $HOME/data/$domain/index.htm
    sed -i "s/#DOMAIN#/$domain/" $HOME/data/$domain/index.htm
    sed -i "s/#DATE#/$rundate/" $HOME/data/$domain/index.htm
fi

echo
echo $medium
echo

###############################################################################################################################

echo "DNSRecon"
echo "    Sub-domains        (1/$total)"
dnsrecon -d $domain -D /usr/share/dnsrecon/namelist.txt -f -t brt > tmp

grep $domain tmp | grep -v "$domain\." | grep -Eiv '(performing)' | awk '{print $3}' > tmp2
grep $domain tmp | grep -v "$domain\." | grep -Eiv '(performing)' | awk '{print $4}' >> tmp2
cat tmp2 | sort -u > subdomains

###############################################################################################################################

echo "    Zone Transfer       (2/$total)"
dnsrecon -d $domain -t axfr > zonetransfer
echo

###############################################################################################################################

echo "Traceroute"
echo "    UDP               (3/$total)"
echo "UDP" > tmp
traceroute $domain | awk -F" " '{print $1,$2,$3}' >> tmp
echo >> tmp
echo "ICMP ECHO" >> tmp
echo "    ICMP ECHO          (4/$total)"
traceroute -I $domain | awk -F" " '{print $1,$2,$3}' >> tmp
echo >> tmp
echo "TCP SYN" >> tmp
echo "    TCP SYN            (5/$total)"
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

echo "Whatweb (~5 min)        (7/$total)     broken"
#grep -v '<' $HOME/data/$domain/data/subdomains.htm | awk '{print $1}' > tmp
#whatweb -i tmp --color=never --no-errors > tmp2 2>/dev/null
#whatweb -i subdomains --color=never --no-errors > tmp2 2>/dev/null

# Find lines that start with http, and insert a line after
#sort tmp2 | sed '/^http/a\ ' > tmp3
# Cleanup
#cat tmp3 | sed 's/,/\n/g; s/\[200 OK\]/\n\[200 OK\]\n/g; s/\[301 Moved Permanently\]/\n\[301 Moved Permanently\]\n/g; s/\[302 Found\]/\n\[302 Found\]\n/g; s/\[404 Not Found\]/\n\[404 Not Found\]\n/g' | grep -Eiv '(unassigned|united states)' | sed 's/^[ \t]*//' | cat -s | more > whatweb

#grep '@' whatweb | sed 's/Email//g; s/\[//g; s/\]//g' | tr '[A-Z]' '[a-z]' | grep "@$domain" | grep -v 'hosting' | cut -d ' ' -f2 | sort -u > emails

#rm tmp*
# Remove all empty files
#find . -type f -empty -exec rm "{}" \;
#echo

###############################################################################################################################

echo "recon-ng               (8/$total)"
echo "marketplace install all" > active.rc
echo "workspaces load $domain" >> active.rc
cat $discover/resource/recon-ng-active.rc >> active.rc
sed -i "s/yyy/$domain/g" active.rc

recon-ng -r $CWD/active.rc

###############################################################################################################################

echo "Summary" > zreport
echo $small >> zreport

echo > tmp

if [ -f subdomains ]; then
    subdomaincount=$(wc -l subdomains | cut -d ' ' -f1)
    echo "Subdomains    $subdomaincount" >> zreport
    echo "Subdomains ($subdomaincount)" >> tmp
    echo $large >> tmp
    cat subdomains >> tmp
    echo >> tmp
fi

echo >> zreport
echo "Traceroute" >> zreport
echo $large >> zreport
cat traceroute >> zreport

echo >> zreport
echo "Web Application Firewall" >> zreport
echo $large >> zreport
cat waf >> zreport

echo >> zreport
echo "Zone Transfer" >> zreport
echo $large >> zreport
cat zonetransfer >> zreport

cat zreport >> $HOME/data/$domain/data/active-recon.htm
echo "</pre>" >> $HOME/data/$domain/data/active-recon.htm
cat ztraceroute >> $HOME/data/$domain/data/traceroute.htm
echo "</pre>" >> $HOME/data/$domain/data/traceroute.htm
cat waf >> $HOME/data/$domain/data/waf.htm
echo "</pre>" >> $HOME/data/$domain/data/waf.htm
#cat whatweb >> $HOME/data/$domain/data/whatweb.htm
#echo "</pre>" >> $HOME/data/$domain/data/whatweb.htm
cat zonetransfer >> $HOME/data/$domain/data/zonetransfer.htm
echo "</pre>" >> $HOME/data/$domain/data/zonetransfer.htm

#if [[ -f $HOME/data/$domain/data/emails.htm && -f emails ]]; then
#    cat $HOME/data/$domain/data/emails.htm emails | grep -v '<' | sort -u > tmp-new-emails
#    cat $HOME/data/$domain/data/emails.htm | grep '<' > tmp-new-page
#    mv tmp-new-page $HOME/data/$domain/data/emails.htm
#    cat tmp-new-emails >> $HOME/data/$domain/data/emails.htm
#    echo "</pre>" >> $HOME/data/$domain/data/emails.htm
#fi

#if [[ -f $HOME/data/$domain/data/hosts.htm && -f hosts ]]; then
#    cat $HOME/data/$domain/data/hosts.htm hosts | grep -v '<' | $sip > tmp-new-hosts
#    cat $HOME/data/$domain/data/hosts.htm | grep '<' > tmp-new-page
#    mv tmp-new-page $HOME/data/$domain/data/hosts.htm
#    cat tmp-new-hosts >> $HOME/data/$domain/data/hosts.htm
#    echo "</pre>" >> $HOME/data/$domain/data/hosts.htm
#fi

mv active.rc subdomains traceroute waf whatweb zonetransfer /tmp/subdomains-active $HOME/data/$domain/tools/active/ 2>/dev/null
rm tmp*

echo
echo $medium
echo
echo "[*] Scan complete."
echo
echo -e "The supporting data folder is located at ${YELLOW}$HOME/data/$domain/${NC}"
