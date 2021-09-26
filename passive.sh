#!/bin/bash

# Number of tests
total=52

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

###############################################################################################################################

f_terminate(){
save_dir=$home/data/cancelled-$(date +%H:%M:%S)

echo
echo "Terminating..."
echo
echo -e "${YELLOW}All data will be saved in $save_dir.${NC}"

mv $name/ $save_dir 2>/dev/null

if [ "$recon" == "1" ]; then
     # Move passive files
     mkdir -p $save_dir/passive/recon-ng/
     cd $discover/
     mv curl debug* email* hosts name* network* raw records registered* squatting sub* tmp* ultratools usernames-recon whois* z* doc pdf ppt txt xls $save_dir/passive/ 2>/dev/null
     cd /tmp/; mv emails names* networks subdomains usernames $save_dir/passive/recon-ng/ 2>/dev/null
     cd $discover
else
     # Move active files
     mkdir -p $save_dir/active/recon-ng/
     cd $discover/
     mv active.rc emails hosts record* sub* tmp waf whatweb z* $save_dir/active/ 2>/dev/null
     cd /tmp/; mv subdomains $save_dir/active/recon-ng/ 2>/dev/null
     cd $discover/
fi

echo
echo "Saving complete."
echo
echo
exit
}

export -f f_terminate

###############################################################################################################################

clear
f_banner

echo -e "${BLUE}Uses ARIN, DNSRecon, dnstwist, goofile, goog-mail, goohost,${NC}"
echo -e "${BLUE}theHarvester, Metasploit, Whois, multiple websites and recon-ng.${NC}"
echo
echo -e "${BLUE}[*] Acquire API keys for maximum results with theHarvester and recon-ng.${NC}"
echo
echo $medium
echo
echo "Usage"
echo
echo "Company: Target"
echo "Domain:  target.com"
echo
echo $medium
echo
echo -n "Company: "
read company

# Check for no answer
if [[ -z $company ]]; then
     f_error
fi

echo -n "Domain:  "
read domain

# Check for no answer
if [[ -z $domain ]]; then
     f_error
fi

companyurl=$( printf "%s\n" "$company" | sed 's/ /%20/g; s/\&/%26/g; s/\,/%2C/g' )
rundate=$(date +%B' '%d,' '%Y)

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

echo "Amass                     (1/$total)"
amass enum -d $domain -ipv4 -noalts -norecursive > tmp
grep "$domain" tmp | sed 's/_//g; s/ /:/g; s/,/, /g' | sort -u > zamass
rm tmp
echo

###############################################################################################################################

echo "ARIN"
echo "     Email                (2/$total)"
curl --cipher ECDHE-RSA-AES256-GCM-SHA384 -k -s https://whois.arin.net/rest/pocs\;domain=$domain > tmp.xml
if ! grep -q 'No Search Results' tmp.xml; then
     xmllint --format tmp.xml | grep 'handle' | cut -d '>' -f2 | cut -d '<' -f1 | sort -u > zurls.txt
     xmllint --format tmp.xml | grep 'handle' | cut -d '"' -f2 | sort -u > zhandles.txt

     while read i; do
          curl --cipher ECDHE-RSA-AES256-GCM-SHA384 -k -s $i > tmp2.xml
          xml_grep 'email' tmp2.xml --text_only >> tmp
     done < zurls.txt

     cat tmp | grep -v '_' | tr '[A-Z]' '[a-z]' | sort -u > zarin-emails
fi

###############################################################################################################################

echo "     Names                (3/$total)"
if [ -e zhandles.txt ]; then
     for i in $(cat zhandles.txt); do
          curl --cipher ECDHE-RSA-AES256-GCM-SHA384 -k -s https://whois.arin.net/rest/poc/$i.txt | grep 'Name' >> tmp
     done

     egrep -v "($company|@|Abuse|Center|Network|Technical|Telecom)" tmp | sed 's/Name:           //g' | tr '[A-Z]' '[a-z]' | sed 's/\b\(.\)/\u\1/g' > tmp2
     awk -F", " '{print $2,$1}' tmp2 | sed 's/  / /g' | sort -u > zarin-names
fi

rm zurls.txt zhandles.txt 2>/dev/null

###############################################################################################################################

echo "     Networks             (4/$total)"
curl --cipher ECDHE-RSA-AES256-GCM-SHA384 -k -s https://whois.arin.net/rest/orgs\;name=$companyurl -o tmp.xml

if ! grep -q 'No Search Results' tmp.xml; then
     xmllint --format tmp.xml | grep 'handle' | cut -d '/' -f6 | cut -d '<' -f1 | sort -uV > tmp

     for i in $(cat tmp); do
          echo "          " $i
          curl --cipher ECDHE-RSA-AES256-GCM-SHA384 -k -s https://whois.arin.net/rest/org/$i/nets.txt >> tmp2
     done
     grep -E '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' tmp2 | awk '{print $4 "-" $6}' | sed '/^-/d' | $sip > networks
fi

echo

###############################################################################################################################

echo "DNSRecon                  (5/$total)"
python3 /opt/DNSRecon/dnsrecon.py -d $domain -n 8.8.8.8 -t std > tmp
cat tmp | egrep -v '(All queries will|Could not|DNSSEC|Error|It is resolving|Performing|Records|Recursion|TXT|Version|Wildcard resolution)' | sed 's/\[\*\]//g; s/\[+\]//g; s/^[ \t]*//' | column -t | sort | sed 's/[ \t]*$//' > records
cat tmp | grep 'TXT' | sed 's/\[\*\]//g; s/\[+\]//g; s/^[ \t]*//' | sort | sed 's/[ \t]*$//' >> records

cat records >> $home/data/$domain/data/records.htm
echo "</pre>" >> $home/data/$domain/data/records.htm
rm tmp
echo

###############################################################################################################################

echo "dnstwist                  (6/$total)"
/opt/dnstwist/dnstwist.py --registered $domain > tmp
# Remove the first 9 lines and clean up
sed '1,9d' tmp | grep -v 'ServFail' | column -t > squatting
echo

###############################################################################################################################

echo "goofile                   (7/$total)"
python3 $discover/mods/goofile.py $domain doc > doc
python3 $discover/mods/goofile.py $domain docx | sort -u >> doc
python3 $discover/mods/goofile.py $domain pdf | sort -u > pdf
python3 $discover/mods/goofile.py $domain ppt > ppt
python3 $discover/mods/goofile.py $domain pptx | sort -u >> ppt
python3 $discover/mods/goofile.py $domain txt | sort -u > txt
python3 $discover/mods/goofile.py $domain xls > xls
python3 $discover/mods/goofile.py $domain xlsx | sort -u >> xls
echo

###############################################################################################################################

echo "goog-mail                 (8/$total)"
$discover/mods/goog-mail.py $domain | grep -v 'cannot' | tr '[A-Z]' '[a-z]' > zgoog-mail
echo

###############################################################################################################################

echo "goohost"
echo "     IP                   (9/$total)"
$discover/mods/goohost.sh -t $domain -m ip >/dev/null
echo "     Email                (10/$total)"
$discover/mods/goohost.sh -t $domain -m mail >/dev/null
cat report-* | grep $domain | column -t | sort -u > zgoohost
rm *-$domain.txt 2>/dev/null
echo

###############################################################################################################################

echo "theHarvester"
# Install path check
if [ -d /pentest/intelligence-gathering/theharvester/ ]; then
     # PTF
     harvesterdir='/pentest/intelligence-gathering/theharvester'
else
     # Kali
     harvesterdir='/opt/theHarvester'
fi

cd $harvesterdir

echo "     anubis               (11/$total)"
python3 theHarvester.py -d $domain -b anubis | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zanubis
echo "     baidu                (12/$total)"
python3 theHarvester.py -d $domain -b baidu | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zbaidu
echo "     binaryedge           (13/$total)"
python3 theHarvester.py -d $domain -b binaryedge | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zbinaryedge
echo "     bing                 (14/$total)"
python3 theHarvester.py -d $domain -b bing | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zbing
echo "     bufferoverun         (15/$total)"
python3 theHarvester.py -d $domain -b bufferoverun | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zbufferoverun
echo "     censys               (16/$total)"
python3 theHarvester.py -d $domain -b censys | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zcensys
echo "     certspotter          (17/$total)"
python3 theHarvester.py -d $domain -b certspotter | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zcertspotter
echo "     crtsh                (18/$total)"
python3 theHarvester.py -d $domain -b crtsh | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zcrtsh
echo "     dnsdumpster          (19/$total)"
python3 theHarvester.py -d $domain -b dnsdumpster | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zdnsdumpster
echo "     duckduckgo           (20/$total)"
python3 theHarvester.py -d $domain -b duckduckgo | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zduckduckgo
echo "     github-code          (21/$total)"
python3 theHarvester.py -d $domain -b github-code | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zgithub-code
echo "     google               (22/$total)"
python3 theHarvester.py -d $domain -b google | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zgoogle
echo "     hackertarget         (23/$total)"
python3 theHarvester.py -d $domain -b hackertarget | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zhackertarget
echo "     hunter               (24/$total)"
python3 theHarvester.py -d $domain -b hunter | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zhunter
echo "     intelx               (25/$total)"
python3 theHarvester.py -d $domain -b intelx | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zintelx
echo "     linkedin             (26/$total)"
python3 theHarvester.py -d "$company" -b linkedin | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > tmp
sleep 15
python3 theHarvester.py -d $domain -b linkedin | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > tmp2
# Make first 2 columns title case. Remove traiing whitespace.
cat tmp tmp2 | sed 's/\( *\)\([^ ]*\)\( *\)\([^ ]*\)/\1\L\u\2\3\L\u\4/' | egrep -iv '(about|google|retired)' | sed "s/ - $company//g" | sed 's/[ \t]*$//' | sort -u > zlinkedin
echo "     linkedin_links       (27/$total)"
sleep 30
python3 theHarvester.py -d $domain -b linkedin_links | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zlinkedin_links
echo "     netcraft             (28/$total)"
python3 theHarvester.py -d $domain -b netcraft | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > znetcraft
echo "     omnisint             (29/$total)"
python3 theHarvester.py -d $domain -b omnisint | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zomnisint
echo "     otx                  (30/$total)"
python3 theHarvester.py -d $domain -b otx | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zotx
echo "     pentesttools         (31/$total)"
python3 theHarvester.py -d $domain -b pentesttools | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zpentesttools
echo "     projectdiscovery     (32/$total)"
python3 theHarvester.py -d $domain -b projectdiscovery | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zprojectdiscovery
echo "     qwant                (33/$total)"
python3 theHarvester.py -d $domain -b qwant | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zqwant
echo "     rapiddns             (34/$total)"
python3 theHarvester.py -d $domain -b rapiddns | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zrapiddns
echo "     securityTrails       (35/$total)"
python3 theHarvester.py -d $domain -b securityTrails | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zsecuritytrails
echo "     spyse                (36/$total)"
python3 theHarvester.py -d $domain -b spyse | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zspyse
echo "     sublist3r            (37/$total)"
python3 theHarvester.py -d $domain -b sublist3r | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zsublist3r
echo "     threatcrowd          (38/$total)"
python3 theHarvester.py -d $domain -b threatcrowd | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zthreatcrowd
echo "     threatminer          (39/$total)"
python3 theHarvester.py -d $domain -b threatminer | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zthreatminer
echo "     trello               (40/$total)"
sleep 30
python3 theHarvester.py -d $domain -b trello | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > ztrello
echo "     twitter              (41/$total)"
python3 theHarvester.py -d $domain -b twitter | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > ztwitter
echo "     urlscan              (42/$total)"
python3 theHarvester.py -d $domain -b urlscan | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zurlscan
echo "     virustotal           (43/$total)"
python3 theHarvester.py -d $domain -b virustotal | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zvirustotal
echo "     yahoo                (44/$total)"
python3 theHarvester.py -d $domain -b yahoo | egrep -v '(!|\*|--|\[|Searching)' | sed '/^$/d' > zyahoo

mv z* $CWD
rm tmp*
cd $CWD
echo

###############################################################################################################################

echo "Metasploit                (45/$total)"
msfconsole -x "use auxiliary/gather/search_email_collector; set DOMAIN $domain; run; exit y" > tmp 2>/dev/null
grep @$domain tmp | awk '{print $2}' | sort -u > zmsf
echo

###############################################################################################################################

echo "Whois"
echo "     Domain               (46/$total)"
whois -H $domain > tmp 2>/dev/null
# Remove leading whitespace
sed 's/^[ \t]*//' tmp > tmp2
# Clean up
egrep -iv '(#|%|<a|=-=-=-=|;|access may|accuracy|additionally|afilias except|and dns hosting|and limitations|any use of|be sure|at the end|by submitting|by the terms|can easily|circumstances|clientdeleteprohibited|clienttransferprohibited|clientupdateprohibited|company may|compilation|complaint will|contact information|contact us|contacting|copy and paste|currently set|database|data contained|data presented|database|date of|details|dissemination|domaininfo ab|domain management|domain names in|domain status: ok|enable high|entirety|except as|existing|failure|facsimile|for commercial|for detailed|for information|for more|for the|get noticed|get a free|guarantee its|href|If you|in europe|in most|in obtaining|in the address|includes|including|information is|is not|is providing|its systems|learn|makes this|markmonitor|minimum|mining this|minute and|modify|must be sent|name cannot|namesbeyond|not to use|note:|notice|obtaining information about|of moniker|of this data|or hiding any|or otherwise support|other use of|please|policy|prior written|privacy is|problem reporting|professional and|prohibited without|promote your|protect the|public interest|queries or|receive|receiving|register your|registrars|registration record|relevant|repackaging|request|reserves all rights|reserves the|responsible for|restricted to network|restrictions|see business|server at|solicitations|sponsorship|status|support questions|support the transmission|supporting|telephone, or facsimile|Temporary|that apply to|that you will|the right| The data is|The fact that|the transmission|this listing|this feature|this information|this service is|to collect or|to entities|to report any|to suppress|to the systems|transmission of|trusted partner|united states|unlimited|unsolicited advertising|users may|version 6|via e-mail|visible|visit aboutus.org|visit|web-based|when you|while believed|will use this|with many different|with no guarantee|we reserve|whitelist|whois|you agree|You may not)' tmp2 > tmp3
# Remove lines starting with "*"
sed '/^*/d' tmp3 > tmp4
# Remove lines starting with "-"
sed '/^-/d' tmp4 > tmp5
# Remove lines starting with http
sed '/^http/d' tmp5 > tmp6
# Remove lines starting with US
sed '/^US/d' tmp6 > tmp7
# Clean up phone numbers
sed 's/+1.//g' tmp7 > tmp8
# Remove leading whitespace from file
awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp8 > tmp9
# Remove trailing whitespace from each line
sed 's/[ \t]*$//' tmp9 > tmp10
# Compress blank lines
cat -s tmp10 > tmp11
# Remove lines that end with various words then a colon or period(s)
egrep -v '(2:$|3:$|Address.$|Address........$|Address.........$|Ext.:$|FAX:$|Fax............$|Fax.............$|Province:$|Server:$)' tmp11 > tmp12
# Remove line after "Domain Servers:"
sed -i '/^Domain Servers:/{n; /.*/d}' tmp12
# Remove line after "Domain servers"
sed -i '/^Domain servers/{n; /.*/d}' tmp12
# Remove blank lines from end of file
awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp12 > tmp13
# Format output
sed 's/: /:#####/g' tmp13 | column -s '#' -t > whois-domain

###############################################################################################################################

echo "     IP                   (47/$total)"
ip=`ping -c1 $domain | grep PING | cut -d '(' -f2 | cut -d ')' -f1`
whois $ip > tmp
egrep -v '(\#|\%|\*|All reports|Comment|dynamic hosting|For fastest|For more|Found a referral|http|OriginAS:$|Parent:$|point in|RegDate:$|remarks:|The activity|the correct|this kind of object|Without these)' tmp > tmp2
# Remove leading whitespace from file
awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp2 > tmp3
# Remove blank lines from end of file
awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp3 > tmp4
# Compress blank lines
cat -s tmp4 > whois-ip
rm tmp*
echo

###############################################################################################################################

echo "dnsdumpster.com           (48/$total)"
# Generate a random cookie value
rando=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | cut -c 1-32)
curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$rando&targetip=$domain" --cookie "csrftoken=$rando; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com/static/map/$domain.png > /dev/null
sleep 25
curl -s -o $home/data/$domain/assets/images/dnsdumpster.png https://dnsdumpster.com/static/map/$domain.png
echo

###############################################################################################################################

echo "intodns.com               (49/$total)"
wget -q http://www.intodns.com/$domain -O tmp
cat tmp | sed '1,32d; s/<table width="99%" cellspacing="1" class="tabular">/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/g; s/Test name/Test/g; s/ <a href="feedback\/?KeepThis=true&amp;TB_iframe=true&amp;height=300&amp;width=240" title="intoDNS feedback" class="thickbox feedback">send feedback<\/a>//g; s/ background-color: #ffffff;//; s/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/<table class="table table-bordered">/; s/<td class="icon">/<td class="inc-table-cell-status">/g; s/<tr class="info">/<tr>/g' | egrep -v '(Processed in|UA-2900375-1|urchinTracker|script|Work in progress)' | sed '/footer/I,+3 d; /google-analytics/I,+5 d' > tmp2
cat tmp2 >> $home/data/$domain/pages/config.htm

# Add new icons
sed -i 's|/static/images/error.gif|\.\./assets/images/icons/fail.png|g' $home/data/$domain/pages/config.htm
sed -i 's|/static/images/fail.gif|\.\./assets/images/icons/fail.png|g' $home/data/$domain/pages/config.htm
sed -i 's|/static/images/info.gif|\.\./assets/images/icons/info.png|g' $home/data/$domain/pages/config.htm
sed -i 's|/static/images/pass.gif|\.\./assets/images/icons/pass.png|g' $home/data/$domain/pages/config.htm
sed -i 's|/static/images/warn.gif|\.\./assets/images/icons/warn.png|g' $home/data/$domain/pages/config.htm
sed -i 's|\.\.\.\.|\.\.|g' $home/data/$domain/pages/config.htm
# Insert missing table tag
sed -i 's/.*<thead>.*/     <table border="4">\n&/' $home/data/$domain/pages/config.htm
# Add blank lines below table
sed -i 's/.*<\/table>.*/&\n<br>\n<br>/' $home/data/$domain/pages/config.htm
# Remove unnecessary JS at bottom of page
sed -i '/Math\.random/I,+6 d' $home/data/$domain/pages/config.htm
# Clean up
sed -i 's/I could use the nameservers/The nameservers/g' $home/data/$domain/pages/config.htm
sed -i 's/I did not detect/Unable to detect/g; s/I have not found/Unable to find/g; s/It may be that I am wrong but the chances of that are low.//g; s/Good.//g; s/Ok. //g; s/OK. //g; s/The reverse (PTR) record://g; s/the same ip./the same IP./g; s/The SOA record is://g; s/WARNING: //g; s/You have/There are/g; s/you have/there are/g; s/You must be/Be/g; s/Your/The/g; s/your/the/g' $home/data/$domain/pages/config.htm
echo

###############################################################################################################################

echo "robtex.com                (50/$total)"
wget -q https://gfx.robtex.com/gfx/graph.png?dns=$domain -O $home/data/$domain/assets/images/robtex.png
echo

###############################################################################################################################

echo "Registered Domains        (51/$total)"
f_regdomain(){
while read regdomain; do
     ipaddr=$(dig +short $regdomain)
     whois -H "$regdomain" 2>&1 | sed -e 's/^[ \t]*//; s/ \+ //g; s/: /:/g' > tmp5
     wait
     registrar=$(grep -m1 -i 'Registrar:' tmp5 | cut -d ':' -f2 | sed 's/,//g')
     regorg=$(grep -m1 -i 'Registrant Organization:' tmp5 | cut -d ':' -f2 | sed 's/,//g')
     regemailtmp=$(grep -m1 -i 'Registrant Email:' tmp5 | cut -d ':' -f2 | tr 'A-Z' 'a-z')

     if [[ $regemailtmp == *'query the rdds service'* ]]; then
          regemail='REDACTED FOR PRIVACY'
     else
          regemail="$regemailtmp"
     fi

     nomatch=$(grep -c -E 'No match for|Name or service not known' tmp5)

     if [[ $nomatch -eq 1 ]]; then
          echo "$regdomain -- No Whois Matches Found" >> tmp4
     else
          if [[ "$ipaddr" == "" ]]; then
               echo "$regdomain,No IP Found,$regemail,$regorg,$registrar" >> tmp4
          else
               echo "$regdomain,$ipaddr,$regemail,$regorg,$registrar" >> tmp4
          fi
     fi

     let number=number+1
     echo -ne "     ${YELLOW}$number ${NC}of ${YELLOW}$domcount ${NC}domains"\\r
     sleep 2
done < tmp3
echo
}

# Get domains registered by company name and email address domain
curl -sL --header "Host:viewdns.info" --referer https://viewdns.info --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" https://viewdns.info/reversewhois/?q=%40$domain > tmp
sleep 2
curl -sL --header "Host:viewdns.info" --referer https://viewdns.info --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" https://viewdns.info/reversewhois/?q=$companyurl > tmp2

echo '111AAA--placeholder--' > tmp4

if grep -q 'There are 0 domains' tmp && grep -q 'There are 0 domains' tmp2; then
     rm tmp tmp2
     echo 'No Domains Found.' > tmp6
elif ! [ -s tmp ] && ! [ -s tmp2 ]; then
     rm tmp tmp2
     echo 'No Domains Found.' > tmp6

# Loop thru list of domains, gathering details about the domain
elif grep -q 'paymenthash' tmp; then
     grep 'Domain Name' tmp | sed 's/<tr>/\n/g' | grep '</td></tr>' | cut -d '>' -f2 | cut -d '<' -f1 > tmp3
     grep 'Domain Name' tmp2 | sed 's/<tr>/\n/g' | grep '</td></tr>' | cut -d '>' -f2 | cut -d '<' -f1 >> tmp3
     sort -uV tmp3 -o tmp3
     domcount=$(wc -l tmp3 | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
     f_regdomain
else
     grep 'ViewDNS.info' tmp | sed 's/<tr>/\n/g' | grep '</td></tr>' | grep -v -E 'font size|Domain Name' | cut -d '>' -f2 | cut -d '<' -f1 > tmp3
     grep 'ViewDNS.info' tmp2 | sed 's/<tr>/\n/g' | grep '</td></tr>' | grep -v -E 'font size|Domain Name' | cut -d '>' -f2 | cut -d '<' -f1 >> tmp3
     sort -uV tmp3 -o tmp3
     domcount=$(wc -l tmp3 | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
     f_regdomain
fi

# Formatting & clean-up
cat tmp4 | sed 's/111AAA--placeholder--/Domain,IP Address,Registration Email,Registration Org,Registrar,/' | grep -v 'Matches Found' > tmp6
cat tmp6 | sed 's/LLC /LLC./g; s/No IP Found//g; s/REDACTED FOR PRIVACY//g; s/select contact domain holder link at https//g' > tmp7
# Remove lines that start with an IP
grep -Ev '^\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' tmp7 > tmp8
egrep -v '(amazonaws.com|connection timed out|Domain Name|please contact|PrivacyGuard|redacted for privacy)' tmp8 > tmp9
grep "@$domain" tmp9 | column -t -s ',' | sort -u > registered-domains

###############################################################################################################################

cat z* | grep "@$domain" | egrep -v '(_|,)' | sort -u > emails

# Thanks Jason Ashton for cleaning up subdomains
cut -d ':' -f2 z* | grep "\.$domain" | grep -v '/' | sort -u > tmp

while read i; do
     ipadd=$(grep -w "$i" z* | cut -d ':' -f3 | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sed 's/, /\n/g' | sort -uV | tr '\n' ',' | sed 's/,$//g')
     echo "$i:$ipadd" >> raw
done < tmp

cat raw | sed 's/FOO$//; s/:,/:/g' | column -t -s ':' | sed 's/,/, /g' > subdomains

cat z* | egrep -v '(@|:|\.|Atlanta|Boston|Detroit|Google|Maryland|North Carolina|Philadelphia|Planning|Search|substring|United|University)' | sed 's/ And / and /; s/ Av / AV /g; s/Dj/DJ/g; s/iii/III/g; s/ii/II/g; s/ It / IT /g; s/Jb/JB/g; s/ Of / of /g; s/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mch/McH/g; s/Mci/McI/g; s/Mcj/McJ/g; s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcp/McP/g; s/Mcq/McQ/g; s/Mcs/McS/g; s/Mcv/McV/g; s/Tj/TJ/g; s/ Ui / UI /g; s/ Ux / UX /g' | sed '/[0-9]/d' | sed 's/ - /,/g; s/ /,/1' | awk -F ',' '{print $2"#"$1"#"$3}' | sort -u > names

###############################################################################################################################

echo "recon-ng                  (52/$total)"
echo "marketplace refresh" > passive.rc
echo "marketplace install all" >> passive.rc
echo "workspaces create $domain" >> passive.rc
echo "db insert companies" >> passive.rc
echo "$companyurl" >> passive.rc
sed -i 's/%26/\&/g; s/%20/ /g; s/%2C/\,/g' passive.rc
echo "none" >> passive.rc
echo "none" >> passive.rc
echo "db insert domains" >> passive.rc
echo "$domain" >> passive.rc
echo "none" >> passive.rc

if [ -e emails ]; then
     cp emails /tmp/tmp-emails
     cat $discover/resource/recon-ng-import-emails.rc >> passive.rc
fi

if [ -e names ]; then
     echo "last_name#first_name#title" > /tmp/names.csv
     cat names >> /tmp/names.csv
     cat $discover/resource/recon-ng-import-names.rc >> passive.rc
fi

cat $discover/resource/recon-ng.rc >> passive.rc
cat $discover/resource/recon-ng-cleanup.rc >> passive.rc
sed -i "s/yyy/$domain/g" passive.rc

recon-ng -r $CWD/passive.rc

###############################################################################################################################

grep '@' /tmp/emails | awk '{print $2}' | egrep -v '(>|query|SELECT)' | sort -u > emails-final

sed '1,4d' /tmp/names | head -n -5 | egrep -v '(last_name|substring)' | sort -u > names-final

grep '/' /tmp/networks | grep -v 'Spooling' | awk '{print $2}' | $sip > tmp
cat tmp networks | sort -u | $sip > networks-final

grep "\.$domain" /tmp/subdomains | egrep -v '(\*|%|>|SELECT|www)' | awk '{print $2,$4}' | sed 's/|//g' | column -t | sort -u > tmp
cat subdomains tmp | grep -E '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | egrep -v '(outlook|www)' | column -t | sort -u | sed 's/[ \t]*$//' > subdomains-final

cut -d ' ' -f2- subdomains-final | sed 's/^[ \t]*//' | grep -v ',' | sort -u > tmp
cut -d ' ' -f2- subdomains-final | sed 's/^[ \t]*//' | grep ',' | sed 's/,/\n/g' | sed 's/^[ \t]*//' | sort -u > tmp2
cat tmp tmp2 | sort -u | $sip | sed 's/[ \t]*$//' > hosts

###############################################################################################################################

if [ -e networks-final ]; then
     cat networks-final > tmp 2>/dev/null
     echo >> tmp
fi

cat hosts >> tmp
cat tmp >> $home/data/$domain/data/hosts.htm
echo "</pre>" >> $home/data/$domain/data/hosts.htm 2>/dev/null

echo "Summary" > zreport
echo $short >> zreport
echo > tmp

if [ -e emails-final ]; then
     emailcount=$(wc -l emails-final | cut -d ' ' -f1)
     echo "Emails               $emailcount" >> zreport
     echo "Emails ($emailcount)" >> tmp
     echo $short >> tmp
     cat emails-final >> tmp
     echo >> tmp
     cat emails-final >> $home/data/$domain/data/emails.htm
     echo "</pre>" >> $home/data/$domain/data/emails.htm
else
     echo "No data found." >> $home/data/$domain/data/emails.htm
     echo "</pre>" >> $home/data/$domain/data/emails.htm
fi

if [ -e names-final ]; then
     namecount=$(wc -l names-final | cut -d ' ' -f1)
     echo "Names                $namecount" >> zreport
     echo "Names ($namecount)" >> tmp
     echo $long >> tmp
     cat names-final >> tmp
     echo >> tmp
     cat names-final >> $home/data/$domain/data/names.htm
     echo "</center>" >> $home/data/$domain/data/names.htm
     echo "</pre>" >> $home/data/$domain/data/names.htm
else
     echo "No data found." >> $home/data/$domain/data/names.htm
     echo "</pre>" >> $home/data/$domain/data/names.htm
fi

if [ -e records ]; then
     recordcount=$(wc -l records | cut -d ' ' -f1)
     echo "DNS Records          $recordcount" >> zreport
     echo "DNS Records ($recordcount)" >> tmp
     echo $long >> tmp
     cat records >> tmp
     echo >> tmp
fi

if [ -s networks-final ]; then
     networkcount=$(wc -l networks-final | cut -d ' ' -f1)
     echo "Networks             $networkcount" >> zreport
     echo "Networks ($networkcount)" >> tmp
     echo $short >> tmp
     cat networks-final >> tmp 2>/dev/null
     echo >> tmp
fi

if [ -e hosts ]; then
     hostcount=$(wc -l hosts | cut -d ' ' -f1)
     echo "Hosts                $hostcount" >> zreport
     echo "Hosts ($hostcount)" >> tmp
     echo $long >> tmp
     cat hosts >> tmp
     echo >> tmp
fi

if [ -s registered-domains ]; then
     domaincount1=$(wc -l registered-domains | cut -d ' ' -f1)
     echo "Registered Domains   $domaincount1" >> zreport
     echo "Registered Domains ($domaincount1)" >> tmp
     echo $long >> tmp
     cat registered-domains >> tmp
     echo >> tmp
     echo "Domains registered to $company using a corporate email." >> $home/data/$domain/data/registered-domains.htm
     echo >> $home/data/$domain/data/registered-domains.htm
     cat registered-domains >> $home/data/$domain/data/registered-domains.htm
     echo "</pre>" >> $home/data/$domain/data/registered-domains.htm
else
     echo "No data found." >> $home/data/$domain/data/registered-domains.htm
     echo "</pre>" >> $home/data/$domain/data/registered-domains.htm
fi

if [ -e squatting ]; then
     urlcount2=$(wc -l squatting | cut -d ' ' -f1)
     echo "Squatting            $urlcount2" >> zreport
     echo "Squatting ($urlcount2)" >> tmp
     echo $long >> tmp
     cat squatting >> tmp
     echo >> tmp
     cat squatting >> $home/data/$domain/data/squatting.htm
     echo "</pre>" >> $home/data/$domain/data/squatting.htm
else
     echo "No data found." >> $home/data/$domain/data/squatting.htm
     echo "</pre>" >> $home/data/$domain/data/squatting.htm
fi

if [ -e subdomains-final ]; then
     urlcount=$(wc -l subdomains-final | cut -d ' ' -f1)
     echo "Subdomains           $urlcount" >> zreport
     echo "Subdomains ($urlcount)" >> tmp
     echo $long >> tmp
     cat subdomains-final >> tmp
     echo >> tmp
     cat subdomains-final >> $home/data/$domain/data/subdomains.htm
     echo "</pre>" >> $home/data/$domain/data/subdomains.htm
else
     echo "No data found." >> $home/data/$domain/data/subdomains.htm
     echo "</pre>" >> $home/data/$domain/data/subdomains.htm
fi

if [ -s xls ]; then
     xlscount=$(wc -l xls | cut -d ' ' -f1)
     echo "Excel                $xlscount" >> zreport
     echo "Excel Files ($xlscount)" >> tmp
     echo $long >> tmp
     cat xls >> tmp
     echo >> tmp
     cat xls >> $home/data/$domain/data/xls.htm
     echo '</pre>' >> $home/data/$domain/data/xls.htm
else
     echo "No data found." >> $home/data/$domain/data/xls.htm
     echo "</pre>" >> $home/data/$domain/data/xls.htm
fi

if [ -s pdf ]; then
     pdfcount=$(wc -l pdf | cut -d ' ' -f1)
     echo "PDF                  $pdfcount" >> zreport
     echo "PDF Files ($pdfcount)" >> tmp
     echo $long >> tmp
     cat pdf >> tmp
     echo >> tmp
     cat pdf >> $home/data/$domain/data/pdf.htm
     echo '</pre>' >> $home/data/$domain/data/pdf.htm
else
     echo "No data found." >> $home/data/$domain/data/pdf.htm
     echo "</pre>" >> $home/data/$domain/data/pdf.htm
fi

if [ -s ppt ]; then
     pptcount=$(wc -l ppt | cut -d ' ' -f1)
     echo "PowerPoint           $pptcount" >> zreport
     echo "PowerPoint Files ($pptcount)" >> tmp
     echo $long >> tmp
     cat ppt >> tmp
     echo >> tmp
     cat ppt >> $home/data/$domain/data/ppt.htm
     echo '</pre>' >> $home/data/$domain/data/ppt.htm
else
     echo "No data found." >> $home/data/$domain/data/ppt.htm
     echo "</pre>" >> $home/data/$domain/data/ppt.htm
fi

if [ -s txt ]; then
     txtcount=$(wc -l txt | cut -d ' ' -f1)
     echo "Text                 $txtcount" >> zreport
     echo "Text Files ($txtcount)" >> tmp
     echo $long >> tmp
     cat txt >> tmp
     echo >> tmp
     cat txt >> $home/data/$domain/data/txt.htm
     echo '</pre>' >> $home/data/$domain/data/txt.htm
else
     echo "No data found." >> $home/data/$domain/data/txt.htm
     echo "</pre>" >> $home/data/$domain/data/txt.htm
fi

if [ -s doc ]; then
     doccount=$(wc -l doc | cut -d ' ' -f1)
     echo "Word                 $doccount" >> zreport
     echo "Word Files ($doccount)" >> tmp
     echo $long >> tmp
     cat doc >> tmp
     echo >> tmp
     cat doc >> $home/data/$domain/data/doc.htm
     echo '</pre>' >> $home/data/$domain/data/doc.htm
else
     echo "No data found." >> $home/data/$domain/data/doc.htm
     echo "</pre>" >> $home/data/$domain/data/doc.htm
fi

cat tmp >> zreport

if [ -e whois-domain ]; then
     echo "Whois Domain" >> zreport
     echo $long >> zreport
     cat whois-domain >> zreport
     cat whois-domain >> $home/data/$domain/data/whois-domain.htm
     echo "</pre>" >> $home/data/$domain/data/whois-domain.htm
else
     echo "No data found." >> $home/data/$domain/data/whois-domain.htm
     echo "</pre>" >> $home/data/$domain/data/whois-domain.htm
fi

if [ -e whois-ip ]; then
     echo >> zreport
     echo "Whois IP" >> zreport
     echo $long >> zreport
     cat whois-ip >> zreport
     cat whois-ip >> $home/data/$domain/data/whois-ip.htm
     echo "</pre>" >> $home/data/$domain/data/whois-ip.htm
else
     echo "No data found." >> $home/data/$domain/data/whois-ip.htm
     echo "</pre>" >> $home/data/$domain/data/whois-ip.htm
fi

cat zreport >> $home/data/$domain/data/passive-recon.htm
echo "</pre>" >> $home/data/$domain/data/passive-recon.htm

rm tmp* zreport
mv asn curl debug* dnstwist email* hosts name* network* raw records registered* squatting sub* whois* z* doc pdf ppt txt xls $home/data/$domain/tools/ 2>/dev/null
mv passive.rc passive2.rc $home/data/$domain/tools/recon-ng/ 2>/dev/null
cd /tmp/; mv emails names* networks sub* tmp-emails $home/data/$domain/tools/recon-ng/ 2>/dev/null
cd $CWD

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The supporting data folder is located at ${YELLOW}$home/data/$domain/${NC}\n"

###############################################################################################################################

f_runlocally

xdg-open https://www.google.com/search?q=$companyurl+logo &
sleep 4
xdg-open https://$companyurl.s3.amazonaws.com &
sleep 4
xdg-open https://www.google.com/search?q=site:$domain+%22internal+use+only%22 &
sleep 4
xdg-open https://www.google.com/search?q=site:$domain+%22index+of/%22+%22parent+directory%22 &
sleep 4
xdg-open https://dockets.justia.com/search?parties=%22$companyurl%22&cases=mostrecent &
sleep 4
xdg-open https://www.google.com/search?q=site:$domain+inurl:login &
sleep 4
xdg-open http://www.reuters.com/finance/stocks/lookup?searchType=any\&search=$companyurl &
sleep 4
xdg-open https://www.google.com/search?q=site:$domain+intext:username+intext:password+inurl:ftp &
sleep 4
xdg-open https://secsearch.sec.gov/search/docs?affiliate=secsearch&query=$companyurl &
sleep 4
xdg-open https://www.google.com/search?q=site:$domain+intext:username+intext:password+-inurl:careers &
sleep 4
xdg-open https://networksdb.io/search/org/$companyurl &
sleep 4
xdg-open https://www.google.com/search?q=site:$domain+intext:Atlassian+intext:jira+-inurl:careers &
sleep 6
xdg-open https://www.google.com/search?q=site:pastebin.com+intext:$domain &
sleep 4
xdg-open https://www.facebook.com &
sleep 4
xdg-open https://www.instagram.com &
sleep 4
xdg-open https://www.linkedin.com &
sleep 4
xdg-open https://www.pinterest.com &
sleep 4
xdg-open https://twitter.com &
sleep 4
xdg-open https://www.youtube.com &
sleep 4
xdg-open https://$domain &

