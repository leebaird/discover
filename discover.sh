#!/bin/bash
#
# by Lee Baird
# Contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
# Special thanks to the following people:
#
# Ben Wood - regex master
# Dave Klug - planning, testing and bug reports
# Jay Townsend (L1ghtn1ng) - conversion from Backtrack to Kali, manages pull requests & issues, python conversion
# Jason Arnold - planning original concept, author of ssl-check and co-author of crack-wifi
# John Kim - Python guru, bug smasher and parsers
# Eric Milam - total re-write using functions
# Martin Bos - IDS evasion techniques
# Matt Banick - original development
# Numerous people on freenode IRC - #bash and #sed (e36freak)
# Rob Dixon - report framework idea
# Robert Clowser - all things
# Saviour Emmanuel - Nmap parser
# Securicon, LLC. - for sponsoring development of parsers
# Steve Copland - report framework design

##############################################################################################################

# Catch ctrl+c from user
trap f_terminate INT

# Global variables
distro=$(uname -n)
interface=$(ip link | awk '{print $2, $9}' | grep UP | cut -d ':' -f1)
ip=$(ip addr | grep global | cut -d '/' -f1 | awk '{print $2}')
long='========================================================================================================='
medium='====================================================================================='
short='========================================'
sip='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'

# Make OS X friendly
if [ `uname -a | awk '{print $1}'` = 'Darwin' ]; then
     user=/Users/$(whoami)
else
     user=$(whoami)
fi

##############################################################################################################

f_banner(){
echo
echo "
______  ___ ______ ______  _____  _    _ ______  _____
|     \  |  |____  |      |     |  \  /  |_____ |____/
|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_

By Lee Baird"
echo
echo
}

##############################################################################################################

f_error(){
echo
echo -e "\e[1;31m$medium\e[0m"
echo
echo -e "\e[1;31m                  *** Invalid choice or entry. ***\e[0m"
echo
echo -e "\e[1;31m$medium\e[0m"
sleep 2
f_main
}

##############################################################################################################

f_location(){
echo
echo -n "Enter the location of your file: "
read location

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
     echo -e "\e[1;31m$medium\e[0m"
     echo
     echo -e "\e[1;31m *** This option must be run locally, in an X-Windows environment. ***\e[0m"
     echo
     echo -e "\e[1;31m$medium\e[0m"
     sleep 4
     f_main
fi
}

##############################################################################################################

f_terminate(){
mkdir /$user/data/cancelled-`date +%H:%M:%S`

# Nmap and Metasploit scans
mv $name/ /$user/data/cancelled-`date +%H:%M:%S` 2>/dev/null

# Recon files
mv emails* names records squatting whois* sub* doc pdf ppt txt xls tmp* z* /$user/data/cancelled-`date +%H:%M:%S` 2>/dev/null
}

##############################################################################################################

f_domain(){
clear
f_banner
echo -e "\e[1;34mRECON\e[0m"
echo
echo "1.  Passive"
echo "2.  Active"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
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
     if [ -z $domain ]; then
          f_error
     fi

     # If folder doesn't exist, create it
     if [ ! -d /$user/data/$domain ]; then
          cp -R /opt/discover/report/ /$user/data/$domain
          sed 's/REPLACEDOMAIN/'$domain'/g' /$user/data/$domain/index.htm > tmp
          mv tmp /$user/data/$domain/index.htm
     fi

     # Number of tests
     total=25

     echo
     echo $medium
     echo

     echo "dnsrecon                  (1/$total)"
     dnsrecon -d $domain -t goo > tmp
     grep $domain tmp | egrep -v '(Performing|Records Found)' | awk '{print $3 " " $4}' | awk '$2 !~ /[a-z]/' | column -t | sort -u > sub1
     echo

     echo "goofile                   (2/$total)"

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
     echo "goog-mail                 (3/$total)"
     /opt/discover/mods/goog-mail.py $domain | sort -u > tmp
     grep -Fv '..' tmp > tmp2
     # Remove lines that start with a number
     sed '/^[0-9]/d' tmp2 > tmp3
     # Change to lower case
     cat tmp3 | tr '[A-Z]' '[a-z]' > tmp4
     # Remove blank lines
     sed '/^$/d' tmp4 > zgoog-mail

     echo
     echo "goohost"
     echo "     IP                   (4/$total)"
     /opt/discover/mods/goohost.sh -t $domain -m ip >/dev/null
     echo "     Email                (5/$total)"
     /opt/discover/mods/goohost.sh -t $domain -m mail >/dev/null
     cat report-* > tmp
     # Move the second column to the first position
     grep $domain tmp | awk '{print $2 " " $1}' > tmp2
     column -t tmp2 > zgoohost
     rm *-$domain.txt

     echo
     echo "theharvester"
     echo "     Baidu                (6/$total)"
     theharvester -d $domain -b baidu > zbaidu
     echo "     Bing                 (7/$total)"
     theharvester -d $domain -b bing > zbing
     echo "     Dogpilesearch        (8/$total)"
     theharvester -d $domain -b dogpilesearch > zdogpilesearch
     echo "     Google               (9/$total)"
     theharvester -d $domain -b google > zgoogle
     echo "     Google+              (10/$total)"
     theharvester -d $domain -b googleplus > zgoogleplus
     echo "     Google profiles	  (11/$total)"
     theharvester -d $domain -b google-profiles > zgoogle-profiles
     echo "     Jigsaw               (12/$total)"
     theharvester -d $domain -b jigsaw > zjigsaw
     echo "     LinkedIn             (13/$total)"
     theharvester -d $domain -b linkedin > zlinkedin
     echo "     People123            (14/$total)"
     theharvester -d $domain -b people123 > zpeople123
     echo "     PGP                  (15/$total)"
     theharvester -d $domain -b pgp > zpgp
     echo "     Yahoo                (16/$total)"
     theharvester -d $domain -b yahoo > zyahoo
     echo "     All                  (17/$total)"
     theharvester -d $domain -b all > zall

     echo
     echo "Metasploit                (18/$total)"
     msfconsole -x "use gather/search_email_collector; set DOMAIN $domain; run; exit y" > tmp 2>/dev/null
     grep @$domain tmp | awk '{print $2}' | grep -v '%' | grep -Fv '...@' | sort -u > tmp2
     # Change to lower case
     cat tmp2 | tr '[A-Z]' '[a-z]' > tmp3
     # Remove blank lines
     sed '/^$/d' tmp3 > zmsf

     echo
     echo "URLCrazy                  (19/$total)"
     urlcrazy $domain -o tmp > /dev/null
     # Clean up
     egrep -v '(#|:|\?|RESERVED|Typo Type|URLCrazy)' tmp | sed 's/[A-Z]\{2\},//g' > tmp2
     # Remove lines that start with -
     grep -v '^-' tmp2 > tmp3
     # Remove blank lines
     sed '/^$/d' tmp3 > tmp4
     sed 's/AUSTRALIA/Australia/g; s/AUSTRIA/Austria/g; s/BAHAMAS/Bahamas/g; s/BANGLADESH/Bangladesh/g; s/BELGIUM/Belgium/g; s/CANADA/Canada/g; s/CAYMAN ISLANDS/Cayman Islands/g;
s/CHILE/Chile/g; s/CHINA/China/g; s/COSTA RICA/Costa Rica/g; s/CZECH REPUBLIC/Czech Republic/g; s/DENMARK/Denmark/g; s/EUROPEAN UNION/European Union/g; s/FINLAND/Finland/g;
s/FRANCE/France/g; s/GERMANY/Germany/g; s/HONG KONG/Hong Kong/g; s/HUNGARY/Hungary/g; s/INDIA/India/g; s/IRELAND/Ireland/g; s/ISRAEL/Israel/g; s/ITALY/Italy/g; s/JAPAN/Japan/g;
s/KOREA REPUBLIC OF/Republic of Korea/g; s/LUXEMBOURG/Luxembourg/g; s/NETHERLANDS/Netherlands/g; s/NORWAY/Norway/g; s/POLAND/Poland/g; s/RUSSIAN FEDERATION/Russia/g;
s/SAUDI ARABIA/Saudi Arabia/g; s/SPAIN/Spain/g; s/SWEDEN/Sweden/g; s/SWITZERLAND/Switzerland/g; s/TAIWAN; REPUBLIC OF China (ROC)/Taiwan/g; s/THAILAND/Thailand/g; s/TURKEY/Turkey/g;
s/UKRAINE/Ukraine/g; s/UNITED KINGDOM/United Kingdom/g; s/UNITED STATES/United States/g; s/VIRGIN ISLANDS (BRITISH)/Virgin Islands/g' tmp4 > squatting

     ##############################################################

     cat z* | egrep -v '(@|\*|-|=|\||;|:|"|<|>|/|\?)' > tmp
     # Remove blank lines
     sed '/^$/d' tmp > tmp2
     # Remove lines that contain a number
     sed '/[0-9]/d' tmp2 > tmp3
     # Remove lines that start with @ or .
     sed '/^\@\./d' tmp3 > tmp4
     # Remove trailing white space from each line
     sed 's/[ \t]*$//' tmp4 > tmp5
     # Substitute a space for a plus sign
     sed 's/+/ /g' tmp5 > tmp6
     # Change to lower case
     cat tmp6 | tr '[A-Z]' '[a-z]' > tmp7
     # Clean up
     egrep -v '(academy|account|achievement|active|administrator|administrative|advanced|adventure|advertising|america|american|analysis|analyst|antivirus|apple seems|application|applications|architect|article|asian|assistant|associate|association|attorney|auditor|australia|automation|automotive|balance|bank|bbc|beginning|berlin|beta theta|between|big game|billion|bioimages|biometrics|bizspark|breaches|broker|business|buyer|buying|california|cannot|capital|career|carrying|cashing|certified|challenger|championship|change|chapter|charge|china|chinese|clearance|cloud|code|college|columbia|communications|community|company pages|competition|competitive|compliance|computer|concept|conference|config|connections|connect|construction|consultant|contractor|contributor|controllang|cooperation|coordinator|corporation|creative|critical|croatia|crm|dallas|day care|death toll|delta|department|description|designer|design|detection|developer|develop|development|devine|digital|diploma|director|disability|disaster|disclosure|dispute|division|document|dos poc|download|drivers|during|economy|ecovillage|editor|education|effect|electronic|else|emails|embargo|emerging|empower|employment|end user|energy|engineer|enterprise|entertainment|entreprises|entrepreneur|entry|environmental|error page|ethical|example|excellence|executive|expertzone|exploit|facebook|faculty|failure|fall edition|fast track|fatherhood|fbi|federal|filmmaker|finance|financial|forensic|found|freelance|from|frontiers in tax|full|function|fuzzing|germany|get control|global|google|government|graphic|greater|group|guardian|hackers|hacking|harden|harder|hawaii|hazing|headquarters|health|help|history|homepage|hospital|house|how to|hurricane|icmp|idc|in the news|index|informatics|information|innovation|installation|insurers|integrated|international|internet|instructor|insurance|interested|investigation|investment|investor|israel|items|japan|job|justice|kelowna|knowing|laptops|leadership|letter|licensing|lighting|limitless|liveedu|llp|local|looking|ltd|lsu|luscous|malware|managed|management|manager|managing|manufacturing|marketplace|mastering|md|media|medical|medicine|member|meta tags|methane|metro|microsoft|middle east|mitigation|money|monitor|more coming|mortgage|museums|negative|network|network|new user|newspaper|new york|next page|nitrogen|nyc|obtain|occupied|offers|office|online|operations|organizational|outbreak|owners|page|partner|pathology|peace|people|perceptions|philippines|photo|picture|places|planning|portfolio|potential|preassigned|preparatory|president|principal|print|private|process|producer|product|professional|professor|profile|project|program|publichealth|published|pyramid|questions|recruiter|redeem|redirect|region|register|registry|regulation|rehab|remote|report|republic|research|resolving|revised|rising|rural health|sales|satellite|save the date|school|scheduling|science|search|searc|sections|secured|security|secretary|secrets|see more|selection|senior|server|service|services|social|software|solutions|source|special|station home|statistics|strategy|student|successful|superheroines|supervisor|support|switch|system|systems|talent|targeted|tax|tcp|technical|technology|tester|textoverflow|theater|time in|tit for tat|title|toolbook|tools|traditions|trafficking|transfer|treasury|trojan|twitter|training|ts|tylenol|types of scams|unclaimed|underground|university|united states|untitled|verification|vietnam|view|Violent|virginia bar|voice|volkswagen|volume|wanted|web search|web site|website|welcome|west virginia|when the|whiskey|window|worker|world|www|xbox)' tmp7 > tmp8
     # Remove leading and trailing whitespace from each line
     sed 's/^[ \t]*//;s/[ \t]*$//' tmp8 > tmp9
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp9 > tmp10
     # Clean up
     sed 's/\..../ /g' tmp10 | sed 's/\.../ /g; s/iii/III/g; s/ii/II/g' > tmp11
     # Capitalize the first letter of every word, print last name then first name
     sed 's/\b\(.\)/\u\1/g' tmp11 | awk '{print $2", "$1}' | sort -u > names

     ##############################################################

     cat z* | grep @$domain | grep -vF '...' | egrep -v '(%|\*|=|\+|\[|\||;|:|"|<|>|/|\?)' > tmp
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp > tmp2
     # Change to lower case
     cat tmp2 | tr '[A-Z]' '[a-z]' > tmp3
     # Clean up
     egrep -v '(web search|www|xxx)' tmp3 | cut -d ' ' -f2 | sed '/^@/d' | sort -u > emails

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

     ##############################################################

     echo
     echo "Whois"
     echo "     Domain               (20/$total)"
     whois -H $domain > tmp 2>/dev/null
     # Remove leading whitespace
     sed 's/^[ \t]*//' tmp > tmp2
     # Clean up
     egrep -v '(#:|%|<a|=-=-=-=|Access may be|Additionally|Afilias except|and DNS Hosting|and limitations of|any use of|Be sure to|By submitting an|by the terms|can easily change|circumstances will|clientDeleteProhibited|clientTransferProhibited|clientUpdateProhibited|company may be|complaint will|contact information|Contact us|Copy and paste|currently set|database|data contained in|data presented in|date of|dissemination|Domaininfo AB|Domain Management|Domain names in|Domain status: ok|enable high|except as reasonably|failure to|facsimile of|for commercial purpose|for detailed information|For information for|for information purposes|for the sole|Get Noticed|Get a FREE|guarantee its|HREF|In Europe|In most cases|in obtaining|in the address|includes restrictions|including spam|information is provided|is not the|is providing|Learn how|Learn more|makes this information|MarkMonitor|mining this data|minute and one|modify existing|modify these terms|must be sent|name cannot|NamesBeyond|not to use|Note: This|NOTICE|obtaining information about|of Moniker|of this data|or hiding any|or otherwise support|other use of|own existing customers|Please be advised|Please note|policy|prior written consent|privacy is|Problem Reporting System|Professional and|prohibited without|Promote your|protect the|Public Interest|queries or|Register your|Registrars|registration record|repackaging,|responsible for|See Business Registration|server at|solicitations via|sponsorship|Status|support questions|support the transmission|telephone, or facsimile|that apply to|that you will|the right| The data is|The fact that|the transmission|The Trusted Partner|This listing is|This feature is|This information|This service is|to collect or|to entities|to report any|transmission of mass|UNITED STATES|United States|unsolicited advertising|Users may|Version 6|via e-mail|Visit AboutUs.org|while believed|will use this|with many different|with no guarantee|We reserve the|Whois|you agree|You may not)' tmp2 > tmp3
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

     while IFS=$': \t'
     read first rest; do
          if [[ $first$rest ]]; then
               printf '%-20s %s\n' "$first:" "$rest"
          else
               echo
          fi
     done < tmp13 > whois-domain

     echo "     IP 		  (21/$total)"
     y=$(ping -c1 -w2 $domain | grep 'PING' | cut -d ')' -f1 | cut -d '(' -f2) ; whois -H $y > tmp
     # Remove leading whitespace
     sed 's/^[ \t]*//' tmp > tmp2
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp2 > tmp3
     # Clean up
     egrep -v '(\#|\%|\*|All reports|Comment|dynamic hosting|For fastest|For more|Found a referral|http|OriginAS:$|Parent:$|point in|RegDate:$|remarks:|The activity|the correct|Without these)' tmp3 > tmp4
     # Remove leading whitespace from file
     awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp4 > tmp5
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp5 > tmp6
     # Compress blank lines
     cat -s tmp6 > tmp7
     # Clean up
     sed 's/+1-//g' tmp7 > tmp8

     while IFS=$': \t'
     read first rest; do
          if [[ $first$rest ]]; then
               printf '%-20s %s\n' "$first:" "$rest"
          else
               echo
          fi
     done < tmp8 > whois-ip
     echo

     # Remove all empty files
     find -type f -empty -exec rm {} +

     echo "dnssy.com                 (22/$total)"
     wget -q http://www.dnssy.com/report.php?q=$domain -O tmp
     sed -n '/Results for/,/\/table/p' tmp > tmp2
     echo "<html>" > tmp3
     cat tmp2 | grep -v 'Results for' >> tmp3
     echo "</html>" >> tmp3
     sed 's/Pass/<center><img src="..\/images\/icons\/green.png" height="50" width="50"><\/center>/g;
     s/Warning/<center><img src="..\/images\/icons\/yellow.png" height="50" width="50"><\/center>/g;
     s/Fail/<center><img src="..\/images\/icons\/red.png" height="50" width="50"><\/center>/g;
     s/ class="info"//g; s/ class="rfail"//g; s/ class="rinfo"//g; s/ class="rpass"//g; s/ class="rsecu"//g; s/ class="rwarn"//g;
     s/All of the glue/Glue/g; s/All of your MX/All MX/g; s/All of your nameservers/Nameservers/g; s/Checking domain format/Domain format/g;
     s/Checking for parent nameservers/Parent nameservers/g; s/Checking for parent glue/Parent glue/g; s/Each of your nameservers/Each nameserver/g;
     s/I expected/Expected/g; s/I found the following MX records://g; s/I got an error response to my/Received an error response to/g;
     s/I was unable/Unable/g; s/None of your MX/No MX/g; s/This is all of the MX servers I found.//g; s/WWW/www/g;
     s/Your nameservers/Nameservers/g; s/Your NS records at your nameservers are://g; s/Your NS records at your parent nameserver are://g;
     s/Your SOA/SOA/g; s/Your web server/The web server/g; s/Your web server says it is://g' tmp3 > /$user/data/$domain/data/config.htm

     echo "ewhois.com                (23/$total)"
     wget -q http://www.ewhois.com/$domain/ -O tmp
     cat tmp | grep 'visitors' | cut -d '(' -f1 | cut -d '>' -f2 | grep -v 'OTHER' | column -t | sort -u > sub3

     echo "myipneighbors.net         (24/$total)"
     wget -q http://www.myipneighbors.net/?s=$domain -O tmp
     grep 'Domains' tmp | sed 's/<\/tr>/\\\n/g' | cut -d '=' -f3,6 | sed 's/" rel=/ /g' | sed 's/" rel//g' | grep -v '/' | column -t | sort -u > sub4

     cat sub* | grep -v "$domain\." | sed 's/www\.//g' | column -t | sort -u > tmp
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp > subdomains

     echo "urlvoid.com               (25/$total)"
     wget -q http://www.urlvoid.com/scan/$domain -O tmp
     sed -n '/Safety Scan Report/,/<\/table>/p' tmp | grep -v 'Safety Scan Report' | sed 's/View more details.../Details/g' > /$user/data/$domain/data/black-listed.htm

     awk '{print $2}' subdomains > tmp
     grep -E '([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})' tmp | egrep -v '(-|=|:)' | $sip > hosts
     cat hosts >> /$user/data/$domain/data/hosts.htm; echo "</pre>" >> /$user/data/$domain/data/hosts.htm

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
          cat emails >> /$user/data/$domain/data/emails.htm
     fi

     if [ -e names ]; then
          namecount=$(wc -l names | cut -d ' ' -f1)
          echo "Names         $namecount" >> zreport
          echo "Names ($namecount)" >> tmp
          echo $short >> tmp
          cat names >> tmp
          echo >> tmp
          cat names >> /$user/data/$domain/data/names.htm
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
          cat squatting >> /$user/data/$domain/data/squatting.htm
     fi

     if [ -e subdomains ]; then
          urlcount=$(wc -l subdomains | cut -d ' ' -f1)
          echo "Subdomains    $urlcount" >> zreport
          echo "Subdomains ($urlcount)" >> tmp
          echo $long >> tmp
          cat subdomains >> tmp
          echo >> tmp
          cat subdomains >> /$user/data/$domain/data/subdomains.htm
     fi

     if [ -e xls ]; then
          xlscount=$(wc -l xls | cut -d ' ' -f1)
          echo "Excel         $xlscount" >> zreport
          echo "Excel Files ($xlscount)" >> tmp
          echo $long >> tmp
          cat xls >> tmp
          echo >> tmp
          cat xls >> /$user/data/$domain/data/xls.htm; echo "</pre>" >> /$user/data/$domain/data/xls.htm
     fi

     if [ -e pdf ]; then
          pdfcount=$(wc -l pdf | cut -d ' ' -f1)
          echo "PDF           $pdfcount" >> zreport
          echo "PDF Files ($pdfcount)" >> tmp
          echo $long >> tmp
          cat pdf >> tmp
          echo >> tmp
          cat pdf >> /$user/data/$domain/data/pdf.htm; echo "</pre>" >> /$user/data/$domain/data/pdf.htm
     fi

     if [ -e ppt ]; then
          pptcount=$(wc -l ppt | cut -d ' ' -f1)
          echo "PowerPoint    $pptcount" >> zreport
          echo "PowerPoint Files ($pptcount)" >> tmp
          echo $long >> tmp
          cat ppt >> tmp
          echo >> tmp
          cat ppt >> /$user/data/$domain/data/ppt.htm; echo "</pre>" >> /$user/data/$domain/data/ppt.htm
     fi

     if [ -e txt ]; then
          txtcount=$(wc -l txt | cut -d ' ' -f1)
          echo "Text          $txtcount" >> zreport
          echo "Text Files ($txtcount)" >> tmp
          echo $long >> tmp
          cat txt >> tmp
          echo >> tmp
          cat txt >> /$user/data/$domain/data/txt.htm; echo "</pre>" >> /$user/data/$domain/data/txt.htm
     fi

     if [ -e doc ]; then
          doccount=$(wc -l doc | cut -d ' ' -f1)
          echo "Word          $doccount" >> zreport
          echo "Word Files ($doccount)" >> tmp
          echo $long >> tmp
          cat doc >> tmp
          echo >> tmp
          cat doc >> /$user/data/$domain/data/doc.htm; echo "</pre>" >> /$user/data/$domain/data/doc.htm
     fi

     cat tmp >> zreport
     echo "Whois Domain" >> zreport
     echo $long >> zreport
     cat whois-domain >> zreport

     echo "Whois IP" >> zreport
     echo $long >> zreport
     cat whois-ip >> zreport

     echo "</pre>" >> /$user/data/$domain/data/emails.htm
     echo "</pre>" >> /$user/data/$domain/data/names.htm
     echo "</pre>" >> /$user/data/$domain/data/squatting.htm
     echo "</pre>" >> /$user/data/$domain/data/subdomains.htm
     cat whois-domain >> /$user/data/$domain/data/whois-domain.htm; echo "</pre>" >> /$user/data/$domain/data/whois-domain.htm
     cat whois-ip >> /$user/data/$domain/data/whois-ip.htm; echo "</pre>" >> /$user/data/$domain/data/whois-ip.htm
     cat zreport >> /$user/data/$domain/data/passive-recon.htm; echo "</pre>" >> /$user/data/$domain/data/passive-recon.htm

     rm emails* hosts names squatting sub* tmp* whois* z* doc pdf ppt txt xls 2>/dev/null

     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The supporting data folder is located at \e[1;33m%s\e[0m\n' /$user/data/$domain/
     echo
     read -p "Press <return> to continue."

     ##############################################################

     f_runlocally

     iceweasel &
     sleep 2
     iceweasel -new-tab google.com/#q=$company+logo &
     sleep 1
     iceweasel -new-tab arin.net &
     sleep 1
     iceweasel -new-tab toolbar.netcraft.com/site_report?url=http://www.$domain &
     sleep 1
     iceweasel -new-tab shodanhq.com/search?q=$domain &
     sleep 1
     iceweasel -new-tab connect.data.com/login/ &
     sleep 1
     iceweasel -new-tab pastebin.com/ &
     sleep 1
     iceweasel -new-tab google.com/#q=filetype%3Axls+OR+filetype%3Axlsx+site%3A$domain &
     sleep 1
     iceweasel -new-tab google.com/#q=filetype%3Appt+OR+filetype%3Apptx+site%3A$domain &
     sleep 1
     iceweasel -new-tab google.com/#q=filetype%3Adoc+OR+filetype%3Adocx+site%3A$domain &
     sleep 1
     iceweasel -new-tab google.com/#q=filetype%3Apdf+site%3A$domain &
     sleep 1
     iceweasel -new-tab google.com/#q=filetype%3Atxt+site%3A$domain &
     sleep 1
     iceweasel -new-tab http://www.urlvoid.com/scan/$domain &
     sleep 1
     iceweasel -new-tab crunchbase.com/organization/$company &
     sleep 1
     iceweasel -new-tab google.com/#q=site:linkedin.com+%22at+$company%22+inurl:%2Fpub%2F+OR+inurl:%2Fin%2F+-inurl:%2Fdir%2F+-inurl:%2Fjobs%2F+-inurl:%2Fskills%2F+-inurl:%2Ftitle%2F &
     sleep 1
     iceweasel -new-tab sec.gov/edgar/searchedgar/companysearch.html &
     sleep 1
     iceweasel -new-tab reuters.com/finance/stocks &
     echo
     echo
     exit
     ;;

     2)
     echo
     echo $medium
     echo
     echo "Usage: target.com"
     echo
     echo -n "Domain: "
     read domain

     # Check for no answer
     if [ -z $domain ]; then
          f_error
     fi

     # If folder doesn't exist, create it
     if [ ! -d /$user/data/$domain ]; then
          cp -R /opt/discover/report/ /$user/data/$domain
          sed 's/REPLACEDOMAIN/'$domain'/' /$user/data/$domain/index.htm > tmp
          mv tmp /$user/data/$domain/index.htm
     fi

     # Number of tests
     total=11

     echo
     echo $medium
     echo

     echo "Nmap"
     echo "     Email                (1/$total)"
     nmap -Pn -n --open -p80 --script=http-email-harvest --script-args=http-email-harvest.maxpagecount=100,http-email-harvest.maxdepth=10 $domain > tmp
     grep @$domain tmp | grep -v '%20' | grep -v 'jpg' | awk '{print $2}' > tmp2
     # Change to lower case
     cat tmp2 | tr '[A-Z]' '[a-z]' | sort -u > emails1

     echo
     echo "dnsrecon"
     echo "     DNS Records          (2/$total)"
     dnsrecon -d $domain -t std > tmp
     egrep -v '(All queries|Bind Version for|Could not|Enumerating SRV|It is resolving|not configured|Performing|Records Found|Recursion|Resolving|TXT|Wildcard)' tmp > tmp2
     # Remove first 6 characters from each line
     sed 's/^......//' tmp2 | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10}' | column -t | sort -u -k2 -k1 > tmp3
     grep 'TXT' tmp | sed 's/^......//' | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15}' >> tmp3
     egrep -v '(SEC3|SKEYs|SSEC)' tmp3 > records
     cat /$user/data/$domain/data/records.htm records | grep -v '<' | column -t | sort -u -k2 -k1 > tmp3

     echo '<pre style="font-size:14px;">' > /$user/data/$domain/data/records.htm
     cat tmp3 | column -t >> /$user/data/$domain/data/records.htm; echo "</pre>" >> /$user/data/$domain/data/records.htm

     echo "     Zone Transfer        (3/$total)"
     dnsrecon -d $domain -t axfr > tmp
     egrep -v '(Checking for|Failed|filtered|NS Servers|Removing|TCP Open|Testing NS)' tmp | sed 's/^....//' | sed /^$/d > zonetransfer

     echo "     Sub-domains (~5 min) (4/$total)"
     dnsrecon -d $domain -t brt -D /usr/share/dnsrecon/namelist.txt --iw -f > tmp
     grep $domain tmp | grep -v "$domain\." | egrep -v '(Performing|Records Found)' | sed 's/\[\*\] //g; s/^[ \t]*//' | awk '{print $2,$3}' | column -t | sort -u > subdomains-dnsrecon

     echo
     echo "Fierce (~5 min)           (5/$total)"
     fierce -dns $domain -wordlist /usr/share/fierce/hosts.txt -suppress -file tmp4

     sed -n '/Now performing/,/Subnets found/p' tmp4 | grep $domain | awk '{print $2 " " $1}' | column -t | sort -u > subdomains-fierce

     cat subdomains-dnsrecon subdomains-fierce | egrep -v '(.nat.|1.1.1.1|6.9.6.9|127.0.0.1)' | column -t | sort -u | awk '$2 !~ /[a-z]/' > subdomains

     if [ -e /$user/data/$domain/data/subdomains.htm ]; then
          cat /$user/data/$domain/data/subdomains.htm subdomains | grep -v "<" | grep -v "$domain\." | column -t | sort -u > subdomains-combined
          echo '<pre style="font-size:14px;">' > /$user/data/$domain/data/subdomains.htm
          cat subdomains-combined >> /$user/data/$domain/data/subdomains.htm
          echo "</pre>" >> /$user/data/$domain/data/subdomains.htm
     fi

     awk '{print $3}' records > tmp
     awk '{print $2}' subdomains-dnsrecon subdomains-fierce >> tmp
     grep -E '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}' tmp | egrep -v '(-|=|:|1.1.1.1|6.9.6.9|127.0.0.1)' | $sip > hosts

     echo
     echo "Loadbalancing             (6/$total)"
     lbd $domain > tmp 2>/dev/null
     egrep -v '(Checks if a given|Written by|Proof-of-concept)' tmp > tmp2
     # Remove leading whitespace from file
     awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp2 > tmp3
     # Remove leading whitespace from each line
     sed 's/^[ \t]*//' tmp3 > tmp4
     egrep -v '(does Load-balancing|does NOT use Load-balancing)' tmp4 | sed 's/Checking for //g' > tmp5
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp5 > tmp6
     # Clean up
     cat -s tmp6 | grep -v 'P3P' > loadbalancing

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
     grep -v '<' /$user/data/$domain/data/subdomains.htm | awk '{print $1}' > tmp
     whatweb -i tmp --color=never --no-errors -t 255 > tmp2
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

     cat loadbalancing >> /$user/data/$domain/data/loadbalancing.htm; echo "</pre>" >> /$user/data/$domain/data/loadbalancing.htm
     cat zreport >> /$user/data/$domain/data/active-recon.htm; echo "</pre>" >> /$user/data/$domain/data/active-recon.htm
     cat ztraceroute >> /$user/data/$domain/data/traceroute.htm; echo "</pre>" >> /$user/data/$domain/data/traceroute.htm
     cat waf >> /$user/data/$domain/data/waf.htm; echo "</pre>" >> /$user/data/$domain/data/waf.htm
     cat whatweb >> /$user/data/$domain/data/whatweb.htm; echo "</pre>" >> /$user/data/$domain/data/whatweb.htm
     cat zonetransfer >> /$user/data/$domain/data/zonetransfer.htm; echo "</pre>" >> /$user/data/$domain/data/zonetransfer.htm

     if [[ -e /$user/data/$domain/data/emails.htm && -e emails ]]; then
          cat /$user/data/$domain/data/emails.htm emails | grep -v '<' | sort -u > tmp
          echo '<pre style="font-size:14px;">' > /$user/data/$domain/data/emails.htm
          cat tmp >> /$user/data/$domain/data/emails.htm; echo "</pre>" >> /$user/data/$domain/data/emails.htm
     fi

     cat hosts /$user/data/$domain/data/hosts.htm | grep -v '<' | $sip > tmp
     echo '<pre style="font-size:14px;">' > /$user/data/$domain/data/hosts.htm
     cat tmp >> /$user/data/$domain/data/hosts.htm; echo "</pre>" >> /$user/data/$domain/data/hosts.htm

     rm emails* hosts loadbalancing records sub* tmp* waf whatweb z*

     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The supporting data folder is located at \e[1;33m%s\e[0m\n' /$user/data/$domain/
     echo
     echo

     iceweasel /$user/data/$domain/index.htm &
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

echo -e "\e[1;34mRECON\e[0m"
echo
echo -n "First name: "
read firstName

# Check for no answer
if [ -z $firstName ]; then
     f_error
fi

echo -n "Last name:  "
read lastName

# Check for no answer
if [ -z $lastName ]; then
     f_error
fi

iceweasel &
sleep 2
iceweasel -new-tab http://www.411.com/name/$firstName-$lastName/ &
sleep 1
uripath="http://www.advancedbackgroundchecks.com/search/results.aspx?type=&fn=${firstName}&mi=&ln=${lastName}&age=&city=&state="
iceweasel -new-tab $uripath &
sleep 1
iceweasel -new-tab http://www.cvgadget.com/person/$firstName/$lastName &
sleep 1
iceweasel -new-tab http://www.peekyou.com/$firstName%5f$lastName &
sleep 1
iceweasel -new-tab http://phonenumbers.addresses.com/people/$firstName+$lastName &
sleep 1
iceweasel -new-tab https://pipl.com/search/?q=$firstName+$lastName&l=&sloc=&in=10 &
sleep 1
iceweasel -new-tab http://www.spokeo.com/search?q=$firstName+$lastName&s3=t24 &
sleep 1
iceweasel -new-tab http://www.zabasearch.com/query1_zaba.php?sname=$firstName%20$lastName&state=ALL&ref=$ref&se=$se&doby=&city=&name_style=1&tm=&tmr=

f_main
}

##############################################################################################################

f_salesforce(){
clear
f_banner

echo -e "\e[1;34mCreate a free account at salesforce (https://connect.data.com/login).\e[0m"
echo -e "\e[1;34mPerform a search on your target company > select the company name > see all.\e[0m"
echo -e "\e[1;34mCopy the results into a new file.\e[0m"

f_location

echo
echo

sed 's/Direct Dial Available//g' $location | sed 's/\[\]//g; s/\.//g; s/,,//g; s/,`//g; s/`,//g; s/-cpg//g; s/3d/3D/g; s/Aberdeen Pr//g; s/ACADEMIC/Academic/g; s/account/Account/g;
s/ACTING/Acting/g; s/3administrator/Administrator/g; s/Europe and Africa//g; s/Sub Saharan Africa//g; s/South Africa//g; s/Agoura Hills//g; s/New Albany//g; s/Albion 	QL//g;
s/Aliso Viejo//g; s/Allison Park//g; s/Altamonte S//g; s/Am-east,//g; s/Am-west,//g; s/Head of Americas//g; s/The Americas//g; s/Amst-north America//g; s/ANALYSIST/Analysist/g;
s/Analyst\//Analyst, /g; s/analytics/Analytics/g; s/and New England//g; s/and Central Us//g; s/North Andover//g; s/Andrews Air//g; s/android/Android/g; s/Annapolis J//g;
s/Ann Arbor//g; s/Apple Valley//g; s/applications/Applications/g; s/Arlington H//g; s/Asia-Pacific//g; s/Asia and India//g; s/asia Pacific Region//g; s/Asia Pacific//g; 
s/assistant/Assistant/g; s/AssistantChiefPatrolAgent/Assistant Chief Patrol Agent/g; s/associate/Associate/g; s/at Google//g; s/Atlantic City//g; s/Atm/ATM/g; s/attorney/Attorney/g; 
s/Australia S//g; s/automated/Automated/g; s/Ballston Spa//g; s/Bangalore S//g; s/banking/Banking/g; s/Basking Ridge//g; s/Baton Rouge//g; s/Battle Creek//g; s/Battle Ground//g; 
s/Bay City//g; s/Bay Shore//g; s/BC//g; s/Bd/BD/g; s/Beaver Falls//g; s/Bel Air//g; s/Bella Vista//g; s/Berkeley He//g; s/Berwyn Hts//g; s/Bethel Park//g; s/Beverly Hills//g; 
s/billing/Billing/g; s/Black Belt//g; s/Boca Raton//g; s/BORDER/Border/g; s/Bowling Green//g; s/Boynton Beach//g; s/branch/Branch/g; s/\/Branch/, Branch/g; s/branch/Branch/g; 
s/Buffalo Grove//g; s/business/Business/g; s/buyer/Buyer/g; s/By The//g; s/Calabasas Hls//g; s/Camp Hill//g; s/Camp Springs//g; s/Canoga Park//g; s/Canyon Country//g; 
s/Cape Canaveral//g; s/Cape Coral//g; s/Cape May//g; s/Capitol Hei//g; s/cargo/Cargo/g; s/Carol Stream//g; s/Carol Stream//g; s/cascade/Cascade/g; s/Castle Rock//g; s/Cedar Hill//g; 
s/Cedar Rapids//g; s/census/Census/g; s/Center Line//g; s/CENTER/Center/g; s/Central California//g; s/Central Region//g; s/central Region//g; s/Chagrin Falls//g; s/Charles Town//g; 
s/Cherry Hill//g; s/Chester Le //g; s/East Chicago//g; s/\/Chief/, Chief/g; s/China //g; s/Chino Hills//g; s/chromecast/Chromecast/g; s/Chula Vista//g; s/Cissp/CISSP/g; 
s/CITRIX/Citrix/g; s/clean/Clean/g; s/Clifton Park//g; s/cms/CMS/g; s/Cms/CMS/g; s/CNN News Group Cable News Network//g; s/Cmms/CMMS/g; s/Cocoa Beach//g; s/Cold Spring//g; 
s/Colorado Sp//g; s/Commerce City//g; s/CommitteemanagementOfficer/Committee Management Officer/g; s/compliance/Compliance/g; s/commercial/Commercial/g; s/connected/Connected/g; 
s/CONSULTANT/Consultant/g; s/consumer/Consumer/g; s/contact/Contact/g; s/content/Content/g; s/corporate/Corporate/g; s/Corpus Christi//g; s/Council Bluffs//g; s/COUNSEL/Counsel/g; 
s/counsel/Counsel/g; s/Cranberry T//g; s/Cranberry Twp//g; s/credit/Credit/g; s/CREDIT/Credit/g; s/Crm/CRM/g; s/Croton On H//g; s/Cross Junction//g; s/Crum Lynne//g; 
s/Crystal Lake//g; s/Ctr/Center/g; s/Culver City//g; s/Cuyahoga Falls//g; s/Daly City//g; s/database/Database/g; s/dealer/Dealer/g; s/defense/Defense/g; s/DELIVERY/Delivery/g; 
s/Del Mar//g; s/Delray Beach//g; s/Deer Park//g; s/Del Rio//g; s/DEPUTY/Deputy/g; s/West Des Mo//g; s/Des Moines//g; s/Des Plaines//g; 
s/DesignatedFederalOfficial/Designated Federal Official/g; s/DESIGNER/Designer/g; s/DESIGN/Design/g; s/development/Development/g; s/DEVICES/Devices/g; s/Diamond Bar//g; 
s/director/Director/g; s/DISCIPLINED/Disciplined/g; s/discovery/Discovery/g; s/display/Display/g; s/Dns/DNS/g; s/Downers Grove//g; s/Drexel Hill//g; s/Du Bois//g; 
s/East Brunswick//g; s/East Central//g; s/East Coast//g; s/East Douglas//g; s/East Greenbush//g; s/East Hanover//g; s/East Hartford//g; s/East Lansing//g; s/East Peters//g; 
s/East Stroud//g; s/East Syracuse//g; s/eastern Region//g; s/Eau Claire//g; s/Eden Prairie//g; s/education/Education/g; s/Egg Harbor//g; s/Egg Harbor//g; s/El Cajon//g; 
s/El Centro//g; s/El Monte//g; s/El Paso//g; s/El Segundo//g; s/ELECTRIC/Electric /g; s/ELECTRONICS/Electronics/g; s/Port Elizabeth//g; s/Elk Grove V//g; s/Elk Grove//g; 
s/Ellicott City//g; s/Elk Grove V//g; s/Elkhart//g; s/Elm Grove//g; s/emerging/Emerging/g; s/endocrinology/Endocrinology/g; s/energy/Energy/g; s/engineer/Engineer/g; 
s/enterprise/Enterprise/g; s/ETHICS/Ethics/g; s/Northern Europe//g; s/EVENT/Event/g; s/executive/Executive/g; s/Fairfax Sta//g; s/Fairview He//g; s/Fall River//g; s/Falls Church//g; 
s/Farmington Hls//g; s/fashion/Fashion/g; s/federal/Federal/g; s/FELLOW/Fellow/g; s/Fha/FHA/g; s/FIELD/Field/g; s/fillmore/Fillmore/g; s/financial/Financial/g; s/Flat Rock//g; 
s/FLIGHT/Flight/g; s/Florham Park//g; s/Flower Mound//g; s/Floyds Knobs//g; s/for Asia and//g; s/Forest Hills//g; s/Forest Hill//g; s/Forest Park//g; s/Forked River//g; 
s/foreign/Foreign/g; s/Fort Belvoir//g; s/Fort Bliss//g; s/Fort Collins//g; s/Fort Dodge//g; s/Fort Fairfield//g; s/Fort George//g; s/Fort Huachuca//g; s/Fort Knox//g; 
s/Fort Lauder//g; s/Fort Leaven//g; s/Fort Mill//g; s/Fort Monmouth//g; s/Fort Monroe//g; s/Fort Myers//g; s/Fort Pierce//g; s/Fort Rucker//g; s/Fort Walton//g; s/Fort Washin//g; 
s/Fort Wayne//g; s/Fort Worth//g; s/Fountain Va//g; s/Franklin Park//g; s/Fremont//g; s/Los Fresnos//g; s/Front Royal//g; s/Fsa/FSA/g; s/Fso/FSO/g; s/Ft Mitchell//g; s/Ft Worth//g; 
s/Ft Wright//g; s/FUNCTIONLead/Function Lead/g; s/Gaap/GAAP/g; s/Galway 	G//g; s/Garden City//g; s/Gig Harbor//g; s/Glen Burnie//g; s/Glen Ellyn//g; s/Glen Ridge//g; 
s/Glen Rock//g; s/global/Global/g; s/A Google Company//g; s/Google Access//g; s/Google Adwords//g; s/Google Analytics//g; s/Google Books//g; s/Google Brand//g; s/Google Checkout//g; 
s/Google Earth//g; s/Google Enterprise//g; s/Google Federal//g; s/Google Fiber//g; s/Google Finance//g; s/Google Geospatial Services//g; s/Google Glass//g; s/Google Health//g; 
s/Google Maps//g; s/Google Media Sales//g; s/Google Offers//g; s/Google Payments//g; s/Google Payment//g; s/Google Plus//g; s/Google Print//g;
s/Google Shopping Express//g; s/Google Shopping//g; s/Google Street View//g; s/Google Talk Team//g; s/Google Travel//g; s/Google Ventures//g; s/Google Voice//g; s/Google Wallet//g;
s/Google X//g; s/Goose Creek//g; s/Granbury//g; s/Grand Forks//g; s/Grand Haven//g; s/Grand Island//g; s/Grand Junction//g; s/Grand Prairie//g; s/Grand Rapids//g; s/Granite City//g;
s/Grants Pass//g; s/Grayslake//g; s/Great Falls//g; s/Green Bay//g; s/Green Belt//g; s/Greenwood Vlg//g; s/Grosse Ile//g; s/Grosse Poin//g; s/group/Group/g; s/Grove City//g;
s/Grp/Group/g; s/Gsa/GSA/g; s/Gsm/GSM/g; s/Gulf Breeze//g; s/Gulf Coast//g; s/Gwynn Oak//g; s/Hampton Cove//g; s/Hampton Roads//g; s/Harbor City//g; s/Harpers Ferry//g;
s/Harrison City//g; s/New Hartford//g; s/West Hartford//g; s/Hanscom Afb//g; s/hazard/Hazard/g; s/Hazel Park//g; s/Hd/HD/g; s/\/Head/, Head/g; s/Hermosa Beach//g; s/Highland Hls//g;
s/Highland Park//g; s/Hilton Head//g; s/Hoffman Est//g; s/West Hollywood//g; s/Homer Glen//g; s/Hot Springs//g; s/Hq/HQ/g; s/Huntingtn Bch//g; s/Hurlburt Field//g; s/Idaho Falls//g;
s/Iii/III/g; s/Ii/II/g; s/IMPORT/Import/g; s/Indian Harb//g; s/information/Information/g; s/institutional/Institutional/g; s/INSTRUMENT/Instrument/g; s/insurance/Insurance/g;
s/intelligence/Intelligence/g; s/international/International/g; s/Inver Grove//g; s/Iselin//g; s/Italy//g; s/Jefferson City//g; s/Jersey City//g; s/Johnson City//g; s/Kansas City//g;
s/KANSS CITY//g; s/Keego Harbor//g; s/Kennett Square//g; s/King George//g; s/King Of Pru//g; s/King Of Pru//g; s/Kings Bay//g; s/Kings Park//g; s/La Follette//g; s/La Grange Park//g;
s/La Grange//g; s/La Jolla//g; s/La Mesa//g; s/La Palma//g; s/La Plata//g; s/La Pocatiere//g; s/Laguna Hills//g; s/Laguna Niguel//g; s/Lake Charles//g; s/Salt Lake City//g;
s/Lake City//g; s/Lake Geneva//g; s/Lake Mary//g; s/Lake Montezuma//g; s/Lake Oswego//g; s/landowner/Landowner/g; s/Las Cruces//g; s/North Las V//g; s/Las Vegas//g;
s/Latin America North//g; s/Latin America//g; s/Mount Laurel//g; s/League City//g; s/LEARNING/Learning/g; s/legal/Legal/g; s/lending/Lending/g; s/Lexington Park//g; s/Linthicum H//g;
s/Little Rock//g; s/Llc/LLC/g; s/New London//g; s/Lone Tree//g; s/Long Beach//g; s/Long Valley//g; s/Logan Township//g; s/Los Angeles//g; s/Los Lunas//g; s/Loves Park//g;
s/Lvl/Level/g; s/Macquarie Park//g; s/MAINFRAME/ Mainframe/g; s/MANAGER/Manager/g; s/Manager\//Manager, /g; s/Mangr/Manager/g; s/manager/Manager/g; s/mangr/Manager/g; s/Manhattan B//g;
s/manufacturing/Manufacturing/g; s/MANUFACTURING/Manufacturing/g; s/Maple Grove//g; s/Maple Shade//g; s/March Air R//g; s/MarketingProductionManager/Marketing Production Manager/g;
s/Marina Del Rey//g; s/market/Market/g; s/master/Master/g; s/materials/Materials/g; s/Mayfield West//g; s/Mays Landing//g; s/Mba/MBA/g; s/Mc Lean//g; s/Mc Coll//g; s/Mc Cordsville//g;
s/Mc Kees Rocks//g; s/Mcse/MCSE/g; s/MECHANIC/Mechanic/g; s/medical/Medical/g; s/Melbourne B//g; s/Menlo Park//g; s/Merritt Island//g; s/Metro Jersey District//g; s/Miami Beach//g;
s/Mid-Atlantic//g; s/Middle East//g; s/Middle River//g; s/Upper Midwest//g; s/Millstone T//g; s/Mira Loma//g; s/Mississauga//g; s/MOBILITY/Mobility/g; s/model/Model/g;
s/Moncks Corner//g; s/Moncton//g; s/Monroe Town//g; s/Moor Row//g; s/Moreno Valley//g; s/mortgage/Mortgage/g; s/Morgan Hill//g; s/Morris Plains//g; s/Moss Point//g;
s/MOTOROLA/Motorola/g; s/motorola/Motorola/g; s/Mound City//g; s/Mount Airy//g; s/Mount Holly//g; s/Mount Laurel//g; s/Mount Morrs//g; s/Mount Pleasant//g; s/Mount Pocono//g;
s/Mount Prospect//g; s/Mount Vernon//g; s/Mount Weather//g; s/mountain Region//g; s/Mountain States//g; s/Mountain View//g; s/Mount Waverley//g; s/Muscle Shoals//g; s/Mullica Hill//g;
s/MULTI/Multi/g; s/Munroe Falls//g; s/music/Music/g; s/MyHR/HR/g; s/Myrtle Beach//g; s/National City//g; s/Naval Anaco//g; s/Needham Hei//g; s/negotiator/Negotiator/g; 
s/New Castle//g; s/New Church//g; s/New Cumberland//g; s/New Delhi//g; s/New Haven//g; s/New Malden//g; s/New Market//g; s/New Martins//g; s/New Orleans//g; s/New Port Ri//g; 
s/New Stanton//g; s/New Town//g; s/New York//g; s/New Zealand//g; s/Newbury Park//g; s/Newport Beach//g; s/Newport News//g; s/Niagara Falls//g; s/North America //g; 
s/North and Central//g; s/North Baldwin//g; s/North Bergen//g; s/North Charl//g; s/North East//g; s/North Highl//g; s/North Holly//g; s/North Kings//g; s/North Myrtl//g; 
s/North Olmsted//g; s/North Royalton//g; s/North Vernon//g; s/North Wales//g; s/North York//g; s/northern/Northern/g; s/Nsa/NSA/g; s/Nso/NSO/g; s/O Fallon//g; s/Oak Brook//g; 
s/Oak Creek//g; s/Oak Hill//g; s/Oak Park//g; s/Oak Ridge//g; s/Oak View//g; s/Oakbrook Te//g; s/Ocean City//g; s/Ocean Grove//g; s/Ocean Springs//g; s/officer/Officer/g; 
s/Officer\//Officer, /g; s/OFFICE/Office/g; s/office/Office/g; s/Offutt A F B//g; s/Oklahoma City//g; s/Old Bridge//g; s/Olmsted Falls//g; s/Onited States//g; s/online/Online/g; 
s/operations/Operations/g; s/Orange Park//g; s/oriented/Oriented/g; s/Orland Park//g; s/Overland Park//g; s/Owings Mills//g; s/Oxon Hill//g; s/PACKAGING/Packaging/g; 
s/PACIFIC NORTHWEST//g; s/Pacific Southwest Region //g; s/Palm Bay//g; s/Palm Beach//g; s/Palm Coast//g; s/Palm Harbor//g; s/Palo Alto//g; s/Palos Hills//g; s/Pompano Beach//g; 
s/Panama City//g; s/paralegal/Paralegal/g; s/parent/Parent/g; s/Park Forest//g; s/Park Ridge//g; s/PATROL/Patrol/g; s/Patuxent River//g; s/payments/Payments/g; s/Pc/PC/g; 
s/Pearl City//g; s/Peachtree City//g; s/Pell City//g; s/Pembroke Pines//g; s/Perry Hall//g; s/physical/Physical/g; s/Pico Rivera//g; s/Pinellas Park//g; s/PLANNER/Planner/g; 
s/PLANNING/Planning/g; s/platform/Platform/g; s/PMo/PMO/g; s/PMp//g; s/PMP, //g; s/Pmp/PMP/g; s/Pm/PM/g; s/Point Pleasant//g; s/PMo/PMO/g; s/Ponca City//g; s/Ponte Vedra//g; 
s/Poplar Branch//g; s/PortDirector/Port Director/g; s/Port Allen//g; s/Port Deposit//g; s/Port Orange//g; s/Port Orchard//g; s/PortDirector/Port Directorg/g; s/portfolio/Portfolio/g; 
s/Powder Springs//g; s/premium/Premium/g; s/Prescott Va//g; s/President -/President, /g; s/President-/President, /g; s/President\//President, /g; s/president/President/g; 
s/Princess Anne//g; s/principal/Principal/g; s/Prineville//g; s/private/Private/g; s/PROCESS/Process/g; s/procurement/Procurement/g; s/PROCUREMENT/Procurement/g; 
s/producer/Producer/g; s/PRODUCER/Producer/g; s/PROGRAMMING/Programming/g; s/program/Program/g; s/project/Project/g; s/Prospect Park//g; s/R and D/R&D/g; s/RADIOLOGY/Radiology/g; 
s/Rancho Palo//g; s/Ransom Canyon//g; s/Rapid City//g; s/real/Real/g; s/receives/Receives/g; s/recreation/Recreation/g; s/Recruiter\//Recruiter, /g; s/Red Bank//g; 
s/Redondo Beach//g; s/Redwood City//g; s/regional/Regional/g; s/relationship/Relationship/g; s/reliability/Reliability/g; s/retail/Retail/g; s/retirement/Retirement/g; s/RFid/RFID/g; 
s/Rf/RF/g; s/New Richmond//g; s/River Edge//g; s/Rllng Hls Est//g; s/Rochester Hls//g; s/Rocky Hill//g; s/Rocky Mount//g; s/Rocky River//g; s/Rock Springs//g; s/Rohnert Park//g; 
s/Rolling Mea//g; s/Round Lk Bch//g; s/Round Rock//g; s/Royal Oak//g; s/SAFETY/Safety/g; s/Saint-laurent//g; s/Saint Albans//g; s/Saint Ann//g; s/Saint Augus//g; s/Saint Charles//g; 
s/Saint Clair//g; s/Saint Cloud//g; s/Saint Joseph//g; s/Saint Louis//g; s/Saint Paul//g; s/Saint Peter//g; s/Saint Rose//g; s/Saint Simon//g; s/sales/Sales/g; s/Salt Lake City//g; 
s/San Antonio//g; s/San Bernardino//g; s/San Bruno//g; s/San Carlos//g; s/San Clemente//g; s/San Diego//g; s/San Dimas//g; s/san Francisco Bay//g; s/San Francisco//g; s/San Jose//g; 
s/San Juan//g; s/San Marcos//g; s/San Mateo//g; s/San Pedro//g; s/San Ramon//g; s/Santa Ana//g; s/Santa Barbara//g; s/Santa Clara//g; s/Santa Clarita//g; s/Santa Fe//g; 
s/Santa Isabel//g; s/Santa Maria//g; s/Santa Monica//g; s/Santa Rosa//g; s/Sao Paulo//g; s/Saratoga Sp//g; s/Schiller Park//g; s/scholar/Scholar/g; s/scientist/Scientist/g; 
s/SCIENTIST/Scientist/g; s/SCONSUTANT/Consultant/g; s/Scotch Plains//g; s/Scott Afb//g; s/Scott Air F//g; s/Scotts Valley//g; s/Seal Beach//g; s/SECURITY/Security/g; 
s/security/Security/g; s/\/Senior/, Senior/g; s/senior/Senior/g; s/SerVices/Services/g; s/service/Service/g; s/Severna Park//g; s/Sftwr/Software/g; s/Sheffield Vlg//g; 
s/Shelby Town//g; s/Sherman Oaks//g; s/Show Low//g; s/Sierra Vista//g; s/Silver Spring//g; s/Sioux City//g; s/Snr/Senior/g; s/Sioux Falls//g; s/smart/Smart/g; s/Smb/SMB/g; 
s/Sms/SMS/g; s/social/Social/g; s/Solana Beach//g; s/Southeast Region//g; s/Southern and  , ,//g; s/Southern Pines//g; s/South Africa//g; s/South Bend//g; s/South Burli//g; 
s/South Central//g; s/South Dakota//g; s/South East//g; s/South-east//g; s/South Orange//g; s/South San F//g; s/South Lake//g; s/South Ozone//g; s/South Plain//g; s/South River//g; 
s/South East Asia//g; s/South-east Asia//g; s/space/Space/g; s/spain/Spain/g; s/Spring City//g; s/Sql/SQL/g; s/SrBranch/Senior Branch/g; s/SrSales/Senior Sales/g; s/Ssl/SSL/g; 
s/St. Asaph//g; s/St Augustine//g; s/St Charles//g; s/St Johnsbury//g; s/St Leonards//g; s/St Petersburg//g; s/St Thomas//g; s/State College//g; s/Stennis Spa//g; s/Stephens City//g; 
s/Sterling He//g; s/Stevens Point//g; s/Stf/Staff/g; s/STOCK/Stock/g; s/Stone Harbor//g; s/Stone Mountain//g; s/strategic/Strategic/g; s/subsidiary/Subsidiary/g; s/Sugar Land//g; 
s/Sugar Grove//g; s/supply/Supply/g; s/support/Support/g; s/Takoma Park//g; s/Tall Timbers//g; s/teacher/Teacher/g; s/TEAM/Team/g; s/Teaneck//g; s/technical/Technical/g; 
s/technology/Technology/g; s/TELECOMMUNICATIONS/Telecommunications/g; s/television/Television/g; s/TEST/Test/g; s/Thailand and Philippines//g; s/The Dalles//g; s/Thousand Oaks//g; 
s/Timber Lake//g; s/Tipp City//g; s/Township Of//g; s/Trabuco Canyon//g; s/TRADEMARKS/Trademarks/g; s/trainer/Trainer/g; s/TRANSPORTATION/Transportation/g; s/treasury/Treasury/g; 
s/Tunbridge W//g; s/Twin Falls//g; s/UK//g; s/U.S.//g; s/UNDERWRITER/Underwriter/g; s/Union Ban//g; s/Union City//g; s/Union Office//g; s/United Kingdom//g; s/United States//g; 
s/Universal City//g; s/university/University/g; s/Upper Chich//g; s/Upper Marlboro//g; s/Uscg/USCG/g; s/valve/Valve/g; s/Valley Stream//g; s/Van Nuys//g; s/vendor/Vendor/g; 
s/Vernon Hills//g; s/Vero Beach//g; s/Vii/VII/g; s/Vi /VI/g; s/Vice-President/Vice President/g; s/Vicepresident/Vice President/g; s/Virginia Beach//g; s/La Vista//g; s/Voip/VoIP/g; 
s/Walled Lake//g; s/Wallops Island//g; s/Walnut Creek//g; s/Warner Robins//g; s/wealth/Wealth/g; s/West Bloomf//g; s/West Chester//g; s/West Columbia//g; s/West Dundee//g; 
s/West Harrison//g; s/West Linn//g; s/West Mifflin//g; s/West Nyack//g; s/West Orange//g; s/West Palm B//g; s/West Paterson//g; s/west Region//g; s/West Sacram//g; s/West Spring//g; 
s/Western Spr//g; s/West Orange//g; s/White Lake//g; s/White Plains//g; s/White River//g; s/Whiteman Ai//g; s/Whitmore Lake//g; s/Williston Park//g; s/Willow Grove//g; 
s/South Windsor//g; s/Windsor Locks//g; s/Windsor Mill//g; s/Winston Salem//g; s/Winter Park//g; s/Winter Springs//g; s/Woodland Hills//g; s/Woodland Park//g; s/worldwide/Worldwide/g;

s/AK //g; s/AL //g; s/AR //g; s/AZ //g; s/CA //g; s/CO //g; s/CT //g; s/DC //g; s/DE //g; s/FL //g; s/GA //g; s/HI //g; s/IA //g; s/ID //g; s/IL //g; s/IN //g; s/KA //g; s/KS //g;
s/KY //g; s/LA //g; s/MA //g; s/ME //g; s/MD //g; s/MI //g; s/MO //g; s/MN //g; s/MS //g; s/MT //g; s/NC //g; s/NE //g; s/ND //g; s/NH //g; s/NJ //g; s/NM //g; s/NV //g; s/NY //g;
s/OH //g; s/OK //g; s/ON //g; s/OR //g; s/PA //g; s/PR //g; s/QC //g; s/RI //g; s/SC //g; s/SD //g; s/TN //g; s/TX //g; s/Uk //g; s/UP //g; s/UT //g; s/VA //g; s/VT //g; s/WA //g;
s/WI //g; s/WV //g; s/WY //g; s/AP //g; s/DL //g; s/NB //g; s/MH //g; s/[0-9]\{2\}\/[0-9]\{2\}\/[0-9]\{2\}//g; s/^[ \tmp]*//g' > tmp

# Author: Ben Wood
perl -ne 'if ($_ =~ /(.*?)\t\s*(.*)/) {printf("%-40s%s\n",$1,$2);}' tmp | sed 's/[ \t]*$//g' | sort > tmp2

cat tmp2 | sed 's/   -/ -/g; s/,  /, /g; s/, , , , //g; s/, , , //g; s/, , /, /g; s/,$//g; s/\/$//g; s/-$//g; s/Aberdeen$//g; s/Abilene$//g; s/Abingdon$//g; s/Abington$//g;
s/Acworth$//g; s/Adamstown$//g; s/Addison$//g; s/Adena$//g; s/Adkins$//g; s/AdSense$//g; s/Adwords$//g; s/Africa$//g; s/Aguadilla$//g; s/Ainsworth$//g; s/Akron$//g; s/Alabaster$//g; 
s/Albany$//g; s/Albuquerque$//g; s/Aldershot$//g; s/Alexandria$//g; s/Allegan$//g; s/Allentown$//g; s/Alma$//g; s/Alpena$//g; s/Alpharetta$//g; s/Americas$//g; s/Americus$//g; 
s/Ambler$//g; s/Amherst$//g; s/Amissville$//g; s/Amsterdam$//g; s/Anaheim$//g; s/Anchorage$//g; s/Anderson$//g; s/Andover$//g; s/Annandale$//g; s/Annapolis$//g; s/Anniston$//g; 
s/Antioch$//g; s/Apalachin$//g; s/Apex$//g; s/Apopka$//g; s/Arcadia$//g; s/Archbald$//g; s/Argentina$//g; s/Arlington$//g; s/Armonk$//g; s/Arnold$//g; s/Artesia$//g; s/Arvada$//g; 
s/Ashburn$//g; s/Ashland$//g; s/Ashtabula$//g; s/Asia$//g; s/Athens$//g; s/Atlanta$//g; s/Atoka$//g; s/Attleboro$//g; s/Auburn$//g; s/Augusta$//g; s/Aurora$//g; s/Austell$//g; 
s/Austin$//g; s/Australia$//g; s/Avondale$//g; s/Avon$//g; s/Azle$//g; s/Azusa$//g; s/Babylon$//g; s/Bakersfield$//g; s/Bainbridge$//g; s/Baltimore$//g; s/Banbury$//g; 
s/Bangalore$//g; s/Bangor$//g; s/Barboursville$//g; s/Barbourville$//g; s/Bardstown$//g; s/Barrington$//g; s/Bartlesville$//g; s/Bartlett$//g; s/Barton$//g; s/Basingstoke$//g; 
s/Batavia$//g; s/Batesville$//g; s/Bath$//g; s/Bayside$//g; s/Beachwood$//g; s/Beckley//g; s/Beaver$//g; s/Berlin$//g; s/Blaine$//g; s/Boron$//g; s/Boston$//g; s/Bowie$//g; 
s/Beaumont$//g; s/Beaverton$//g; s/Bedford$//g; s/Belcamp$//g; s/Belgium$//g; s/Bellaire$//g; s/Belleville$//g; s/Bellevue$//g;s/Bellflower$//g; s/Beltsville$//g; s/Belux$//g; 
s/Benelux$//g; s/Benicia$//g; s/Bensalem$//g; s/Bensenville$//g; s/Berkeley$//g; s/Berryville$//g; s/Berwyn$//g; s/Bethesda$//g; s/Bethlehem$//g; s/Bethpage$//g; s/Billerica$//g; 
s/Biloxi$//g; s/Binghamton$//g; s/Birmingham$//g; s/Bismarck$//g; s/Bison$//g; s/Blacksburg$//g; s/Bloomfield$//g; s/Bloomingdale$//g; s/Bloomington$//g; s/Bloomsburg$//g; 
s/Bluemont$//g; s/Blythewood$//g; s/Bohemia$//g; s/Boise$//g; s/Bolingbrook$//g; s/Bordentown$//g; s/Bothell$//g; s/Boulder$//g; s/Boxborough$//g; s/Boyds$//g; s/Bradenton$//g; 
s/Brampton$//g; s/Brandywine$//g; s/Brazil$//g; s/Brecksville$//g; s/Brentwood$//g; s/Bridgeport$//g; s/Bridgewater$//g; s/Brisbane$//g; s/Bristol$//g; s/Brooklyn$//g; 
s/Brookpark$//g; s/Brookwood$//g; s/Brownstown$//g; s/Buckeye$//g; s/Burbank$//g; s/Burlington$//g; s/Burnsville$//g; s/Burtonsville$//g; s/Brockton$//g; s/Broomfield$//g; 
s/Bristow$//g; s/Brunswick$//g; s/Buffalo$//g; s/Burke$//g; s/Burleson$//g; s/Burlingame$//g; s/Calabasas$//g; s/Calexico$//g; s/California$//g; s/Califon$//g; s/Calpella$//g; 
s/Camarillo$//g; s/Cambridge$//g; s/Camden$//g; s/Campbell$//g; s/Canada$//g; s/Canfield$//g; s/Canonsburg$//g; s/Canton$//g; s/Capitola$//g; s/Captiva$//g; s/Carlisle$//g; 
s/Carlsbad$//g; s/Carnegie$//g; s/Carpinteria$//g; s/Carrollton$//g; s/Carson$//g; s/Cary$//g; s/Cantonment$//g; s/Casper$//g; s/Castaic$//g; s/Catawba$//g; s/Catonsville$//g; 
s/Cedar Park$//g; s/Centreville$//g; s/Cerritos$//g; s/Chalmette$//g; s/Chambersburg$//g; s/Champaign$//g; s/Champlain$//g; s/Chandler$//g; s/Chantilly$//g; s/Chappaqua$//g; 
s/Charleston$//g; s/Charlestown$//g; s/Charlottesvle$//g; s/Charlotte$//g; s/Chatswood$//g; s/Chatsworth$//g; s/Chattanooga$//g; s/Chelmsford$//g; s/Cheltenham$//g; s/Chennai$//g; 
s/Chertsey$//g; s/Chesapeake$//g; s/Chesterfield$//g; s/Chester$//g; s/Cheyenne$//g; s/chicago$//g; s/Chicago$//g; s/CHICAGO$//g; s/Chorley$//g; s/Christiana$//g; 
s/Christiansburg$//g; s/Cibolo$//g; s/Cicero$//g; s/Cincinnati$//g; s/Claremont$//g; s/Clarendon$//g; s/Clarksburg$//g; s/Clarkston$//g; s/Clarksville$//g; s/Clawson$//g; 
s/Claymont$//g; s/Clayton$//g; s/Clearfield$//g; s/Clearwater$//g; s/Clementon$//g; s/Clermont$//g; s/Cleveland$//g; s/Clifton$//g; s/Clinton$//g; s/Cockeysville$//g; s/Cocoa$//g; 
s/Colchester$//g; s/Colleyville$//g; s/Collinsville$//g; s/Colorado$//g; s/Columbia$//g; s/Columbus$//g; s/Converse$//g; s/Commack$//g; s/Concord$//g; s/Conifer$//g; s/Conroe$//g; 
s/Conshohocken$//g; s/Conyers$//g; s/Cookeville$//g; s/Coopersburg$//g; s/Cooperstown$//g; s/Coppell$//g; s/Copperopolis$//g; s/Coraopolis$//g; s/Corbin$//g; s/Cordova$//g; 
s/Corona$//g; s/Corsicana$//g; s/Cortland$//g; s/Countryside$//g; s/Crane$//g; s/Cranston$//g; s/Cresskill$//g; s/Crofton$//g; s/Crossville$//g; s/Crownsville$//g; s/Csc$//g; 
s/CSC$//g; s/Culpeper$//g; s/Cumberland$//g; s/Cupertino$//g; s/Cypress$//g; s/D$//g; s/Dahlgren$//g; s/Daleville$//g; s/DALLAS$//g; s/Dallas$//g; s/Danbury$//g; s/Danville$//g; 
s/Darby$//g; s/Davenport$//g; s/Daventry$//g; s/Davis$//g; s/Dayton$//g; s/Decatur$//g; s/Defiance$//g; s/Delaplane$//g; s/Denton$//g; s/Denver$//g; s/Deerfield$//g; s/Delmont$//g; 
s/DENVER$//g; s/Deptford$//g; s/Derby$//g; s/Desoto$//g; s/Destiny$//g; s/Destin$//g; s/Detroit$//g; s/Devens$//g; s/Dhs$//g; s/Douglasville$//g; s/Douglas$//g; s/Dover$//g; 
s/Doylestown$//g; s/Drummondville$//g; s/Dublin$//g; s/Dulles$//g; s/Duluth$//g; s/Dumas$//g; s/Dumfries$//g; s/Duncan$//g; s/Dundee$//g; s/Dunkirk$//g; s/Dupree$//g; s/Durango$//g; 
s/Durham$//g; s/Eastern$//g; s/Easton$//g; s/Eatontown$//g; s/Edgecomb$//g; s/Edgewater$//g; s/Edgewood$//g; s/Edinburgh$//g; s/Edinburg$//g; s/Edison$//g; s/Edwards$//g; 
s/Elbert$//g; s/Elgin$//g; s/Elizabethtown$//g; s/Elizabeth$//g; s/Elkhart$//g; s/Elkhorn$//g; s/Elkridge$//g; s/Elkton$//g; s/Elmsford$//g; s/Eloy$//g; s/Elyria$//g; s/EMEA$//g; 
s/Emea$//g; s/Emeryville$//g; s/Emmitsburg$//g; s/Encino$//g; s/Endicott$//g; s/Englewood$//g; s/Englishtown$//g; s/Ennis$//g; s/Erie$//g; s/Escondido$//g; s/Eugene$//g; 
s/Euless$//g; s/Europe$//g; s/Evanston$//g; s/Evansville$//g; s/Evans$//g; s/Exton$//g; s/Eynon$//g; s/Fairbanks$//g; s/Fairborn$//g; s/Fairfax$//g; s/Fairfield$//g; s/Fairmont$//g; 
s/Fairview$//g; s/Fallbrook$//g; s/Fallston$//g; s/Fareham$//g; s/Fargo$//g; s/Farmingdale$//g; s/Farmington$//g; s/Farnboroug$h//g; s/Farnham$//g; s/Fayetteville$//g; 
s/Feastervill$//g; s/Feltham$//g; s/Findlay$//g; s/Finksburg$//g; s/Fishers$//g; s/Fisherville$//g; s/Flemington$//g; s/Florence$//g; s/Floresville$//g; s/Flossmoor$//g; 
s/Flourtown$//g; s/Flowood$//g; s/Fogelsville$//g; s/for$//g; s/Forsyth$//g; s/france$//g; s/Framingham$//g; s/Frankfort$//g; s/Franklin$//g; s/Fredericksburg$//g; s/Frederick$//g; 
s/Freehold$//g; s/Fremont$//g; s/Fresno$//g; s/Frisco$//g; s/Fullerton$//g; s/Gainesville$//g; s/Gaithersburg$//g; s/Gardena$//g; s/Gardners$//g; s/Garland$//g; s/Gastonia$//g; 
s/Gatineau$//g; s/Gateille$//g; s/Germantown$//g; s/Germany$//g; s/GERMANY$//g; s/Geyserville$//g; s/Gibsonia$//g; s/Gibsonville$//g; s/Glasgow$//g; s/Glastonbury$//g; s/Glencoe$//g; 
s/Glendale$//g; s/Glendora$//g; s/Glenside$//g; s/GMBH$//g; s/Gnadenhutten$//g; s/Goleta$//g; s/Goodyear$//g; s/Google$//g; s/-google$//g; s/Grafton$//g; s/Granbury$//g; 
s/Granville$//g; s/Grayslake$//g; s/Greeley$//g; s/Greenbelt$//g; s/Greenbrae$//g; s/Greensboro$//g; s/Greensburg$//g; s/Greencastle$//g; s/Greeneville$//g; s/Greenfield$//g; 
s/Greenwood$//g; s/Greenport$//g; s/Greenville$//g; s/Greenwich$//g; s/Gretna$//g; s/Groton$//g; s/Grovel$//g; s/Gulfport$//g; s/Gunpowder$//g; s/Gurgaon$//g; s/Gurnee$//g; 
s/Hackensack$//g; s/Hackettstown$//g; s/Haddon$//g; s/Halethorpe$//g; s/Halifax$//g; s/Hamilton$//g; s/Hamlin$//g; s/Hammond$//g; s/Hampden$//g; s/Hampstead$//g; s/Hampton$//g; 
s/Hamtramck$//g; s/Hanahan$//g; s/Hanover$//g; s/Harlingen$//g; s/Harrisburg$//g; s/Harrisonburg$//g; s/Hartbeespoort$//g; s/Hartford$//g; s/Hartland$//g; s/Harvard$//g; 
s/Hatboro$//g; s/Haslet$//g; s/Hattiesburg$//g; s/Hauppauge$//g; s/Havant$//g; s/Hawthorne$//g; s/Haymarket$//g; s/Hazelwood$//g; s/Hazlehurst$//g; s/Hebron$//g; s/Heights$//g; 
s/Helena$//g; s/Helotes$//g; s/Hendersonville$//g; s/Henderson$//g; s/Henrico$//g; s/Hermitage$//g; s/Herndon$//g; s/Hershey$//g; s/Hialeah$//g; s/Highland$//g; s/Hilliard$//g; 
s/Hillsborough$//g; s/Hilo$//g; s/Hinckley$//g; s/Hingham$//g; s/Hobart$//g; s/Hodgdon$//g; s/Hodgkins$//g; s/Holbrook$//g; s/Hollywood$//g; s/Holtsville$//g; s/Homestead$//g; 
s/Honolulu$//g; s/Hookstown$//g; s/Hopewell$//g; s/Hopkins$//g; s/Hopkinton$//g; s/Horsham$//g; s/Houston$//g; s/HR$//g; s/Huntersville$//g; s/Huntingdon$//g; s/Huntington$//g; 
s/Huntingtown$//g; s/Huntsville$//g; s/Huron$//g; s/Hurricane$//g; s/Hyattsville$//g; s/Hyderabad$//g; s/Illinois$//g; s/Imperial$//g; s/Indialantic$//g; s/indianapolis$//g; 
s/Indianapolis$//g; s/Indiana$//g; s/India$//g; s/Indio$//g; s/Inglewood$//g; s/Ireland$//g; s/Irvine$//g; s/Irving$//g; s/Israel$//g; s/Iselin$//g; s/Italy$//g; s/JA$//g; 
s/Jacksonville$//g; s/Jackson$//g; s/Jamaica$//g; s/Japan$//g; s/Jber$//g; s/Jeffersonville$//g; s/Jerseyville$//g; s/Jenkintown$//g; s/Jessup$//g; s/Johnston$//g; s/Johnstown$//g; 
s/Joliet$//g; s/Joplin$//g; s/Jupiter$//g; s/Kalamazoo$//g; s/Kanata$//g; s/Kankakee$//g; s/Kaysville$//g; s/Kearney$//g; s/Kearny$//g; s/Kennebec$//g; s/Kenner$//g;
s/Kennesaw$//g; s/Kennett$//g; s/Kensington$//g; s/Kent$//g; s/Kerrville$//g; s/Kihei$//g; s/Killeen$//g; s/Kingille$//g; s/Kingston$//g; s/Kingwood$//g; s/Kinston$//g; s/Kirkland$//g;
s/Kissimmee$//g; s/Knightdale$//g; s/Knoxville$//g; s/Korea$//g; s/Lachine$//g; s/Lafayette$//g; s/Lakehurst$//g; s/Lakeland$//g; s/Lakeville$//g; s/Lakewood$//g; s/Lamesa$//g;
s/Lancaster$//g; s/Landenberg$//g; s/Lanham$//g; s/Lansdale$//g; s/Lansdowne$//g; s/Lansing$//g; s/Laredo$//g; s/Lantana$//g; s/Laurel$//g; s/Lawndale$//g; s/Lawnside$//g;
s/Lawrenceville$//g; s/Lawrence$//g; s/Lawton$//g; s/Layton$//g; s/Leavenworth$//g; s/Leawood$//g; s/Lebanon$//g; s/Leeds$//g; s/Leesburg$//g; s/Leesville$//g; s/Lenexa$//g;
s/Lenoir$//g; s/Leonardtown$//g; s/Leonia$//g; s/Letchworth$//g; s/Lewisburg$//g; s/Lewiston$//g; s/Lewisville$//g; s/Lexington$//g; s/Libertyville$//g; s/Lichfield$//g;s/Lima$//g;
s/Lincoln$//g; s/Linden$//g; s/Lindon$//g; s/Linesville$//g; s/Linthicum$//g; s/Linwood$//g; s/Lisle$//g; s/Litchfield$//g; s/Lithonia$//g; s/Lititz$//g; s/Littleton$//g;
s/Livermore$//g; s/Liverpool$//g; s/Livonia$//g; s/Lockport$//g; s/Logansport$//g; s/logistics$//g; s/Lomita$//g; s/Lompoc$//g; s/London$//g; s/Longmont$//g; s/Longueuil$//g;
s/Lorton$//g; s/Louisville$//g; s/Loveland$//g; s/Lovettsville$//g; s/Lowell$//g; s/Lubbock$//g; s/Lucedale$//g; s/Lufkin$//g; s/Lumberton$//g; s/Lutherville$//g; s/Luton$//g;
s/Lyndhurst$//g; s/Lynnwood$//g; s/Machias$//g; s/Macon$//g; s/Madison$//g; s/Mahwah$//g; s/Maidstone$//g; s/Maineville$//g; s/Maine$//g; s/Maitland$//g; s/Malaysia$//g; s/Malvern$//g;
s/Manalapan$//g; s/Manassas$//g; s/Manchester$//g; s/Manhattan$//g; s/Manistee$//g; s/Mansfield$//g; s/Marblehead$//g; s/Marietta$//g; s/Marion$//g; s/Marlborough$//g; s/Marlton$//g;
s/Martin$//g; s/Masontown$//g; s/Maumee$//g; s/Mayfield$//g; s/Maynard$//g; s/Maysville$//g; s/Mcallen$//g; s/Mcclellan$//g; s/Mckinney$//g; s/Meadville$//g; s/Mechanicsburg$//g;
s/Medford$//g; s/Media$//g; s/Melbourne$//g; s/Melrose$//g; s/Melville$//g; s/Memphis$//g; s/Menifee$//g; s/Mentor$//g; s/Meriden$//g; s/Meridian$//g; s/Merrill$//g; s/Mesa$//g;
s/Metairie$//g; s/Methuen$//g; s/Mexico$//g; s/Miamisburg$//g; s/Miami$//g; s/Michigan$//g; s/Mid-Atlantic$//g; s/Middleburg$//g; s/Middlebury$//g; s/Middlesex$//g; s/Middleton$//g;
s/Middletown$//g; s/Midland$//g; s/Midwest$//g; s/Milford$//g; s/Millburn$//g; s/Millersville$//g; s/Milpitas$//g; s/Milwaukee$//g; s/Minneapolis$//g; s/Minnesota$//g;
s/Minnetonka$//g; s/Mishawaka$//g; s/Missouri$//g; s/Mitchell$//g; s/Mobile$//g; s/Modesto$//g; s/Moline$//g; s/Mongmong$//g; s/Monroeville$//g; s/Monroe$//g; s/Montclair$//g; 
s/Monterey$//g; s/Montezuma$//g; s/Montgomery$//g; s/Montoursville$//g; s/Montreal$//g; s/Montvale$//g; s/Moorestown$//g; s/Mooresville$//g; s/Morgantown$//g; 
s/Morristown$//g; s/Morrisville$//g; s/Moscow$//g; s/Mumbai$//g; s/Mundelein$//g; s/Murdock$//g; s/Murfreesboro$//g; s/Murrysville$//g; s/Muskegon$//g; s/Mystic$//g; 
s/Napa$//g; s/Naperville$//g; s/Naples$//g; s/Narberth$//g; s/Narragansett$//g; s/Narrows$//g; s/Nashua$//g; s/Nashville$//g; s/Natick$//g; s/Navarre$//g; s/Nazareth$//g; s/NB$//g; 
s/Nebraska$//g; s/Neotsu$//g; s/Newark$//g; s/Newington$//g; s/Newport$//g; s/Newtown$//g; s/Newville$//g; s/Niceville$//g; s/Niles$//g; s/Noblesville$//g; s/Nogales$//g; 
s/Noida$//g; s/Moncton$//g; s/Norcross$//g; s/Norfolk$//g; s/Norman$//g; s/Norristown$//g; s/Northbrook$//g; s/Northeastern$//g; s/Northeast$//g; s/Northville$//g; s/Norton$//g; 
s/Norwalk$//g; s/Norwich$//g; s/Norwood$//g; s/Novato$//g; s/NSW$//g; s/Nutley$//g; s/nyc$//g; s/Oakdale$//g; s/Oakland$//g; s/Oakton$//g; s/Oakville$//g; s/Ocala$//g; 
s/Oceanport$//g; s/Ocoee$//g; s/Odenton$//g; s/Odessa$//g; s/Odon$//g; s/of$//g; s/Ogdensburg$//g; s/Ogden$//g; s/Ohio$//g; s/Okemos$//g; s/Olathe$//g; s/Oldsmar$//g; s/Olney$//g; 
s/Olympia$//g; s/Omaha$//g; s/Onalaska$//g; s/Ontario$//g; s/Oologah$//g; s/Oregon$//g; s/Orem$//g; s/orlando$//g; s/Orlando$//g; s/Orrville$//g; s/Ottawa$//g; s/Oviedo$//g; 
s/Owego$//g; s/Owensboro$//g; s/Palatine$//g; s/Palermo$//g; s/Palmdale$//g; s/Palmer$//g; s/Palo$//g; s/Papillion$//g; s/Paramus$//g; s/Parkesburg$//g; s/Parkville$//g; 
s/Parsippany$//g; s/Pasadena$//g; s/Pascagoula$//g; s/Pasco$//g; s/Passaic$//g; s/Pelham$//g; s/Pemberton$//g; s/Pembina$//g; s/Pennington$//g; s/Pensacola$//g; s/Peoria$//g; 
s/Peterborough$//g; s/Pewaukee$//g; s/Pharr$//g; s/philadelphia$//g; s/Philadelphia$//g; s/PHILADELPHRegion$//g; s/Philip$//g; s/Phillipsburg$//g; s/Phoenix$//g; s/Picayune$//g; 
s/Pickerington$//g; s/Pierre$//g; s/Pikesville$//g; s/Pinckney$//g; s/Pinconning$//g; s/Pinehurst$//g; s/Pineville$//g; s/Pipersville$//g; s/Piscataway$//g; s/Pittsburgh$//g; 
s/Pittsfield$//g; s/Placitas$//g; s/Plainfield$//g; s/Plainsboro$//g; s/planner$//g; s/Plano$//g; s/Plaquemine$//g; s/Pleasanton$//g; s/Pleasantville$//g; s/Plymouth$//g; 
s/Pocahontas$//g; s/Pomona$//g; s/Pontiac$//g; s/Portage$//g; s/Portland$//g; s/Portsmouth$//g; s/Portugal$//g; s/Potomac$//g; s/Poway$//g; s/Prattville$//g; s/Preston$//g; 
s/Prestwick$//g; s/Princeton$//g; s/Prineville$//g; s/Proctorville$//g; s/Providence$//g; s/Provos$//g; s/Pueblo$//g; s/Purcellville$//g; s/Pyrmont$//g; s/Quantico$//g; s/Quincy$//g; 
s/Radcliff$//g; s/Raleigh$//g; s/Radnor$//g; s/Ramsey$//g; s/Rancho$//g; s/Randallstown$//g; s/Randolph$//g; s/Raritan$//g; s/Raymondville$//g; s/Rayville$//g; s/Reading$//g; 
s/Redlands$//g; s/Redmond$//g; s/Reisterstown$//g; s/Reno$//g; s/Rensselaer$//g; s/Reston$//g; s/Reynoldsburg$//g; s/Richardson$//g; s/Richland$//g; s/Richmond$//g; s/Ridgecrest$//g; 
s/Ridgeland$//g; s/Ridgewood$//g; s/Ringoes$//g; s/Riverdale$//g; s/Riverside$//g; s/Rivervale$//g; s/Roanoke$//g; s/Rochester$//g; s/Rockaway$//g; s/Rockford$//g; s/Rockledge$//g; 
s/Rocklin$//g; s/Rockport$//g; s/Rockville$//g; s/Romeoville$//g; s/Rome$//g; s/Romulus$//g; s/Rosamond$//g; s/Roseburg$//g; s/Rosemead$//g; s/Roseville$//g; s/Roswell$//g; 
s/Rougemont$//g; s/Royersford$//g; s/Riverton$//g; s/Ruckersville$//g; s/Russia$//g; s/Sacramento$//g; s/Salina$//g; s/Salisbury$//g; s/Sandton$//g; s/Sanford$//g; s/Sanibel$//g; 
s/Santee$//g; s/Sarasota$//g; s/Saucier$//g; s/Savannah$//g; s/Sayreville$//g; s/Scarsdale$//g; s/Schaumburg$//g; s/Schenectady$//g; s/Schererville$//g; s/Scottsdale$//g; 
s/Scranton$//g; s/Seaford$//g; s/Seattle$//g; s/SEATTLE$//g; s/Sebring$//g; s/Secaucus$//g; s/Sedalia$//g; s/Sylmar$//g; s/Seminole$//g; s/Serilingamp$//g; s/Severn$//g; 
s/Sewell$//g; s/Shalimar$//g; s/Sharpes$//g; s/Shelbyville$//g; s/Shorewood$//g; s/Shreveport$//g; s/Shrewsbury$//g; s/Silverdale$//g; s/Simpsonville$//g; s/Singapore$//g; 
s/Sitka$//g; s/Skillman$//g; s/Slc$//g; s/Slidell$//g; s/Smithville$//g; s/Smyrna$//g; s/Socorro$//g; s/Solihull$//g; s/Somerset$//g; s/Southborough$//g; s/Southbridge$//g; 
s/Southfield$//g; s/southeast$//g; s/Southeast$//g; s/Southaven$//g; s/Southampton$//g; s/Southlake$//g; s/Southwest$//g; s/SP$//g; s/Sparks$//g; s/Spartanburg$//g; s/Sparta$//g; 
s/Spokane$//g; s/Spotsylvania$//g; s/Springfield$//g; s/Spring$//g; s/Square$//g; s/Stafford$//g; s/Stamford$//g; s/Sterling$//g; s/Stillwater$//g; s/Strasburg$//g; 
s/Strongsville$//g; s/Subiaco$//g; s/Sudbury$//g; s/Suffolk$//g; s/Suitland$//g; s/Summerville$//g; s/Summit$//g; s/Sunnyvale$//g; s/Superior$//g; s/Surbiton$//g; s/Suwanee$//g; 
s/Swainsboro$//g; s/Swanton$//g; s/Swarthmore$//g; s/Swindon$//g; s/Switzerland$//g; s/Sydney$//g; s/Sykesville$//g; s/Syracuse$//g; s/Tacoma$//g; s/Taiwan$//g; s/Tallahassee$//g; 
s/Tampa$//g; s/Taneytown$//g; s/Tarzana$//g; s/Taunton$//g; s/Tavares$//g; s/Tecate$//g; s/Telluride$//g; s/Tempe$//g; s/Tenafly$//g; s/Terrell$//g; s/Tewksbury$//g; s/Texas$//g; 
s/-the$//g; s/Thomaston$//g; s/Thomasville$//g; s/Thorndale$//g; s/Thurso$//g; s/Timonium$//g; s/Tipton$//g; s/Titusville$//g; s/Toledo$//g; s/Toll$//g; s/Tomball$//g; s/Toney$//g; 
s/Topeka$//g; s/Tornado$//g; s/Toronto$//g; s/Torrance$//g; s/Towson$//g; s/Trenton$//g; s/Tifton$//g; s/Troy$//g; s/Tucson$//g; s/Tullahoma$//g; s/Tulsa$//g; s/Turkey$//g; 
s/Tuscaloosa$//g; s/Tustin$//g; s/Twinsburg$//g; s/Tyngsboro$//g; s/Underhill$//g; s/Uniondale$//g; s/Uniontown$//g; s/Union$//g; s/Urbana$//g; s/Urbandale$//g; s/Uxbridge$//g; 
s/Uvalde$//g; s/Vail$//g; s/Valdosta$//g; s/Valencia$//g; s/Vanceboro$//g; s/Vancouver$//g; s/Vandalia$//g; s/Vandergrift$//g; s/Venice$//g; s/Ventura$//g; s/Verona$//g; 
s/Vestal$//g; s/VIC$//g; s/Vicksburg$//g; s/Vienna$//g; s/Vincentown$//g; s/Vineland$//g; s/Visalia$//g; s/Vista$//g; s/Wagoner$//g; s/Wakefield$//g; s/Waldorf$//g; 
s/Wallingford$//g; s/Waltham$//g; s/Warminster$//g; s/Warrenton$//g; s/Warren$//g; s/Warrington$//g; s/Warsaw$//g; s/Warwick$//g; s/Washington$//g; s/Wasilla$//g; s/Waterford$//g; 
s/Watertown$//g; s/Wauconda$//g; s/Waukesha$//g; s/Wausau$//g; s/Wayne$//g; s/Weare$//g; s/Weatherford$//g; s/Webster$//g; s/Wellington$//g; s/Westbury$//g; s/Westborough$//g; 
s/Westchester$//g; s/Westerville$//g; s/Westlake$//g; s/Westminster$//g; s/Westmont$//g; s/Westport$//g; s/Westwego$//g; s/Wexford$//g; s/Wheaton$//g; s/Wheeling$//g; s/Whippany$//g; 
s/Whittier$//g; s/Wildfires//g; s/Wildwood//g; s/Williamsburg//g; s/Williamsport//g; s/Willimantic//g; s/Williston$//g; s/Wilmington$//g; s/Wilton$//g; s/Winchester$//g; 
s/Windsor$//g; s/Windermere$//g; s/Winder$//g; s/Winnetka$//g; s/Winona$//g; s/Wisconsin$//g; s/Wisconsin$//g; s/Wichita$//g; s/Woburn$//g; s/Woking$//g; s/Woodbridge$//g; 
s/Woodstock$//g; s/Woodstown$//g; s/Wynnewood$//g; s/Wyoming$//g; s/Xenia$//g; s/Yardley$//g; s/Yeovil$//g; s/Yokine$//g; s/Youngstown$//g; s/Youngsville$//g; s/Yorktown$//g; 
s/York$//g; s/Yuma$//g; s/Zanesville$//g; s/Zionsville$//g; s/Zion$//g' > tmp3

head tmp3
echo
echo
echo -n "Copy/paste the company name from the second column: "
read name

# Check for no answer
if [[ -z $name ]]; then
     f_error
fi

sed "s/$name//g" tmp3 > /$user/data/names.txt
rm tmp*

echo
echo $medium
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/names.txt
echo
echo
exit
}

##############################################################################################################

f_generateTargetList(){
clear
f_banner

echo -e "\e[1;34mSCANNING\e[0m"
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
     1) echo -n "Interface to scan: "
	read interface
	arp-scan -l -I $interface | egrep -v '(arp-scan|Interface|packets|Polycom|Unknown)' | awk '{print $1}' | $sip | sed '/^$/d' > /$user/data/hosts-arp.txt   echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/hosts-arp.txt
     echo
     echo
     exit;;
     2) f_netbios;;
     3) netdiscover;;
     4) f_pingsweep;;
     5) f_nmapAscan;;
     6) f_main;;
     *) f_error;;
esac
}

##############################################################################################################

f_netbios(){
clear
f_banner

echo -e "\e[1;34mType of input:\e[0m"
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
     if [ -z $cidr ]; then
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

echo -e "\e[1;34mType of input:\e[0m"
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
     nmap -sn --stats-every 10s -g $sourceport -iL $location > tmp
     ;;

     2)
     echo
     echo -n "Enter your targets: "
     read manual

     # Check for no answer
     if [ -z $manual ]; then
          f_error
     fi

     echo
     echo "Running an Nmap ping sweep for live hosts."
     nmap -sn --stats-every 10s -g $sourceport $manual > tmp
     ;;

     *) f_error;;
esac

##############################################################

perl << 'EOF'
# Author: Ben Wood
# Description: Reads an nmap ping sweep and correctly identifies lives hosts

use strict;

undef $/; # Enable slurping

open(my $handle, '<', "tmp");
open(my $output, '>', "tmp2");
while(<$handle>)
{
	# Read report lines
	while (/((?:[\x00-\xFF]*?(?=Nmap\s+scan\s+report)|[\x00-\xFF]*))/mixg) {
		my $report = $1;

		# Print IP if host is REALLY up
		if (($report =~ /MAC\s+Address/mix)
		or ($report =~ /Nmap\s+scan\s+report\s+for\s+\S+?\s+\(\S+\)/mix)) {
			my ($ip) = $report =~ /(\d+\.\d+\.\d+\.\d+)/mix;
			print $output "$ip\n";
		}
	}
}
EOF

##############################################################

rm tmp
mv tmp2 /$user/data/hosts-ping.txt

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/hosts-ping.txt
echo
echo
exit
}

##############################################################################################################

f_nmapAscan(){
clear
f_banner
f_typeofscan

echo -e "\e[1;34mType of input:\e[0m"
echo
echo "1.  List containing IPs, ranges and/or CIDRs."
echo "2.  Manual"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     echo -n "Name your scan: "
     read scanname
     f_location

     echo
     echo "Running an Nmap -A scan for live hosts."
     nmap -A -oA ~/data/$scanname --stats-every 10s -g $sourceport -iL $location > tmp
     ;;

     2)
     echo
     echo -n "Enter your targets: "
     read manual
     echo -n "Name your scan: "
     read scanname

     # Check for no answer
     if [ -z $manual ]; then
          f_error
     fi

     echo
     echo "Running an Nmap -A scan for live hosts."
     nmap -A -oA ~/data/$scanname --stats-every 10s -g $sourceport $manual > tmp
     ;;

     *) f_error;;
esac

##############################################################

perl << 'EOF'
# Author: Ben Wood
# Description: Reads an nmap ping sweep and correctly identifies lives hosts

use strict;

undef $/; # Enable slurping

open(my $handle, '<', "tmp");
open(my $output, '>', "tmp2");
while(<$handle>)
{
	# Read report lines
	while (/((?:[\x00-\xFF]*?(?=Nmap\s+scan\s+report)|[\x00-\xFF]*))/mixg) {
		my $report = $1;

		# Print IP if host is REALLY up
		if (($report =~ /MAC\s+Address/mix)
		or ($report =~ /Nmap\s+scan\s+report\s+for\s+\S+?\s+\(\S+\)/mix)) {
			my ($ip) = $report =~ /(\d+\.\d+\.\d+\.\d+)/mix;
			print $output "$ip\n";
		}
	}
}
EOF

##############################################################

rm tmp
mv tmp2 /$user/data/targets.txt

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The list of targets is located at \e[1;33m%s\e[0m\n' /$user/data/targets.txt
echo
printf 'The output files from the Nmap -A scan are located at \e[1;33m%s\e[0m\n' /$user/data/
echo
exit
}

##############################################################################################################

f_scanname(){
f_typeofscan

echo -n "Name of scan: "
read name

# Check for no answer
if [ -z $name ]; then
     f_error
fi

mkdir -p $name
}

##############################################################################################################

f_typeofscan(){
echo -e "\e[1;34mType of scan: \e[0m"
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
     echo -e "\e[1;33m[*] Setting source port to 53 and the max probe round trip time to 1.5s.\e[0m"
     sourceport=53
     maxrtt=1500ms
     echo
     echo $medium
     echo
     ;;

     2)
     echo
     echo -e "\e[1;33m[*] Setting source port to 88 and the max probe round trip time to 500ms.\e[0m"
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
if [ -z $cidr ]; then
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

     if [ -z $excludefile ]; then
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
echo -n "IP, Range or URL: "
read target

# Check for no answer
if [ -z $target ]; then
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
custom='1-1040,1050,1080,1099,1125,1158,1194,1214,1220,1344,1352,1433,1500,1503,1521,1524,1526,1720,1723,1731,1812,1813,1953,1959,2000,2002,2030,2049,2100,2121,2200,2202,2222,2301,2381,2401,2433,2456,2500,2556,2628,2745,2780-2783,2947,3000,3001,3031,3121,3127,3128,3200,3201,3230-3235,3260,3268,3269,3306,3339,3389,3460,3500,3527,3632,3689,4000,4045,4100,4242,4369,4430,4443,4445,4661,4662,4711,4848,5000,5001,5009,5010,5019,5038,5040,5059,5060,5061,5101,5180,5190,5191,5192,5193,5250,5432,5554,5555,5560,5566,5631,5666,5672,5678,5800,5801,5802,5803,5804,5850,5900-6009,6101,6106,6112,6161,6346,6379,6588,6666,6667,6697,6777,7000,7001,7002,7070,7100,7210,7510,7634,7777,7778,8000,8001,8004,8005,8008,8009,8080,8081,8082,8083,8091,8098,8099,8100,8180,8181,8222,8332,8333,8383,8384,8400,8443,8444,8470-8480,8500,8787,8834,8866,8888,9090,9100,9101,9102,9160,9343,9470-9476,9480,9495,9996,9999,10000,10025,10168,11211,12000,12345,12346,13659,15000,16080,18181-18185,18207,18208,18231,18232,19150,19190,19191,20034,22226,27017,27374,27665,28784,30718,31337,32764,32768,32771,33333,35871,37172,38903,39991,39992,40096,46144,46824,49400,50000,50030,50060,50070,50075,50090,51080,51443,53050,54320,58847,60000,60010,60030,60148,60365,62078,63148'
full='1-65535'
udp='53,67,123,137,161,500,523,1434,1604,2302,3478,5353,6481,17185,31337'

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
     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     echo -e "\e[1;33mNo live hosts were found.\e[0m"
     echo
     echo
     exit
fi

# Clean up
egrep -v '(0000|0010|0020|0030|0040|0050|0060|0070|0080|0090|00a0|00b0|00c0|00d0|1 hop|closed|guesses|GUESSING|filtered|fingerprint|FINGERPRINT|general purpose|initiated|latency|Network Distance|No exact OS|No OS matches|OS:|OS CPE|Please report|RTTVAR|scanned in|SF|unreachable|Warning|WARNING)' $name/nmap.nmap | sed 's/Nmap scan report for //' | sed '/^$/! b end; n; /^$/d; : end' > $name/nmap.txt

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
echo -e "\e[1;34mLocating high value ports.\e[0m"
echo "     TCP"
TCP_PORTS="13 19 21 22 23 25 37 70 79 80 110 111 135 139 143 389 443 445 465 502 512 513 514 523 524 548 554 587 623 631 771 873 902 993 995 1050 1080 1099 1158 1344 1352 1433 1521 1720 1723 2202 2628 2947 3000 3031 3260 3306 3389 3500 3632 4369 5019 5040 5060 5432 5560 5631 5666 5672 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6379 6666 7210 7634 7777 8000 8009 8080 8081 8091 8222 8332 8333 8400 8443 8834 9100 9160 9999 10000 11211 12000 12345 19150 27017 28784 30718 35871 46824 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $TCP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/tcp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [ -e $name/523.txt ]; then
     mv $name/523.txt $name/523-tcp.txt
fi

if [ -e $name/5060.txt ]; then
     mv $name/5060.txt $name/5060-tcp.txt
fi

echo "     UDP"
UDP_PORTS="53 67 123 137 161 500 523 1434 1604 2302 3478 5353 6481 17185 31337"

for i in $UDP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/udp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [ -e $name/523.txt ]; then
     mv $name/523.txt $name/523-udp.txt
fi

# Combine Apache HBase ports and sort
cat $name/60010.txt $name/60030.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/apache-hbase.txt

# Combine Bitcoin ports and sort
cat $name/8332.txt $name/8333.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/bitcoin.txt

# Combine DB2 ports and sort
cat $name/523-tcp.txt $name/523-udp.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/db2.txt

# Combine Hadoop ports and sort
cat $name/50030.txt $name/50060.txt $name/50070.txt $name/50075.txt $name/50090.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/hadoop.txt

# Combine SMTP ports and sort
cat $name/25.txt $name/465.txt $name/587.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/smtp.txt

# Combine X11 ports and sort
cat $name/6000.txt $name/6001.txt $name/6002.txt $name/6003.txt $name/6004.txt $name/6005.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/x11.txt

# Remove all empty files
find $name/ -type f -empty -exec rm {} +
}

##############################################################################################################

f_cleanup(){
sed 's/Nmap scan report for //' tmp > tmp2

# Remove lines that start with |, and have various numbers of trailing spaces.
sed -i '/^| *$/d' tmp2

egrep -v '(0 of 100|afp-serverinfo:|ACCESS_DENIED|appears to be clean|cannot|closed|close|Compressors|Could not|Couldn|ctr-|Denied|denied|Did not|DISABLED|dns-nsid:|dns-service-discovery:|Document Moved|doesn|eppc-enum-processes|error|Error|ERROR|Failed to get|failed|filtered|GET|hbase-region-info:|HEAD|Host is up|Host script results|impervious|incorrect|latency|ldap-rootdse:|LDAP Results|Likely CLEAN|MAC Address|Mac OS X security type|nbstat:|No accounts left|No Allow|no banner|none|Nope.|not allowed|Not Found|Not Shown|not supported|NOT VULNERABLE|nrpe-enum:|ntp-info:|rdp-enum-encryption:|remaining|rpcinfo:|seconds|Security types|See http|Server not returning|Service Info|Skipping|smb-check-vulns|smb-mbenum:|sorry|Starting|telnet-encryption:|Telnet server does not|TIMEOUT|Unauthorized|uncompressed|unhandled|Unknown|viewed over a secure|vnc-info:|wdb-version:)' tmp2 | grep -v "Can't" > tmp3

mv tmp3 tmp4
}

##############################################################################################################

f_scripts(){
echo
echo $medium
echo
echo -e "\e[1;34mRunning nmap scripts.\e[0m"

# If the file for the corresponding port doesn't exist, skip
if [ -e $name/13.txt ]; then
	echo "     Daytime"
	nmap -iL $name/13.txt -Pn -n --open -p13 --script=daytime --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-13.txt
fi

if [ -e $name/21.txt ]; then
	echo "     FTP"
	nmap -iL $name/21.txt -Pn -n --open -p21 --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-21.txt
fi

if [ -e $name/22.txt ]; then
	echo "     SSH"
	nmap -iL $name/22.txt -Pn -n --open -p22 --script=sshv1,ssh2-enum-algos --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-22.txt
fi

if [ -e $name/23.txt ]; then
	echo "     Telnet"
	nmap -iL $name/23.txt -Pn -n --open -p23 --script=banner,telnet-encryption --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-23.txt
fi

if [ -e $name/smtp.txt ]; then
	echo "     SMTP"
	nmap -iL $name/smtp.txt -Pn -n --open -p25,465,587 --script=banner,smtp-commands,smtp-open-relay,smtp-strangeport,smtp-enum-users --script-args smtp-enum-users.methods={EXPN,RCPT,VRFY} --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	printf '%s\n' 'g/NOT VULNERABLE/d\' '-d' w | ed -s tmp4
	mv tmp4 $name/script-25.txt
fi

if [ -e $name/37.txt ]; then
	echo "     Time"
	nmap -iL $name/37.txt -Pn -n --open -p37 --script=rfc868-time --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-37.txt
fi

if [ -e $name/53.txt ]; then
	echo "     DNS"
	nmap -iL $name/53.txt -Pn -n -sU --open -p53 --script=dns-blacklist,dns-cache-snoop,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zeustracker,dns-zone-transfer --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-53.txt
fi

if [ -e $name/67.txt ]; then
	echo "     DHCP"
	nmap -iL $name/67.txt -Pn -n -sU --open -p67 --script=dhcp-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-67.txt
fi

if [ -e $name/70.txt ]; then
	echo "     Gopher"
	nmap -iL $name/70.txt -Pn -n --open -p70 --script=gopher-ls --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-70.txt
fi

if [ -e $name/79.txt ]; then
	echo "     Finger"
	nmap -iL $name/79.txt -Pn -n --open -p79 --script=finger --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-79.txt
fi

if [ -e $name/110.txt ]; then
	echo "     POP3"
	nmap -iL $name/110.txt -Pn -n --open -p110 --script=banner,pop3-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-110.txt
fi

if [ -e $name/111.txt ]; then
	echo "     NFS"
	nmap -iL $name/111.txt -Pn -n --open -p111 --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-111.txt
fi

if [ -e $name/123.txt ]; then
	echo "     NTP"
	nmap -iL $name/123.txt -Pn -n -sU --open -p123 --script=ntp-monlist --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-123.txt
fi

if [ -e $name/137.txt ]; then
	echo "     NetBIOS"
	nmap -iL $name/137.txt -Pn -n -sU --open -p137 --script=nbstat --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	sed -i '/^MAC/{n; /.*/d}' tmp4		# Find lines that start with MAC, and delete the following line
	sed -i '/^137\/udp/{n; /.*/d}' tmp4	# Find lines that start with 137/udp, and delete the following line
	mv tmp4 $name/script-137.txt
fi

if [ -e $name/139.txt ]; then
     echo "     MS08-067"
     nmap -iL $name/139.txt -Pn -n --open -p139 --script=smb-check-vulns --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(SERVICE|netbios)' tmp4 > tmp5
     sed '1N;N;/\(.*\n\)\{2\}.*VULNERABLE/P;$d;D' tmp5
     sed '/^$/d' tmp5 > tmp6
     grep -v '|' tmp6 > $name/script-ms08-067.txt
fi

if [ -e $name/143.txt ]; then
	echo "     IMAP"
	nmap -iL $name/143.txt -Pn -n --open -p143 --script=imap-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-143.txt
fi

if [ -e $name/161.txt ]; then
	echo "     SNMP"
	nmap -iL $name/161.txt -Pn -n -sU --open -p161 --script=snmp-hh3c-logins,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-161.txt
fi

if [ -e $name/389.txt ]; then
	echo "     LDAP"
	nmap -iL $name/389.txt -Pn -n --open -p389 --script=ldap-rootdse --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-389.txt
fi

if [ -e $name/445.txt ]; then
	echo "     SMB"
	nmap -iL $name/445.txt -Pn -n --open -p445 --script=msrpc-enum,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-server-stats,smb-system-info,smbv2-enabled,stuxnet-detect --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	sed -i '/^445/{n; /.*/d}' tmp4		# Find lines that start with 445, and delete the following line
	mv tmp4 $name/script-445.txt
fi

if [ -e $name/500.txt ]; then
	echo "     Ike"
	nmap -iL $name/500.txt -Pn -n -sS -sU --open -p500 --script=ike-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-500.txt
fi

if [ -e $name/db2.txt ]; then
	echo "     DB2"
	nmap -iL $name/db2.txt -Pn -n -sS -sU --open -p523 --script=db2-das-info,db2-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-523.txt
fi

if [ -e $name/524.txt ]; then
	echo "     Novell NetWare Core Protocol"
	nmap -iL $name/524.txt -Pn -n --open -p524 --script=ncp-enum-users,ncp-serverinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-524.txt
fi

if [ -e $name/548.txt ]; then
	echo "     AFP"
	nmap -iL $name/548.txt -Pn -n --open -p548 --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-548.txt
fi

if [ -e $name/554.txt ]; then
	echo "     RTSP"
	nmap -iL $name/554.txt -Pn -n --open -p554 --script=rtsp-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-554.txt
fi

if [ -e $name/631.txt ]; then
	echo "     CUPS"
	nmap -iL $name/631.txt -Pn -n --open -p631 --script=cups-info,cups-queue-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-631.txt
fi

if [ -e $name/873.txt ]; then
	echo "     rsync"
	nmap -iL $name/873.txt -Pn -n --open -p873 --script=rsync-list-modules --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-873.txt
fi

if [ -e $name/993.txt ]; then
	echo "     IMAP/S"
	nmap -iL $name/993.txt -Pn -n --open -p993 --script=banner,sslv2,imap-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-993.txt
fi

if [ -e $name/995.txt ]; then
	echo "     POP3/S"
	nmap -iL $name/995.txt -Pn -n --open -p995 --script=banner,sslv2,pop3-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-995.txt
fi

if [ -e $name/1050.txt ]; then
	echo "     COBRA"
	nmap -iL $name/1050.txt -Pn -n --open -p1050 --script=giop-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1050.txt
fi

if [ -e $name/1080.txt ]; then
	echo "     SOCKS"
	nmap -iL $name/1080.txt -Pn -n --open -p1080 --script=socks-auth-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1080.txt
fi

if [ -e $name/1099.txt ]; then
	echo "     RMI Registry"
	nmap -iL $name/1099.txt -Pn -n --open -p1099 --script=rmi-dumpregistry --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1099.txt
fi

if [ -e $name/1344.txt ]; then
	echo "     ICAP"
	nmap -iL $name/1344.txt -Pn -n --open -p1344 --script=icap-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1344.txt
fi

if [ -e $name/1352.txt ]; then
	echo "     Lotus Domino"
	nmap -iL $name/1352.txt -Pn -n --open -p1352 --script=domino-enum-users --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1352.txt
fi

if [ -e $name/1433.txt ]; then
	echo "     MS-SQL"
	nmap -iL $name/1433.txt -Pn -n --open -p1433 --script=ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1433.txt
fi

if [ -e $name/1434.txt ]; then
	echo "     MS-SQL UDP"
	nmap -iL $name/1434.txt -Pn -n -sU --open -p1434 --script=ms-sql-dac --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1434.txt
fi

if [ -e $name/1521.txt ]; then
	echo "     Oracle"
	nmap -iL $name/1521.txt -Pn -n --open -p1521 --script=oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1521.txt
fi

if [ -e $name/1604.txt ]; then
	echo "     Citrix"
	nmap -iL $name/1604.txt -Pn -n -sU --open -p1604 --script=citrix-enum-apps,citrix-enum-servers --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1604.txt
fi

if [ -e $name/1723.txt ]; then
	echo "     PPTP"
	nmap -iL $name/1723.txt -Pn -n --open -p1723 --script=pptp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1723.txt
fi

if [ -e $name/2202.txt ]; then
	echo "     ACARS"
	nmap -iL $name/2202.txt -Pn -n --open -p2202 --script=acarsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-2202.txt
fi

if [ -e $name/2302.txt ]; then
	echo "     Freelancer"
	nmap -iL $name/2302.txt -Pn -n -sU --open -p2302 --script=freelancer-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-2302.txt
fi

if [ -e $name/2628.txt ]; then
	echo "     DICT"
	nmap -iL $name/2628.txt -Pn -n --open -p2628 --script=dict-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-2628.txt
fi

if [ -e $name/2947.txt ]; then
	echo "     GPS"
	nmap -iL $name/2947.txt -Pn -n --open -p2947 --script=gpsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-2947.txt
fi

if [ -e $name/3031.txt ]; then
	echo "     Apple Remote Event"
	nmap -iL $name/3031.txt -Pn -n --open -p3031 --script=eppc-enum-processes --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-3031.txt
fi

if [ -e $name/3260.txt ]; then
	echo "     iSCSI"
	nmap -iL $name/3260.txt -Pn -n --open -p3260 --script=iscsi-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-3260.txt
fi

if [ -e $name/3306.txt ]; then
	echo "     MySQL"
	nmap -iL $name/3306.txt -Pn -n --open -p3306 --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-3306.txt
fi

if [ -e $name/3389.txt ]; then
	echo "     Remote Desktop"
	nmap -iL $name/3389.txt -Pn -n --open -p3389 --script=rdp-vuln-ms12-020,rdp-enum-encryption --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	egrep -v '(attackers|Description|Disclosure|http|References|Risk factor)' tmp4 > $name/script-3389.txt
fi

if [ -e $name/3478.txt ]; then
	echo "     STUN"
	nmap -iL $name/3478.txt -Pn -n -sU --open -p3478 --script=stun-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-3478.txt
fi

if [ -e $name/3632.txt ]; then
	echo "     Distributed Compiler Daemon"
	nmap -iL $name/3632.txt -Pn -n --open -p3632 --script=distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
     egrep -v '(IDs|Risk factor|Description|Allows|earlier|Disclosure|Extra|References|http)' tmp4 > $name/script-3632.txt
fi

if [ -e $name/4369.txt ]; then
	echo "     Erlang Port Mapper"
	nmap -iL $name/4369.txt -Pn -n --open -p4369 --script=epmd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-4369.txt
fi

if [ -e $name/5019.txt ]; then
	echo "     Versant"
	nmap -iL $name/5019.txt -Pn -n --open -p5019 --script=versant-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5019.txt
fi

if [ -e $name/5060.txt ]; then
	echo "     SIP"
	nmap -iL $name/5060.txt -Pn -n --open -p5060 --script=sip-enum-users,sip-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5060.txt
fi

if [ -e $name/5353.txt ]; then
	echo "     DNS Service Discovery"
	nmap -iL $name/5353.txt -Pn -n -sU --open -p5353 --script=dns-service-discovery --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5353.txt
fi

if [ -e $name/5666.txt ]; then
	echo "     Nagios"
	nmap -iL $name/5666.txt -Pn -n --open -p5666 --script=nrpe-enum --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5666.txt
fi

if [ -e $name/5672.txt ]; then
	echo "     AMQP"
	nmap -iL $name/5672.txt -Pn -n --open -p5672 --script=amqp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5672.txt
fi

if [ -e $name/5850.txt ]; then
	echo "     OpenLookup"
	nmap -iL $name/5850.txt -Pn -n --open -p5850 --script=openlookup-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5850.txt
fi

if [ -e $name/5900.txt ]; then
	echo "     VNC"
	nmap -iL $name/5900.txt -Pn -n --open -p5900 --script=realvnc-auth-bypass,vnc-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5900.txt
fi

if [ -e $name/5984.txt ]; then
	echo "     CouchDB"
	nmap -iL $name/5984.txt -Pn -n --open -p5984 --script=couchdb-databases,couchdb-stats --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5984.txt
fi

if [ -e $name/x11.txt ]; then
	echo "     X11"
	nmap -iL $name/x11.txt -Pn -n --open -p6000-6005 --script=x11-access --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-x11.txt
fi

if [ -e $name/6379.txt ]; then
	echo "     Redis"
	nmap -iL $name/6379.txt -Pn -n --open -p6379 --script=redis-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-6379.txt
fi

if [ -e $name/6481.txt ]; then
	echo "     Sun Service Tags"
	nmap -iL $name/6481.txt -Pn -n -sU --open -p6481 --script=servicetags --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-6481.txt
fi

if [ -e $name/6666.txt ]; then
	echo "     Voldemort"
	nmap -iL $name/6666.txt -Pn -n --open -p6666 --script=voldemort-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-6666.txt
fi

if [ -e $name/7210.txt ]; then
	echo "     Max DB"
	nmap -iL $name/7210.txt -Pn -n --open -p7210 --script=maxdb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-7210.txt
fi

if [ -e $name/7634.txt ]; then
	echo "     Hard Disk Info"
	nmap -iL $name/7634.txt -Pn -n --open -p7634 --script=hddtemp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-7634.txt
fi

if [ -e $name/8000.txt ]; then
        echo "     QNX QCONN"
        nmap -iL $name/8000.txt -Pn -n --open -p8000 --script=qconn-exec --script-args=qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd="uname -a" --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
        f_cleanup
        mv tmp4 $name/script-8000.txt
fi

if [ -e $name/8009.txt ]; then
        echo "     AJP"
        nmap -iL $name/8009.txt -Pn -n --open -p8009 --script=ajp-methods,ajp-request --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
        f_cleanup
        mv tmp4 $name/script-8009.txt
fi

if [ -e $name/8081.txt ]; then
	echo "     McAfee ePO"
	nmap -iL $name/8081.txt -Pn -n --open -p8081 --script=mcafee-epo-agent --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-8081.txt
fi

if [ -e $name/8091.txt ]; then
	echo "     CouchBase Web Administration"
	nmap -iL $name/8091.txt -Pn -n --open -p8091 --script=membase-http-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-8091.txt
fi

if [ -e $name/bitcoin.txt ]; then
	echo "     Bitcoin"
	nmap -iL $name/bitcoin.txt -Pn -n --open -p8332,8333 --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-bitcoin.txt
fi

if [ -e $name/9100.txt ]; then
	echo "     Lexmark"
	nmap -iL $name/9100.txt -Pn -n --open -p9100 --script=lexmark-config --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-9100.txt
fi

if [ -e $name/9160.txt ]; then
	echo "     Cassandra"
	nmap -iL $name/9160.txt -Pn -n --open -p9160 --script=cassandra-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-9160.txt
fi

if [ -e $name/9999.txt ]; then
	echo "     Java Debug Wire Protocol"
	nmap -iL $name/9999.txt -Pn -n --open -p9999 --script=jdwp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-9999.txt
fi

if [ -e $name/10000.txt ]; then
	echo "     Network Data Management"
	nmap -iL $name/10000.txt -Pn -n --open -p10000 --script=ndmp-fs-info,ndmp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-10000.txt
fi

if [ -e $name/11211.txt ]; then
	echo "     Memory Object Caching"
	nmap -iL $name/11211.txt -Pn -n --open -p11211 --script=memcached-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-11211.txt
fi

if [ -e $name/12000.txt ]; then
	echo "     CCcam"
	nmap -iL $name/12000.txt -Pn -n --open -p12000 --script=cccam-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-12000.txt
fi

if [ -e $name/12345.txt ]; then
	echo "     NetBus"
	nmap -iL $name/12345.txt -Pn -n --open -p12345 --script=netbus-auth-bypass,netbus-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-12345.txt
fi

if [ -e $name/17185.txt ]; then
	echo "     VxWorks"
	nmap -iL $name/17185.txt -Pn -n -sU --open -p17185 --script=wdb-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-17185.txt
fi

if [ -e $name/19150.txt ]; then
	echo "     GKRellM"
	nmap -iL $name/19150.txt -Pn -n --open -p19150 --script=gkrellm-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-19150.txt
fi

if [ -e $name/27017.txt ]; then
	echo "     MongoDB"
	nmap -iL $name/27017.txt -Pn -n --open -p27017 --script=mongodb-databases,mongodb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-27017.txt
fi

if [ -e $name/31337.txt ]; then
	echo "     BackOrifice"
	nmap -iL $name/31337.txt -Pn -n -sU --open -p31337 --script=backorifice-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-31337.txt
fi

if [ -e $name/35871.txt ]; then
	echo "     Flume"
	nmap -iL $name/35871.txt -Pn -n --open -p35871 --script=flume-master-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-35871.txt
fi

if [ -e $name/50000.txt ]; then
	echo "     DRDA"
	nmap -iL $name/50000.txt -Pn -n --open -p50000 --script=drda-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-50000.txt
fi

if [ -e $name/hadoop.txt ]; then
	echo "     Hadoop"
	nmap -iL $name/hadoop.txt -Pn -n --open -p50030,50060,50070,50075,50090 --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-hadoop.txt
fi

if [ -e $name/apache-hbase.txt ]; then
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
}

##############################################################################################################

f_metasploit(){
echo
echo $medium
echo
echo -ne "\e[1;33mRun matching Metasploit auxiliaries? (y/N) \e[0m"
read msf

if [ "$msf" == "y" ]; then
     f_runmsf
else
     f_report
fi
}

##############################################################################################################

f_runmsf(){
echo
echo -e "\e[1;34mStarting Postgres.\e[0m"
service postgresql start

echo
echo -e "\e[1;34mStarting Metasploit, this takes about 45 sec.\e[0m"
echo
echo -e "\e[1;34mUsing the following resource files.\e[0m"
cp -R /opt/discover/resource/ /tmp/

echo workspace -a $name > $name/master.rc

if [ -e $name/19.txt ]; then
     echo "     CHARGEN"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/19.txt/g" /tmp/resource/chargen.rc
     cat /tmp/resource/chargen.rc >> $name/master.rc
fi

if [ -e $name/21.txt ]; then
     echo "     FTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/21.txt/g" /tmp/resource/ftp.rc
     cat /tmp/resource/ftp.rc >> $name/master.rc
fi

if [ -e $name/22.txt ]; then
     echo "     SSH"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/22.txt/g" /tmp/resource/ssh.rc
     cat /tmp/resource/ssh.rc >> $name/master.rc
fi

if [ -e $name/23.txt ]; then
     echo "     Telnet"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/23.txt/g" /tmp/resource/telnet.rc
     cat /tmp/resource/telnet.rc >> $name/master.rc
fi

if [ -e $name/25.txt ]; then
     echo "     SMTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/25.txt/g" /tmp/resource/smtp.rc
     cat /tmp/resource/smtp.rc >> $name/master.rc
fi

if [ -e $name/69.txt ]; then
     echo "     TFTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/69.txt/g" /tmp/resource/tftp.rc
     cat /tmp/resource/tftp.rc >> $name/master.rc
fi

if [ -e $name/79.txt ]; then
     echo "     Finger"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/79.txt/g" /tmp/resource/finger.rc
     cat /tmp/resource/finger.rc >> $name/master.rc
fi

if [ -e $name/80.txt ]; then
     echo "     Lotus"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/80.txt/g" /tmp/resource/lotus.rc
     cat /tmp/resource/lotus.rc >> $name/master.rc
fi

if [ -e $name/80.txt ]; then
     echo "     SCADA Indusoft WebStudio NTWebServer"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/80.txt/g" /tmp/resource/scada3.rc
     cat /tmp/resource/scada3.rc >> $name/master.rc
fi

if [ -e $name/110.txt ]; then
     echo "     POP3"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/110.txt/g" /tmp/resource/pop3.rc
     cat /tmp/resource/pop3.rc >> $name/master.rc
fi

if [ -e $name/111.txt ]; then
     echo "     NFS"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/111.txt/g" /tmp/resource/nfs.rc
     cat /tmp/resource/nfs.rc >> $name/master.rc
fi

if [ -e $name/123.txt ]; then
     echo "     NTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/123.txt/g" /tmp/resource/ntp.rc
     cat /tmp/resource/ntp.rc >> $name/master.rc
fi

if [ -e $name/135.txt ]; then
     echo "     DCE/RPC"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/135.txt/g" /tmp/resource/dcerpc.rc
     cat /tmp/resource/dcerpc.rc >> $name/master.rc
fi

if [ -e $name/137.txt ]; then
     echo "     NetBIOS"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/137.txt/g" /tmp/resource/netbios.rc
     cat /tmp/resource/netbios.rc >> $name/master.rc
fi

if [ -e $name/143.txt ]; then
     echo "     IMAP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/143.txt/g" /tmp/resource/imap.rc
     cat /tmp/resource/imap.rc >> $name/master.rc
fi

if [ -e $name/161.txt ]; then
     echo "     SNMP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/161.txt/g" /tmp/resource/snmp.rc
     cat /tmp/resource/snmp.rc >> $name/master.rc
fi

if [ -e $name/407.txt ]; then
     echo "     Motorola"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/407.txt/g" /tmp/resource/motorola.rc
     cat /tmp/resource/motorola.rc >> $name/master.rc
fi

if [ -e $name/443.txt ]; then
     echo "     VMware"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/443.txt/g" /tmp/resource/vmware.rc
     cat /tmp/resource/motorola.rc >> $name/master.rc
fi

if [ -e $name/445.txt ]; then
     echo "     SMB"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/445.txt/g" /tmp/resource/smb.rc
     cat /tmp/resource/smb.rc >> $name/master.rc
fi

if [ -e $name/465.txt ]; then
     echo "     SMTP/S"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/465.txt/g" /tmp/resource/smtp2.rc
     cat /tmp/resource/smtp2.rc >> $name/master.rc
fi

if [ -e $name/502.txt ]; then
     echo "     SCADA Modbus Client Utility"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/502.txt/g" /tmp/resource/scada5.rc
     cat /tmp/resource/scada5.rc >> $name/master.rc
fi

if [ -e $name/512.txt ]; then
     echo "     Rexec"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/512.txt/g" /tmp/resource/rservices.rc
     cat /tmp/resource/rservices.rc >> $name/master.rc
fi

if [ -e $name/513.txt ]; then
     echo "     rlogin"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/513.txt/g" /tmp/resource/rservices2.rc
     cat /tmp/resource/rservices2.rc >> $name/master.rc
fi

if [ -e $name/514.txt ]; then
     echo "     rshell"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/514.txt/g" /tmp/resource/rservices3.rc
     cat /tmp/resource/rservices3.rc >> $name/master.rc
fi

if [ -e $name/523.txt ]; then
     echo "     db2"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/523.txt/g" /tmp/resource/db2.rc
     cat /tmp/resource/db2.rc >> $name/master.rc
fi

if [ -e $name/548.txt ]; then
     echo "     AFP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/548.txt/g" /tmp/resource/afp.rc
     cat /tmp/resource/afp.rc >> $name/master.rc
fi

if [ -e $name/623.txt ]; then
     echo "     IPMI"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/623.txt/g" /tmp/resource/ipmi.rc
     cat /tmp/resource/ipmi.rc >> $name/master.rc
fi

if [ -e $name/771.txt ]; then
     echo "     SCADA Digi"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/771.txt/g" /tmp/resource/scada2.rc
     cat /tmp/resource/scada2.rc >> $name/master.rc
fi

if [ -e $name/902.txt ]; then
     echo "     VMware"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/902.txt/g" /tmp/resource/vmware2.rc
     cat /tmp/resource/motorola.rc >> $name/master.rc
fi

if [ -e $name/1099.txt ]; then
     echo "     RMI Registery"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/1099.txt/g" /tmp/resource/rmi.rc
     cat /tmp/resource/rmi.rc >> $name/master.rc
fi

if [ -e $name/1158.txt ]; then
     echo "     Oracle"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/1158.txt/g" /tmp/resource/oracle.rc
     cat /tmp/resource/oracle.rc >> $name/master.rc
fi

if [ -e $name/1433.txt ]; then
     echo "     MS-SQL"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/1433.txt/g" /tmp/resource/mssql.rc
     cat /tmp/resource/mssql.rc >> $name/master.rc
fi

if [ -e $name/1521.txt ]; then
     echo "     Oracle"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/1521.txt/g" /tmp/resource/oracle3.rc
     cat /tmp/resource/oracle3.rc >> $name/master.rc
fi

if [ -e $name/1604.txt ]; then
     echo "     Citrix"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/1604.txt/g" /tmp/resource/citrix.rc
     cat /tmp/resource/citrix.rc >> $name/master.rc
fi

if [ -e $name/1720.txt ]; then
     echo "     H323"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/1720.txt/g" /tmp/resource/h323.rc
     cat /tmp/resource/h323.rc >> $name/master.rc
fi

if [ -e $name/1900.txt ]; then
     echo "     UPnP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/1900.txt/g" /tmp/resource/upnp.rc
     cat /tmp/resource/upnp.rc >> $name/master.rc
fi

if [ -e $name/2362.txt ]; then
     echo "     SCADA Digi"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/2362.txt/g" /tmp/resource/scada.rc
     cat /tmp/resource/scada.rc >> $name/master.rc
fi

if [ -e $name/3000.txt ]; then
     echo "     EMC"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/3000.txt/g" /tmp/resource/emc.rc
     cat /tmp/resource/emc.rc >> $name/master.rc
fi

if [ -e $name/3306.txt ]; then
     echo "     MySQL"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/3306.txt/g" /tmp/resource/mysql.rc
     cat /tmp/resource/mysql.rc >> $name/master.rc
fi

if [ -e $name/3389.txt ]; then
     echo "     RDP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/3389.txt/g" /tmp/resource/rdp.rc
     cat /tmp/resource/rdp.rc >> $name/master.rc
fi

if [ -e $name/3500.txt ]; then
     echo "     EMC"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/3500.txt/g" /tmp/resource/emc2.rc
     cat /tmp/resource/emc2.rc >> $name/master.rc
fi

if [ -e $name/5040.txt ]; then
     echo "     DCE/RPC"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5040.txt/g" /tmp/resource/dcerpc2.rc
     cat /tmp/resource/dcerpc2.rc >> $name/master.rc
fi

if [ -e $name/5060.txt ]; then
     echo "     SIP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5060.txt/g" /tmp/resource/sip.rc
     cat /tmp/resource/sip.rc >> $name/master.rc
fi

if [ -e $name/5060-tcp.txt ]; then
     echo "     SIP TCP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5060-tcp.txt/g" /tmp/resource/sip2.rc
     cat /tmp/resource/sip2.rc >> $name/master.rc
fi

if [ -e $name/5432.txt ]; then
     echo "     Postgres"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5432.txt/g" /tmp/resource/postgres.rc
     cat /tmp/resource/postgres.rc >> $name/master.rc
fi

if [ -e $name/5560.txt ]; then
     echo "     Oracle iSQL"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5560.txt/g" /tmp/resource/oracle2.rc
     cat /tmp/resource/oracle2.rc >> $name/master.rc
fi

if [ -e $name/5631.txt ]; then
     echo "     pcAnywhere"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5631.txt/g" /tmp/resource/pcanywhere.rc
     cat /tmp/resource/pcanywhere.rc >> $name/master.rc
fi

if [ -e $name/5632.txt ]; then
     echo "     pcAnywhere"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5632.txt/g" /tmp/resource/pcanywhere2.rc
     cat /tmp/resource/pcanywhere2.rc >> $name/master.rc
fi

if [ -e $name/5900.txt ]; then
     echo "     VNC"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5900.txt/g" /tmp/resource/vnc.rc
     cat /tmp/resource/vnc.rc >> $name/master.rc
fi

if [ -e $name/5920.txt ]; then
     echo "     Misc CCTV DVR"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5920.txt/g" /tmp/resource/misc.rc
     cat /tmp/resource/misc.rc >> $name/master.rc
fi

if [ -e $name/5984.txt ]; then
     echo "     CouchDB"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5984.txt/g" /tmp/resource/couchdb.rc
     cat /tmp/resource/couchdb.rc >> $name/master.rc
fi

if [ -e $name/5985.txt ]; then
     echo "     winrm"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/5985.txt/g" /tmp/resource/winrm.rc
     cat /tmp/resource/winrm.rc >> $name/master.rc
fi

if [ -e $name/x11.txt ]; then
     echo "     x11"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/x11.txt/g" /tmp/resource/x11.rc
     cat /tmp/resource/x11.rc >> $name/master.rc
fi

if [ -e $name/6379.txt ]; then
     echo "     Redis"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/6379.txt/g" /tmp/resource/redis.rc
     cat /tmp/resource/redis.rc >> $name/master.rc
fi

if [ -e $name/7777.txt ]; then
     echo "     Backdoor"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/7777.txt/g" /tmp/resource/backdoor.rc
     cat /tmp/resource/backdoor.rc >> $name/master.rc
fi

if [ -e $name/8080.txt ]; then
     echo "     Tomcat"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/8080.txt/g" /tmp/resource/tomcat.rc
     cat /tmp/resource/tomcat.rc >> $name/master.rc
fi

if [ -e $name/8222.txt ]; then
     echo "     VMware"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/8222.txt/g" /tmp/resource/vmware.rc
     cat /tmp/resource/vmware.rc >> $name/master.rc
fi

if [ -e $name/8400.txt ]; then
     echo "     Adobe"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/8400.txt/g" /tmp/resource/adobe.rc
     cat /tmp/resource/adobe.rc >> $name/master.rc
fi

if [ -e $name/8834.txt ]; then
     echo "     Nessus"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/8834.txt/g" /tmp/resource/nessus.rc
     cat /tmp/resource/nessus.rc >> $name/master.rc
fi

if [ -e $name/9100.txt ]; then
     echo "     Printers"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/9100.txt/g" /tmp/resource/printers.rc
     cat /tmp/resource/printers.rc >> $name/master.rc
fi

if [ -e $name/9999.txt ]; then
     echo "     Telnet"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/9999.txt/g" /tmp/resource/telnet3.rc
     cat /tmp/resource/telnet3.rc >> $name/master.rc
fi

if [ -e $name/17185.txt ]; then
     echo "     VxWorks"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/17185.txt/g" /tmp/resource/vxworks.rc
     cat /tmp/resource/vxworks.rc >> $name/master.rc
fi

if [ -e $name/28784.txt ]; then
     echo "     SCADA Koyo DirectLogic PLC"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/28784.txt/g" /tmp/resource/scada4.rc
     cat /tmp/resource/scada4.rc >> $name/master.rc
fi

if [ -e $name/30718.txt ]; then
     echo "     Telnet"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/30718.txt/g" /tmp/resource/telnet2.rc
     cat /tmp/resource/telnet2.rc >> $name/master.rc
fi

if [ -e $name/46824.txt ]; then
     echo "     SCADA Sielco Sistemi"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/46824.txt/g" /tmp/resource/scada6.rc
     cat /tmp/resource/scada6.rc >> $name/master.rc
fi

if [ -e $name/50000.txt ]; then
     echo "     db2"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/discover\/$name\/50000.txt/g" /tmp/resource/db2-2.rc
     cat /tmp/resource/db2-2.rc >> $name/master.rc
fi

echo db_export -f xml -a $name/metasploit.xml >> $name/master.rc
echo db_import $name/nmap.xml >> $name/master.rc
echo exit >> $name/master.rc

x=$(wc -l $name/master.rc | cut -d ' ' -f1)

if [ $x -eq 3 ]; then
     echo 2>/dev/null
else
     msfconsole -r /opt/discover/$name/master.rc
fi

f_report
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

if [ -e $name/script-ms08-067.txt ]; then
     echo "May be vulnerable to MS08-067." >> $filename
     echo >> $filename
     cat $name/script-ms08-067.txt >> $filename
     echo >> $filename
     echo $medium >> $filename
     echo >> $filename
fi

if [ $hosts -eq 1 ]; then
     echo "1 host discovered." >> $filename
     echo >> $filename
     echo $medium >> $filename
     echo >> $filename
     cat $name/nmap.txt >> $filename
     echo $medium >> $filename
     echo $medium >> $filename
     echo >> $filename
     echo "Nmap Scripts" >> $filename

     SCRIPTS="script-13 script-21 script-22 script-23 script-25 script-37 script-53 script-67 script-70 script-79 script-110 script-111 script-123 script-137 script-143 script-161 script-389 script-445 script-465 script-500 script-523 script-524 script-548 script-554 script-631 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-2202 script-2302 script-2628 script-2947 script-3031 script-3260 script-3306 script-3389 script-3478 script-3632 script-4369 script-5019 script-5060 script-5353 script-5666 script-5672 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8000 script-8009 script-8081 script-8091 script-bitcoin script-9100 script-9160 script-9999 script-10000 script-11211 script-12000 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-50000 script-hadoop script-apache-hbase script-web"

     for i in $SCRIPTS; do
          if [ -e $name/"$i.txt" ]; then
               cat $name/"$i.txt" >> $filename
               echo $medium >> $filename
          fi
     done

     mv $name /$user/data/

     START=0
     END=0

     echo
	echo $medium
	echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/$name/report.txt
     echo
     echo
     exit
fi

echo "Hosts Discovered ($host)" >> $filename
echo >> $filename
cat $name/hosts.txt >> $filename
echo >> $filename

if [ ! -s $name/ports.txt ]; then
     rm -rf "$name" tmp*
     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     echo -e "\e[1;33mNo hosts found with open ports.\e[0m"
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

HVPORTS="13 21 22 23 25 37 53 67 69 70 79 80 110 111 123 137 139 143 161 389 443 445 465 500 523 524 548 554 631 873 993 995 1050 1080 1099 1158 1344 1352 1433 1434 1521 1604 1720 1723 2202 2302 2628 2947 3031 3260 3306 3389 3478 3632 4369 5019 5060 5353 5432 5666 5672 5850 5900 5984 6000 6001 6002 6003 6004 6005 6379 6481 6666 7210 7634 7777 8000 8009 8080 8081 8091 8222 8332 8333 8400 8443 9100 9160 9999 10000 11211 12000 12345 17185 19150 27017 31337 35871 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $HVPORTS; do
     if [ -e $name/$i.txt ]; then
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

SCRIPTS="script-13 script-21 script-22 script-23 script-25 script-37 script-53 script-67 script-70 script-79 script-110 script-111 script-123 script-137 script-143 script-161 script-389 script-445 script-465 script-500 script-523 script-524 script-548 script-554 script-631 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-2202 script-2302 script-2628 script-2947 script-3031 script-3260 script-3306 script-3389 script-3478 script-3632 script-4369 script-5019 script-5060 script-5353 script-5666 script-5672 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8000 script-8009 script-8081 script-8091 script-bitcoin script-9100 script-9160 script-9999 script-10000 script-11211 script-12000 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-50000 script-hadoop script-apache-hbase script-web"

for i in $SCRIPTS; do
     if [ -e $name/"$i.txt" ]; then
          cat $name/"$i.txt" >> $filename
          echo $medium >> $filename
     fi
done

echo >> $filename

mv $name /$user/data/

START=0
END=0

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/$name/report.txt
echo
echo
exit
}

##############################################################################################################

f_multitabs(){
f_runlocally
clear
f_banner

echo -e "\e[1;34mOpen multiple tabs in Iceweasel with:\e[0m"
echo
echo "1.  List"
echo "2.  Directories from a domain's robot.txt."
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     f_location

     echo -n "Use SSL? (y/N) "
     read ssl

     iceweasel &
     sleep 2

     if [ -z $ssl ]; then
          for i in $(cat $location); do
               iceweasel -new-tab $i &
               sleep 1
          done
     elif [ "$ssl" == "y" ]; then
          for i in $(cat $location); do
               iceweasel -new-tab https://$i &
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
     if [ -z $domain ]; then
          f_error
     fi

     wget -q $domain/robots.txt

     grep 'Disallow' robots.txt | awk '{print $2}' > /$user/data/$domain-robots.txt
     rm robots.txt

     iceweasel &
     sleep 2

     for i in $(cat /$user/data/$domain-robots.txt); do
          iceweasel -new-tab $domain$i &
          sleep 1
     done

     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/$domain-robots.txt
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

echo -e "\e[1;34mRun multiple instances of Nikto in parallel.\e[0m"
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

     mkdir /$user/data/nikto-$port

     while read -r line; do
          xdotool key ctrl+shift+t
          xdotool type "nikto -h $line -port $port -Format htm --output /$user/data/nikto-$port/$line.htm ; exit"
          sleep 1
          xdotool key Return
     done < "$location"
     ;;

     2)
     f_location

     mkdir /$user/data/nikto

     while IFS=: read -r host port; do
          xdotool key ctrl+shift+t
          sleep 1
          xdotool type "nikto -h $host -port $port -Format htm --output /$user/data/nikto/$host-$port.htm ; exit"
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
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/nikto/
echo
echo
exit
}

##############################################################################################################

f_parse(){
clear
f_banner

echo -e "\e[1;34mParse XML to CSV.\e[0m"
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

     mv burp.csv /$user/data/burp-`date +%H:%M:%S`.csv

     echo
     echo $medium
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/burp-`date +%H:%M:%S`.csv
     echo
     echo
     exit
     ;;

     2)
     f_location
     parsers/parse-nessus.py $location

     # Delete findings with CVSS score of 0 and solution of n/a
     egrep -v "(Adobe Acrobat Detection|Adobe Extension Manager Installed|Adobe Flash Player for Mac Installed|Adobe Flash Professional Detection|Adobe Illustrator Detection|Adobe Photoshop Detection|Adobe Reader Detection|Adobe Reader Installed \(Mac OS X\)|ADSI Settings|Advanced Message Queuing Protocol Detection|AJP Connector Detection|AirWatch API Settings|Antivirus Software Check|Apache Axis2 Detection|Apache HTTP Server HttpOnly Cookie Information Disclosure|Apple Filing Protocol Server Detection|Apple Profile Manager API Settings|AppSocket & socketAPI Printers - Do Not Scan|Appweb HTTP Server Version|ASG-Sentry SNMP Agent Detection|Authenticated Check: OS Name and Installed Package Enumeration|Autodesk AutoCAD Detection|Backported Security Patch Detection \(FTP\)|Backported Security Patch Detection \(SSH\)|Authenticated Check: OS Name and Installed Package Enumeration|Backported Security Patch Detection \(WWW\)|BACnet Protocol Detection|BIOS Version Information \(via SMB\)|BIOS Version \(WMI\)|Blackboard Learn Detection|Broken Web Servers|CA Message Queuing Service Detection|CDE Subprocess Control Service \(dtspcd\) Detection|Check Point FireWall-1 ICA Service Detection|Check Point SecuRemote Hostname Information Disclosure|Cisco AnyConnect Secure Mobility Client Detection|CISCO ASA SSL VPN Detection|Cisco TelePresence Multipoint Control Unit Detection|Cleartext protocols settings|Common Platform Enumeration \(CPE\)|Computer Manufacturer Information \(WMI\)|CORBA IIOP Listener Detection|Database settings|DB2 Administration Server Detection|DB2 Discovery Service Detection|DCE Services Enumeration|Dell OpenManage Web Server Detection|Derby Network Server Detection|Detect RPC over TCP|Device Hostname|Device Type|DNS Sender Policy Framework \(SPF\) Enabled|DNS Server DNSSEC Aware Resolver|DNS Server Fingerprinting|DNS Server Version Detection|Do not scan fragile devices|EMC SMARTS Application Server Detection|Erlang Port Mapper Daemon Detection|Ethernet Card Manufacturer Detection|External URLs|FileZilla Client Installed|iceweasel Installed \(Mac OS X\)|Firewall Rule Enumeration|Flash Player Detection|FTP Service AUTH TLS Command Support|FTP Server Detection|Global variable settings|Good MDM Settings|Google Chrome Detection \(Windows\)|Google Chrome Installed \(Mac OS X\)|Google Picasa Detection \(Windows\)|Host Fully Qualified Domain Name \(FQDN\) Resolution|HMAP Web Server Fingerprinting|Hosts File Whitelisted Entries|HP OpenView BBC Service Detection|HP SiteScope Detection|HSTS Missing From HTTPS Server|HTTP cookies import|HTTP Cookie 'secure' Property Transport Mismatch|HTTP login page|HTTP Methods Allowed \(per directory\)|HTTP Proxy Open Relay Detection|HTTP Reverse Proxy Detection|HTTP Server Cookies Set|HTTP Server Type and Version|HTTP TRACE \/ TRACK Methods Allowed|HTTP X-Frame-Options Response Header Usage|Hyper-V Virtual Machine Detection|HyperText Transfer Protocol \(HTTP\) Information|IBM Domino Detection \(uncredentialed check\)|IBM Domino Installed|IBM GSKit Installed|IBM iSeries Credentials|IBM Lotus Notes Detection|IBM Notes Client Detection|IBM Remote Supervisor Adapter Detection \(HTTP\)|IBM Tivoli Endpoint Manager Client Detection|IBM Tivoli Endpoint Manager Web Server Detection|IBM Tivoli Storage Manager Client Installed|IBM Tivoli Storage Manager Service Detection|IBM WebSphere Application Server Detection|IMAP Service Banner Retrieval|IMAP Service STARTTLS Command Support|IP Protocols Scan|IPMI Cipher Suites Supported|IPMI Versions Supported|iTunes Version Detection \(credentialed check\)|Kerberos configuration|Kerberos Information Disclosure|L2TP Network Server Detection|LDAP Server Detection|LDAP Service STARTTLS Command Support|LibreOffice Detection|Login configurations|Lotus Sametime Detection|MacOSX Cisco AnyConnect Secure Mobility Client Detection|McAfee Common Management Agent Detection|McAfee Common Management Agent Installation Detection|McAfee ePolicy Orchestrator Application Server Detection|MediaWiki Detection|Microsoft Exchange Installed|Microsoft Internet Explorer Enhanced Security Configuration Detection|Microsoft Internet Explorer Version Detection|Microsoft Lync Server Installed|Microsoft Malicious Software Removal Tool Installed|Microsoft .NET Framework Detection|Microsoft .NET Handlers Enumeration|Microsoft Office Detection|Microsoft OneNote Detection|Microsoft Patch Bulletin Feasibility Check|Microsoft Revoked Digital Certificates Enumeration|Microsoft Silverlight Detection|Microsoft Silverlight Installed \(Mac OS X\)|Microsoft SQL Server STARTTLS Support|Microsoft SMS\/SCCM Installed|Microsoft System Center Configuration Manager Client Installed|Microsoft System Center Operations Manager Component Installed|Microsoft Update Installed|Microsoft Windows AutoRuns Boot Execute|Microsoft Windows AutoRuns Codecs|Microsoft Windows AutoRuns Explorer|Microsoft Windows AutoRuns Internet Explorer|Microsoft Windows AutoRuns Known DLLs|Microsoft Windows AutoRuns Logon|Microsoft Windows AutoRuns LSA Providers|Microsoft Windows AutoRuns Network Providers|Microsoft Windows AutoRuns Print Monitor|Microsoft Windows AutoRuns Registry Hijack Possible Locations|Microsoft Windows AutoRuns Report|Microsoft Windows AutoRuns Scheduled Tasks|Microsoft Windows AutoRuns Services and Drivers|Microsoft Windows AutoRuns Unique Entries|Microsoft Windows AutoRuns Winlogon|Microsoft Windows AutoRuns Winsock Provider|Microsoft Windows 'CWDIllegalInDllSearch' Registry Setting|Microsoft Windows Installed Hotfixes|Microsoft Windows NTLMSSP Authentication Request Remote Network Name Disclosure|Microsoft Windows Process Module Information|Microsoft Windows Process Unique Process Name|Microsoft Windows Remote Listeners Enumeration \(WMI\)|Microsoft Windows SMB : Obtains the Password Policy|Microsoft Windows SMB LanMan Pipe Server Listing Disclosure|Microsoft Windows SMB Log In Possible|Microsoft Windows SMB LsaQueryInformationPolicy Function NULL Session Domain SID Enumeration|Microsoft Windows SMB NativeLanManager Remote System Information Disclosure|Microsoft Windows SMB Registry : Enumerate the list of SNMP communities|Microsoft Windows SMB Registry : Nessus Cannot Access the Windows Registry|Microsoft Windows SMB Registry : OS Version and Processor Architecture|Microsoft Windows SMB Registry : Remote PDC\/BDC Detection|Microsoft Windows SMB Registry : Vista \/ Server 2008 Service Pack Detection|Microsoft Windows SMB Registry : XP Service Pack Detection|Microsoft Windows SMB Registry Remotely Accessible|Microsoft Windows SMB Registry : Win 7 \/ Server 2008 R2 Service Pack Detection|Microsoft Windows SMB Registry : Windows 2000 Service Pack Detection|Microsoft Windows SMB Registry : Windows 2003 Server Service Pack Detection|Microsoft Windows SMB Service Detection|Microsoft Windows Update Installed|MobileIron API Settings|MSRPC Service Detection|Modem Enumeration \(WMI\)|MongoDB Settings|Mozilla Foundation Application Detection|MySQL Server Detection|Nessus Internal: Put cgibin in the KB|Nessus Scan Information|Nessus SNMP Scanner|NetBIOS Multiple IP Address Enumeration|Netstat Active Connections|Netstat Connection Information|netstat portscanner \(SSH\)|Netstat Portscanner \(WMI\)|Network Interfaces Enumeration \(WMI\)|Network Time Protocol \(NTP\) Server Detection|Nmap \(XML file importer\)|Non-compliant Strict Transport Security (STS)|OpenSSL Detection|OpenSSL Version Detection|Oracle Application Express \(Apex\) Detection|Oracle Application Express \(Apex\) Version Detection|Oracle Java Runtime Environment \(JRE\) Detection \(Unix\)|Oracle Java Runtime Environment \(JRE\) Detection|Oracle Installed Software Enumeration \(Windows\)|Oracle Settings|OS Identification|Palo Alto Networks PAN-OS Settings|Patch Management: Dell KACE K1000 Settings|Patch Management: IBM Tivoli Endpoint Manager Server Settings|Patch Management: Patch Schedule From Red Hat Satellite Server|Patch Management: Red Hat Satellite Server Get Installed Packages|Patch Management: Red Hat Satellite Server Get Managed Servers|Patch Management: Red Hat Satellite Server Get System Information|Patch Management: Red Hat Satellite Server Settings|Patch Management: SCCM Server Settings|Patch Management: Symantec Altiris Settings|Patch Management: VMware Go Server Settings|Patch Management: WSUS Server Settings|PCI DSS compliance : options settings|PHP Version|Ping the remote host|POP3 Service STLS Command Support|Port scanner dependency|Port scanners settings|Post-Scan Rules Application|Post-Scan Status|Protected Web Page Detection|RADIUS Server Detection|RDP Screenshot|RealPlayer Detection|Record Route|Remote listeners enumeration \(Linux \/ AIX\)|Remote web server screenshot|Reputation of Windows Executables: Known Process\(es\)|Reputation of Windows Executables: Unknown Process\(es\)|RHEV Settings|RIP Detection|RMI Registry Detection|RPC portmapper \(TCP\)|RPC portmapper Service Detection|RPC Services Enumeration|Salesforce.com Settings|Samba Server Detection|SAP Dynamic Information and Action Gateway Detection|Service Detection \(GET request\)|Service Detection \(HELP Request\)|slident \/ fake identd Detection|Service Detection \(2nd Pass\)|Service Detection: 3 ASCII Digit Code Responses|SMB : Disable the C$ and ADMIN$ shares after the scan (WMI)|SMB : Enable the C$ and ADMIN$ shares during the scan \(WMI\)|SMB Registry : Start the Registry Service during the scan|SMB Registry : Start the Registry Service during the scan \(WMI\)|SMB Registry : Starting the Registry Service during the scan failed|SMB Registry : Stop the Registry Service after the scan|SMB Registry : Stop the Registry Service after the scan \(WMI\)|SMB Registry : Stopping the Registry Service after the scan failed|SMB QuickFixEngineering \(QFE\) Enumeration|SMB Scope|SMTP Server Connection Check|SMTP settings|smtpscan SMTP Fingerprinting|Snagit Installed|SNMP settings|SNMP Supported Protocols Detection|SNMPc Management Server Detection|SOCKS Server Detection|SolarWinds TFTP Server Installed|Spybot Search & Destroy Detection|SquirrelMail Detection|SSH Algorithms and Languages Supported|SSH Protocol Versions Supported|SSH Server Type and Version Information|SSH settings|SSL \/ TLS Versions Supported|SSL Certificate Information|SSL Cipher Block Chaining Cipher Suites Supported|SSL Cipher Suites Supported|SSL Compression Methods Supported|SSL Perfect Forward Secrecy Cipher Suites Supported|SSL Resume With Different Cipher Issue|SSL Service Requests Client Certificate|SSL Session Resume Supported|Strict Transport Security \(STS\) Detection|Subversion Client/Server Detection \(Windows\)|Symantec Backup Exec Server \/ System Recovery Installed|Symantec Encryption Desktop Installed|Symantec Endpoint Protection Manager Installed \(credentialed check\)|Symantec Veritas Enterprise Administrator Service \(vxsvc\) Detection|TCP\/IP Timestamps Supported|TeamViewer Version Detection|Tenable Appliance Check \(deprecated\)|Terminal Services Use SSL\/TLS|Thunderbird Installed \(Mac OS X\)|Time of Last System Startup|TLS Next Protocols Supported|Traceroute Information|Unknown Service Detection: Banner Retrieval|UPnP Client Detection|VERITAS Backup Agent Detection|VERITAS NetBackup Agent Detection|Viscosity VPN Client Detection \(Mac OS X\)|VMware vCenter Detect|VMware vCenter Orchestrator Installed|VMware ESX\/GSX Server detection|VMware SOAP API Settings|VMware vCenter SOAP API Settings|VMware Virtual Machine Detection|VMware vSphere Client Installed|VMware vSphere Detect|VNC Server Security Type Detection|VNC Server Unencrypted Communication Detection|vsftpd Detection|Wake-on-LAN|Web Application Firewall Detection|Web Application Tests Settings|Web mirroring|Web Server Directory Enumeration|Web Server Harvested Email Addresses|Web Server HTTP Header Internal IP Disclosure|Web Server Load Balancer Detection|Web Server No 404 Error Code Check|Web Server robots.txt Information Disclosure|Web Server UDDI Detection|Window Process Information|Window Process Module Information|Window Process Unique Process Name|Windows Compliance Checks|Windows ComputerSystemProduct Enumeration \(WMI\)|Windows Display Driver Enumeration|Windows DNS Server Enumeration|Windows Management Instrumentation \(WMI\) Available|Windows NetBIOS \/ SMB Remote Host Information Disclosure|Windows Prefetch Folder|Windows Product Key Retrieval|WinSCP Installed|Wireless Access Point Detection|Wireshark \/ Ethereal Detection \(Windows\)|WinZip Installed|WMI Anti-spyware Enumeration|WMI Antivirus Enumeration|WMI Bluetooth Network Adapter Enumeration|WMI Encryptable Volume Enumeration|WMI Firewall Enumeration|WMI QuickFixEngineering \(QFE\) Enumeration|WMI Server Feature Enumeration|WMI Trusted Platform Module Enumeration|Yosemite Backup Service Driver Detection|ZENworks Remote Management Agent Detection)" nessus.csv > tmp.csv

     # Delete additional findings with CVSS score of 0
     egrep -v "(Acronis Agent Detection \(TCP\)|Acronis Agent Detection \(UDP\)|Additional DNS Hostnames|Adobe AIR Detection|Adobe Reader Enabled in Browser \(Internet Explorer\)|Adobe Reader Enabled in Browser \(Mozilla iceweasel\)|Alert Standard Format \/ Remote Management and Control Protocol Detection|Amazon Web Services Settings|Apache Banner Linux Distribution Disclosure|Apache Tomcat Default Error Page Version Detection|Authentication Failure - Local Checks Not Run|CA ARCServe UniversalAgent Detection|CA BrightStor ARCserve Backup Discovery Service Detection|Cache' SuperServer Detection|Citrix Licensing Service Detection|Citrix Server Detection|COM+ Internet Services \(CIS\) Server Detection|Crystal Reports Central Management Server Detection|Data Execution Prevention \(DEP\) is Disabled|Daytime Service Detection|DB2 Connection Port Detection|Discard Service Detection|DNS Server BIND version Directive Remote Version Disclosure|DNS Server Detection|DNS Server hostname.bind Map Hostname Disclosure|Do not scan Novell NetWare|Do not scan printers|Do not scan printers \(AppSocket\)|Dropbox Installed \(Mac OS X\)|Dropbox Software Detection \(uncredentialed check\)|Enumerate IPv4 Interfaces via SSH|Echo Service Detection|EMC Replication Manager Client Detection|Enumerate IPv6 Interfaces via SSH|Enumerate MAC Addresses via SSH|Exclude top-level domain wildcard hosts|H323 Protocol \/ VoIP Application Detection|HP LoadRunner Agent Service Detection|HP Integrated Lights-Out \(iLO\) Detection|IBM Tivoli Storage Manager Client Acceptor Daemon Detection|IBM WebSphere MQ Listener Detection|ICMP Timestamp Request Remote Date Disclosure|Identd Service Detection|Ingres Communications Server Detection|Internet Cache Protocol \(ICP\) Version 2 Detection|IPSEC Internet Key Exchange \(IKE\) Detection|IPSEC Internet Key Exchange \(IKE\) Version 1 Detection|iTunes Music Sharing Enabled|iTunes Version Detection \(Mac OS X\)|JavaScript Enabled in Adobe Reader|IPSEC Internet Key Exchange \(IKE\) Version 2 Detection|iSCSI Target Detection|Link-Local Multicast Name Resolution \(LLMNR\) Detection|LPD Detection|mDNS Detection \(Local Network\)|Microsoft IIS 404 Response Service Pack Signature|Microsoft SharePoint Server Detection|Microsoft SQL Server Detection \(credentialed check\)|Microsoft SQL Server TCP\/IP Listener Detection|Microsoft SQL Server UDP Query Remote Version Disclosure|Microsoft Windows Installed Software Enumeration \(credentialed check\)|Microsoft Windows Messenger Detection|Microsoft Windows Mounted Devices|Microsoft Windows Security Center Settings|Microsoft Windows SMB Fully Accessible Registry Detection|Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration|Microsoft Windows SMB Registry Not Fully Accessible Detection|Microsoft Windows SMB Share Hosting Possibly Copyrighted Material|Microsoft Windows SMB : WSUS Client Configured|Microsoft Windows Startup Software Enumeration|Microsoft Windows Summary of Missing Patches|NIS Server Detection|Nessus SYN scanner|Nessus TCP scanner|Nessus UDP scanner|Nessus Windows Scan Not Performed with Admin Privileges|Netscape Enterprise Server Default Files Present|NetVault Process Manager Service Detection|NFS Server Superfluous|News Server \(NNTP\) Information Disclosure|NNTP Authentication Methods|OEJP Daemon Detection|Open Port Re-check|OpenVAS Manager \/ Administrator Detection|Oracle Database Detection|Oracle Database tnslsnr Service Remote Version Disclosure|Oracle Java JRE Enabled \(Google Chrome\)|Oracle Java JRE Enabled \(Internet Explorer\)|Oracle Java JRE Enabled \(Mozilla iceweasel\)|Oracle Java JRE Premier Support and Extended Support Version Detection|Oracle Java JRE Universally Enabled|Panda AdminSecure Communications Agent Detection|Patch Report|PCI DSS compliance : Insecure Communication Has Been Detected|Pervasive PSQL \/ Btrieve Server Detection|OSSIM Server Detection|POP Server Detection|PostgreSQL Server Detection|PPTP Detection|QuickTime for Windows Detection|Quote of the Day \(QOTD\) Service Detection|Reverse NAT\/Intercepting Proxy Detection|RMI Remote Object Detection|RPC rstatd Service Detection|rsync Service Detection|RTMP Server Detection|RTSP Server Type \/ Version Detection|Session Initiation Protocol Detection|SFTP Supported|Skype Detection|Skype for Mac Installed \(credentialed check\)|Skype Stack Version Detection|SLP Server Detection \(TCP\)|SLP Server Detection \(UDP\)|SMTP Authentication Methods|SMTP Server Detection|SNMP Protocol Version Detection|SNMP Query Installed Software Disclosure|SNMP Query Routing Information Disclosure|SNMP Query Running Process List Disclosure|SNMP Query System Information Disclosure|SNMP Request Network Interfaces Enumeration|Software Enumeration \(SSH\)|SSL Certificate Chain Contains Certificates Expiring Soon|SSL Certificate Chain Contains RSA Keys Less Than 2048 bits|SSL Certificate Chain Contains Unnecessary Certificates|SSL Certificate Chain Not Sorted|SSL Certificate commonName Mismatch|SSL Certificate Expiry - Future Expiry|Symantec pcAnywhere Detection \(TCP\)|Symantec pcAnywhere Status Service Detection \(UDP\)|TCP Channel Detection|Telnet Server Detection|TFTP Daemon Detection|Universal Plug and Play \(UPnP\) Protocol Detection|Unix Operating System on Extended Support|USB Drives Enumeration \(WMI\)|VMware Fusion Version Detection \(Mac OS X\)|WebDAV Detection|Web Server \/ Application favicon.ico Vendor Fingerprinting|Web Server Crafted Request Vendor/Version Information Disclosure|Web Server on Extended Support|Web Server SSL Port HTTP Traffic Detection|Web Server Unconfigured - Default Install Page Present|Web Server UPnP Detection|Windows Terminal Services Enabled|WINS Server Detection|X Font Service Detection)" tmp.csv > tmp2.csv

     # Delete additional findings.
	 egrep -v '(DHCP Server Detection|mDNS Detection \(Remote Network\))' tmp2.csv > tmp3.csv

cat tmp3.csv | sed 's/httpOnly/HttpOnly/g; s/Service Pack /SP/g; s/ (banner check)//; s/ (credentialed check)//; s/ (intrusive check)//g; s/ (remote check)//; s/ (safe check)//; s/ (uncredentialed check)//g; s/ (version check)//g; s/()//g; s/(un)//g' > /$user/data/nessus-`date +%H:%M:%S`.csv

     rm nessus* tmp*

     echo
     echo $medium
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/nessus-`date +%H:%M:%S`.csv
     echo
     echo
     exit
     ;;

     3)
     f_location
     parsers/parse-nexpose.py $location

     # Delete additional findings with CVSS score of 0
#     egrep -v '(NetBIOS NBSTAT Traffic Amplification)' nexpose.csv > tmp.csv
#     mv tmp.csv /$user/data/nexpose-`date +%H:%M:%S`.csv

     mv nexpose.csv /$user/data/nexpose-`date +%H:%M:%S`.csv

     echo
     echo $medium
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/nexpose-`date +%H:%M:%S`.csv
     echo
     echo
     exit
     ;;

     4)
     f_location
     cp $location ./nmap.xml
     parsers/parse-nmap.py
     mv nmap.csv /$user/data/nmap-`date +%H:%M:%S`.csv
     rm nmap.xml

     echo
     echo $medium
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/nmap-`date +%H:%M:%S`.csv
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
     mv qualys.csv /$user/data/qualys-`date +%H:%M:%S`.csv

     echo
     echo $medium
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/qualys-`date +%H:%M:%S`.csv
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

echo -e "\e[1;34mCheck for SSL certificate issues.\e[0m"
echo
echo "List of IP:port."
echo

f_location

echo
echo $medium
echo
echo "Running sslyze."
sslyze --targets_in=$location --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers > /$user/data/sslyze.txt
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
               echo -e "\e[1;31mCould not open a connection.\e[0m"
               echo "[*] Could not open a connection." >> ssl_$line
               echo >> ssl_$line
               echo $medium >> ssl_$line
               echo >> ssl_$line
               cat ssl_$line >> tmp
          fi
     else
          echo -e "\e[1;31mNo response.\e[0m"
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

mv tmp2 /$user/data/sslscan.txt

grep -v 'Issuer info not available.' tmp | grep -v 'Certificate subject info not available.' >> /$user/data/sslscan.txt

rm tmp* ssl_* 2>/dev/null

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
printf 'The new reports are located at \e[1;33m%s\e[0m\n' /$user/data/sslscan.txt

echo
echo -n "If your IPs are public, do you want to test them using an external source? (y/N) "
read extquery

if [ "$extquery" == "y" ]; then
     f_runlocally
     echo "Launching the browser, opening $number tabs, please wait..."
     processname='iceweasel'

     if ps ax | grep -v grep | grep $processname > /dev/null; then
          echo
     else
          iceweasel &
	     sleep 4
     fi

     while read -r line; do
	     iceweasel -new-tab "https://www.sslshopper.com/ssl-checker.html#hostname=$line" &
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

f_listener(){
clear

cp /opt/discover/resource/misc/listener.rc /tmp/

sed -i "s/#/$ip/g" /tmp/listener.rc

x=`ps aux | grep 'postgres' | grep -v 'grep'`

if [[ -z $x ]]; then
     echo
     service postgresql start
fi

echo
echo "Starting a Metasploit listener on port 443."
echo "Type - Windows meterpreter reverse TCP."
echo
echo "This takes about 20 seconds."
echo
msfconsole -r /tmp/listener.rc
}

##############################################################################################################

f_updates(){
# Remove entire script categories
ls -l /usr/share/nmap/scripts/ | awk '{print $9}' | cut -d '.' -f1 | egrep -v '(address-info|ajp-auth|ajp-headers|allseeingeye-info|asn-query|auth-owners|auth-spoof|broadcast|brute|citrix-enum-apps-xml|citrix-enum-servers-xml|creds-summary|daap-get-library|discover|dns-brute|dns-check-zone|dns-client-subnet-scan|dns-fuzz|dns-ip6-arpa-scan|dns-srv-enum|dns-nsec3-enum|domcon-cmd|duplicates|eap-info|firewalk|firewall-bypass|ftp-libopie|ganglia-info|ftp-libopie|ftp-vuln-cve2010-4221|hostmap-bfk|hostmap-ip2hosts|hostmap-robtex|http|iax2-version|informix-query|informix-tables|ip-forwarding|ip-geolocation-geobytes|ip-geolocation-geoplugin|ip-geolocation-ipinfodb|ip-geolocation-maxmind|ipidseq|ipv6-node-info|ipv6-ra-flood|irc-botnet-channels|irc-info|irc-unrealircd-backdoor|isns-info|jdwp-exec|jdwp-info|jdwp-inject|krb5-enum-users|ldap-novell-getpass|ldap-search|llmnr-resolve|metasploit-info|mmouse-exec|ms-sql-config|mrinfo|ms-sql-hasdbaccess|ms-sql-query|ms-sql-tables|ms-sql-xp-cmdshell|mtrace|murmur-version|mysql-audit|mysql-enum|mysql-dump-hashes|mysql-query|mysql-vuln-cve2012-2122|nat-pmp-info|nat-pmp-mapport|netbus-info|ntp-info|omp2-enum-targets|oracle-enum-users|ovs-agent-version|p2p-conficker|path-mtu|pjl-ready-message|quake1-info|quake3-info|quake3-master-getservers|qscan|resolveall|reverse-index|rpc-grind|rpcap-info|samba-vuln-cve-2012-1182|script|sip-call-spoof|skypev2-version|smb-flood|smb-ls|smb-print-text|smb-psexec|smb-vuln-ms10-054|smb-vuln-ms10-061|smtp-vuln-cve2010-4344|smtp-vuln-cve2011-1720|smtp-vuln-cve2011-1764|sniffer-detect|snmp-ios-config|socks-open-proxy|sql-injection|ssh-hostkey|ssh2-enum-algos|sshv1|ssl|stun-info|teamspeak2-version|tftp-enum|targets|tls-nextprotoneg|traceroute-geolocation|unittest|unusual-port|upnp-info|url-snarf|ventrilo-info|vuze-dht-info|weblogic-t3-info|whois|xmpp-info)' > tmp

grep 'script=' discover.sh | egrep -v '(discover.sh|22.txt|smtp.txt)' | cut -d '=' -f2- | cut -d ' ' -f1 | tr ',' '\n' | egrep -v '(db2-discover|dhcp-discover|dns-service-discovery|http-email-harvest|membase-http-info|oracle-sid-brute|smb-os-discovery|sslv2)' | sort -u > tmp2

echo "New modules to be added." > tmp-updates
echo >> tmp-updates
echo >> tmp-updates
echo "Nmap scripts" >> tmp-updates
echo "==============================" >> tmp-updates

diff tmp tmp2 | egrep '^[<>]' | awk '{print $2}' | sed '/^$/d' | egrep -v '(smtp-commands|smtp-enum-users|smtp-open-relay|smtp-strangeport|tmp)' >> tmp-updates

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

# Remove scanners not used
egrep -v '(ack|afp_login|arp_sweep|call_scanner|couchdb_enum|dvr_config_disclosure|endpoint_mapper|ftp_login|ftpbounce|hidden|ipidseq|ipv6_multicast_ping|ipv6_neighbor|ipv6_neighbor_router_advertisement|lotus_domino_login|management|mongodb_login|ms08_067_check|msf_rpc_login|msf_web_login|mysql_file_enum|mysql_hashdump|mysql_login|mysql_schemadump|natpmp_portscan|nessus_ntp_login|nessus_xmlrpc_login|nexpose_api_login|openvas_gsad_login|openvas_omp_login|openvas_otp_login|pcanywhere_login|poisonivy_control_scanner|pop3_login|recorder|rogue_recv|rogue_send|sipdroid_ext_enum|snmp_set|ssh_enumusers|ssh_identify_pubkeys|ssh_login|ssh_login_pubkey|station_scanner|syn|tcp|telnet_login|udp_probe|udp_sweep|vmauthd_login|vmware_http_login|wardial|winrm_cmd|winrm_login|winrm_wql|xmas)' tmp2 | sort > tmp-msf-all

grep 'use ' /opt/discover/resource/*.rc | grep -v 'recon-ng' > tmp

# Print from the last /, to the end of the line
sed -e 's:.*/\(.*\):\1:g' tmp > tmp-msf-used

grep -v -f tmp-msf-used tmp-msf-all >> tmp-updates

echo >> tmp-updates
echo >> tmp-updates
echo "recon-ng" >> tmp-updates
echo "==============================" >> tmp-updates
python /usr/share/recon-ng/recon-cli -M > tmp
egrep -v '(---|adobe|bozocrack|brute_suffix|census_2012|command_injector|dev_diver|Discovery|exit|Exploitation|geocode|hashes_org|Import|import|jigsaw|leakdb|mangle|namechk|pushpins|pwnedlist|Recon|Reporting|reporting|reverse_resolve|show modules|shodan_net|Spooling|twitter|xpath_bruter)' tmp > tmp2

# Remove blank lines
sed '/^$/d' tmp2 > tmp3
# Remove leading whitespace from each line
sed 's/^[ \t]*//' tmp3 > tmp4

cat /opt/discover/resource/recon-ng/active.rc /opt/discover/resource/recon-ng/passive.rc | grep 'use' | sed 's/use //g' | sort > tmp5
diff tmp4 tmp5 | egrep '^[<>]' | awk '{print $2}' | egrep -v '(ip_neighbor|pwnedlist)' >> tmp-updates

echo >> tmp-updates
echo >> tmp-updates

mv tmp-updates /$user/data/updates.txt
rm tmp*

echo
echo $medium
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/data/updates.txt
echo
echo
exit
}

##############################################################################################################

f_recon-ng(){
clear
f_banner

echo "For best results, you should acquire keys to the following APIs and add them to recon-ng."
echo "See: https://bitbucket.org/LaNMaSteR53/recon-ng/wiki/Usage%20Guide"
echo
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
if [ -z $company ]; then
     f_error
fi

echo -n "Domain:  "
read domain

# Check for no answer
if [ -z $domain ]; then
     f_error
fi

cp /opt/discover/resource/recon-ng/passive.rc /tmp/
sed -i "s/xxx/$company/g" /tmp/passive.rc
sed -i "s/yyy/$domain/g" /tmp/passive.rc

recon-ng -r /tmp/passive.rc
}

##############################################################################################################

f_parse_recon_ng(){
clear
f_banner

python /usr/share/recon-ng/recon-cli -C "workspaces list"
echo
echo
echo -n "Workspace:  "
read workspace

# Check for no answer
if [ -z $workspace ]; then
     f_error
fi

recon-ng -w $workspace -r /opt/discover/resource/recon-ng/export.rc
egrep -v '(\+|contacts|Output|output|returned|show|Spooling|spool|title)' tmp | cut -d '|' -f3,5-7 | sed 's/BuiltWith contact//g; s/Employee//g; s/PGP key association//g; s/Whois contact//g' > zcontacts
egrep -v '(\+|contacts|Output|output|returned|show|Spooling|spool|title)' tmp2 | cut -d '|' -f3-7 > zcreds
egrep -v '(\+|contacts|Output|output|returned|show|Spooling|spool|title)' tmp3 | cut -d '|' -f3-6 > zhosts
egrep -v '(\+|contacts|Output|output|returned|show|Spooling|spool|title)' tmp4 > zleaks
egrep -v '(\+|contacts|Output|output|returned|show|Spooling|spool|title)' tmp5 | cut -d '|' -f3-6 > zports
egrep -v '(\+|contacts|example|Output|output|returned|show|Spooling|spool|title)' tmp6 | cut -d '|' -f5 > zvulns
rm tmp*
echo
echo
exit
}

##############################################################################################################

f_main(){
clear
f_banner

if [ ! -d /$user/data ]; then
     mkdir -p /$user/data
fi

echo -e "\e[1;34mRECON\e[0m"
echo "1.  Domain"
echo "2.  Person"
echo "3.  Parse salesforce"
echo
echo -e "\e[1;34mSCANNING\e[0m"
echo "4.  Generate target list"
echo "5.  CIDR"
echo "6.  List"
echo "7.  IP, Range or URL"
echo
echo -e "\e[1;34mWEB\e[0m"
echo "8.  Open multiple tabs in Iceweasel"
echo "9.  Nikto"
echo "10. SSL"
echo
echo -e "\e[1;34mMISC\e[0m"
echo "11. Crack WiFi"
echo "12. Parse XML"
echo "13. Start a Metasploit listener"
echo "14. Update"
echo "15. Exit"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_domain;;
     2) f_person;;
     3) f_salesforce;;
     4) f_generateTargetList;;
     5) f_cidr;;
     6) f_list;;
     7) f_single;;
     8) f_multitabs;;
     9) f_nikto;;
     10) f_ssl;;
     11) f_runlocally && /opt/discover/crack-wifi.sh;;
     12) f_parse;;
     13) f_listener;;
     14) /opt/discover/update.sh && exit;;
     15) clear && exit;;
     97) f_parse_recon_ng;;
     98) f_recon-ng;;
     99) f_updates;;
     *) f_error;;
esac
}

##############################################################################################################

while true; do f_main; done
