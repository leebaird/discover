#!/bin/bash
#
# By Lee Baird
# Feel free to contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
# Special thanks to the following people:
#
# Jay Townsend - conversion of discover.sh to Kali.
# Jason Arnold - planning original concept, author of ssl-check and co-author of crack-wifi.
# Dave Klug - planning, testing and bug reports.
# Matt Banick - original development.
# Eric Milam - total re-write using functions.
# Martin Bos - IDS evasion techniques.
# Numerous people on freenode IRC - #bash and #sed (e36freak)
# Ben Wood - regex master
# Rob Dixon - report framework idea
# Steve Copland - report framework design

##############################################################################################################

# Variables
distro=$(uname -n)
interface=$(ifconfig | grep -B10 'Loopback'| grep 'Ethernet' | cut -d ' ' -f1)
ip=$(ifconfig | grep -B10 'Loopback' | grep 'Bcast' | cut -d ':' -f2 | cut -d ' ' -f1)
line="======================================================================"
user=$(whoami)

# Catch ctrl+c from user
trap f_terminate 2

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
echo -e "\e[1;31m$line\e[0m"
echo
echo -e "\e[1;31m                  *** Invalid choice or entry. ***\e[0m"
echo
echo -e "\e[1;31m$line\e[0m"
sleep 2
f_main
}

##############################################################################################################

f_location(){
echo
echo -n "Enter the location of your list: "
read location

# Check for no answer
if [ -z $location ]; then
     f_error
fi

# Check for wrong answer
if [ ! -f $location ]; then
     f_error
fi
}

##############################################################################################################

f_runlocally(){
if [ -z $DISPLAY ]; then
     clear
     f_banner
     echo
     echo $line
     echo
     echo "This option must be run locally, in an X-Windows environment."
     echo
     read -p "Press <return> to continue."

     f_main
fi
}

##############################################################################################################

f_terminate(){
rm emails names squatting whois* subdomain* doc pdf ppt txt xls tmp* z* 2>/dev/null

if [ -f $name ]; then
     rm -rf $name
fi

PID=$(ps -ef | grep 'discover.sh' | grep -v 'grep' | awk '{print $2}')
kill -9 $PID

echo
echo
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
     echo $line
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
     if [ ! -d /$user/$domain ]; then
          cp -R /opt/scripts/report/ /$user/$domain
          sed 's/REPLACEDOMAIN/'$domain'/g' /$user/$domain/index.htm > tmp
          mv tmp /$user/$domain/index.htm
     fi

     # Number of tests
     total=23

     echo
     echo $line
     echo

     echo "goofile                   (1/$total)"
     python /pentest/enumeration/google/goofile/goofile.py -d $domain -f doc > tmp
     python /pentest/enumeration/google/goofile/goofile.py -d $domain -f docx >> tmp
     python /pentest/enumeration/google/goofile/goofile.py -d $domain -f pdf >> tmp
     python /pentest/enumeration/google/goofile/goofile.py -d $domain -f ppt >> tmp
     python /pentest/enumeration/google/goofile/goofile.py -d $domain -f pptx >> tmp
     python /pentest/enumeration/google/goofile/goofile.py -d $domain -f txt >> tmp
     python /pentest/enumeration/google/goofile/goofile.py -d $domain -f xls >> tmp
     python /pentest/enumeration/google/goofile/goofile.py -d $domain -f xlsx >> tmp

     grep $domain tmp | grep -v 'Searching in' | grep -Fv '...' | sort > tmp2

     grep '.doc' tmp2 | egrep -v '(.pdf|.ppt|.xls)' > doc
     grep '.pdf' tmp2 > pdf
     grep '.ppt' tmp2 > ppt
     grep '.txt' tmp2 | grep -v 'robots.txt' > txt
     grep '.xls' tmp2 > xls

     echo
     echo "goog-mail                 (2/$total)"
     /opt/scripts/mods/goog-mail.py $domain | sort -u > tmp
     grep -Fv '..' tmp > tmp2
     # Remove lines that start with a number
     sed '/^[0-9]/d' tmp2 > tmp3
     # Change to lower case
     cat tmp3 | tr '[A-Z]' '[a-z]' > tmp4
     # Remove blank lines
     sed '/^$/d' tmp4 > zgoog-mail

     echo
     echo "goohost"
     echo "     IP                   (3/$total)"
     /pentest/enumeration/google/goohost/goohost.sh -t $domain -m ip >/dev/null
     echo "     Email                (4/$total)"
     /pentest/enumeration/google/goohost/goohost.sh -t $domain -m mail >/dev/null
     cat report-* > tmp
     # Move the second column to the first position
     grep $domain tmp | awk '{ print $2 " " $1 }' > tmp2
     column -t tmp2 > zgoohost
     rm *-$domain.txt

     echo
     echo "theHarvester"
     echo "     123people            (5/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b people123 > z123people
     echo "     Ask-mod              (6/$total)"
     /opt/scripts/mods/theHarvester2.py -d $domain -b ask > zask-mod
     echo "     Bing                 (7/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b bing > zbing
     echo "     Google               (8/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b google > zgoogle
     echo "     Google Profiles	  (9/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b google-profiles > zgoogle-profiles
     echo "     Jigsaw               (10/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b jigsaw > zjigsaw
     echo "     LinkedIn             (11/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b linkedin > zlinkedin
     echo "     Login-mod            (12/$total)"
     /opt/scripts/mods/theHarvester2.py -d $domain -b login > zlogin-mod
     echo "     PGP                  (13/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b pgp > zpgp
     echo "     Yahoo-mod            (14/$total)"
     /opt/scripts/mods/theHarvester2.py -d $domain -b yahoo > zyahoo-mod
     echo "     All                  (15/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b all > zall

     echo
     echo "Metasploit                (16/$total)"
     /opt/metasploit/msf3/msfcli gather/search_email_collector DOMAIN=$domain E > tmp 2>/dev/null
     grep @$domain tmp | awk '{print $2}' | grep -v '%' | grep -Fv '...@' | sort -u > tmp2
     # Change to lower case
     cat tmp2 | tr '[A-Z]' '[a-z]' > tmp3
     # Remove blank lines
     sed '/^$/d' tmp3 > zmsf

     echo
     echo "dnsrecon                  (17/$total)"
     /pentest/enumeration/dns/dnsrecon/dnsrecon.py -d $domain -t goo > tmp
     grep $domain tmp | egrep -v '(Performing Google|Records Found)' > tmp2
     # Remove first 6 characters from each line
     sed 's/^......//' tmp2 > tmp3
     sed 's/A //g' tmp3 | sed 's/CNAME //g' | column -t | sort -u > subdomains1.txt

     echo
     echo "URLCrazy                  (18/$total)"
	/pentest/enumeration/web/urlcrazy/urlcrazy $domain -o tmp > /dev/null
     # Clean up
     egrep -v '(#|:|\?|Typo Type|URLCrazy)' tmp | sed 's/[A-Z]\{2\},//g' > tmp2
     # Remove lines that start with -
     grep -v '^-' tmp2 > tmp3
     # Remove blank lines
     sed '/^$/d' tmp3 > tmp4
     sed 's/BAHAMAS/Bahamas/g; s/BELGIUM/Belgium/g; s/CANADA/Canada/g; s/CHINA/China/g; s/GERMANY/Germany/g; s/IRELAND/Ireland/g; s/ITALY/Italy/g; s/JAPAN/Japan/g; s/KOREA REPUBLIC OF/Republic of Korea/g; s/NETHERLANDS/Netherlands/g; s/NORWAY/Norway/g; s/RUSSIAN FEDERATION/Russia/g; s/SPAIN/Spain/g; s/SWEDEN/Sweden/g; s/SWITZERLAND/Switzerland/g; s/UNITED KINGDOM/United Kingdom/g; s/UNITED STATES/United States/g' tmp4 > squatting

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
     egrep -v '(academy|account|active|administrator|administrative|advanced|adventure|advertising|america|american|analysis|analyst|antivirus|apple seems|application|applications|architect|article|asian|associate|association|attorney|australia|automation|automotive|balance|bank|bbc|beginning|berlin|beta theta|between|big game|billion|bioimages|biometrics|bizspark|breaches|broker|business|buyer|buying|california|cannot|capital|career|carrying|cashing|certified|challenger|championship|change|chapter|charge|china|chinese|clearance|cloud|code|college|columbia|communications|community|company pages|competition|competitive|compliance|computer|concept|conference|config|connections|construction|consultant|contributor|controllang|cooperation|coordinator|corporation|creative|croatia|crm|dallas|day care|death toll|delta|department|description|designer|detection|developer|develop|development|devine|digital|diploma|director|disability|disaster|disclosure|dispute|division|dos poc|download|drivers|during|economy|ecovillage|editor|education|effect|electronic|emails|embargo|empower|end user|energy|engineer|enterprise|entertainment|entreprises|entrepreneur|environmental|error page|ethical|example|excellence|executive|expertzone|exploit|facebook|faculty|fall edition|fast track|fatherhood|fbi|federal|filmmaker|finance|financial|forensic|found|freelance|from|frontiers in tax|full|fuzzing|germany|get control|global|google|government|graphic|greater|group|guardian|hackers|hacking|harden|harder|hawaii|hazing|headquarters|health|help|history|homepage|hospital|house|how to|hurricane|icmp|idc|in the news|index|informatics|information|innovation|installation|insurers|integrated|international|internet|instructor|insurance|investigation|investment|investor|israel|japan|job|justice|kelowna|knowing|laptops|letter|licensing|lighting|limitless|liveedu|llp|ltd|lsu|luscous|malware|managed|management|manager|managing|manufacturing|marketplace|mastering|md|media|medical|medicine|meta tags|methane|metro|microsoft|middle east|mitigation|money|monitor|more coming|museums|negative|network|network|new user|newspaper|new york|next page|nitrogen|nyc|obtain|occupied|offers|office|online|organizational|outbreak|owners|partner|pathology|people|perceptions|philippines|photo|picture|places|planning|portfolio|potential|preparatory|president|principal|print|private|process|producer|product|professional|professor|profile|project|publichealth|published|pyramid|questions|redeem|redirect|register|registry|regulation|rehab|remote|report|republic|research|resolving|revised|rising|rural health|sales|satellite|save the date|school|scheduling|science|search|searc|secured|security|secretary|secrets|see more|selection|senior|server|service|services|software|solutions|source|special|station home|statistics|strategy|student|successful|superheroines|supervisor|support|switch|system|systems|targeted|tcp|technical|technology|tester|textoverflow|theater|time in|tit for tat|title|toolbook|tools|traditions|trafficking|transfer|treasury|trojan|twitter|training|ts|tylenol|types of scams|unclaimed|underground|university|united states|untitled|view|Violent|virginia bar|voice|volkswagen|volume|wanted|web search|web site|website|welcome|west virginia|when the|whiskey|windows|workers|world|www|xbox)' tmp7 > tmp8
     # Remove leading and trailing whitespace from each line
     sed 's/^[ \t]*//;s/[ \t]*$//' tmp8 > tmp9
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp9 > tmp10
     # Clean up
     sed 's/\..../ /g' tmp10 | sed 's/\.../ /g' | sed 's/iii/III/g' | sed 's/ii/II/g' > tmp11
     # Capitalize the first letter of every word, print last name then first name
     sed 's/\b\(.\)/\u\1/g' tmp11 | awk '{print $2", "$1}' | sort -u > names

     ##############################################################

     cat z* | grep @$domain | grep -vF '...' | egrep -v '(\*|=|\+|\[|\||;|:|"|<|>|/|\?)' > tmp
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp > tmp2
     # Change to lower case
     cat tmp2 | tr '[A-Z]' '[a-z]' > tmp3
     # Clean up
     egrep -v '(web search|www)' tmp3 | sort -u > emails

     ##############################################################

     cat z* | sed '/^[0-9]/!d' | grep -v '@' > tmp
     # Substitute a space for a colon
     sed 's/:/ /g' tmp > tmp2
     # Move the second column to the first position
     awk '{ print $2 " " $1 }' tmp2 > tmp3
     column -t tmp3 > tmp4
     # Change to lower case
     cat tmp4 | tr '[A-Z]' '[a-z]' > tmp5
     grep $domain tmp5 | sort -u > subdomains2.txt
     cat subdomain* | grep -v "$domain\." | egrep -v '(.nat.|252f)' | sed 's/www\.//g' | column -t | sort -u > subdomains

     ##############################################################

     echo
     echo "Whois"
     echo "     Domain               (19/$total)"
     whois -H $domain > tmp
     # Remove leading whitespace
     sed 's/^[ \t]*//' tmp > tmp2
     # Clean up
     egrep -v '(%|<a|=-=-=-=|Access may be|Additionally|Afilias except|and DNS Hosting|and limitations of|any use of|Be sure to|By submitting an|by the terms|can easily change|circumstances will|clientDeleteProhibited|clientTransferProhibited|clientUpdateProhibited|complaint will|contact information|Contact us|Copy and paste|currently set|database|data contained in|data presented in|date of|dissemination|Domaininfo AB|Domain Management|Domain names in|Domain status: ok|enable high|except as reasonably|failure to|facsimile of|for commercial purpose|for detailed information|For information for|for information purposes|for the sole|Get Noticed|Get a FREE|guarantee its|HREF|In Europe|In most cases|in obtaining|in the address|includes restrictions|including spam|information is provided|is not the|is providing|Learn how|Learn more|makes this information|MarkMonitor|mining this data|minute and one|modify existing|modify these terms|must be sent|name cannot|NamesBeyond|not to use|Note: This|NOTICE|obtaining information about|of Moniker|of this data|or hiding any|or otherwise support|other use of|own existing customers|Please be advised|Please note|policy|prior written consent|privacy is|Professional and|prohibited without|Promote your|protect the|Public Interest|queries or|Register your|Registrars|registration record|repackaging,|responsible for|See Business Registration|server at|solicitations via|sponsorship|Status|support the transmission|telephone, or facsimile|that apply to|that you will|the right| The data is|The fact that|the transmission|The Trusted Partner|This listing is|This feature is|This information|This service is|to collect or|to entities|to report any|transmission of mass|UNITED STATES|United States|unsolicited advertising|Users may|Version 6|via e-mail|Visit AboutUs.org|while believed|will use this|with many different|with no guarantee|We reserve the|Whois|you agree|You may not)' tmp2 > tmp3
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
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp12 > whois-domain

     echo "     IP 		  (20/$total)"
     y=$(ping -c1 -w2 $domain | grep 'PING' | cut -d ')' -f1 | cut -d '(' -f2) ; whois -H $y > tmp
     # Remove leading whitespace
     sed 's/^[ \t]*//' tmp > tmp2
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp2 > tmp3
     # Clean up
     egrep -v '(\#|\%|\*|All reports|Comment|dynamic hosting|For fastest|For more|Found a referral|http|OriginAS:$|Parent:$|point in|RegDate:$|The activity|the correct|Without these)' tmp3 > tmp4
     # Remove leading whitespace from file
     awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp4 > tmp5
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp5 > tmp6
     # Compress blank lines
     cat -s tmp6 > tmp7
     # Clean up
     sed 's/+1-//g' tmp7 > whois-ip
     echo

     # Remove all empty files
     find -type f -empty -exec rm {} +

     echo "dnssy.com                 (21/$total)"
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
     s/Your SOA/SOA/g; s/Your web server/The web server/g; s/Your web server says it is://g' tmp3 > /$user/$domain/data/config.htm

     echo "robtex.com                (22/$total)"
     wget -q http://top.robtex.com/$domain.html#records -O robtex-records.htm
     wget -q http://top.robtex.com/$domain.html#shared -O robtex-shared.htm

     x=$(ls -l | grep 'robtex' | awk '{print $5,$8}' | sort | head -1 | awk '{print $2}')
     mv $x tmp

     sed '/<!DOCTYPE html>/,/<div id="c0a">/d' tmp | sed '/nopad sortable nospan/,/<\/html>/d' | sed '/<div id="c0b1">/,/DNS Records/d' | sed 's/<h2 class="h2s">Graph<\/h2>//g; s/<h2 class="h2s">Shared<\/h2>//g; s/"7.00"/"10.00"/g; s/"9.00"/"12.00"/g' > tmp2

     echo "          </div>" >> tmp2
     echo "     </div>" >> tmp2
     echo "</div>" >> tmp2
     echo "" >> tmp2
     echo "</body>" >> tmp2
     echo "" >> tmp2
     echo "</html>" >> tmp2

     cat tmp2 >> /$user/$domain/pages/robtex.htm

     echo "urlvoid.com               (23/$total)"
     wget -q http://www.urlvoid.com/scan/$domain -O tmp
     sed -n '/Website Blacklist Report/,/<\/table>/p' tmp > tmp2
     sed 's/<img src="http:\/\/www.urlvoid.com\/images\/valid.ico" alt="Clean" title="Clean" \/> NOT FOUND/<center><img src="..\/images\/icons\/green.png" height="25" width="25"><\/center>/g; s/<img src="http:\/\/www.urlvoid.com\/images\/alert.ico" alt="Alert" title="Detected!" \/> <font color="red">DETECTED<\/font>/<center><img src="..\/images\/icons\/red.png" height="25" width="25"><\/center>/g; s/rel="nofollow" //g; s/ title="View more details" target="_blank"//g; s/<img src="http:\/\/www.urlvoid.com\/images\/link.ico" alt="Link" \/>//g; s/ class="tasks"//g; s/<th>Info<\/th>//g' tmp2 | grep -v 'Blacklist Report' > tmp3
     # Remove leading whitespace from each line
     sed 's/^[ \t]*//' tmp3 > /$user/$domain/data/black-listed.htm

     awk '{print $2}' subdomains > tmp
     grep -E '([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})' tmp | sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 > hosts 
     cat hosts >> /$user/$domain/data/hosts.htm; echo "</pre>" >> /$user/$domain/data/hosts.htm

     ##############################################################

     echo "Passive Recon" > zreport
     echo $domain >> zreport
     date +%A" - "%B" "%d", "%Y >> zreport
     echo >> zreport
     echo >> zreport

     echo "Summary" >> zreport
     echo $line >> zreport

     echo > tmp

     if [ -f emails ]; then
          emailcount=$(wc -l emails | cut -d ' ' -f1)
          echo "Emails        $emailcount" >> zreport
          echo "Emails ($emailcount)" >> tmp
          echo $line >> tmp
          cat emails >> tmp
          echo >> tmp
     fi

     if [ -f names ]; then
          namecount=$(wc -l names | cut -d ' ' -f1)
          echo "Names         $namecount" >> zreport
          echo "Names ($namecount)" >> tmp
          echo $line >> tmp
          cat names >> tmp
          echo >> tmp
     fi

     if [ -f hosts ]; then
          hostcount=$(wc -l hosts | cut -d ' ' -f1)
          echo "Hosts         $hostcount" >> zreport
          echo "Hosts ($hostcount)" >> tmp
          echo $line >> tmp
          cat hosts >> tmp
          echo >> tmp
     fi

     if [ -f squatting ]; then
          urlcount2=$(wc -l squatting | cut -d ' ' -f1)
          echo "Squatting     $urlcount2" >> zreport
          echo "Squatting ($urlcount2)" >> tmp
          echo $line >> tmp
          cat squatting >> tmp
          echo >> tmp
     fi

     if [ -f subdomains ]; then
          urlcount=$(wc -l subdomains | cut -d ' ' -f1)
          echo "Subdomains    $urlcount" >> zreport
          echo "Subdomains ($urlcount)" >> tmp
          echo $line >> tmp
          cat subdomains >> tmp
          echo >> tmp
     fi

     if [ -f xls ]; then
          xlscount=$(wc -l xls | cut -d ' ' -f1)
          echo "Excel         $xlscount" >> zreport
          echo "Excel Files ($xlscount)" >> tmp
          echo $line >> tmp
          cat xls >> tmp
          echo >> tmp
          cat xls >> /$user/$domain/data/xls.htm; echo "</pre>" >> /$user/$domain/data/xls.htm
     fi

     if [ -f pdf ]; then
          pdfcount=$(wc -l pdf | cut -d ' ' -f1)
          echo "PDF           $pdfcount" >> zreport
          echo "PDF Files ($pdfcount)" >> tmp
          echo $line >> tmp
          cat pdf >> tmp
          echo >> tmp
          cat pdf >> /$user/$domain/data/pdf.htm; echo "</pre>" >> /$user/$domain/data/pdf.htm
     fi

     if [ -f ppt ]; then
          pptcount=$(wc -l ppt | cut -d ' ' -f1)
          echo "PowerPoint    $pptcount" >> zreport
          echo "PowerPoint Files ($pptcount)" >> tmp
          echo $line >> tmp
          cat ppt >> tmp
          echo >> tmp
          cat ppt >> /$user/$domain/data/ppt.htm; echo "</pre>" >> /$user/$domain/data/ppt.htm
     fi

     if [ -f txt ]; then
          txtcount=$(wc -l txt | cut -d ' ' -f1)
          echo "Text          $txtcount" >> zreport
          echo "Text Files ($txtcount)" >> tmp
          echo $line >> tmp
          cat txt >> tmp
          echo >> tmp
          cat txt >> /$user/$domain/data/txt.htm; echo "</pre>" >> /$user/$domain/data/txt.htm
     fi

     if [ -f doc ]; then
          doccount=$(wc -l doc | cut -d ' ' -f1)
          echo "Word          $doccount" >> zreport
          echo "Word Files ($doccount)" >> tmp
          echo $line >> tmp
          cat doc >> tmp
          echo >> tmp
          cat doc >> /$user/$domain/data/doc.htm; echo "</pre>" >> /$user/$domain/data/doc.htm
     fi

     cat tmp >> zreport
     echo "Whois Domain" >> zreport
     echo $line >> zreport
     cat whois-domain >> zreport

     echo >> zreport
     echo "Whois IP" >> zreport
     echo $line >> zreport
     cat whois-ip >> zreport

     cat emails >> /$user/$domain/data/emails.htm; echo "</pre>" >> /$user/$domain/data/emails.htm
     cat names >> /$user/$domain/data/names.htm; echo "</pre>" >> /$user/$domain/data/names.htm
     cat squatting >> /$user/$domain/data/squatting.htm; echo "</pre>" >> /$user/$domain/data/squatting.htm
     cat subdomains >> /$user/$domain/data/subdomains.htm; echo "</pre>" >> /$user/$domain/data/subdomains.htm
     cat whois-domain >> /$user/$domain/data/whois-domain.htm; echo "</pre>" >> /$user/$domain/data/whois-domain.htm
     cat whois-ip >> /$user/$domain/data/whois-ip.htm; echo "</pre>" >> /$user/$domain/data/whois-ip.htm
     cat zreport >> /$user/$domain/data/passive-recon.htm; echo "</pre>" >> /$user/$domain/data/passive-recon.htm

     rm emails hosts names robtex* squatting subdomains* tmp* whois* z* doc pdf ppt txt xls 2>/dev/null

     echo
     echo $line
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The supporting data folder is located at \e[1;33m%s\e[0m\n' /$user/$domain/
     echo
     read -p "Press <return> to continue."

     ##############################################################

     f_runlocally

     firefox &
     sleep 4
     firefox -new-tab images.google.com &
     sleep 1
     firefox -new-tab arin.net &
     sleep 1
     firefox -new-tab toolbar.netcraft.com/site_report?url=http://www.$domain &
     sleep 1
     firefox -new-tab shodanhq.com/search?q=$domain &
     sleep 1
     firefox -new-tab jigsaw.com/ &
     sleep 1
     firefox -new-tab pastebin.com/ &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Axls+OR+filetype%3Axlsx+site%3A$domain &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Appt+OR+filetype%3Apptx+site%3A$domain &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Adoc+OR+filetype%3Adocx+site%3A$domain &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Apdf+site%3A$domain &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Atxt+site%3A$domain &
     sleep 1
     firefox -new-tab http://www.urlvoid.com/scan/$domain &
     sleep 1
     firefox -new-tab sec.gov/edgar/searchedgar/companysearch.html &
     sleep 1
     firefox -new-tab google.com/finance/ &
     sleep 1
     firefox -new-tab reuters.com/finance/stocks
     echo
     echo
     exit
     ;;

     2)
     echo
     echo $line
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
     if [ ! -d /$user/$domain ]; then
          cp -R /opt/scripts/report/ /$user/$domain
          sed 's/REPLACEDOMAIN/'$domain'/' /$user/$domain/index.htm > tmp
          mv tmp /$user/$domain/index.htm
     fi

     # Number of tests
     total=11

     echo
     echo $line
     echo

     echo "Nmap"
     echo "     Email                (1/$total)"
     nmap -Pn -n --open -p80 --script=http-email-harvest --script-args=http-email-harvest.maxpagecount=100,http-email-harvest.maxdepth=10 $domain > tmp
     grep @$domain tmp | grep -v '%20' | grep -v 'jpg' | awk '{print $2}' > tmp2
     # Change to lower case
     cat tmp2 | tr '[A-Z]' '[a-z]' | sort -u > emails1

     # Check if file is empty
     if [ ! -s emails1 ]; then
          rm emails1
     fi

     echo
     echo "dnsrecon"
     echo "     DNS Records          (2/$total)"
     /pentest/enumeration/dns/dnsrecon/dnsrecon.py -d $domain -t std > tmp
     egrep -v '(Bind Version for|Could not|Enumerating SRV|not configured|Performing|Records Found|Recursion|Resolving|TXT)' tmp > tmp2
     # Remove first 6 characters from each line
     sed 's/^......//' tmp2 | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10}' | column -t | sort -u -k2 -k1 > tmp3
     grep 'TXT' tmp | sed 's/^......//' | awk '{print $2,$1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15}' >> tmp3
     egrep -v '(SEC3|SKEYs|SSEC)' tmp3 > records
     cat /$user/$domain/data/records.htm records | grep -v '<' | column -t | sort -u -k2 -k1 > tmp3

     echo '<pre style="font-size:14px;">' > /$user/$domain/data/records.htm
     cat tmp3 >> /$user/$domain/data/records.htm; echo "</pre>" >> /$user/$domain/data/records.htm

     echo "     Zone Transfer        (3/$total)"
     /pentest/enumeration/dns/dnsrecon/dnsrecon.py -d $domain -t axfr > tmp
     egrep -v '(Checking for|Failed|filtered|NS Servers|Removing|TCP Open|Testing NS)' tmp | sed 's/^....//' | sed /^$/d > zonetransfer

     echo "     Sub-domains (~5 min) (4/$total)"
     /pentest/enumeration/dns/dnsrecon/dnsrecon.py -d $domain -t brt -D /pentest/enumeration/dns/dnsrecon/namelist.txt --iw -f > tmp
     grep $domain tmp | grep -v "$domain\." | egrep -v '(Performing|Records Found)' | sed 's/\[\*\] //g' | sed 's/^[ \t]*//' | awk '{print $2,$3}' | column -t | sort -u > subdomains-dnsrecon

     echo
     echo "Fierce (~5 min)           (5/$total)"
     /pentest/enumeration/dns/fierce/fierce.pl -dns $domain -wordlist /pentest/enumeration/dns/fierce/hosts.txt -suppress -file tmp4

     sed -n '/Now performing/,/Subnets found/p' tmp4 | grep $domain | awk '{print $2 " " $1}' | column -t | sort -u > subdomains-fierce

     cat subdomains-dnsrecon subdomains-fierce | grep -v '.nat.' | column -t | sort -u > subdomains

     if [ -f /$user/$domain/data/subdomains.htm ]; then
          cat /$user/$domain/data/subdomains.htm subdomains | grep -v "<" | grep -v "$domain\." | column -t | sort -u > subdomains-combined
          echo '<pre style="font-size:14px;">' > /$user/$domain/data/subdomains.htm
          cat subdomains-combined >> /$user/$domain/data/subdomains.htm; echo "</pre>" >> /$user/$domain/data/subdomains.htm
     fi

     awk '{print $3}' records > tmp
     awk '{print $2}' subdomains-dnsrecon subdomains-fierce >> tmp
     grep -E '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}' tmp | egrep -v '(-|:|127.0.0.1)' | sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 > hosts

     echo
     echo "Loadbalancing             (6/$total)"
     /pentest/enumeration/web/lbd/lbd.sh $domain > tmp 2>/dev/null
     egrep -v '(Checks if a given|Written by|Proof-of-concept)' tmp > tmp2
     # Remove leading whitespace from file
     awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp2 > tmp3
     # Remove leading whitespace from each line
     sed 's/^[ \t]*//' tmp3 > tmp4
     egrep -v '(does Load-balancing|does NOT use Load-balancing)' tmp4 | sed 's/Checking for //g' > tmp5
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp5 > tmp6
     # Clean up
     cat -s tmp6 > loadbalancing

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
     grep -v '<' /$user/$domain/data/subdomains.htm | awk '{print $1}' > tmp
     /pentest/enumeration/web/whatweb/whatweb -i tmp --color=never --no-errors -t 255 > tmp2
     # Find lines that start with http, and insert a line after
     sort tmp2 | sed '/^http/a\ ' > tmp3
     # Cleanup
     sed 's/,/\n/g' tmp3 | sed 's/^[ \t]*//' | sed 's/\(\[[0-9][0-9][0-9]\]\)/\n\1/g' | sed 's/http:\/\///g' | grep -v 'Country' > whatweb

     grep '@' whatweb | sed 's/Email//g' | sed 's/\[//g' | sed 's/\]//g' > emails2
     cat emails1 emails2 | sort -u > emails

     ##############################################################

     echo "Active Recon" > zreport
     echo $domain >> zreport
     date +%A" - "%B" "%d", "%Y >> zreport
     echo >> zreport
     echo >> zreport

     echo "Summary" >> zreport
     echo $line >> zreport

     echo > tmp

     if [ -f /opt/scripts/emails ]; then
          emailcount=$(wc -l emails | cut -d ' ' -f1)
          echo "Emails        $emailcount" >> zreport
          echo "Emails ($emailcount)" >> tmp
          echo $line >> tmp
          cat emails >> tmp
          echo >> tmp
     fi

     if [ -f /opt/scripts/hosts ]; then
          hostcount=$(wc -l hosts | cut -d ' ' -f1)
          echo "Hosts         $hostcount" >> zreport
          echo "Hosts ($hostcount)" >> tmp
          echo $line >> tmp
          cat hosts >> tmp
          echo >> tmp
     fi

     if [ -f /opt/scripts/records ]; then
          recordcount=$(wc -l records | cut -d ' ' -f1)
          echo "DNS Records   $recordcount" >> zreport
          echo "DNS Records ($record         count)" >> tmp
          echo $line >> tmp
          cat records >> tmp
          echo >> tmp
     fi

     if [ -f /opt/scripts/subdomains ]; then
          subdomaincount=$(wc -l subdomains | cut -d ' ' -f1)
          echo "Subdomains    $subdomaincount" >> zreport
          echo "Subdomains ($subdomaincount)" >> tmp
          echo $line >> tmp
          cat subdomains >> tmp
          echo >> tmp
     fi

     cat tmp >> zreport

     echo "Loadbalancing" >> zreport
     echo $line >> zreport
     cat loadbalancing >> zreport

     echo >> zreport
     echo "Web Application Firewall" >> zreport
     echo $line >> zreport
     cat waf >> zreport

     echo >> zreport
     echo "Traceroute" >> zreport
     echo $line >> zreport
     cat ztraceroute >> zreport

     echo >> zreport
     echo "Zone Transfer" >> zreport
     echo $line >> zreport
     cat zonetransfer >> zreport

     echo >> zreport
     echo "Whatweb" >> zreport
     echo $line >> zreport
     cat whatweb >> zreport

     cat loadbalancing >> /$user/$domain/data/loadbalancing.htm; echo "</pre>" >> /$user/$domain/data/loadbalancing.htm
     cat zreport >> /$user/$domain/data/active-recon.htm; echo "</pre>" >> /$user/$domain/data/active-recon.htm
     cat ztraceroute >> /$user/$domain/data/traceroute.htm; echo "</pre>" >> /$user/$domain/data/traceroute.htm
     cat waf >> /$user/$domain/data/waf.htm; echo "</pre>" >> /$user/$domain/data/waf.htm
     cat whatweb >> /$user/$domain/data/whatweb.htm; echo "</pre>" >> /$user/$domain/data/whatweb.htm
     cat zonetransfer >> /$user/$domain/data/zonetransfer.htm; echo "</pre>" >> /$user/$domain/data/zonetransfer.htm

     if [[ -f /$user/$domain/data/emails.htm && -f emails ]]; then
          cat /$user/$domain/data/emails.htm emails | grep -v '<' | sort -u > tmp
          echo '<pre style="font-size:14px;">' > /$user/$domain/data/emails.htm
          cat tmp >> /$user/$domain/data/emails.htm; echo "</pre>" >> /$user/$domain/data/emails.htm
     fi

     cat hosts /$user/$domain/data/hosts.htm | grep -v '<' | sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 > tmp
     echo '<pre style="font-size:14px;">' > /$user/$domain/data/hosts.htm
     cat tmp >> /$user/$domain/data/hosts.htm; echo "</pre>" >> /$user/$domain/data/hosts.htm

     rm emails* hosts loadbalancing records subdomains* tmp* waf whatweb z*

     echo
     echo $line
     echo
     echo "***Scan complete.***"
     echo
     echo
     printf 'The supporting data folder is located at \e[1;33m%s\e[0m\n' /$user/$domain/
     echo
     echo

     firefox /$user/$domain/index.htm &
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

firefox &
sleep 2
firefox -new-tab http://www.123people.com/s/$firstName+$lastName &
sleep 1
firefox -new-tab http://www.411.com/name/$firstName-$lastName/ &
sleep 1
firefox -new-tab http://www.cvgadget.com/person/$firstName/$lastName &
sleep 1
firefox -new-tab http://www.peekyou.com/$fireName%5F$lastName &
sleep 1
firefox -new-tab http://phonenumbers.addresses.com/people/$firstName+$lastName &
sleep 1
firefox -new-tab http://search.nndb.com/search/nndb.cgi?type=unspecified&query=$firstName+$lastName &
sleep 1
firefox -new-tab http://www.spokeo.com/search?q=$firstName+$lastName&s3=t24 &
sleep 1
firefox -new-tab http://www.zabasearch.com/query1_zaba.php?sname=$firstName%20$lastName&state=ALL&ref=$ref&se=$se&doby=&city=&name_style=1&tm=&tmr=

f_main
}

##############################################################################################################

f_generateTargetList(){
clear
f_banner

echo -e "\e[1;34mSCANNING\e[0m"
echo
echo "1.  Angry IP Scanner"
echo "2.  LAN"
echo "3.  netdiscover"
echo "4.  Ping sweep"
echo "5.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1) ipscan;;
     2) arp-scan -l | egrep -v '(arp-scan|Interface|packets|Polycom|Unknown)' | awk '{print $1}' > /$user/hosts-arp.txt
     echo
     echo $line
     echo
     echo "***Scan complete.***"
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/hosts-arp.txt
     echo
     echo
     exit;;
     3) netdiscover;;
     4) f_pingsweep;;
     5) f_main;;
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
     nmap -iL $location -sn -T4 --stats-every 10s -g $sourceport > tmp
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
     nmap -sn -T4 --stats-every 10s -g $sourceport $manual > tmp
     ;;

     *) f_error;;
esac

##############################################################

perl <<'EOF'
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
mv tmp2 /$user/hosts-ping.txt

echo
echo $line
echo
echo "***Scan complete.***"
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/hosts-ping.txt
echo
echo
exit
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
     echo -e "\e[1;33m[*] Setting source port to 53.\e[0m"
     sourceport=53
     echo
     echo $line
     echo
     ;;

     2)
     echo
     echo -e "\e[1;33m[*] Setting source port to 88.\e[0m"
     sourceport=88
     echo
     echo $line
     echo
     ;;

     3) f_main;;
     *) f_error;;
esac
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

f_single(){
clear
f_banner
f_scanname

echo
echo -n "Single IP, URL or Range: "
read target

# Check for no answer
if [ -z $target ]; then
     rm -rf $name
     f_error
fi

echo $target > tmp-list
location=tmp-list

START=$(date +%r\ %Z)

f_discovery
f_numhosts
f_scan
f_ports
f_scripts
f_metasploit
f_report
}

##############################################################################################################

f_lan(){
clear
f_banner
f_scanname

START=$(date +%r\ %Z)

arp-scan -localnet | egrep -v '(Ending|Interface|packets|Starting)' | awk '{print $1}' | sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 > tmp

# Remove blank lines
sed '/^$/d' tmp > $name/hosts.txt

if [ ! -s $name/hosts.txt ]; then
     rm -rf "$name" tmp*
     echo
     echo $line
     echo
     echo "***Scan complete.***"
     echo
     echo -e "\e[1;33mNo hosts found with open ports.\e[0m"
     echo
     echo
     exit
fi

# Number of hosts
number=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

if [ $number -eq 1 ]; then
     echo
     echo $line
     echo
     echo -e "\e[1;33mHost discovered.\e[0m"
else
     echo
     echo $line
     echo
     echo -e "\e[1;33m$number hosts discovered.\e[0m"
fi

f_scan
f_ports
f_scripts
f_metasploit
f_report
}

##############################################################################################################

f_lists(){
clear
f_banner
f_scanname

f_location

START=$(date +%r\ %Z)

f_discovery
f_numhosts
f_scan
f_ports
f_scripts
f_metasploit
f_report
}

##############################################################################################################

f_cidr(){
clear
f_banner
f_scanname

echo
echo Usage: 192.168.0.0/16
echo
echo -n "Enter CIDR notation: "
read cidr

# Check for no answer
if [ -z $cidr ]; then
     rm -rf $name
     f_error
fi

# Check for wrong answer

sub=$(echo $cidr|cut -d '/' -f2)
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
read ExFile

if [ -z $ExFile ]; then
     ExFile="n"
fi

ExFile="$(echo ${ExFile} | tr 'A-Z' 'a-z')"

if [ $ExFile == "y" ]; then
     echo -n "Enter the path to the exclude list file: "
     read excludefile

     START=$(date +%r\ %Z)

     if [ -z $excludefile ]; then
          f_error
     fi

     if [ ! -f $excludefile ]; then
          f_error
     fi

     f_discoveryexclude
else
     f_discovery
fi

f_numhosts
f_scan
f_ports
f_scripts
f_metasploit
f_report
}

##############################################################################################################

f_discovery(){
echo
echo $line
echo
echo -e "\e[1;34mHost discovery.\e[0m"

nmap -sS -T4 -PP -PE -PM -PI -PA20,53,80,113,443,5060,10043 --host-timeout=300m -O --max-rtt-timeout=3000ms --initial-rtt-timeout=1000ms --min-rtt-timeout=1000ms --max-retries=2 --stats-every 10s --min-hostgroup=64 -PS1,7,9,13,21-23,25,37,42,49,53,69,79-81,85,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,407,443-446,465,500,502,512-515,523-524,540,548,554,587,617,623,689,705,771,783,888,902,910,912,921,993,995,998,1000,1024,1030,1035,1090,1098-1103,1128-1129,1158,1199,1211,1220,1234,1241,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1811,1900,2000-2001,2049,2100,2103,2121,2199,2207,2222,2323,2362,2380-2381,2525,2533,2598,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3217,3273,3299,3306,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4322,4444-4445,4659,4679,4848,5038,5051,5060-5061,5093,5168,5250,5351,5353,5355,5400,5405,5432-5433,5498,5520-5521,5554-5555,5560,5580,5631-5632,5666,5800,5900-5910,5920,5984-5986,6000,6050,6060,6070,6080,6101,6106,6112,6262,6379,6405,6502-6504,6660-6661,6667,6905,6988,7001,7021,7080,7144,7181,7210,7443,7510,7579-7580,7700,7770,7777,7787,7800-7801,7879,7902,8000-8001,8008,8014,8028,8030,8080-8082,8087,8090,8095,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8834,8880,8888-8890,8899,8901-8903,9000,9080-9081,9084,9090,9099-9100,9111,9152,9390-9391,9495,9809-9815,9999-10001,10008,10050-10051,10098,10162,10202-10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12345,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20031,20034,20101,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,30718,31001,31099,32913,34443,37718,38080,38292,41025,41080,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,49152,50000-50004,50013,50500-50504,55553,57772,62078,62514,65535 --min-rate=400 -PU50822 -iL $location -p1,7,9,13,21-23,25,37,42,49,53,69,79-81,85,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,407,443-446,465,500,502,512-515,523-524,540,548,554,587,617,623,689,705,771,783,888,902,910,912,921,993,995,998,1000,1024,1030,1035,1090,1098-1103,1128-1129,1158,1199,1211,1220,1234,1241,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1811,1900,2000-2001,2049,2100,2103,2121,2199,2207,2222,2323,2362,2380-2381,2525,2533,2598,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3217,3273,3299,3306,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4322,4444-4445,4659,4679,4848,5038,5051,5060-5061,5093,5168,5250,5351,5353,5355,5400,5405,5432-5433,5498,5520-5521,5554-5555,5560,5580,5631-5632,5666,5800,5900-5910,5920,5984-5986,6000,6050,6060,6070,6080,6101,6106,6112,6262,6379,6405,6502-6504,6660-6661,6667,6905,6988,7001,7021,7080,7144,7181,7210,7443,7510,7579-7580,7700,7770,7777,7787,7800-7801,7879,7902,8000-8001,8008,8014,8028,8030,8080-8082,8087,8090,8095,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8834,8880,8888-8890,8899,8901-8903,9000,9080-9081,9084,9090,9099-9100,9111,9152,9390-9391,9495,9809-9815,9999-10001,10008,10050-10051,10098,10162,10202-10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12345,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20031,20034,20101,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,30718,31001,31099,32913,34443,37718,38080,38292,41025,41080,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,49152,50000-50004,50013,50500-50504,55553,57772,62078,62514,65535 -g $sourceport -oN tmp
}

##############################################################################################################

f_discoveryexclude(){
echo
echo $line
echo
echo -e "\e[1;34mHost discovery.\e[0m"

nmap -sS -T4 -PP -PE -PM -PI -PA20,53,80,113,443,5060,10043 --host-timeout=300m -O --max-rtt-timeout=3000ms --initial-rtt-timeout=1000ms --min-rtt-timeout=1000ms --max-retries=2 --stats-every 10s --min-hostgroup=64 -PS1,7,9,13,21-23,25,37,42,49,53,69,79-81,85,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,407,443-446,465,500,502,512-515,523-524,540,548,554,587,617,623,689,705,771,783,888,902,910,912,921,993,995,998,1000,1024,1030,1035,1090,1098-1103,1128-1129,1158,1199,1211,1220,1234,1241,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1811,1900,2000-2001,2049,2100,2103,2121,2199,2207,2222,2323,2362,2380-2381,2525,2533,2598,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3217,3273,3299,3306,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4322,4444-4445,4659,4679,4848,5038,5051,5060-5061,5093,5168,5250,5351,5353,5355,5400,5405,5432-5433,5498,5520-5521,5554-5555,5560,5580,5631-5632,5666,5800,5900-5910,5920,5984-5986,6000,6050,6060,6070,6080,6101,6106,6112,6262,6379,6405,6502-6504,6660-6661,6667,6905,6988,7001,7021,7080,7144,7181,7210,7443,7510,7579-7580,7700,7770,7777,7787,7800-7801,7879,7902,8000-8001,8008,8014,8028,8030,8080-8082,8087,8090,8095,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8834,8880,8888-8890,8899,8901-8903,9000,9080-9081,9084,9090,9099-9100,9111,9152,9390-9391,9495,9809-9815,9999-10001,10008,10050-10051,10098,10162,10202-10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12345,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20031,20034,20101,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,30718,31001,31099,32913,34443,37718,38080,38292,41025,41080,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,49152,50000-50004,50013,50500-50504,55553,57772,62078,62514,65535 --min-rate=400 -PU50822 -iL $location --excludefile $excludefile -p1,7,9,13,21-23,25,37,42,49,53,69,79-81,85,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,407,443-446,465,500,502,512-515,523-524,540,548,554,587,617,623,689,705,771,783,888,902,910,912,921,993,995,998,1000,1024,1030,1035,1090,1098-1103,1128-1129,1158,1199,1211,1220,1234,1241,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1811,1900,2000-2001,2049,2100,2103,2121,2199,2207,2222,2323,2362,2380-2381,2525,2533,2598,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3217,3273,3299,3306,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4322,4444-4445,4659,4679,4848,5038,5051,5060-5061,5093,5168,5250,5351,5353,5355,5400,5405,5432-5433,5498,5520-5521,5554-5555,5560,5580,5631-5632,5666,5800,5900-5910,5920,5984-5986,6000,6050,6060,6070,6080,6101,6106,6112,6262,6379,6405,6502-6504,6660-6661,6667,6905,6988,7001,7021,7080,7144,7181,7210,7443,7510,7579-7580,7700,7770,7777,7787,7800-7801,7879,7902,8000-8001,8008,8014,8028,8030,8080-8082,8087,8090,8095,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8834,8880,8888-8890,8899,8901-8903,9000,9080-9081,9084,9090,9099-9100,9111,9152,9390-9391,9495,9809-9815,9999-10001,10008,10050-10051,10098,10162,10202-10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12345,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20031,20034,20101,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,30718,31001,31099,32913,34443,37718,38080,38292,41025,41080,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,49152,50000-50004,50013,50500-50504,55553,57772,62078,62514,65535 -g $sourceport -oN tmp
}

##############################################################################################################

f_numhosts(){
egrep -v '(close|filtered|initiated|latency|rDNS|seconds|STATE|Warning)' tmp | grep 'open' -B1 | grep 'Nmap' | cut -d '(' -f2 | cut -d ')' -f1 > tmp2
sed 's/Nmap scan report for //' tmp2 > tmp3

# Remove blank lines
sed '/^$/d' tmp3 > $name/hosts.txt

if [ ! -s $name/hosts.txt ] ; then
     rm -rf "$name" tmp*
     echo
     echo $line
     echo
     echo "***Scan complete.***"
     echo
     echo -e "\e[1;33mNo hosts found with open ports.\e[0m"
     echo
     echo
     exit
fi

# Number of hosts
number=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

if [ $number -eq 1 ]; then
     echo
     echo $line
     echo
     echo -e "\e[1;33mHost discovered.\e[0m"
else
     echo
     echo $line
     echo
     echo -e "\e[1;33m$number hosts discovered.\e[0m"
fi
}

##############################################################################################################

f_scan(){
echo
echo $line
echo
echo -e "\e[1;34mRunning default nmap scan.\e[0m"

nmap -iL $name/hosts.txt -Pn -n -sSV -sUV -p U:53,67-69,111,123,135,137-139,161,162,445,500,514,520,523,631,998,1434,1701,1900,4500,5353,6481,17185,31337,49152,49154,T:13,21-23,25,37,42,49,53,67,69,79-81,88,105,109-111,113,123,135,137-139,143,161,179,222,384,389,407,443,445,465,500,512-515,523,524,540,548,554,617,623,631,689,705,783,873,910,912,921,993,995,1000,1024,1050,1080,1099,1100,1158,1220,1300,1311,1344,1352,1433-1435,1494,1521,1524,1533,1581-1582,1604,1720,1723,1755,1900,2000,2049,2100,2103,2121,2202,2207,2222,2323,2380,2525,2533,2598,2628,2638,2947,2967,3000,3031,3050,3057,3128,3260,3306,3389,3500,3628,3632,3690,3780,3790,4000,4369,4445,5019,5051,5060-5061,5093,5168,5250,5353,5400,5405,5432-5433,5554-5555,5666,5672,5800,5850,5900-5910,5984,6000-6005,6050,6060,6070,6080,6101,6106,6112,6379,6405,6502-6504,6660,6666-6667,6697,7080,7144,7210,7510,7634,7777,7787,8000,8008-8009,8028,8030,8080-8081,8090,8091,8180,8222,8300,8332-8333,8400,8443-8444,8787,8800,8880,8888,8899,9080-9081,9090,9100,9111,9152,9160,9999-10000,10050,10202-10203,10443,10616,10628,11000,11211,12174,12203,12345,13500,14330,17185,18881,19150,19300,19810,20031,20222,22222,25000,25025,26000,26122,27017,28222,30000,35871,38292,39292,41025,41523-41524,41364,43729,44334,44813,48992,49663,50000-50004,50013,50030,50060,50070,50075,50090,55852,57772,59034,60010,60030,62078,62514,65535 --open -O --osscan-guess --max-os-tries 1 --version-intensity 0 --host-timeout 5m --min-hostgroup 100 --max-rtt-timeout 600ms --initial-rtt-timeout=300ms --min-rtt-timeout 300ms --max-retries 3 --min-rate 150 --stats-every 10s -g $sourceport -oA $name/nmap

# Clean up nmap output
egrep -v '(1 hop|All|CPE|elapsed|filtered|fingerprint|guesses|GUESSING|hops|initiated|latency|matches|NEXT|Not|NSE|OS:|Please|remaining|RTTVAR|scanned|SF|Skipping|specialized|Starting|Timing|unrecognized|Warning|WARNING)' $name/nmap.nmap > tmp
sed 's/Nmap scan report for //' tmp > tmp2
sed '/^$/! b end; n; /^$/d; : end' tmp2 > $name/nmap.txt

rm $name/nmap.nmap

# Show open ports
grep 'open' $name/nmap.txt | awk '{print $1}' | sort -u | sort -n > $name/ports.txt
grep 'tcp' $name/ports.txt | cut -d '/' -f1 > $name/ports-tcp.txt
grep 'udp' $name/ports.txt | cut -d '/' -f1 > $name/ports-udp.txt

# Clean up and show banners
grep 'open' $name/nmap.txt | awk '{for (i=4;i<=NF;i++) {printf "%s%s",sep, $i;sep=" "}; printf "\n"}' | sort -u > tmp
sed 's/^ //' tmp | sort -u > tmp2

# Remove blank lines
sed '/^$/d' tmp2 > $name/banners.txt

# Remove all empty files
find $name/ -type f -empty -exec rm {} +
}

##############################################################################################################

f_ports(){
echo
echo $line
echo
echo -e "\e[1;34mLocating high-value ports.\e[0m"
echo "     TCP"
TCP_PORTS="13 21 22 23 25 70 79 80 110 111 139 143 389 443 445 465 523 524 548 554 631 873 993 995 1050 1080 1099 1158 1344 1352 1433 1521 1720 1723 2202 2628 2947 3031 3260 3306 3389 3632 4369 5019 5432 5666 5672 5850 5900 5984 6000 6001 6002 6003 6004 6005 6379 6666 7210 7634 7777 8000 8009 8080 8081 8091 8222 8332 8333 8400 8443 9100 9160 9999 10000 11211 12345 19150 27017 35871 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $TCP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/tcp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [ -f $name/523.txt ]; then
     mv $name/523.txt $name/523-tcp.txt
fi

echo "     UDP"
UDP_PORTS="53 67 69 123 137 161 500 523 1434 1604 3478 5353 6481 17185 31337"

for i in $UDP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/udp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [ -f $name/523.txt ]; then
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

# Combine SSL ports
echo > tmp

port="21 25 443 465 993 995 8443"

for i in $port; do
     if [ -f $name/$i.txt ]; then
          sed -e 's/$/:'$i'/' $name/$i.txt >> tmp
     fi
done

# Remove blank lines
sed '/^$/d' tmp > $name/ssl.txt

# Combine web ports and sort
cat $name/80.txt $name/443.txt $name/8000.txt $name/8080.txt $name/8443.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/web.txt

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

egrep -v '(0 of 100|afp-serverinfo:|ACCESS_DENIED|appears to be clean|cannot|close|closed|Compressors|Could not|Couldn|Denied|denied|Did not|DISABLED|dns-nsid:|dns-service-discovery:|Document Moved|doesn|eppc-enum-processes|error|Error|ERROR|failed|filtered|GET|hbase-region-info:|HEAD|Host is up|Host script results|impervious|incorrect|latency|ldap-rootdse:|LDAP Results|Likely CLEAN|nbstat:|No accounts left|No Allow|no banner|none|Nope.|not allowed|Not Found|Not Shown|not supported|NOT VULNERABLE|nrpe-enum:|ntp-info:|rdp-enum-encryption:|remaining|rpcinfo:|seconds|See http|Service Info|Skipping|smb-check-vulns|smb-mbenum:|sorry|Starting|telnet-encryption:|Telnet server does not|TIMEOUT|Unauthorized|uncompressed|unhandled|Unknown|viewed over a secure|vnc-info:|wdb-version:)' tmp2 > tmp3

grep -v "Can't" tmp3 > tmp4
}

##############################################################################################################

f_scripts(){
echo
echo $line
echo
echo -e "\e[1;34mRunning nmap scripts.\e[0m"

# If the file for the corresponding port doesn't exist, skip
if [ -f $name/13.txt ]; then
	echo "     Daytime"
	nmap -iL $name/13.txt -Pn -n --open -p13 --script=daytime --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-13.txt
fi

if [ -f $name/21.txt ]; then
	echo "     FTP"
	nmap -iL $name/21.txt -Pn -n --open -p21 --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-21.txt
fi

if [ -f $name/22.txt ]; then
	echo "     SSH"
	nmap -iL $name/22.txt -Pn -n --open -p22 --script=ssh2-enum-algos,sshv1 --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-22.txt
fi

if [ -f $name/23.txt ]; then
	echo "     Telnet"
	nmap -iL $name/23.txt -Pn -n --open -p23 --script=banner,telnet-encryption --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-23.txt
fi

if [ -f $name/25.txt ]; then
	echo "     SMTP"
	nmap -iL $name/25.txt -Pn -n --open -p25 --script=banner,smtp-commands,smtp-open-relay,smtp-strangeport --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	printf '%s\n' 'g/NOT VULNERABLE/d\' '-d' w | ed -s tmp4
	mv tmp4 $name/script-25.txt
fi

if [ -f $name/53.txt ]; then
	echo "     DNS"
	nmap -iL $name/53.txt -Pn -n -sU --open -p53 --script=dns-cache-snoop,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zone-transfer --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-53.txt
fi

if [ -f $name/67.txt ]; then
	echo "     DHCP"
	nmap -iL $name/67.txt -Pn -n -sU --open -p67 --script=dhcp-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-67.txt
fi

if [ -f $name/70.txt ]; then
	echo "     Gopher"
	nmap -iL $name/70.txt -Pn -n --open -p70 --script=gopher-ls --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-70.txt
fi

if [ -f $name/79.txt ]; then
	echo "     Finger"
	nmap -iL $name/79.txt -Pn -n --open -p79 --script=finger --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-79.txt
fi

if [ -f $name/110.txt ]; then
	echo "     POP3"
	nmap -iL $name/110.txt -Pn -n --open -p110 --script=banner,pop3-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-110.txt
fi

if [ -f $name/111.txt ]; then
	echo "     NFS"
	nmap -iL $name/111.txt -Pn -n --open -p111 --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-111.txt
fi

if [ -f $name/123.txt ]; then
	echo "     NTP"
	nmap -iL $name/123.txt -Pn -n -sU --open -p123 --script=ntp-info,ntp-monlist --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-123.txt
fi

if [ -f $name/137.txt ]; then
	echo "     NetBIOS"
	nmap -iL $name/137.txt -Pn -n -sU --open -p137 --script=nbstat --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	sed -i '/^MAC/{n; /.*/d}' tmp4		# Find lines that start with MAC, and delete the following line
	sed -i '/^137\/udp/{n; /.*/d}' tmp4	# Find lines that start with 137/udp, and delete the following line
	mv tmp4 $name/script-137.txt
fi

if [ -f $name/139.txt ]; then
     echo "     MS08-067"
     nmap -iL $name/139.txt -Pn -n --open -p139 --script=smb-check-vulns --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
     f_cleanup
     egrep -v '(SERVICE|netbios)' tmp4 > tmp5
     sed '1N;N;/\(.*\n\)\{2\}.*VULNERABLE/P;$d;D' tmp5
     sed '/^$/d' tmp5 > tmp6
     grep -v '|' tmp6 > $name/script-ms08-067.txt
fi

if [ -f $name/143.txt ]; then
	echo "     IMAP"
	nmap -iL $name/143.txt -Pn -n --open -p143 --script=imap-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-143.txt
fi

if [ -f $name/161.txt ]; then
	echo "     SNMP"
	nmap -iL $name/161.txt -Pn -n -sU --open -p161 --script=snmp-hh3c-logins,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-161.txt
fi

if [ -f $name/389.txt ]; then
	echo "     LDAP"
	nmap -iL $name/389.txt -Pn -n --open -p389 --script=ldap-rootdse --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-389.txt
fi

if [ -f $name/445.txt ]; then
	echo "     SMB"
	nmap -iL $name/445.txt -Pn -n --open -p445 --script=msrpc-enum,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-server-stats,smb-system-info,smbv2-enabled,stuxnet-detect --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	sed -i '/^445/{n; /.*/d}' tmp4		# Find lines that start with 445, and delete the following line
	mv tmp4 $name/script-445.txt
fi

if [ -f $name/465.txt ]; then
	echo "     SMTP/S"
	nmap -iL $name/465.txt -Pn -n --open -p465 --script=banner,smtp-commands,smtp-open-relay,smtp-strangeport,smtp-enum-users --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	printf '%s\n' 'g/NOT VULNERABLE/d\' '-d' w | ed -s tmp4
	mv tmp4 $name/script-465.txt
fi

if [ -f $name/500.txt ]; then
	echo "     Ike"
	nmap -iL $name/500.txt -Pn -n -sS -sU --open -p500 --script=ike-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-500.txt
fi

if [ -f $name/db2.txt ]; then
	echo "     DB2"
	nmap -iL $name/db2.txt -Pn -n -sS -sU --open -p523 --script=db2-das-info,db2-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-523.txt
fi

if [ -f $name/524.txt ]; then
	echo "     Novell NetWare Core Protocol"
	nmap -iL $name/524.txt -Pn -n --open -p524 --script=ncp-enum-users,ncp-serverinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-524.txt
fi

if [ -f $name/548.txt ]; then
	echo "     AFP"
	nmap -iL $name/548.txt -Pn -n --open -p548 --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-548.txt
fi

if [ -f $name/554.txt ]; then
	echo "     RTSP"
	nmap -iL $name/554.txt -Pn -n --open -p554 --script=rtsp-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-554.txt
fi

if [ -f $name/631.txt ]; then
	echo "     CUPS"
	nmap -iL $name/631.txt -Pn -n --open -p631 --script=cups-info,cups-queue-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-631.txt
fi

if [ -f $name/873.txt ]; then
	echo "     rsync"
	nmap -iL $name/873.txt -Pn -n --open -p873 --script=rsync-list-modules --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-873.txt
fi

if [ -f $name/993.txt ]; then
	echo "     IMAP/S"
	nmap -iL $name/993.txt -Pn -n --open -p993 --script=banner,sslv2,imap-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-993.txt
fi

if [ -f $name/995.txt ]; then
	echo "     POP3/S"
	nmap -iL $name/995.txt -Pn -n --open -p995 --script=banner,sslv2,pop3-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-995.txt
fi

if [ -f $name/1050.txt ]; then
	echo "     COBRA"
	nmap -iL $name/1050.txt -Pn -n --open -p1050 --script=giop-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1050.txt
fi

if [ -f $name/1080.txt ]; then
	echo "     SOCKS"
	nmap -iL $name/1080.txt -Pn -n --open -p1080 --script=socks-auth-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1080.txt
fi

if [ -f $name/1099.txt ]; then
	echo "     RMI Registry"
	nmap -iL $name/1099.txt -Pn -n --open -p1099 --script=rmi-dumpregistry --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1099.txt
fi

if [ -f $name/1344.txt ]; then
	echo "     ICAP"
	nmap -iL $name/1344.txt -Pn -n --open -p1344 --script=icap-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1344.txt
fi

if [ -f $name/1352.txt ]; then
	echo "     Lotus Domino"
	nmap -iL $name/1352.txt -Pn -n --open -p1352 --script=domino-enum-users --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1352.txt
fi

if [ -f $name/1433.txt ]; then
	echo "     MS-SQL"
	nmap -iL $name/1433.txt -Pn -n --open -p1433 --script=ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1433.txt
fi

if [ -f $name/1434.txt ]; then
	echo "     MS-SQL UDP"
	nmap -iL $name/1434.txt -Pn -n -sU --open -p1434 --script=ms-sql-dac --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1434.txt
fi

if [ -f $name/1521.txt ]; then
	echo "     Oracle"
	nmap -iL $name/1521.txt -Pn -n --open -p1521 --script=oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1521.txt
fi

if [ -f $name/1604.txt ]; then
	echo "     Citrix"
	nmap -iL $name/1604.txt -Pn -n -sU --open -p1604 --script=citrix-enum-apps,citrix-enum-servers --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1604.txt
fi

if [ -f $name/1723.txt ]; then
	echo "     PPTP"
	nmap -iL $name/1723.txt -Pn -n --open -p1723 --script=pptp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-1723.txt
fi

if [ -f $name/2202.txt ]; then
	echo "     ACARS"
	nmap -iL $name/2202.txt -Pn -n --open -p2202 --script=acarsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-2202.txt
fi

if [ -f $name/2628.txt ]; then
	echo "     DICT"
	nmap -iL $name/2628.txt -Pn -n --open -p2628 --script=dict-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-2628.txt
fi

if [ -f $name/2947.txt ]; then
	echo "     GPS"
	nmap -iL $name/2947.txt -Pn -n --open -p2947 --script=gpsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-2947.txt
fi

if [ -f $name/3031.txt ]; then
	echo "     Apple Remote Event"
	nmap -iL $name/3031.txt -Pn -n --open -p3031 --script=eppc-enum-processes --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-3031.txt
fi

if [ -f $name/3260.txt ]; then
	echo "     iSCSI"
	nmap -iL $name/3260.txt -Pn -n --open -p3260 --script=iscsi-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-3260.txt
fi

if [ -f $name/3306.txt ]; then
	echo "     MySQL"
	nmap -iL $name/3306.txt -Pn -n --open -p3306 --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-3306.txt
fi

if [ -f $name/3389.txt ]; then
	echo "     Remote Desktop"
	nmap -iL $name/3389.txt -Pn -n --open -p3389 --script=rdp-vuln-ms12-020,rdp-enum-encryption --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	egrep -v '(attackers|Description|Disclosure|http|References|Risk factor)' tmp4 > $name/script-3389.txt
fi

if [ -f $name/3478.txt ]; then
	echo "     STUN"
	nmap -iL $name/3478.txt -Pn -n -sU --open -p3478 --script=stun-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-3478.txt
fi

if [ -f $name/3632.txt ]; then
	echo "     Distributed Compiler Daemon"
	nmap -iL $name/3632.txt -Pn -n --open -p3632 --script=distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
     egrep -v '(IDs|Risk factor|Description|Allows|earlier|Disclosure|Extra|References|http)' tmp4 > $name/script-3632.txt
fi

if [ -f $name/4369.txt ]; then
	echo "     Erlang Port Mapper"
	nmap -iL $name/4369.txt -Pn -n --open -p4369 --script=epmd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-4369.txt
fi

if [ -f $name/5019.txt ]; then
	echo "     Versant"
	nmap -iL $name/5019.txt -Pn -n --open -p5019 --script=versant-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-5019.txt
fi

if [ -f $name/5353.txt ]; then
	echo "     DNS Service Discovery"
	nmap -iL $name/5353.txt -Pn -n -sU --open -p5353 --script=dns-service-discovery --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-5353.txt
fi

if [ -f $name/5666.txt ]; then
	echo "     Nagios"
	nmap -iL $name/5666.txt -Pn -n --open -p5666 --script=nrpe-enum --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-5666.txt
fi

if [ -f $name/5672.txt ]; then
	echo "     AMQP"
	nmap -iL $name/5672.txt -Pn -n --open -p5672 --script=amqp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-5672.txt
fi

if [ -f $name/5850.txt ]; then
	echo "     OpenLookup"
	nmap -iL $name/5850.txt -Pn -n --open -p5850 --script=openlookup-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-5850.txt
fi

if [ -f $name/5900.txt ]; then
	echo "     VNC"
	nmap -iL $name/5900.txt -Pn -n --open -p5900 --script=realvnc-auth-bypass,vnc-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-5900.txt
fi

if [ -f $name/5984.txt ]; then
	echo "     CouchDB"
	nmap -iL $name/5984.txt -Pn -n --open -p5984 --script=couchdb-databases,couchdb-stats --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-5984.txt
fi

if [ -f $name/x11.txt ]; then
	echo "     X11"
	nmap -iL $name/x11.txt -Pn -n --open -p6000-6005 --script=x11-access --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-x11.txt
fi

if [ -f $name/6379.txt ]; then
	echo "     Redis"
	nmap -iL $name/6379.txt -Pn -n --open -p6379 --script=redis-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-6379.txt
fi

if [ -f $name/6481.txt ]; then
	echo "     Sun Service Tags"
	nmap -iL $name/6481.txt -Pn -n -sU --open -p6481 --script=servicetags --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-6481.txt
fi

if [ -f $name/6666.txt ]; then
	echo "     Voldemort"
	nmap -iL $name/6666.txt -Pn -n --open -p6666 --script=voldemort-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-6666.txt
fi

if [ -f $name/7210.txt ]; then
	echo "     Max DB"
	nmap -iL $name/7210.txt -Pn -n --open -p7210 --script=maxdb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-7210.txt
fi

if [ -f $name/7634.txt ]; then
	echo "     Hard Disk Info"
	nmap -iL $name/7634.txt -Pn -n --open -p7634 --script=hddtemp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-7634.txt
fi

#if [ -f $name/8009.txt ]; then
#	echo "     AJP"
#	nmap -iL $name/8009.txt -Pn -n --open -p8009 --script=ajp-methods,ajp-request --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
#	f_cleanup
#	mv tmp4 $name/script-8009.txt
#fi

if [ -f $name/8081.txt ]; then
	echo "     McAfee ePO"
	nmap -iL $name/8081.txt -Pn -n --open -p8081 --script=mcafee-epo-agent --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-8081.txt
fi

if [ -f $name/8091.txt ]; then
	echo "     CouchBase Web Administration"
	nmap -iL $name/8091.txt -Pn -n --open -p8091 --script=membase-http-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-8091.txt
fi

if [ -f $name/bitcoin.txt ]; then
	echo "     Bitcoin"
	nmap -iL $name/bitcoin.txt -Pn -n --open -p8332,8333 --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-bitcoin.txt
fi

if [ -f $name/9100.txt ]; then
	echo "     Lexmark"
	nmap -iL $name/9100.txt -Pn -n --open -p9100 --script=lexmark-config --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-9100.txt
fi

if [ -f $name/9160.txt ]; then
	echo "     Cassandra"
	nmap -iL $name/9160.txt -Pn -n --open -p9160 --script=cassandra-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-9160.txt
fi

if [ -f $name/9999.txt ]; then
	echo "     Java Debug Wire Protocol"
	nmap -iL $name/9999.txt -Pn -n --open -p9999 --script=jdwp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-9999.txt
fi

if [ -f $name/10000.txt ]; then
	echo "     Network Data Management"
	nmap -iL $name/10000.txt -Pn -n --open -p10000 --script=ndmp-fs-info,ndmp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-10000.txt
fi

if [ -f $name/11211.txt ]; then
	echo "     Memory Object Caching"
	nmap -iL $name/11211.txt -Pn -n --open -p11211 --script=memcached-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-11211.txt
fi

if [ -f $name/12345.txt ]; then
	echo "     NetBus"
	nmap -iL $name/12345.txt -Pn -n --open -p12345 --script=netbus-auth-bypass,netbus-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-12345.txt
fi

if [ -f $name/17185.txt ]; then
	echo "     VxWorks"
	nmap -iL $name/17185.txt -Pn -n -sU --open -p17185 --script=wdb-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-17185.txt
fi

if [ -f $name/19150.txt ]; then
	echo "     GKRellM"
	nmap -iL $name/19150.txt -Pn -n --open -p19150 --script=gkrellm-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-19150.txt
fi

if [ -f $name/27017.txt ]; then
	echo "     MongoDB"
	nmap -iL $name/27017.txt -Pn -n --open -p27017 --script=mongodb-databases,mongodb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-27017.txt
fi

if [ -f $name/31337.txt ]; then
	echo "     BackOrifice"
	nmap -iL $name/31337.txt -Pn -n -sU --open -p31337 --script=backorifice-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-31337.txt
fi

if [ -f $name/35871.txt ]; then
	echo "     Flume"
	nmap -iL $name/35871.txt -Pn -n --open -p35871 --script=flume-master-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-35871.txt
fi

if [ -f $name/50000.txt ]; then
	echo "     DRDA"
	nmap -iL $name/50000.txt -Pn -n --open -p50000 --script=drda-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-50000.txt
fi

if [ -f $name/hadoop.txt ]; then
	echo "     Hadoop"
	nmap -iL $name/hadoop.txt -Pn -n --open -p50030,50060,50070,50075,50090 --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-hadoop.txt
fi

if [ -f $name/apache-hbase.txt ]; then
	echo "     Apache HBase"
	nmap -iL $name/apache-hbase.txt -Pn -n --open -p60010,60030 --script=hbase-master-info,hbase-region-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	mv tmp4 $name/script-apache-hbase.txt
fi

if [ -f $name/web.txt ]; then
	echo "     Web"
	nmap -iL $name/web.txt -Pn -n --open -p80,443,8000,8080,8443 --script=http-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_cleanup
	egrep -v '(html|No Allow|Potentially)' tmp4 > $name/script-web.txt
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
echo $line
echo
echo -ne "\e[1;33mRun matching Metasploit auxilaries? (y/N) \e[0m"
read msf

if [ -z $msf ]; then
     msf="n"
fi

msf="$(echo ${msf} | tr 'A-Z' 'a-z')"

if [ $msf == "y" ]; then
     f_runmsf
else
     f_report
fi
}

##############################################################################################################

f_runmsf(){
echo
echo -e "\e[1;34mStarting Metasploit, this takes about 15 sec.\e[0m"

echo workspace -a $name > $name/master.rc

# If the file for the corresponding port doesn't exist, skip
if [ -f $name/21.txt ]; then
     echo "     FTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/21.txt/g" /opt/scripts/resource/ftp.rc
     cat /opt/scripts/resource/ftp.rc >> $name/master.rc
fi

if [ -f $name/22.txt ]; then
     echo "     SSH"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/22.txt/g" /opt/scripts/resource/ssh.rc
     cat /opt/scripts/resource/ssh.rc >> $name/master.rc
fi

if [ -f $name/23.txt ]; then
     echo "     Telnet"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/23.txt/g" /opt/scripts/resource/telnet.rc
     cat /opt/scripts/resource/telnet.rc >> $name/master.rc
fi

if [ -f $name/25.txt ]; then
     echo "     SMTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/25.txt/g" /opt/scripts/resource/smtp.rc
     cat /opt/scripts/resource/smtp.rc >> $name/master.rc
fi

if [ -f $name/69.txt ]; then
     echo "     TFTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/69.txt/g" /opt/scripts/resource/tftp.rc
     cat /opt/scripts/resource/tftp.rc >> $name/master.rc
fi

if [ -f $name/79.txt ]; then
     echo "     Finger"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/79.txt/g" /opt/scripts/resource/finger.rc
     cat /opt/scripts/resource/finger.rc >> $name/master.rc
fi

if [ -f $name/110.txt ]; then
     echo "     POP3"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/110.txt/g" /opt/scripts/resource/pop3.rc
     cat /opt/scripts/resource/pop3.rc >> $name/master.rc
fi

if [ -f $name/111.txt ]; then
     echo "     NFS"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/111.txt/g" /opt/scripts/resource/nfs.rc
     cat /opt/scripts/resource/nfs.rc >> $name/master.rc
fi

if [ -f $name/123.txt ]; then
     echo "     NTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/123.txt/g" /opt/scripts/resource/ntp.rc
     cat /opt/scripts/resource/ntp.rc >> $name/master.rc
fi

if [ -f $name/137.txt ]; then
     echo "     NetBIOS"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/137.txt/g" /opt/scripts/resource/netbios.rc
     cat /opt/scripts/resource/netbios.rc >> $name/master.rc
fi

if [ -f $name/143.txt ]; then
     echo "     IMAP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/143.txt/g" /opt/scripts/resource/imap.rc
     cat /opt/scripts/resource/imap.rc >> $name/master.rc
fi

if [ -f $name/161.txt ]; then
     echo "     SNMP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/161.txt/g" /opt/scripts/resource/snmp.rc
     cat /opt/scripts/resource/snmp.rc >> $name/master.rc
fi

if [ -f $name/445.txt ]; then
     echo "     SMB"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/445.txt/g" /opt/scripts/resource/smb.rc
     cat /opt/scripts/resource/smb.rc >> $name/master.rc
fi

if [ -f $name/465.txt ]; then
     echo "     SMTP/S"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/465.txt/g" /opt/scripts/resource/smtp-s.rc
     cat /opt/scripts/resource/smtp-s.rc >> $name/master.rc
fi

if [ -f $name/523.txt ]; then
     echo "     db2"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/523.txt/g" /opt/scripts/resource/db2.rc
     cat /opt/scripts/resource/db2.rc >> $name/master.rc
fi

if [ -f $name/548.txt ]; then
     echo "     AFP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/548.txt/g" /opt/scripts/resource/afp.rc
     cat /opt/scripts/resource/afp.rc >> $name/master.rc
fi

if [ -f $name/1099.txt ]; then
     echo "     RMI Registery"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1099.txt/g" /opt/scripts/resource/rmi.rc
     cat /opt/scripts/resource/rmi.rc >> $name/master.rc
fi

if [ -f $name/1158.txt ]; then
     echo "     Oracle"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1158.txt/g" /opt/scripts/resource/oracle.rc
     cat /opt/scripts/resource/oracle.rc >> $name/master.rc
fi

if [ -f $name/1433.txt ]; then
     echo "     MS-SQL"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1433.txt/g" /opt/scripts/resource/mssql.rc
     cat /opt/scripts/resource/mssql.rc >> $name/master.rc
fi

if [ -f $name/1521.txt ]; then
     echo "     Oracle 2"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1521.txt/g" /opt/scripts/resource/oracle2.rc
     cat /opt/scripts/resource/oracle2.rc >> $name/master.rc
fi

if [ -f $name/1604.txt ]; then
     echo "     Citrix"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1604.txt/g" /opt/scripts/resource/citrix.rc
     cat /opt/scripts/resource/citrix.rc >> $name/master.rc
fi

if [ -f $name/1720.txt ]; then
     echo "     H323"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1720.txt/g" /opt/scripts/resource/h323.rc
     cat /opt/scripts/resource/h323.rc >> $name/master.rc
fi

if [ -f $name/3306.txt ]; then
     echo "     MySQL"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/3306.txt/g" /opt/scripts/resource/mysql.rc
     cat /opt/scripts/resource/mysql.rc >> $name/master.rc
fi

if [ -f $name/5432.txt ]; then
     echo "     Postgres"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/5432.txt/g" /opt/scripts/resource/postgres.rc
     cat /opt/scripts/resource/postgres.rc >> $name/master.rc
fi

if [ -f $name/5900.txt ]; then
     echo "     VNC"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/5900.txt/g" /opt/scripts/resource/vnc.rc
     cat /opt/scripts/resource/vnc.rc >> $name/master.rc
fi

if [ -f $name/x11.txt ]; then
     echo "     x11"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/x11.txt/g" /opt/scripts/resource/x11.rc
     cat /opt/scripts/resource/x11.rc >> $name/master.rc
fi

if [ -f $name/7777.txt ]; then
     echo "     Energizer Duo"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/7777.txt/g" /opt/scripts/resource/energizer-duo.rc
     cat /opt/scripts/resource/energizer-duo.rc >> $name/master.rc
fi

if [ -f $name/8080.txt ]; then
     echo "     Tomcat"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/8080.txt/g" /opt/scripts/resource/tomcat.rc
     cat /opt/scripts/resource/tomcat.rc >> $name/master.rc
fi

if [ -f $name/8222.txt ]; then
     echo "     VMware"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/8222.txt/g" /opt/scripts/resource/vmware.rc
     cat /opt/scripts/resource/vmware.rc >> $name/master.rc
fi

if [ -f $name/8400.txt ]; then
     echo "     Adobe"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/8400.txt/g" /opt/scripts/resource/adobe.rc
     cat /opt/scripts/resource/adobe.rc >> $name/master.rc
fi

if [ -f $name/9999.txt ]; then
     echo "     Telnet 2"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/9999.txt/g" /opt/scripts/resource/telnet2.rc
     cat /opt/scripts/resource/telnet2.rc >> $name/master.rc
fi

if [ -f $name/17185.txt ]; then
     echo "     VxWorks"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/17185.txt/g" /opt/scripts/resource/vxworks.rc
     cat /opt/scripts/resource/vxworks.rc >> $name/master.rc
fi

if [ -f $name/50000.txt ]; then
     echo "     db2 version"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/50000.txt/g" /opt/scripts/resource/db2-version.rc
     cat /opt/scripts/resource/db2-version.rc >> $name/master.rc
fi

if [ -f $name/web.txt ]; then
     echo "     HTTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/web.txt/g" /opt/scripts/resource/http-short.rc
     cat /opt/scripts/resource/http-short.rc >> $name/master.rc
fi

# services -c port,proto,name,info -o /root/test.csv
# hosts -c address,name,os_name,os_flavor,os_sp -o /root/test2.csv

echo db_export -f xml -a $name/metasploit.xml >> $name/master.rc
echo db_import $name/nmap.xml >> $name/master.rc
echo exit >> $name/master.rc

x=$(wc -l $name/master.rc | cut -d ' ' -f1)

if [ $x -eq 3 ]; then
     rm $name/master.rc
else
     msfconsole -r /opt/scripts/$name/master.rc
     rm $name/master.rc
fi

f_report
}

##############################################################################################################

f_report(){
END=$(date +%r\ %Z)
filename=$name/report.txt
host=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

echo "Discover Report" > $filename
echo "$name" >> $filename
date +%A" - "%B" "%d", "%Y >> $filename
echo >> $filename
echo "Start time - $START" >> $filename
echo "Finish time - $END" >> $filename
echo "Scanner IP - $ip" >> $filename
nmap -V | grep 'version' | cut -d ' ' -f1-3 >> $filename
echo >> $filename
echo $line >> $filename
echo >> $filename

if [ -f $name/script-ms08-067.txt ]; then
     echo "May be vulnerable to MS08-067." >> $filename
     echo >> $filename
     cat $name/script-ms08-067.txt >> $filename
     echo >> $filename
     echo $line >> $filename
     echo >> $filename
fi

if [ $host -eq 1 ]; then
     echo "1 host discovered." >> $filename
     echo >> $filename
     echo $line >> $filename
     echo >> $filename
     cat $name/nmap.txt >> $filename
     echo $line >> $filename
     echo $line >> $filename
     echo >> $filename
     echo "Nmap Scripts" >> $filename

     SCRIPTS="script-13 script-21 script-22 script-23 script-25 script-53 script-67 script-70 script-79 script-110 script-111 script-123 script-137 script-143 script-161 script-389 script-445 script-465 script-500 script-523 script-524 script-548 script-554 script-631 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-2202 script-2628 script-2947 script-3031 script-3260 script-3306 script-3389 script-3478 script-3632 script-4369 script-5019 script-5353 script-5666 script-5672 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8009 script-8081 script-8091 script-bitcoin script-9100 script-9160 script-9999 script-10000 script-11211 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-50000 script-hadoop script-apache-hbase script-web"

     for i in $SCRIPTS; do
          if [ -f $name/"$i.txt" ]; then
               cat $name/"$i.txt" >> $filename
               echo $line >> $filename
          fi
     done

     mv $name /$user/

     START=0
     END=0

     echo
	echo $line
	echo
     echo "***Scan complete.***"
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/$name/report.txt
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
     echo $line
     echo
     echo "***Scan complete.***"
     echo
     echo -e "\e[1;33mNo hosts found with open ports.\e[0m"
     echo
     echo
     exit
else
     ports=$(wc -l $name/ports.txt | cut -d ' ' -f1)
fi

echo $line >> $filename
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

echo $line >> $filename

if [ -f $name/banners.txt ]; then
     banners=$(wc -l $name/banners.txt | cut -d ' ' -f1)
     echo >> $filename
     echo "Banners ($banners)" >> $filename
     echo >> $filename
     cat $name/banners.txt >> $filename
     echo >> $filename
     echo $line >> $filename
fi

echo >> $filename
echo "High Value Hosts by Port" >> $filename
echo >> $filename

HVPORTS="13 21 22 23 25 53 67 69 70 79 80 110 111 123 137 139 143 161 389 443 445 465 500 523 524 548 554 631 873 993 995 1050 1080 1099 1158 1344 1352 1433 1434 1521 1604 1720 1723 2202 2628 2947 3031 3260 3306 3389 3478 3632 4369 5019 5353 5432 5666 5672 5850 5900 5984 6000 6001 6002 6003 6004 6005 6379 6481 6666 7210 7634 7777 8000 8009 8080 8081 8091 8222 8332 8333 8400 8443 9100 9160 9999 10000 11211 12345 17185 19150 27017 31337 35871 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $HVPORTS; do
     if [ -f $name/$i.txt ]; then
          echo "Port $i" >> $filename
          cat $name/$i.txt >> $filename
          echo >> $filename
     fi
done

echo $line >> $filename
echo >> $filename
cat $name/nmap.txt >> $filename
echo $line >> $filename
echo $line >> $filename
echo >> $filename
echo "Nmap Scripts" >> $filename

SCRIPTS="script-13 script-21 script-22 script-23 script-25 script-53 script-67 script-70 script-79 script-110 script-111 script-123 script-137 script-143 script-161 script-389 script-445 script-465 script-500 script-523 script-524 script-548 script-554 script-631 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-2202 script-2628 script-2947 script-3031 script-3260 script-3306 script-3389 script-3478 script-3632 script-4369 script-5019 script-5353 script-5666 script-5672 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8009 script-8081 script-8091 script-bitcoin script-9100 script-9160 script-9999 script-10000 script-11211 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-50000 script-hadoop script-apache-hbase script-web"

for i in $SCRIPTS; do
     if [ -f $name/"$i.txt" ]; then
          cat $name/"$i.txt" >> $filename
          echo $line >> $filename
     fi
done

echo >> $filename

mv $name /$user/

START=0
END=0

echo
echo $line
echo
echo "***Scan complete.***"
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/$name/report.txt
echo
echo
exit
}

##############################################################################################################

f_multitabs(){
f_runlocally
clear
f_banner

echo -e "\e[1;34mOpen multiple tabs in Firefox with:\e[0m"
echo
echo "1.  List containing IPs and/or URLs."
echo "2.  Directories from a domain's robot.txt."
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     f_location

     echo -n "Port (default 80): "
     read port

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

     firefox &
     sleep 2

     if [ $port -eq 21 ]; then
          for i in $(cat $location); do
               firefox -new-tab ftp://$i &
               sleep 1
          done
     elif [ $port -eq 80 ]; then
          for i in $(cat $location); do
               firefox -new-tab $i &
               sleep 1
          done
     elif [ $port -eq 443 ]; then
          for i in $(cat $location); do
               firefox -new-tab https://$i &
               sleep 1
          done
     else
          for i in $(cat $location); do
               firefox -new-tab $i:$port &
               sleep 1
          done
     fi
     ;;

     2)
     echo
     echo $line
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

     grep 'Disallow' robots.txt | awk '{print $2}' > /$user/$domain-robots.txt
     rm robots.txt

     firefox &
     sleep 2

     for i in $(cat /$user/$domain-robots.txt); do
          firefox -new-tab $domain$i &
          sleep 1
     done

     echo
     echo $line
     echo
     echo "***Scan complete.***"
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/$domain-robots.txt
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

echo -e "\e[1;34mRun multiple instances of Nikto in parallel against a list of IP addresses.\e[0m"
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

     mkdir /$user/nikto

     while read -r line; do
          xdotool key ctrl+shift+t
          sleep 1
          xdotool type "cd /pentest/web/nikto/program/ && ./nikto.pl -h $line -port $port -Format htm --output /$user/nikto/$line.htm ; exit"
          xdotool key Return
     done < "$location"
     ;;

     2)
     f_location

     mkdir /$user/nikto

     while IFS=: read -r host port; do
          xdotool key ctrl+shift+t
          sleep 1
          xdotool type "cd /pentest/web/nikto/program/ && ./nikto.pl -h $host -port $port -Format htm --output /root/nikto/$host-$port.htm ; exit"
          xdotool key Return
     done < "$location"
     ;;

     3) f_main;;
     *) f_error;;
esac

echo
echo $line
echo
echo "***Scan complete.***"
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/nikto/
echo
echo
exit
}

##############################################################################################################
# Jason
# Need a better way to see if a host is live and has an SSL port open. Try using nmap -p 443.
# Need a better way to locate hosts running SSL on alternate ports. Try using the nmap.grep file.

f_sslcheck(){
clear
f_banner

echo -e "\e[1;34mCheck for SSL certificate issues.\e[0m"

f_location

date2stamp(){
date --utc --date "$1" +%s
}

stamp2date(){
date --utc --date "1970-01-01 $1 sec" "+%Y-%m-%d %T"
}

datediff(){
case $1 in
     -s) sec=1; shift;;
     -m) sec=60; shift;;
     -h) sec=3600; shift;;
     -d) sec=86400; shift;;
     *)  sec=86400;;
esac

dte1=$(date2stamp $1)
dte2=$(date2stamp $2)
diffSec=$((dte2-dte1))

if ((diffSec < 0)); then
     abs=-1
else
     abs=1
fi

echo $((diffSec/sec*abs))
}

monthconv(){
if [ "$1" == "Jan" ]; then monthnum="01"; fi
if [ "$1" == "Feb" ]; then monthnum="02"; fi
if [ "$1" == "Mar" ]; then monthnum="03"; fi
if [ "$1" == "Apr" ]; then monthnum="04"; fi
if [ "$1" == "May" ]; then monthnum="05"; fi
if [ "$1" == "Jun" ]; then monthnum="06"; fi
if [ "$1" == "Jul" ]; then monthnum="07"; fi
if [ "$1" == "Aug" ]; then monthnum="08"; fi
if [ "$1" == "Sep" ]; then monthnum="09"; fi
if [ "$1" == "Oct" ]; then monthnum="10"; fi
if [ "$1" == "Nov" ]; then monthnum="11"; fi
if [ "$1" == "Dec" ]; then monthnum="12"; fi
}

# Number of hosts
number=$(wc -l $location | cut -d ' ' -f1)
N=0

echo
echo "Scanning $number hosts."
echo

echo > tmp-report
echo >> tmp-report
echo "SSL Report" >> tmp-report
reportdate=$(date +%A" - "%B" "%d", "%Y)
echo $reportdate >> tmp-report
echo sslscan $(sslscan | grep 'Version' | awk '{print $2}') >> tmp-report
echo >> tmp-report
echo $line >> tmp-report
echo >> tmp-report

while read -r line; do

     # Initialize ssl_$line.txt file
     echo "$line" > ssl_$line.txt
     N=$((N+1))
     sslscan --no-failed $line > ssltmp_$line & pid=$!

     # echo "pid = $pid"  # debug statement
     echo -n "$line  [$N/$number]  "; sleep 40
     echo >> ssl_$line.txt

     if [ -s ssltmp_$line ]; then
          ERRORCHECK=$(cat ssltmp_$line | grep 'ERROR:')
          if [[ ! $ERRORCHECK ]]; then

               ISSUER=$(cat ssltmp_$line | grep 'Issuer:')
               if [[ $ISSUER ]]; then
                    cat ssltmp_$line | grep 'Issuer:' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               else
                    echo "Issuer information not available for this certificate. Look into this!" >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               SUBJECT=$(cat ssltmp_$line | grep 'Subject:')
               if [[ $SUBJECT ]]; then
                    cat ssltmp_$line | grep 'Subject:' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               else
                    echo "Certificate subject information not available. Look into this!" >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               DNS=$(cat ssltmp_$line | grep 'DNS:')
               if [[ $DNS ]]; then
                    cat ssltmp_$line | grep 'DNS:' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               A=$(cat ssltmp_$line | grep -i 'MD5WithRSAEncryption')
               if [[ $A ]]; then
                    echo [*] MD5-based Signature in TLS/SSL Server X.509 Certificate >> ssl_$line.txt
                    cat ssltmp_$line | grep -i 'MD5WithRSAEncryption' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               B=$(cat ssltmp_$line | grep 'NULL')
               if [[ $B ]]; then
                    echo [*] NULL Ciphers >> ssl_$line.txt
                    cat ssltmp_$line | grep 'NULL' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               C=$(cat ssltmp_$line | grep 'SSLv2')
               if [[ $C ]]; then
                    echo [*] TLS/SSL Server Supports SSLv2 >> ssl_$line.txt
                    cat ssltmp_$line | grep 'SSLv2' > ssltmp2_$line
                    sed '/^    SSL/d' ssltmp2_$line >> ssl_$line.txt
                    echo >> ssl_$line.txt
                    rm ssltmp2_$line
               fi

               D=$(cat ssltmp_$line | grep ' 40 bits')
               D2=$(cat ssltmp_$line | grep ' 56 bits')

               if [[ $D || $D2 ]]; then
                    echo [*] TLS/SSL Server Supports Weak Cipher Algorithms >> ssl_$line.txt
                    cat ssltmp_$line | grep ' 40 bits' >> ssl_$line.txt
                    cat ssltmp_$line | grep ' 56 bits' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               datenow=$(date +%F)
               # echo datenow=$datenow
               datenowstamp=$(date2stamp "$datenow")
               # echo datenowstamp=$datenowstamp
               monthconv $(grep "Not valid after:" ssltmp_$line | awk -F" " {'print $4'})
               # echo monthnum=$monthnum
               expyear=$(grep "Not valid after:" ssltmp_$line | awk -F" " {'print $7'})
               # echo expyear=$expyear
               expday=$(grep "Not valid after:" ssltmp_$line | awk -F" " {'print $5'})
               # echo expday=$expday
               expdate=$(echo "$expyear-$monthnum-$expday")
               # echo expdate=$expdate
               expdatestamp=$(date2stamp "$expdate")
               # echo expdatestamp=$expdatestamp
               numdaysdiff=$(datediff $datenow $expdate)
               # echo numdaysdiff=$numdaysdiff

               if (($expdatestamp < $datenowstamp)); then
                    echo [*] X.509 Server Certificate is Invalid/Expired >> ssl_$line.txt
                    echo "    Cert Expire Date: $expdate" >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               E=$(cat ssltmp_$line | grep 'Authority Information Access:')
               if [[ ! $E ]]; then
                    echo [*] Self-signed TLS/SSL Certificate >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               echo $line >> ssl_$line.txt
               echo >> ssl_$line.txt
               echo
               # echo "kill $pid process test"
               (sleep 5 && kill -9 $pid 2>/dev/null) &

               # Add current data to tmp-report
               cat ssl_$line.txt >> tmp-report
          else
               echo -e "\e[1;31mCould not open a connection.\e[0m"
               echo $ERRORCHECK >> ssl_$line.txt
               echo >> ssl_$line.txt
               echo $line >> ssl_$line.txt
               cat ssl_$line.txt >> tmp-report
          fi
     else
          echo -e "\e[1;31mNo response.\e[0m"
          echo "[*] No response." >> ssl_$line.txt
          echo >> ssl_$line.txt
          echo $line >> ssl_$line.txt

          # Add current data to tmp-report
          cat ssl_$line.txt >> tmp-report
     fi
done < "$location"

mv tmp-report /$user/ssl-report.txt
rm ssltmp_* ssl_*.txt 2>/dev/null

echo
echo $line
echo
echo "***Scan complete.***"
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/ssl-report.txt
echo
echo
exit
}

##############################################################################################################

f_salesforce(){
clear
f_banner

echo -e "\e[1;34mCopy the results of a query from salesforce (https://connect.data.com/login) to a file.\e[0m"

f_location

echo
echo

sed 's/Direct Dial Available//g' $location | sed 's/\[\]//g; s/Addison//g; s/Akron//g; s/Alma //g; s/Apple Valley//g; s/Arlington//g; s/Artesia//g; s/Ashburn//g; s/Atlanta//g; s/Austin//g; s/Baltimore//g; s/Barboursville//g; s/Binghamton//g; s/Birmingham//g; s/Boston//g; s/Burbank//g ; s/Burlington//g; s/Brockton//g; s/Canada//g; s/Camp Springs//g; s/Charleston//g; s/Charlotte//g; s/Chesapeake//g; s/Chicago//g; s/Cincinnati//g; s/Cleveland//g; s/CNN News Group Cable News Network//g; s/Columbia//g; s/Cresskill//g; s/Dallas//g; s/Denver//g; s/Dunkirk//g; s/Durham//g; s/El Paso//g; s/Englewood//g; s/Emeryville//g; s/Encino//g; s/Fallbrook//g; s/Fremont//g; s/Front Royal//g; s/Gardena//g; s/Gastonia//g; s/Gig Harbor//g; s/Glendale//g; s/Hamlin//g; s/Harbor City//g; s/Hawthorne//g; s/Hermosa Beach//g; s/Herndon//g; s/Huntington//g; s/Hurricane//g; s/Hyattsville//g; s/Indianapolis//g; s/Irvine//g; s/JA//g; s/Kansas City//g; s/Knoxville//g; s/La Follette//g; s/La Plata//g; s/Lawrenceville//g; s/Lawndale//g; s/Lithonia//g; s/Lomita//g; s/London//g; s/Long Beach//g; s/Los Angeles//g; s/Machias//g; s/Manhattan//g; s/Marietta//g; s/Marina Del Rey//g; s/Mc Lean//g; s/Menlo Park//g; s/Miami//g; s/Milpitas//g; s/Milton//g; s/Minneapolis//g; s/Mumbai//g; s/Needham//g; s/New York//g; s/North Holly...//g; s/Norwalk//g; s/Oakland//g; s/Oceanport//g; s/Odessa//g; s/Ottawa//g; s/Orange//g; s/Palo Alto//g; s/Park Ridge//g; s/Philadelphia//g; s/Point Pleasant//g; s/Portland//g; s/Proctorville//g; s/Rancho//g; s/Redondo Beach//g; s/Reston//g; s/Richmond//g; s/Riverdale//g; s/Rllng Hls Est//g; s/Rochester//g; s/Rockville//g; s/Royal Oak//g; s/Sacramento//g; s/Salt Lake City//g; s/San Diego//g; s/San Francisco//g; s/San Jose//g; s/San Mateo//g; s/San Pedro//g; s/Santa Clara//g; s/Santa Monica//g; s/Schaumburg//g; s/Scotts Valley//g; s/Seattle//g; s/Sebring//g; s/Show Low//g; s/Sitka//g; s/Southfield//g; s/South Lake//g; s/Stephens City//g; s/Stillwater//g; s/Tacoma//g; s/Tallahassee//g; s/Toronto//g; s/Torrance//g; s/Twin Falls//g; s/U.S.//g; s/United Kingdom//g; s/United States//g; s/Vienna//g; s/Walnut Creek//g; s/Washington//g; s/Welch//g; s/Westport//g; s/Wheeling//g; s/Wilton//g; s/Winchester//g; s/Williamsport//g; s/Wilmington//g; s/Winder//g; s/Wynnewood//g; 

s/AK //g; s/AL //g; s/AR //g; s/AZ //g; s/CA //g; s/CT //g; s/DC //g; s/DE //g; s/FL //g; s/GA //g; s/HI //g; s/IA //g; s/ID //g; s/IL //g; s/IN //g; s/KS //g; s/KY //g; s/LA //g; s/MA //g; s/ME //g; s/MD //g; s/MI //g; s/MN //g; s/MS //g; s/MT //g; s/NC //g; s/NE //g; s/ND //g; s/NH //g; s/NJ //g; s/NM //g; s/NV //g; s/NY //g; s/OH //g; s/ON //g; s/OK //g; s/OR //g; s/PA //g; s/RI //g; s/SC //g; s/SD //g; s/TN //g; s/TX //g; s/UT //g; s/VA //g; s/VT //g; s/WA //g; s/WI //g; s/WV //g; s/WY //g; s/[0-9]\{2\}\/[0-9]\{2\}\/[0-9]\{2\}//g; s/^[ \t]*//' > tmp

# Author: Ben Wood
perl -ne 'if ($_ =~ /(.*?)\t\s*(.*)/) {printf("%-30s%s\n",$1,$2);}' tmp > tmp2

# Remove trailing whitespace from each line
sed 's/[ \t]*$//' tmp2 | sort > /$user/names.txt

rm tmp*
cat /$user/names.txt

echo
echo $line
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/names.txt
echo
echo
exit
}

##############################################################################################################

f_listener(){
clear
echo
echo
echo "Starting a Metasploit listener on port 443."
echo "Type - Windows meterpreter reverse TCP."
echo
echo "This takes about 20 seconds."
echo
msfconsole -r /opt/scripts/resource/listener.rc
}

##############################################################################################################

f_updates(){
# Remove entire script categories
if [ -d /root/nmap-svn ]; then
     ls -l /root/nmap-svn/scripts | awk '{print $8}' | cut -d '.' -f1 | egrep -v '(broadcast|brute|discover|http|ip-|ssl|targets)' > tmp
else
     ls -l /usr/local/share/nmap/scripts | awk '{print $8}' | cut -d '.' -f1 | egrep -v '(broadcast|brute|discover|http|ip-|ssl|targets)' > tmp
fi

# Remove Nmap scripts that take too many arguments, DOS or not relevant
egrep -v '(address-info|ajp-auth|ajp-headers|asn-query|auth-owners|auth-spoof|cccam-version|citrix-enum-apps-xml|citrix-enum-servers-xml|creds-summary|daap-get-library|dns-blacklist|dns-check-zone|dns-client-subnet-scan|dns-fuzz|dns-ip6-arpa-scan|dns-nsec3-enum|dns-nsec-enum|dns-srv-enum|dns-zeustracker|domcon-cmd|duplicates|eap-info|firewalk|firewall-bypass|ftp-libopie|ganglia-info|ftp-vuln-cve2010-4221|hostmap-bfk|hostmap-robtex|iax2-version|informix-query|informix-tables|ipidseq|ipv6-node-info|ipv6-ra-flood|irc-botnet-channels|irc-info|irc-unrealircd-backdoor|isns-info|jdwp-exec|jdwp-info|jdwp-inject|krb5-enum-users|ldap-novell-getpass|ldap-search|llmnr-resolve|metasploit-info|mmouse-exec|ms-sql-config|mrinfo|ms-sql-hasdbaccess|ms-sql-query|ms-sql-tables|ms-sql-xp-cmdshell|mtrace|murmur-version|mysql-audit|mysql-enum|mysql-dump-hashes|mysql-query|mysql-vuln-cve2012-2122|nat-pmp-info|nat-pmp-mapport|netbus-info|omp2-enum-targets|oracle-enum-users|ovs-agent-version|p2p-conficker|path-mtu|pjl-ready-message|quake3-info|quake3-master-getservers|qscan|resolveall|reverse-index|rpc-grind|rpcap-info|samba-vuln-cve-2012-1182|script|sip-enum-users|skypev2-version|smb-flood|smb-ls|smb-print-text|smb-psexec|smb-vuln-ms10-054|smb-vuln-ms10-061|smtp-vuln-cve2010-4344|smtp-vuln-cve2011-1720|smtp-vuln-cve2011-1764|sniffer-detect|snmp-ios-config|socks-open-proxy|sql-injection|ssh-hostkey|ssh2-enum-algos|sshv1|stun-info|tftp-enum|tls-nextprotoneg|traceroute-geolocation|unusual-port|upnp-info|url-snarf|ventrilo-info|vuze-dht-info|whois|xmpp-info)' tmp > tmp-all

grep 'script=' discover.sh | egrep -v '(discover.sh|22.txt|smtp.txt|web.txt)' > tmp
cat tmp | cut -d '=' -f2- | cut -d ' ' -f1 | tr ',' '\n' | egrep -v '(db2-discover|dhcp-discover|dns-service-discovery|membase-http-info|oracle-sid-brute|smb-os-discovery|sslv2)' | sort -u > tmp-used

echo "New Modules" > tmp-updates
echo >> tmp-updates
echo "Nmap scripts" >> tmp-updates
echo "==============================" >> tmp-updates

diff tmp-all tmp-used | egrep '^[<>]' | awk '{print $2}' | sed '/^$/d' >> tmp-updates

rm tmp

echo >> tmp-updates
echo "Metasploit auxiliary/scanners" >> tmp-updates
echo "==============================" >> tmp-updates

categories="afp backdoor db2 finger ftp h323 http imap lotus mongodb motorola mssql mysql netbios nfs ntp oracle pcanywhere pop3 postgres rservices scada sip smb smtp snmp ssh telnet tftp upnp vmware vnc vxworks winrm x11"

for i in $categories; do
     ls -l /opt/metasploit/msf3/modules/auxiliary/scanner/$i | awk '{print $8}' | cut -d '.' -f1 >> tmp
done

sed '/^$/d' tmp > tmp2

# Remove brute force and misc
egrep -v '(afp_login|anonymous|axis_login|brute_dirs|cisco_upload_file|crawler|db2_auth|dolibarr_login|ektron_cms400net|enum_delicious|enum_wayback|file_same_name_dir|ftp_login|httpbl_lookup|isqlplus_login|isqlplus_sidbrute|lotus_domino_hashes|lotus_domino_login|lucky_punch|mongodb_login|mysql_hashdump|mysql_login|mysql_schemadump|oracle_hashdump|oracle_login|owa_login|pop3_login|postgres_hashdump|postgres_login|postgres_schemadump|postgres_version|prev_dir_same_name_file|rexec_login|rlogin_login|rsh_login|sid_brute|smb_login|snmp_login|snmp_set|squid_pivot_scanning|ssh_identify_pubkeys|ssh_login|ssh_login_pubkey|sybase_easerver_traversal|telnet_encrypt_overflow|telnet_login|tftpbrute|vcms_login|vhost_scanner|vnc_login|web_vulndb|xdb_sid|xdb_sid_brute|xpath)' tmp2 | sort > tmp-msf-all

cat /opt/scripts/resource/*.rc | grep 'use' > tmp

# Print from the last /, to the end of the line
sed -e 's:.*/\(.*\):\1:g' tmp > tmp-msf-used

grep -v -f tmp-msf-used tmp-msf-all >> tmp-updates

mv tmp-updates /$user/updates
rm tmp*

echo
echo $line
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/updates
echo
echo
exit
}

##############################################################################################################

f_main(){
clear
f_banner

echo -e "\e[1;34mRECON\e[0m"
echo "1.  Domain"
echo "2.  Person"
echo
echo -e "\e[1;34mSCANNING\e[0m" "- Host discovery, port scanning, service enumeration"
echo "and OS identification using Nmap, NSE and Metasploit scanners."
echo "3.  Generate target list"
echo "4.  CIDR"
echo "5.  List"
echo "6.  Local area network"
echo "7.  Single IP, URL or range"
echo
echo -e "\e[1;34mWEB\e[0m"
echo "8.  Open multiple tabs in Firefox"
echo "9.  Nikto"
echo "10. SSL Check"
echo
echo -e "\e[1;34mMISC\e[0m"
echo "11. Crack WiFi"
echo "12. Parse salesforce"
echo "13. Start a Metasploit listener"
echo "14. Update"
echo "15. Exit"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_domain;;
     2) f_person;;
     3) f_generateTargetList;;
     4) f_cidr;;
     5) f_lists;;
     6) f_lan;;
     7) f_single;;
     8) f_multitabs;;
     9) f_nikto;;
     10) f_sslcheck;;
     11) /opt/scripts/crack-wifi.sh;;
     12) f_salesforce;;
     13) f_listener;;
     14) /opt/scripts/update.sh && exit;;
     15) clear && exit;;
     99) f_updates;;
     *) f_error;;
esac
}

##############################################################################################################

while true; do f_main; done

