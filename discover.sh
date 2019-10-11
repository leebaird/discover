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
# Arthur Kay (@arthurakay) - python scripts

##############################################################################################################

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

##############################################################################################################

# Global variables
discover=$(updatedb; locate discover.sh | sed 's:/[^/]*$::')
interface=$(ip addr | grep 'global' | awk '{print $8}')
ip=$(ip addr | grep 'global' | cut -d '/' -f1 | awk '{print $2}')
port=443
web="firefox -new-tab"

CWD=$(pwd)
home=$HOME

long='==============================================================================================================================='
medium='=================================================================='
short='========================================'

sip='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

export discover
export ip
export web

export CWD
export home

export long
export medium
export short

export sip

export BLUE
export RED
export YELLOW
export NC

##############################################################################################################

# Check that the number of instances of Discover >1
updatedb
locate discover.sh > tmpinstance
instqty=$(wc -l tmpinstance | cut -d ' ' -f1)

if [ $instqty -gt 1 ]; then
     echo
     echo -e "$medium ${NC}"
     echo
     echo -e "Found ${YELLOW}$instqty${NC} instances of Discover on your system."
     echo 'Refer to the following paths:'
     cat tmpinstance | sed 's/^/\t/'
     echo
     echo 'Remove or rename all but the install path and try again.'
     echo -e "If renaming, ${YELLOW}'discover.sh'${NC} can't be in name. Try ${YELLOW}'discover.bu'${NC} etc."
     echo
     echo -e "${YELLOW}$medium ${NC}"
     echo
     rm tmpinstance
     exit
else
     rm tmpinstance
fi

##############################################################################################################

f_banner(){
echo
echo -e "${YELLOW}
 _____  ___  _____  _____  _____  _    _  _____  _____
|     \  |  |____  |      |     |  \  /  |____  |____/
|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_

By Lee Baird${NC}"
echo
echo
}

export -f f_banner

##############################################################################################################

f_error(){
echo
echo -e "${RED}$medium${NC}"
echo
echo -e "${RED}                *** Invalid choice or entry. ***${NC}"
echo
echo -e "${RED}$medium${NC}"
sleep 2
f_main
}

export -f f_error

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
     echo
     echo -e "${RED}$medium${NC}"
     echo
     echo -e "${RED}             *** This option must be ran locally. ***${NC}"
     echo
     echo -e "${RED}$medium${NC}"
     echo
     echo
     exit
fi
}

##############################################################################################################

f_terminate(){

save_dir=$home/data/cancelled-$(date +%H:%M:%S)
echo
echo "Terminating..."
echo
echo -e "${YELLOW}All data will be saved in $save_dir.${NC}"

mkdir $save_dir

# Nmap and Metasploit scans
mv $name/ $save_dir 2>/dev/null

# Passive files
cd $CWD
mv curl debug* email* hosts name* network* records registered* squatting sub* usernames-recon whois* z* doc pdf ppt txt xls $save_dir/passive/ 2>/dev/null
cd /tmp/; mv emails names* networks subdomains usernames $save_dir/passive/recon-ng/ 2>/dev/null

# Active files
cd $CWD
mv active.rc emails hosts record* sub* waf whatweb z* $save_dir/active/ 2>/dev/null
cd /tmp/; mv subdomains $save_dir/active/recon-ng/ 2>/dev/null
cd $CWD

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
echo -e "${BLUE}RECON${NC}"
echo
echo "1.  Passive"
echo "2.  Active"
echo "3.  Import names into an existing recon-ng workspace"
echo "4.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     clear
     f_banner

     echo -e "${BLUE}Uses ARIN, dnsrecon, goofile, goog-mail, goohost, theHarvester,${NC}"
     echo -e "${BLUE}  Metasploit, URLCrazy, Whois, multiple websites, and recon-ng.${NC}"
     echo
     echo -e "${BLUE}[*] Acquire API keys for Bing, Builtwith, Fullcontact, GitHub,${NC}"
     echo -e "${BLUE}    Google, Hashes, Hunter, SecurityTrails, and Shodan for${NC}"
     echo -e "${BLUE}    maximum results with recon-ng and theHarvester.${NC}"
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

     # If folder doesn't exist, create it
     if [ ! -d $home/data/$domain ]; then
          cp -R $discover/report/ $home/data/$domain
          sed -i "s/#COMPANY#/$company/" $home/data/$domain/index.htm
          sed -i "s/#DOMAIN#/$domain/" $home/data/$domain/index.htm
          sed -i "s/#DATE#/$rundate/" $home/data/$domain/index.htm
     fi

     echo
     echo $medium
     echo

     export company
     export companyurl
     export domain
     recon/passive.sh
     exit
     ;;

     2)
     clear
     f_banner

     echo -e "${BLUE}Uses dnsrecon, WAF00W, traceroute, Whatweb, and recon-ng.${NC}"
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

     companyurl=$( printf "%s\n" "$company" | sed 's/ /%20/g; s/\&/%26/g; s/\,/%2C/g' )

     # If folder doesn't exist, create it
     if [ ! -d $home/data/$domain ]; then
          cp -R $discover/report/ $home/data/$domain
          sed 's/REPLACEDOMAIN/'$domain'/g' $home/data/$domain/index.htm > tmp
          mv tmp $home/data/$domain/index.htm
     fi

     echo
     echo $medium
     echo

     export company
     export companyurl
     export domain
     recon/active.sh
     exit
     ;;

     3)
     clear
     f_banner

     echo -e "${BLUE}Import names into an existing recon-ng workspace.${NC}"
     echo
     echo "Example: last, first"
     f_location
     echo "last_name#first_name" > /tmp/names.csv
     sed 's/, /#/' $location  >> /tmp/names.csv

     echo -n "Use Workspace: "
     read -e workspace

     # Check for no answer
     if [[ -z $workspace ]]; then
          f_error
     fi

     # Check for wrong answer
     if [ ! -d /root/.recon-ng/workspaces/$workspace ]; then
          f_error
     fi

     if [ ! -d $home/data/$workspace ]; then
          mkdir -p $home/data/$workspace
     fi

     echo "workspaces select $workspace" > tmp.rc
     cat $discover/resource/recon-ng-import-names.rc >> tmp.rc
     cat $discover/resource/recon-ng-cleanup.rc >> tmp.rc
     sed -i "s/yyy/$workspace/g" tmp.rc

     recon-ng -r $discover/tmp.rc
     rm tmp.rc

     grep '@' emails | cut -d ' ' -f4 | egrep -v '(email|SELECT|username)' | sort -u > $home/data/$workspace/emails.txt
     sed '1,4d' /tmp/names | head -n -5 > $home/data/$workspace/names.txt
     sed '1,4d' /tmp/usernames | head -n -5 > $home/data/$workspace/usernames.txt
     cd /tmp/; rm emails names* usernames 2>/dev/null

     echo
     echo $medium
     echo
     echo -e "The new files are located at ${YELLOW}$home/data/$workspace/${NC}\n"
     echo
     echo
     exit
     ;;

     4) f_main;;

     *) f_error;;
esac
}

##############################################################################################################

f_person(){
f_runlocally
clear
f_banner

echo -e "${BLUE}RECON${NC}"
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

echo -e "${BLUE}Create a free account at salesforce (https://connect.data.com/login).${NC}"
echo -e "${BLUE}Perform a search on your target > select the company name > see all.${NC}"
echo -e "${BLUE}Copy the results into a new file.${NC}"
echo -e "${BLUE}[*] Note: each record should be on a single line.${NC}"

f_location

echo

# Remove blank lines, strings, and leading white space. Set tab as the delimiter
cat $location | sed '/^$/d; s/Direct Dial Available//g; s/[] 	//g; s/^[ \t]*//; s/ \+ /\t/g' > tmp

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
s/5/V/g; s/2cfinancedistributionoperations//g; s/-administration/, Administration/g; s/-air/, Air/g; s/, ,  and$//g; s/ And / and /g; s/ at.*$//g; 
s/ asic / ASIC /g; s/ Asm/ ASM/g; ; s/ api / API /g; s/AssistantChiefPatrolAgent/Assistant Chief Patrol Agent/g; s/-associate/-associate/g; s/ at .*//g; 
s/ At / at /g; s/ atm / ATM /g; s/ bd / BD /g; s/-big/, Big/g; s/BIIb/B2B/g; s/-board/, Board/g; s/-boiler/, Boiler/g; s/ bsc / BSC /g; s/-call/, Call/g; 
s/-capacity/, Capacity/g; s/-cash/, Cash/g; s/ cbt / CBT /g; s/ Cc/ CC/g; s/-chief/, Chief/g; s/ cip / CIP /g; s/ cissp / CISSP /g; s/-civil/, Civil/g; 
s/ cj / CJ /g; s/Clients//g; s/ cmms / CMMS /g; s/ cms / CMS /g; s/-commercial/, Commercial/g; 
s/CommitteemanagementOfficer/Committee Management Officer/g; s/-communications/, Communications/g; s/-community/, Community/g;
s/-compliance/, Compliance/g; s/-consumer/, Consumer/g; s/contact sold, to//g; s/-corporate/, Corporate/g; s/ cpa/ CPA/g; s/-creative/, Creative/g; 
s/ Crm / CRM /g; s/ Csa/ CSA/g; s/ Csc/ CSC/g; s/ctr /Center/g; s/-customer/, Customer/g; s/Datapower/DataPower/g; s/-data/, Data/g; s/ db2 / DB2 /g; 
s/ dbii / DB2 /g; s/ Dc/ DC/g; s/DDesigner/Designer/g; s/DesignatedFederalOfficial/Designated Federal Official/g; s/-design/, Design/g; s/dhs/DHS/g; 
s/-digital/, Digital/g; s/-distribution/, Distribution/g; s/ Disa / DISA /g; s/ dns / DNS /g; s/-dominion/-dominion/g; s/-drilling/, Drilling/g; 
s/ dvp / DVP /g; s/ ebs / EBS /g; s/ Edi / EDI /g; s/editorr/Editor/g; s/ edrm / EDRM /g; s/ eeo / EEO /g; s/ efi / EFI /g; s/-electric/, Electric/g; 
s/EleCenterEngineer/Electric Engineer/g; s/ emc / EMC /g; s/ emea/ EMEA/g; s/-employee/, Employee/g; s/ ems / EMS /g; s/-energy/, Energy/g; 
s/engineer5/Engineer V/g; s/-engineering/, Engineering/g; s/-engineer/, Engineer/g; s/-environmental/, Environmental/g; s/-executive/, Executive/g; 
s/faa / FAA /g; s/-facilities/, Facilities/g; s/ Fdr / FDR /g; s/ ferc / FERC /g; s/ fha / FHA /g; s/-finance/, Finance/g; s/-financial/, Financial/g; 
s/-fleet/, Fleet/g; s/ For / for /g; s/ fsa / FSA /g; s/ fso / FSO /g; s/ fx / FX /g; s/ gaap / GAAP /g; s/-gas/, Gas/g; s/-general/, General/g; 
s/-generation/, Generation/g; s/grp/Group/g; s/ gsa / GSA /g; s/ gsis / GSIS /g; s/ gsm / GSM /g; s/Hbss/HBSS/g; s/ hd / HD /g; s/ hiv / HIV /g; 
s/ hmrc / HMRC /g; s/ hp / HP /g; s/ hq / HQ /g; s/ hris / HRIS /g; s/-human/, Human/g; s/ hvac / HVAC /g; s/ ia / IA /g; s/ id / ID /g; s/ iii/ III/g; 
s/ Ii/ II/g; s/ Iis / IIS /g; s/ In / in /g; s/-industrial/, Industrial/g; s/information technology/IT/g; s/-information/, Information/g; 
s/-infrastructure/, Infrastructure/g; s/-instrumentation/, Instrumentation/g; s/-internal/, Internal/g; s/ ip / IP /g; s/ ir / IR /g; s/ Issm/ ISSM/; 
s/itenterpriseprojectmanager/IT Enterprise Project Manager/g; s/-IT/, IT/g; s/ iv / IV /g; s/ Iv,/ IV,/g; s/Jboss/JBoss/g; s/ jc / JC /g; s/ jd / JD /g; 
s/ jt / JT /g; s/konsult, konsultchef, projektledare/Consultant/g; s/laboratorynetwork/Laboratory, Network/g; s/-labor/, Labor/g; 
s/lan administrator/LAN Administrator/g; s/lan admin/LAN Admin/g; s/-land/, Land/g; s/-licensing/, Licensing/g; s/LawIII60/Law360/g; s/ llc / LLC. /g; 
s/-logistics/, Logistics/g; s/ Lp/ LP/g; s/lvl/Level/g; s/-mail/, Mail/g; s/-manager/, Manager/g; s/-marketing/, Marketing/g; s/-materials/, Materials/g; 
s/ mba / MBA /g; s/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mch/McH/g; s/Mci/McI/g; s/Mcj/McJ/g; 
s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcp/McP/g; s/Mcq/McQ/g; s/Mcs/McS/g; s/Mcv/McV/g; s/mcse/MCSE/g; s/-mechanical/, Mechanical/g; 
s/-metals/, Metals/g; s/-metro/, Metro/g; s/, mp//g; s/ nerc / NERC /g; s/mcp/McP/g; s/mcq/McQ/g; s/mcs/McS/g; s/-media/, Media/g; 
s/-mergers/,Mergers/g; s/-millstone/, Millstone/g; s/-motor/, Motor/g; s/ mssp / MSSP /g; s/-networking/, Networking/g; s/-network/, Network/g; 
s/-new/, New/g; s/-north/, North/g; s/not in it//g; s/ nso / NSO /g; s/-nuclear/, Nuclear/g; s/ Nz / NZ /g; s/ oem / OEM /g; s/-office/, Office/g; 
s/ Of / of /g; s/-operations/, Operations/g; s/-oracle/, Oracle/g; s/-other/, Other/g; s/ pca / PCA /g; s/ pcs / PCS /g; s/ pc / PC /g; s/ pdm / PDM /g; 
s/ phd / PhD /g; s/ pj / PJ /g; s/-plant/, Plant/g; s/plt/Plant/g; s/pmo/PMO/g; s/Pmp/PMP/g; s/ pm / PM /g; s/ Pm / PM /g; s/-power/, Power/g; 
s/-property/, Property/g; s/-public/, Public/g; s/ Psa/ PSA/g; s/pyble/Payble/g; s/ os / OS /g; s/r&d/R&D/g; s/ r and d /R&D/g; s/-records/, Records/g; 
s/-regulated/, Regulated/g; s/-regulatory/, Regulatory/g; s/-related/, Related/g; s/-remittance/, Remittance/g; s/-renewals/, Renewals/g; 
s/-revenue/, Revenue/g; s/ rfid / RFID /g; s/ rfp / RFP /g; s/ rf / RF /g; s/ Roip / RoIP /g; s/Rtls/RTLS/g; s/ Rtm/ RTM/g; s/saas/SaaS/g; 
s/-safety/, Safety/g; s/san manager/SAN Manager/g; s/scada/SCADA/g; s/sdlc/SDLC/g; s/setac-/SETAC,/g; s/sftwr/Software/g; s/-short/, Short/g; 
s/ smb / SMB /g; s/sms/SMS/g; s/smtp/SMTP/g; s/snr/Senior/g; s/.specialist./ Specialist /g; s/ Soc / SOC /g; s/sql/SQL/g; s/spvr/Supervisor/g; 
s/srbranch/Senior Branch/g; s/srsales/Senior Sales/g; s/ ssl / SSL /g; s/-staff/, Staff/g; s/stf/Staff/g; s/-station/, Station/g; 
s/-strategic/, Strategic/g; s/-student/, Student/g; s/-substation/, Substation/g; s/-supplier/, Supplier/g; s/-supply/, Supply/g; 
s/-surveillance/, Surveillance/g; s/swepco/SWEPCO/g; s/-system/, System/g; s/-tax/, Tax/g; s/-technical/, Technical/g; 
s/-telecommunications/, Telecommunications/g; s/ The / the /g; s/-three/, Three/g; s/-tickets/, Tickets/g; s/TierIII/Tier III/g; s/-trading/, Trading/g; 
s/-transmission/, Transmission/g; s/ttechnical/Technical/g; s/-turbine/, Turbine/g; s/ to .*$//g; s/ ui / UI /g; s/ uk / UK /g; 
s/unsupervisor/Supervisor/g; s/uscg/USCG/g; s/ usa / USA /g; s/ us / US /g; s/ Us / US /g; s/ u.s / US /g; s/usmc/USMC/g; s/-utility/, Utility/g; 
s/ ux / UX /g; s/vicepresident/Vice President/g; s/ Va / VA /g; s/ vii / VII /g; s/ vi / VI /g; s/ vms / VMS /g; s/ voip / VoIP /g; s/ vpn / VPN /g; 
s/Weblogic/WebLogic/g; s/Websphere/WebSphere/g; s/ With / with /g' > tmp5

# Remove lines that contain 2 words and clean up.
awk 'NF != 2' tmp5 | sed "s/d'a/D'A/g; s/d'c/D'C/g; s/d'e/D'E/g; s/d'h/D'H/g; s/d's/D'S/g; s/l'a/L'A/g; s/o'b/O'B/g; s/o'c/O'C/g; s/o'd/O'D/g; 
s/o'f/O'F/g; s/o'g/O'G/g; s/o'h/O'H/g; s/o'k/O'K/g; s/o'l/O'L/g; s/o'm/O'M/g; s/o'N/O'N/g; s/Obrien/O'Brien/g; s/Oconnor/O'Connor/g; 
s/Odonnell/O'Donnell/g; s/Ohara/O'Hara/g; s/o'p/O'P/g; s/o'r/O'R/g; s/o's/O'S/g; s/Otoole/O'Toole/g; s/o't/O'T/i" > tmp6

# Replace parenthesis and the contents inside with spaces - thanks Mike G
cat tmp6 | perl -pe 's/(\(.*\))/q[ ] x length $1/ge' > tmp7

# Remove trailing white space, railing commas, and delete lines with a single word
sed 's/[ \t]*$//; s/,$//; /[[:blank:]]/!d' tmp7 | sort -u > $home/data/names.txt
rm tmp*

echo
echo $medium
echo
echo -e "The new report is located at ${YELLOW}$home/data/names.txt${NC}\n"
echo
echo
exit
}

##############################################################################################################

f_generateTargetList(){
clear
f_banner

echo -e "${BLUE}SCANNING${NC}"
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
     1) 
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
     echo -e "The new report is located at ${YELLOW}$home/data/hosts-arp.txt${NC}\n"
     echo
     echo
     exit;;
     2) f_netbios;;
     3) f_netdiscover;;
     4) f_pingsweep;;
     5) f_main;;
     *) f_error;;
esac
}

##############################################################################################################

f_netbios(){
clear
f_banner

echo -e "${BLUE}Type of input:${NC}"
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
echo -e "The new report is located at ${YELLOW}$home/data/netdiscover.txt${NC}\n"
echo
echo
exit
}

##############################################################################################################

f_pingsweep(){
clear
f_banner
f_typeofscan

echo -e "${BLUE}Type of input:${NC}"
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
echo -e "The new report is located at ${YELLOW}$home/data/hosts-ping.txt${NC}\n"
echo
echo
exit
}

##############################################################################################################

f_scanname(){
f_typeofscan

echo -e "${YELLOW}[*] Warning spaces in the name will cause errors${NC}"
echo
echo -n "Name of scan: "
read name

# Check for no answer
if [[ -z $name ]]; then
     f_error
fi

mkdir -p $name
export name
}

##############################################################################################################

f_typeofscan(){
echo -e "${BLUE}Type of scan: ${NC}"
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
     echo -e "${YELLOW}[*] Setting source port to 53 and max probe round trip to 1.5s.${NC}"
     sourceport=53
     export sourceport
     maxrtt=1500ms
     echo
     echo $medium
     echo
     ;;

     2)
     echo
     echo -e "${YELLOW}[*] Setting source port to 88 and max probe round trip to 500ms.${NC}"
     sourceport=88
     export sourceport
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
f_run-metasploit
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
f_run-metasploit
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
f_run-metasploit
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

export delay
f_metasploit

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
     echo -e "${YELLOW}[*] No live hosts were found.${NC}"
     echo
     echo
     exit
fi

# Clean up
egrep -iv '(0000:|0010:|0020:|0030:|0040:|0050:|0060:|0070:|0080:|0090:|00a0:|00b0:|00c0:|00d0:|1 hop|closed|guesses|guessing|filtered|fingerprint|general purpose|initiated|latency|network distance|no exact os|no os matches|os:|os cpe|please report|rttvar|scanned in|sf|unreachable|warning)' $name/nmap.nmap | sed 's/Nmap scan report for //g; /^$/! b end; n; /^$/d; : end' > $name/nmap.txt

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
echo -e "${BLUE}Locating high value ports.${NC}"
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

f_scripts(){
echo
echo $medium
echo
echo -e "${BLUE}Running Nmap scripts.${NC}"

export name
nse.sh
}

##############################################################################################################

f_metasploit(){
echo
echo -n "Run matching Metasploit auxiliaries? (y/N) "
read aux
}

##############################################################################################################

f_run-metasploit(){
if [ "$aux" == "y" ]; then
     echo
     echo -e "${BLUE}Starting Postgres.${NC}"
     service postgresql start

     echo
     echo -e "${BLUE}Starting Metasploit.${NC}"
     echo
     echo -e "${BLUE}Using the following resource files.${NC}"
     cp -R $discover/resource/ /tmp/

     echo workspace -a $name > /tmp/master
     echo spool tmpmsf > /tmp/master

     msf-aux.sh

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
          cat tmpmsf | egrep -iv "(> exit|> run|% complete|attempting to extract|authorization not requested|checking if file|completed|connecting to the server|connection reset by peer|data_connect failed|db_export|did not reply|does not appear|doesn't exist|finished export|handshake failed|ineffective|it doesn't seem|login fail|negotiation failed|nomethoderror|no relay detected|no response|No users found|not be identified|not foundnot vulnerable|providing some time|request timeout|responded with error|rport|rhosts|scanning for vulnerable|shutting down the tftp|spooling|starting export|starting tftp server|starting vnc login|threads|timed out|trying to acquire|unable to|unknown state)" > $name/metasploit.txt
          rm $name/master.rc
          rm tmpmsf
     fi
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
echo -e "${BLUE}Stopping Postgres.${NC}"
service postgresql stop

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The supporting data folder is located at ${YELLOW}$name${NC}\n"
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
     echo -e "${YELLOW}No hosts found with open ports.${NC}"
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
echo -e "The new report is located at ${YELLOW}$home/data/$name/report.txt${NC}\n"
echo
echo
exit
}

##############################################################################################################

f_directObjectRef(){
clear
f_banner

echo -e "${BLUE}Using Burp, authenticate to a site, map & Spider, then log out.${NC}"
echo -e "${BLUE}Target > Site map > select the URL > right click > Copy URLs in this host.${NC}"
echo -e "${BLUE}Paste the results into a new file.${NC}"

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
echo -e "The new report is located at ${YELLOW}$home/data/DirectObjectRef.txt${NC}\n"
echo
echo
exit
}

##############################################################################################################

f_multitabs(){
f_runlocally
clear
f_banner

echo -e "${BLUE}Open multiple tabs in Firefox with:${NC}"
echo
echo "1.  List"
echo "2.  Directories from robots.txt."
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

     # Check if the file is empty
     if [ ! -s robots.txt ]; then
          echo
          echo -e "${RED}$medium${NC}"
          echo
          echo -e "${RED}                          *** No robots file discovered. ***${NC}"
          echo
          echo -e "${RED}$medium${NC}"
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
     echo -e "The new report is located at ${YELLOW}$home/data/$domain-robots.txt${NC}\n"
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

echo -e "${BLUE}Run multiple instances of Nikto in parallel.${NC}"
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
echo -e "The new report is located at ${YELLOW}$home/data/nikto/${NC}\n"
echo
echo
exit
}

##############################################################################################################

f_parse(){
clear
f_banner

echo -e "${BLUE}Parse XML to CSV.${NC}"
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
     echo -e "The new report is located at ${YELLOW}$home/data/burp-`date +%H:%M:%S`.csv${NC}\n"
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
     echo -e "The new report is located at ${YELLOW}$home/data/nessus-`date +%H:%M:%S`.csv${NC}\n"
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
     echo -e "The new report is located at ${YELLOW}$home/data/nexpose-`date +%H:%M:%S`.csv${NC}\n"
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
     echo -e "The new report is located at ${YELLOW}$home/data/nmap-`date +%H:%M:%S`.csv${NC}\n"
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
     echo -e "The new report is located at ${YELLOW}$home/data/qualys-`date +%H:%M:%S`.csv${NC}\n"
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

echo -e "${BLUE}Check for SSL certificate issues.${NC}"
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
               echo -e "${RED}Could not open a connection.${NC}"
               echo "[*] Could not open a connection." >> ssl_$line
               echo >> ssl_$line
               echo $medium >> ssl_$line
               echo >> ssl_$line
               cat ssl_$line >> tmp
          fi
     else
          echo -e "${RED}No response.${NC}"
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
echo -e "The new reports are located at ${YELLOW}$home/data/sslscan.txt, sslyze.txt, ${NC}and ${YELLOW}nmap-ssl.txt ${NC}"
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

echo -e "${BLUE}RECON${NC}"
echo "1.  Domain"
echo "2.  Person"
echo "3.  Parse salesforce"
echo
echo -e "${BLUE}SCANNING${NC}"
echo "4.  Generate target list"
echo "5.  CIDR"
echo "6.  List"
echo "7.  IP, range, or URL"
echo "8.  Rerun Nmap scripts and MSF aux"
echo
echo -e "${BLUE}WEB${NC}"
echo "9.  Insecure direct object reference"
echo "10. Open multiple tabs in Firefox"
echo "11. Nikto"
echo "12. SSL"
echo
echo -e "${BLUE}MISC${NC}"
echo "13. Parse XML"
echo "14. Generate a malicious payload"
echo "15. Start a Metasploit listener"
echo "16. Update"
echo "17. Exit"
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
     8) f_enumerate;;
     9) f_directObjectRef;;
     10) f_multitabs;;
     11) f_nikto;;
     12) f_ssl;;
     13) f_parse;;
     14) f_payload; clear; f_banner; $discover/payload.sh; exit;;
     15) f_listener; clear; f_banner; $discover/listener.sh; exit;;
     16) $discover/update.sh; exit;;
     17) echo; echo; exit;;
     99) $discover/new-stuff.sh; exit;;
     *) f_error;;
esac
}

export -f f_main

##############################################################################################################

while true; do f_main; done
