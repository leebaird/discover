#!/usr/bin/bash

# by Lee Baird
# Contact me via chat or email with any feedback or suggestions:leebaird@gmail.com
#
# Special thanks to:
# Jay Townsend - everything, conversion from Backtrack to Kali
# Jason Ashton (@ninewires)- Penetration Testers Framework (PTF) compatibility, bug crusher, and bash ninja
#
# Thanks to:
# Ben Wood (@DilithiumCore) - regex master
# Dave Klug - planning, testing, and bug reports
# Jason Arnold (@jasonarnold) - original concept and planning, co-author of crack-wifi
# John Kim - Python guru, bug smasher, and parsers
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
# Arthur Kay (@arthurakay) - Python scripts
# Brett Fitzpatrick (@brettfitz) - SQL query
# Robleh Esa (@RoblehEsa) - SQL queries

###############################################################################################################################

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

###############################################################################################################################

# Global variables
CWD=$(pwd)
discover=$(updatedb; locate discover.sh | sed 's:/[^/]*$::')
home=$HOME
interface=$(ip addr | grep 'global' | grep -v 'secondary' | awk '{print $9}')
ip=$(ip addr | grep 'global' | egrep -v '(:|docker)' | cut -d '/' -f1 | awk '{print $2}')
port=443
range=$(ip addr | grep 'global' | grep -v 'secondary' | cut -d '/' -f1 | awk '{print $2}' | cut -d '.' -f1-3)'.1'
rundate=$(date +%B' '%d,' '%Y)
sip='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'
discover=$CWD

long='==============================================================================================================================='
medium='=================================================================='
short='========================================'

RED='\033[1;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

###############################################################################################################################

export CWD
export discover
export home
export interface
export ip
export port
export range
export rundate
export sip
export terminate

export long
export medium
export short

export BLUE
export RED
export YELLOW
export NC

###############################################################################################################################

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

###############################################################################################################################

f_error(){
echo
echo
echo -e "${RED}$medium${NC}"
echo
echo -e "${RED}                *** Invalid choice or entry. ***${NC}"
echo
echo -e "${RED}$medium${NC}"
echo
echo
exit
}

export -f f_error

###############################################################################################################################

f_location(){
echo
echo -n "Enter the location of your file: "
read -e location

# Check for no answer
if [ -z $location ]; then
     f_error
fi

# Check for wrong answer
if [ ! -f $location ]; then
     f_error
fi
}

export -f f_location

###############################################################################################################################

f_runlocally(){
if [ -z $DISPLAY ]; then
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

export -f f_runlocally

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
     cd $discover/
     mv curl debug* email* hosts name* network* records registered* squatting sub* tmp* ultratools usernames-recon whois* z* doc pdf ppt txt xls $save_dir/passive/ 2>/dev/null
     mkdir -p $save_dir/passive/recon-ng/
     cd /tmp/; mv emails names* networks subdomains usernames $save_dir/passive/recon-ng/ 2>/dev/null
     cd $discover
else
     # Move active files
     mkdir -p $save_dir/active/recon-ng/
     cd $discover/
     mv active.rc emails hosts record* robots.txt sub* tmp waf whatweb z* $save_dir/active/ 2>/dev/null
     cd /tmp/; mv subdomains $save_dir/active/recon-ng/ 2>/dev/null
     cd $discover/
fi

echo
echo "Saving complete."
echo
echo
exit 1
}

export -f f_terminate

###############################################################################################################################

f_scanname(){
f_typeofscan

echo -e "${YELLOW}[*] Warning: no spaces allowed${NC}"
echo
echo -n "Name of scan: "
read name

# Check for no answer
if [ -z $name ]; then
     f_error
fi

mkdir -p $name
export name
}

###############################################################################################################################

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
     maxrtt=1500ms
     export sourceport
     export maxrtt
     echo
     echo $medium
     echo
     ;;

     2)
     echo
     echo -e "${YELLOW}[*] Setting source port to 88 and max probe round trip to 500ms.${NC}"
     sourceport=88
     maxrtt=500ms
     export sourceport
     export maxrtt
     echo
     echo $medium
     echo
     ;;

     3) f_main;;

     *) f_error;;
esac
}

###############################################################################################################################

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

# Validate CIDR
sub=$(echo $cidr | cut -d '/' -f2)
min=8
max=32

if ! [[ $sub =~ ^[0-9]+$ ]] || [[ $sub -lt $min || $sub -gt $max ]]; then
     f_error
fi

echo $cidr | grep '/' > /dev/null 2>&1

if [ $? -ne 0 ]; then
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
export START

f_scan
f_ports
$discover/nse.sh
f_run-metasploit
$discover/report.sh && exit
}

###############################################################################################################################

f_list(){
clear
f_banner
f_scanname
f_location

touch tmp
excludefile=tmp

START=$(date +%r\ %Z)
export START

f_scan
f_ports
$discover/nse.sh
f_run-metasploit
$discover/report.sh && exit
}

###############################################################################################################################

f_single(){
clear
f_banner
f_scanname

echo
echo -n "IP, range or URL: "
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
export START

f_scan
f_ports
$discover/nse.sh
f_run-metasploit
$discover/report.sh && exit
}

###############################################################################################################################

f_scan(){
custom='1-1040,1050,1080,1099,1158,1344,1352,1414,1433,1521,1720,1723,1883,1911,1962,2049,2202,2375,2628,2947,3000,3031,3050,3260,3306,3310,3389,3500,3632,4369,4786,5000,5019,5040,5060,5432,5560,5631,5632,5666,5672,5850,5900,5920,5984,5985,6000,6001,6002,6003,6004,6005,6379,6666,7210,7634,7777,8000,8009,8080,8081,8091,8140,8222,8332,8333,8400,8443,8834,9000,9084,9100,9160,9600,9999,10000,10809,11211,12000,12345,13364,19150,20256,27017,28784,30718,35871,37777,46824,49152,50000,50030,50060,50070,50075,50090,60010,60030'
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
if [ -z $delay ]; then
     delay='0'
fi

if [ $delay -lt 0 ] || [ $delay -gt 5 ]; then
     f_error
fi

export delay

echo
echo -n "Run matching Metasploit auxiliaries? (y/N) "
read msf

echo
echo $medium
echo

nmap -iL $location --excludefile $excludefile --privileged -n -PE -PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 -$S -$U -O --osscan-guess --max-os-tries 1 -p T:$tcp,U:$udp --max-retries 3 --min-rtt-timeout 100ms --max-rtt-timeout $maxrtt --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 --open --stats-every 10s -g $sourceport --scan-delay $delay -oA $name/nmap

if [[ -n $(grep '(0 hosts up)' $name/nmap.nmap) ]]; then
     rm -rf "$name" tmp*
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
egrep -iv '(0000:|0010:|0020:|0030:|0040:|0050:|0060:|0070:|0080:|0090:|00a0:|00b0:|00c0:|00d0:|1 hop|closed|guesses|guessing|filtered|fingerprint|general purpose|initiated|latency|network distance|no exact os|no os matches|os cpe|please report|rttvar|scanned in|unreachable|warning)' $name/nmap.nmap | sed 's/Nmap scan report for //g' | sed '/^OS:/d' > $name/nmap.txt

grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $name/nmap.nmap | $sip > $name/hosts.txt
hosts=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

grep 'open' $name/nmap.txt | grep -v 'WARNING' | awk '{print $1}' | sort -un > $name/ports.txt
grep 'tcp' $name/ports.txt | cut -d '/' -f1 > $name/ports-tcp.txt
grep 'udp' $name/ports.txt | cut -d '/' -f1 > $name/ports-udp.txt

grep 'open' $name/nmap.txt | grep -v 'really open' | awk '{for (i=4;i<=NF;i++) {printf "%s%s",sep, $i;sep=" "}; printf "\n"}' | sed 's/^ //' | sort -u | sed '/^$/d' > $name/banners.txt

for i in $(cat $name/ports-tcp.txt); do
     TCPPORT=$i
     cat $name/nmap.gnmap | grep " $i/open/tcp//appserv-http/| $i/open/tcp//http/\| $i/open/tcp//http-alt/\| $i/open/tcp//http-proxy/\| $i/open/tcp//snet-sensor-mgmt/\| $i/open/tcp//sun-answerbook/\| $i/open/tcp//vnc-http/\| $i/open/tcp//wbem-http/\| $i/open/tcp//wsman/" | 
     sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.http://.g' -e "s/$/:$i/g" | $sip >> tmp
     cat $name/nmap.gnmap | grep " $i/open/tcp//compaq-https/\| $i/open/tcp//https/\| $i/open/tcp//https-alt/\| $i/open/tcp//ssl|giop/\| $i/open/tcp//ssl|http/\| $i/open/tcp//tungsten-https/\| $i/open/tcp//ssl|unknown/\| $i/open/tcp//wsmans/" |
     sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.https://.g' -e "s/$/:$i/g" | $sip >> tmp2
done

sed 's/http:\/\///g' tmp > $name/http.txt
sed 's/https:\/\///g' tmp2 > $name/https.txt

# Remove all empty files
find $name/ -type f -empty -exec rm {} +
}

###############################################################################################################################

f_ports(){
echo
echo $medium
echo
echo -e "${BLUE}Locating high value ports.${NC}"
echo "     TCP"
TCP_PORTS="13 19 21 22 23 25 37 69 70 79 80 102 110 111 119 135 139 143 389 433 443 445 465 502 512 513 514 523 524 548 554 563 587 623 631 636 771 831 873 902 993 995 998 1050 1080 1099 1158 1344 1352 1414 1433 1521 1720 1723 1883 1911 1962 2049 2202 2375 2628 2947 3000 3031 3050 3260 3306 3310 3389 3500 3632 4369 4786 5000 5019 5040 5060 5432 5560 5631 5632 5666 5672 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6379 6666 7210 7634 7777 8000 8009 8080 8081 8091 8140 8222 8332 8333 8400 8443 8834 9000 9084 9100 9160 9600 9999 10000 10809 11211 12000 12345 13364 19150 20256 27017 28784 30718 35871 37777 46824 49152 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $TCP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/tcp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [ -f $name/523.txt ]; then
     mv $name/523.txt $name/523-tcp.txt
fi

if [ -f $name/5060.txt ]; then
     mv $name/5060.txt $name/5060-tcp.txt
fi

echo "     UDP"
UDP_PORTS="53 67 123 137 161 407 500 523 623 1434 1604 1900 2302 2362 3478 3671 4800 5353 5683 6481 17185 31337 44818 47808"

for i in $UDP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/udp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [ -f $name/523.txt ]; then
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

###############################################################################################################################

f_cleanup(){
grep -v -E 'Starting Nmap|Host is up|SF|:$|Service detection performed|https' tmp | sed '/^Nmap scan report/{n;d}' | sed 's/Nmap scan report for/Host:/g' > tmp4
}

export -f f_cleanup

###############################################################################################################################

f_run-metasploit(){
if [ "$msf" == "y" ]; then
     $discover/msf-aux.sh
fi
}

###############################################################################################################################

f_enumerate(){
clear
f_banner
f_typeofscan

echo -n "Enter the location of your previous scan: "
read -e location

# Check for no answer
if [ -z $location ]; then
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
if [ -z $delay ]; then
     delay='0'
fi

if [ $delay -lt 0 ] || [ $delay -gt 5 ]; then
     f_error
fi

export delay

$discover/nse.sh
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

###############################################################################################################################

f_main(){
clear
f_banner

if [ ! -d $home/data ]; then
     mkdir -p $home/data
fi

echo -e "${BLUE}RECON${NC}"
echo "1.  Domain"
echo "2.  Person"
echo
echo -e "${BLUE}SCANNING${NC}"
echo "3.  Generate target list"
echo "4.  CIDR"
echo "5.  List"
echo "6.  IP, range, or URL"
echo "7.  Rerun Nmap scripts and MSF aux"
echo
echo -e "${BLUE}WEB${NC}"
echo "8.  Insecure direct object reference"
echo "9.  Open multiple tabs in Firefox"
echo "10. Nikto"
echo "11. SSL"
echo
echo -e "${BLUE}MISC${NC}"
echo "12. Parse XML"
echo "13. Generate a malicious payload"
echo "14. Start a Metasploit listener"
echo "15. Update"
echo "16. Exit"
echo
echo -n "Choice: "
read choice

case $choice in
     1) $discover/domain.sh && exit;;
     2) $discover/person.sh && exit;;
     3) $discover/generateTargets.sh && exit;;
     4) f_cidr;;
     5) f_list;;
     6) f_single;;
     7) f_enumerate;;
     8) $discover/directObjectRef.sh && exit;;
     9) $discover/multiTabs.sh && exit;;
     10) $discover/nikto.sh && exit;;
     11) $discover/ssl.sh && exit;;
     12) $discover/parse.sh && exit;;
     13) $discover/payload.sh && exit;;
     14) $discover/listener.sh && exit;;
     15) $discover/update.sh && exit;;
     16) clear && exit;;
     99) $discover/newModules.sh && exit;;
     *) f_error;;
esac
}

export -f f_main

###############################################################################################################################

while true; do f_main; done
