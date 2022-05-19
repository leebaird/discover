#!/usr/bin/bash


f_targets(){
clear
f_banner

echo -e "${BLUE}SCANNING${NC}"
echo
echo "1.  ARP scan"
echo "2.  Ping sweep"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_arpscan;;
     2) f_pingsweep;;
     3) f_main;;
     *) f_error;;
esac
}

###############################################################################################################################

f_arpscan(){
echo
echo -n "Interface to scan: "
read interface

# Check for no answer
if [ -z $interface ]; then
     f_error
fi

arp-scan -l -I $interface | egrep -v '(arp-scan|DUP:|Interface|packets)' > tmp
sed '/^$/d' tmp | sort -k3 > $home/data/arp-scan.txt
awk '{print $1}' tmp | $sip | sed '/^$/d' > $home/data/targets-arp-scan.txt
rm tmp

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The new report is located at ${YELLOW}$home/data/targets-arp-scan.txt${NC}\n"
echo
echo
exit
}

###############################################################################################################################

f_pingsweep(){
echo
echo -e "${BLUE}Type of input:${NC}"
echo
echo "1.  List containing IPs, ranges, and/or CIDRs."
echo "2.  Manual"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     f_location

     echo
     echo "Running an Nmap ping sweep for live hosts."
     nmap -sn -PS -PE --stats-every 10s -iL $location > tmp
     ;;

     2)
     echo
     echo -n "Enter a CIDR or range: "
     read manual

     # Check for no answer
     if [ -z $manual ]; then
          f_error
     fi

     echo
     echo "Running an Nmap ping sweep for live hosts."
     nmap -sn -PS -PE --stats-every 10s $manual > tmp
     ;;

     *) f_error;;
esac

grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' tmp > $home/data/targets-pingsweep.txt
rm tmp

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The new report is located at ${YELLOW}$home/data/targets-pingsweep.txt${NC}\n"
echo
echo
exit
}

###############################################################################################################################

while true; do f_targets; done
