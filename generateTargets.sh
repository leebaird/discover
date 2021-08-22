#!/bin/bash


f_sub(){
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
     1) echo
     echo -n "Interface to scan: "
     read interface

     # Check for no answer
     if [[ -z $interface ]]; then
          f_error
     fi

     arp-scan -l -I $interface | egrep -v '(arp-scan|DUP:|Interface|packets)' > tmp
     sed '/^$/d' tmp | sort -k3 > $home/data/arp-scan.txt
     awk '{print $1}' tmp | $sip | sed '/^$/d' > $home/data/host-arp-scan.txt
     rm tmp

     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     echo -e "The new report is located at ${YELLOW}$home/data/hosts-arp.txt${NC}\n"
     echo
     echo
     exit
     ;;

     2) f_netbios;;
     3) f_netdiscover;;
     4) f_pingsweep;;
     5) f_main;;
     *) f_error;;
esac
}

###############################################################################################################################

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
     exit
     ;;

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
     exit
     ;;

     *) f_error;;
esac
}

###############################################################################################################################

f_netdiscover(){

echo $interface
echo $ip
echo $range

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

###############################################################################################################################

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

###############################################################################################################################

while true; do f_sub; done
