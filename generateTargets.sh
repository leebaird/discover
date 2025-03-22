#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

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
    read -r CHOICE

    case "$CHOICE" in
        1) f_arpscan ;;
        2) f_pingsweep ;;
        3) f_main ;;
        *) echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; "$DISCOVER"./generateTargets.sh ;;
    esac
}

###############################################################################################################################

f_arpscan(){
    echo
    echo "[*] Scanning"

    sudo arp-scan --localnet | grep -Eiv '(interface|arp-scan|packets)' > tmp
    sed '/^$/d' tmp | grep -v "$MYIP" | sort -t ' ' -k 1,1 -V > "$HOME"/data/arp-scan.txt
    awk '{print $1}' tmp | grep -v "$MYIP" | $SIP | sed '/^$/d' > "$HOME"/data/arp-scan-targets.txt
    rm tmp

    echo
    echo "$MEDIUM"
    echo
    echo "[*] Scan complete."
    echo
    echo -e "The new report is located at ${YELLOW}$HOME/data/arp-scan.txt${NC}"
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
    read -r CHOICE

    case "$CHOICE" in
        1)
            f_location

            echo
            echo "[*] Scanning"
            nmap -sn -PS -PE --stats-every 10s -iL "$LOCATION" > tmp
            ;;
        2)
            echo
            echo -n "Enter a CIDR: "
            read -r CIDR

            # Check for no answer
            if [ -z "$CIDR" ]; then
                f_error
            fi

            # Check for a valid CIDR
            if [[ ! "$CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]+$ ]]; then
                f_error
            fi

            echo
            echo "[*] Scanning"
            nmap -sn -PS -PE --stats-every 10s "$CIDR" > tmp
            ;;
        *)
            echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; "$DISCOVER"./generateTargets.sh ;;
    esac

    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' tmp | grep -v "$MYIP" | $SIP > "$HOME"/data/pingsweep.txt
    rm tmp

    echo
    echo "$MEDIUM"
    echo
    echo "[*] Scan complete."
    echo
    echo -e "The new report is located at ${YELLOW}$HOME/data/pingsweep.txt${NC}"
    echo
    exit
}

###############################################################################################################################

while true; do f_targets; done
