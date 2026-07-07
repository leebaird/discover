#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

f_typeofscan(){
    echo -e "${BLUE}Type of scan: ${NC}"
    echo
    echo "1.  External"
    echo "2.  Internal"
    echo "3.  Previous menu"
    echo
    echo -n "Choice: "
    read -r CHOICE

    case "$CHOICE" in
        1)
           echo
           echo -e "${YELLOW}[*] Setting the max probe round trip to 1s.${NC}"
           MAXRTT=1000ms
           echo
           echo "$MEDIUM"
           echo
           ;;
        2)
           echo
           echo -e "${YELLOW}[*] Setting the max probe round trip to 500ms.${NC}"
           MAXRTT=500ms
           echo
           echo "$MEDIUM"
           echo
           ;;
        3) f_return_main ;;
        *) f_invalid ;;
    esac
}

###############################################################################################################################

f_scanname(){
    f_typeofscan

    echo -e "${YELLOW}[*] Warning: no spaces allowed${NC}"
    echo
    echo -n "Name of scan: "
    read -r NAME

    # Validate scan name: only allow alphanumeric, dashes, and underscores
    if ! [[ "$NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        f_error
    fi

    mkdir -p "$NAME"
    export NAME
}

###############################################################################################################################

f_scan(){
    CUSTOM='1-1040,1050,1080,1099,1158,1344,1352,1414,1433,1521,1720,1723,1883,1911,1962,2049,2202,2375,2628,2947,3000,3031,3050,3260,3306,3310,3389,3500,3632,4242,4369,4786,5000,5019,5060,5094,5432,5560,5631,5632,5666,5672,5850,5900,5920,5984,5985,6000,6001,6002,6003,6004,6005,6633,6653,6379,6666,7210,7634,7777,8000,8009,8080,8081,8091,8140,8222,8332,8333,8400,8443,8834,9000,9084,9100,9160,9600,9998,9999,10000,10443,10809,11211,12000,12345,13364,19150,20256,27017,28784,30718,35871,37777,46824,49152,50000,50030,50060,50070,50075,50090,60010,60030'
    FULL='1-65535'
    UDP='53,67,69,123,137,161,407,500,523,623,1434,1604,1900,2302,2362,3478,3671,4800,5353,5683,6481,17185,31337,34964,44818,47808'

    echo
    echo -n "Perform full TCP port scan? (y/N) "
    read -r SCAN

    if [ "$SCAN" == "y" ]; then
        TCP=$FULL
    else
        TCP=$CUSTOM
    fi

    echo
    echo -n "Perform version detection? (y/N) "
    read -r VDETECTION

    if [ "$VDETECTION" == "y" ]; then
        S='sTV'
        U='sUV'
    else
        S='sT'
        U='sU'
    fi

    echo
    echo -n "Set scan delay. (0-5, enter for normal) "
    read -r DELAY

    # Check for no answer
    if [ -z "$DELAY" ]; then
        DELAY='0'
    fi

    if [ "$DELAY" -lt 0 ] || [ "$DELAY" -gt 5 ]; then
        f_error
    fi

    export DELAY

    echo
    echo -n "Run matching Metasploit auxiliaries? (y/N) "
    read -r MSF

    echo
    echo "$MEDIUM"
    echo

    sudo nmap --randomize-hosts -iL "$LOCATION" --excludefile "$EXCLUDEFILE" --privileged -n -PE -PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,49152 -"$S" -"$U" -p T:"$TCP",U:"$UDP" -O --osscan-guess --max-os-tries 1 --max-retries 2 --min-rtt-timeout 100ms --max-rtt-timeout "$MAXRTT" --initial-rtt-timeout 500ms --min-rate 450 --max-rate 5000 --open --stats-every 20s --scan-delay "$DELAY" -oA "$NAME"/nmap

    if grep -q '(0 hosts up)' "$NAME"/nmap.nmap; then
        rm -rf "$NAME" tmp*
        echo
        echo "$MEDIUM"
        echo
        echo "[*] Scan complete."
        echo
        echo -e "${YELLOW}[*] No live hosts were found.${NC}"
        echo
        exit
    fi
}

###############################################################################################################################

f_cleanup(){
    grep -Eiv '(0000:|0010:|0020:|0030:|0040:|0050:|0060:|0070:|0080:|0090:|00a0:|00b0:|00c0:|00d0:|=|1 hop|closed|guesses|guessing|failed|filtered|fingerprint|general purpose|initiated|latency|network distance|no exact os|no os matches|not scanned|os:|os cpe|please report|rttvar|scanned in|sf:|unreachable|warning)' "$NAME"/nmap.nmap | sed 's/Nmap scan report for //g' > "$NAME"/nmap.txt

    grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' "$NAME"/nmap.nmap | $SIP > "$NAME"/hosts.txt
    grep 'open' "$NAME"/nmap.txt | grep -v 'WARNING' | awk '{print $1}' | sort -un > "$NAME"/ports.txt
    grep 'tcp' "$NAME"/ports.txt | cut -d '/' -f1 > "$NAME"/ports-tcp.txt
    grep 'udp' "$NAME"/ports.txt | cut -d '/' -f1 > "$NAME"/ports-udp.txt

    grep 'open' "$NAME"/nmap.txt | grep -v 'really open' | awk '{for (i=4;i<=NF;i++) {printf "%s%s",sep, $i;sep=" "}; printf "\n"}' | sed 's/^ //' | sort -u | sed '/^$/d' > "$NAME"/banners.txt

    while read -r i; do
        grep " $i/open/tcp//appserv-http/\| $i/open/tcp//http/\| $i/open/tcp//http-alt/\| $i/open/tcp//http-proxy/\| $i/open/tcp//snet-sensor-mgmt/\| $i/open/tcp//sun-answerbook/\| $i/open/tcp//vnc-http/\| $i/open/tcp//wbem-http/\| $i/open/tcp//wsman/" "$NAME"/nmap.gnmap |
        sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.http://.g' -e "s/$/:$i/g" | $SIP >> tmp
        grep " $i/open/tcp//compaq-https/\| $i/open/tcp//https/\| $i/open/tcp//https-alt/\| $i/open/tcp//ssl|giop/\| $i/open/tcp//ssl|http/\| $i/open/tcp//ssl|https-alt/\| $i/open/tcp//tungsten-https/\| $i/open/tcp//ssl|unknown/\| $i/open/tcp//wsmans/" "$NAME"/nmap.gnmap |
        sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.https://.g' -e "s/$/:$i/g" | $SIP >> tmp2
    done < "$NAME"/ports-tcp.txt

    sed 's/http:\/\///g' tmp | $SIP > "$NAME"/http.txt
    sed 's/https:\/\///g' tmp2 | $SIP > "$NAME"/https.txt

    # Remove all empty files
    find "$NAME"/ -type f -empty -delete

    # Cleanup temp files
    rm tmp* 2>/dev/null
}

###############################################################################################################################

f_ports(){
    echo
    echo "$MEDIUM"
    echo
    echo -e "${BLUE}Locating high value ports.${NC}"
    echo "     TCP"
    TCP_PORTS="13 19 21 22 23 25 37 69 70 79 80 102 110 111 119 135 139 143 389 433 443 445 465 502 512 513 514 523 524 548 554 563 587 623 631 636 771 831 873 902 993 995 998 1050 1080 1099 1158 1344 1352 1414 1433 1521 1720 1723 1883 1911 1962 2049 2202 2375 2628 2947 3000 3031 3050 3260 3306 3310 3389 3500 3632 4242 4369 4786 5000 5019 5060 5094 5432 5560 5631 5632 5666 5672 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6633 6653 6379 6666 7210 7634 7777 8000 8009 8080 8081 8091 8140 8222 8332 8333 8400 8443 8834 9000 9084 9100 9160 9600 9998 9999 10000 10443 10809 11211 12000 12345 13364 19150 20256 27017 28784 30718 35871 37777 46824 49152 50000 50030 50060 50070 50075 50090 60010 60030"

    for i in $TCP_PORTS; do
        cat "$NAME"/nmap.gnmap | grep "\<$i/open/tcp\>" | cut -d ' ' -f2 | $SIP > "$NAME"/"$i".txt
    done

    if [ -f "$NAME"/523.txt ]; then
        mv "$NAME"/523.txt "$NAME"/523-tcp.txt
    fi

    if [ -f "$NAME"/5060.txt ]; then
        mv "$NAME"/5060.txt "$NAME"/5060-tcp.txt
    fi

    echo "     UDP"
    UDP_PORTS="53 67 69 123 137 161 407 500 523 623 1434 1604 1900 2302 2362 3478 3671 4800 5353 5683 6481 17185 31337 34964 44818 47808"

    for i in $UDP_PORTS; do
        cat "$NAME"/nmap.gnmap | grep "\<$i/open/udp\>" | cut -d ' ' -f2 | $SIP > "$NAME"/"$i".txt
    done

    if [ -f "$NAME"/523.txt ]; then
        mv "$NAME"/523.txt "$NAME"/523-udp.txt
    fi

    tmp_files=()
    for file in "$NAME"/60010.txt "$NAME"/60030.txt; do
        [ -s "$file" ] && tmp_files+=("$file")
    done

    if [ ${#tmp_files[@]} -gt 0 ]; then
        cat "${tmp_files[@]}" > tmp
        $SIP tmp > "$NAME"/apache-hbase.txt
    fi

    # Combine Bitcoin ports and sort
    cat "$NAME"/8332.txt "$NAME"/8333.txt > tmp
    $SIP tmp > "$NAME"/bitcoin.txt

    # Combine DB2 ports and sort
    cat "$NAME"/523-tcp.txt "$NAME"/523-udp.txt > tmp
    $SIP tmp > "$NAME"/db2.txt

    # Combine Hadoop ports and sort
    cat "$NAME"/50030.txt "$NAME"/50060.txt "$NAME"/50070.txt "$NAME"/50075.txt "$NAME"/50090.txt > tmp
    $SIP tmp > "$NAME"/hadoop.txt

    # Combine NNTP ports and sort
    cat "$NAME"/119.txt "$NAME"/433.txt "$NAME"/563.txt > tmp
    $SIP tmp > "$NAME"/nntp.txt

    # Combine SMTP ports and sort
    cat "$NAME"/25.txt "$NAME"/465.txt "$NAME"/587.txt > tmp
    $SIP tmp > "$NAME"/smtp.txt

    # Combine X11 ports and sort
    cat "$NAME"/6000.txt "$NAME"/6001.txt "$NAME"/6002.txt "$NAME"/6003.txt "$NAME"/6004.txt "$NAME"/6005.txt > tmp
    $SIP tmp > "$NAME"/x11.txt

    # Combine Openflow ports and sort
    cat "$NAME"/6633.txt "$NAME"/6653.txt > tmp
    $SIP tmp > "$NAME"/openflow.txt

    # Remove all empty files
    find "$NAME"/ -type f -empty -delete

    # Cleanup temp files
    rm tmp* 2>/dev/null
}

###############################################################################################################################

f_location(){
    echo
    echo -n "Enter the location of your file: "
    read -r LOCATION

    # Check for no answer
    if [ -z "$LOCATION" ]; then
        f_error
    fi

    # Check for wrong answer
    if [ ! -f "$LOCATION" ]; then
        f_error
    fi
}

export -f f_location

###############################################################################################################################

f_cidr(){
    clear
    f_banner
    f_scanname

    echo
    echo "Usage: 192.168.1.0/24"
    echo
    echo -n "CIDR: "
    read -r CIDR

    # Check for no answer
    if [ -z "$CIDR" ]; then
        rm -rf "$NAME"
        f_error
    fi

    # Check for a valid CIDR
    if [[ ! "$CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]+$ ]]; then
        f_error
    fi

    echo "$CIDR" > tmp-list
    LOCATION=tmp-list

    echo
    echo -n "Do you have an exclusion list? (y/N) "
    read -r EXCLUDE

    if [ "$EXCLUDE" == "y" ]; then
        echo -n "Enter the path to the file: "
        read -r EXCLUDEFILE

        if [ -z "$EXCLUDEFILE" ]; then
            f_error
        fi

        if [ ! -f "$EXCLUDEFILE" ]; then
            f_error
        fi
    else
        touch tmp
        EXCLUDEFILE=tmp
    fi

    START=$(date +%r\ %Z)
    export START

    f_scan
    f_cleanup
    f_ports
    "$SCAN_DIR/nse.sh"
    f_run-metasploit
    "$SCAN_DIR/report.sh" && exit
}

###############################################################################################################################

f_list(){
    clear
    f_banner
    f_scanname
    f_location

    touch tmp
    EXCLUDEFILE=tmp

    START=$(date +%r\ %Z)
    export START

    f_scan
    f_cleanup
    f_ports
    "$SCAN_DIR/nse.sh"
    f_run-metasploit
    "$SCAN_DIR/report.sh" && exit
}

###############################################################################################################################

f_single(){
    clear
    f_banner
    f_scanname

    echo
    echo -n "IP, range or URL: "
    read -r TARGET

    # Check for no answer
    if [ -z "$TARGET" ]; then
        rm -rf "$NAME"
        f_error
    fi

    echo "$TARGET" > tmp-target
    LOCATION=tmp-target

    touch tmp
    EXCLUDEFILE=tmp

    START=$(date +%r\ %Z)
    export START

    f_scan
    f_cleanup
    f_ports
    "$SCAN_DIR/nse.sh"
    f_run-metasploit
    "$SCAN_DIR/report.sh" && exit
}

###############################################################################################################################

f_run-metasploit(){
    if [ "$MSF" == "y" ]; then
        "$SCAN_DIR/msf-aux.sh"
    fi
}

###############################################################################################################################

f_rerun(){
    clear
    f_banner

    echo "Rerum NSEs and Metasploit aux modules against a previous nmap scan."
    echo
    echo -n "Enter the folder location of your previous scan: "
    read -r LOCATION

    # Check for no answer
    if [ -z "$LOCATION" ]; then
        f_error
    fi

    # Check for file
    if [ ! -f "$LOCATION"/nmap.nmap ]; then
        echo
        echo -e "${RED}[!] This folder must contain nmap.nmap.${NC}"
        echo
        exit 1
    fi

    NAME=$LOCATION
    export NAME

    echo
    echo -n "Set scan delay. (0-5, enter for normal) "
    read -r DELAY

    # Check for no answer
    if [ -z "$DELAY" ]; then
        DELAY='0'
    fi

    if [ "$DELAY" -lt 0 ] || [ "$DELAY" -gt 5 ]; then
        f_error
    fi

    export DELAY

    f_cleanup
    f_ports

    START=$(date +%r\ %Z)
    export START

    "$SCAN_DIR/nse.sh"
    "$SCAN_DIR/msf-aux.sh"
    "$SCAN_DIR/report.sh" && exit
}

export -f f_typeofscan f_scanname f_scan f_cleanup f_ports f_cidr f_list f_single f_rerun f_run-metasploit
