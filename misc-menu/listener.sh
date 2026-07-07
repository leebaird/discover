#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

clear
f_banner

echo -e "${BLUE}Metasploit Listeners${NC}"
echo
echo "1.   android/meterpreter/reverse_tcp"
echo "2.   cmd/windows/reverse_powershell"
echo "3.   java/jsp_shell_reverse_tcp"
echo "4.   linux/x64/meterpreter_reverse_https"
echo "5.   linux/x64/meterpreter_reverse_tcp"
echo "6.   linux/x64/shell/reverse_tcp"
echo "7.   osx/x64/meterpreter_reverse_https"
echo "8.   osx/x64/meterpreter_reverse_tcp"
echo "9.   php/meterpreter/reverse_tcp"
echo "10.  python/meterpreter_reverse_https"
echo "11.  python/meterpreter_reverse_tcp"
echo "12.  windows/x64/meterpreter_reverse_https"
echo "13.  windows/x64/meterpreter_reverse_tcp"
echo "14.  Previous menu"
echo
echo -n "Choice: "
read -r CHOICE

case "$CHOICE" in
    1) PAYLOAD="android/meterpreter/reverse_tcp" ;;
    2) PAYLOAD="cmd/windows/reverse_powershell" ;;
    3) PAYLOAD="java/jsp_shell_reverse_tcp" ;;
    4) PAYLOAD="linux/x64/meterpreter_reverse_https" ;;
    5) PAYLOAD="linux/x64/meterpreter_reverse_tcp" ;;
    6) PAYLOAD="linux/x64/shell/reverse_tcp" ;;
    7) PAYLOAD="osx/x64/meterpreter_reverse_https" ;;
    8) PAYLOAD="osx/x64/meterpreter_reverse_tcp" ;;
    9) PAYLOAD="php/meterpreter/reverse_tcp" ;;
    10) PAYLOAD="python/meterpreter_reverse_https" ;;
    11) PAYLOAD="python/meterpreter_reverse_tcp" ;;
    12) PAYLOAD="windows/x64/meterpreter_reverse_https" ;;
    13) PAYLOAD="windows/x64/meterpreter_reverse_tcp" ;;
    14) f_main ;;
    *) f_error ;;
esac

echo
echo -n "LHOST: "
read -r LHOST

# Check for no answer
if [ -z "$LHOST" ]; then
    LHOST="$MYIP"
    echo "[*] Using $MYIP"
    echo
fi

echo -n "LPORT: "
read -r LPORT

# Check for no answer
if [ -z "$LPORT" ]; then
    LPORT=443
    echo "[*] Using 443"
fi

# Check for valid port number.
if [[ "$LPORT" -lt 1 || "$LPORT" -gt 65535 ]]; then
    f_error
fi

# Check for root when binding to a low port
if [[ "$LPORT" -lt 1025 && "$(id -u)" != "0" ]]; then
    echo
    echo "[!] You must be root to bind to a port below 1025."
    echo
    exit 1
fi

cp "$DISCOVER"/resource/listener.rc /tmp/

sed -i "s|aaa|$PAYLOAD|g" /tmp/listener.rc
sed -i "s/bbb/$LHOST/g" /tmp/listener.rc
sed -i "s/ccc/$LPORT/g" /tmp/listener.rc

echo
msfconsole -q -r /tmp/listener.rc
