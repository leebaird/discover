#!/bin/bash

clear
echo
echo

echo -e "\e[1;34mUpdating Kali.\e[0m"
apt-get update ; apt-get -y upgrade ; apt-get -y dist-upgrade ; apt-get -y autoremove ; apt-get -y autoclean ; echo

echo -e "\e[1;34mUpdating Discover scripts.\e[0m"
cd /opt/scripts/ ; git pull ; echo

cp /opt/scripts/alias /root/.bash_aliases ; source /root/.bash_aliases

if [ ! -f /usr/bin/ipscan ]; then
     echo -e "\e[1;33mInstalling Angry IP Scanner.\e[0m"
     wget -q http://sourceforge.net/projects/ipscan/files/ipscan3-binary/3.2.1/ipscan_3.2.1_amd64.deb
     dpkg -i ipscan_3.2.1_amd64.deb
     rm ipscan_3.2.1_amd64.deb
     echo
fi

if [ -d /opt/easy-creds/.git ]; then
     echo -e "\e[1;34mUpdating easy-creds.\e[0m"
     cd /opt/easy-creds/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling easy-creds.\e[0m"
     git clone git://github.com/brav0hax/easy-creds.git /opt/easy-creds
     ln -s /opt/easy-creds/easy-creds.sh  /usr/bin/easy-creds
     echo
fi

if [ -d /opt/smbexec/.git ]; then
     echo -e "\e[1;34mUpdating smbexec.\e[0m"
     cd /opt/smbexec/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling smbexec.\e[0m"
     git clone git://github.com/pentestgeek/smbexec-2.git /opt/smbexec
     ln -s /opt/smbexec/smbexec.rb  /usr/bin/smbexec
     echo
fi

if [ -d /opt/veil/.git ]; then
     echo -e "\e[1;34mUpdating Veil-Evasion.\e[0m"
     cd /opt/veil/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling Veil-Evasion.\e[0m"
     git clone git://github.com/Veil-Framework/Veil-Evasion.git /opt/veil
     ln -s /opt/veil/Veil-Evasion.py /usr/bin/veil
     cd /opt/veil/setup/ ; ./setup.sh
     echo
fi

if [ ! -f /usr/share/windows-binaries/wce.exe ]; then
     echo -e "\e[1;33mInstalling Windows Credential Editor.\e[0m"
     wget http://www.ampliasecurity.com/research/wce_v1_4beta_universal.zip
     unzip wce_v1_4beta_universal.zip
     chmod 755 wce.exe
     mkdir -p /usr/share/windows-binaries/
     mv wce.exe /usr/share/windows-binaries/
     rm Changelog LICENSE.txt README wce_v1_4beta_universal.zip
     echo
fi

echo -e "\e[1;34mUpdating locate database.\e[0m" ; updatedb

echo
echo

