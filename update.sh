#!/bin/bash

clear
echo
echo

if [ -d /pentest ]; then
     echo -e "\e[1;34mUpdating Discover.\e[0m"
     git pull
     echo
     echo
     exit
fi

echo -e "\e[1;34mUpdating Kali.\e[0m"
apt-get update ; apt-get -y upgrade ; apt-get -y dist-upgrade ; apt-get -y autoremove ; apt-get -y autoclean ; echo

if [ -d /opt/CrackMapExec/.git ]; then
     echo -e "\e[1;34mUpdating CrackMapExec.\e[0m"
     cd /opt/CrackMapExec/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling CrackMapExec.\e[0m"
     git clone https://github.com/byt3bl33d3r/CrackMapExec.git /opt/CrackMapExec
     echo
fi

if [ -d /opt/discover/.git ]; then
     echo -e "\e[1;34mUpdating Discover.\e[0m"
     cd /opt/discover ; git pull
     echo
fi

if [ -d /opt/Empire/Empire.git ]; then
     echo -e "\e[1;34mUpdating Empire.\e[0m"
     cd /opt/rawr/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling Empire.\e[0m"
     git clone https://github.com/PowerShellEmpire/Empire.git /opt/Empire
     /opt/Empire/setup/install.sh
     echo
fi

if [ ! -f /usr/bin/goofile ]; then
     echo -e "\e[1;33mInstalling goofile.\e[0m"
     apt-get install -y goofile
     echo
fi

if [ -d /opt/rawr/.git ]; then
     echo -e "\e[1;34mUpdating RAWR.\e[0m"
     cd /opt/rawr/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling RAWR.\e[0m"
     git clone https://bitbucket.org/al14s/rawr.git /opt/rawr
     /opt/rawr/install.sh y
fi

if [ -f /usr/bin/theharvester ]; then
     echo -e "\e[1;34mUpdating theHarvester.\e[0m"
     mv /usr/bin/theharvester /usr/bin/theHarvester
     echo
fi

if [ ! -f /usr/bin/xdotool ]; then
     echo -e "\e[1;33mInstalling xdotool.\e[0m"
     apt-get install -y xdotool
     echo
fi

echo -e "\e[1;34mUpdating locate database.\e[0m" ; updatedb

echo
echo
