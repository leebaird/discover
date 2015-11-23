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

if [ -d /opt/discover/.git ]; then
     echo -e "\e[1;34mUpdating Discover.\e[0m"
    git pull
     cp alias /root/.bash_aliases ; source /root/.bash_aliases
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

if [ -d /opt/EyeWitness/.git ]; then
     echo -e "\e[1;34mUpdating EyeWitness.\e[0m"
     cd /opt/EyeWitness/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling EyeWitness.\e[0m"
     git clone git://github.com/ChrisTruncer/EyeWitness.git /opt/EyeWitness
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

if [ -f /usr/bin/theharvester ]; then
     echo -e "\e[1;34mUpdating theHarvester.\e[0m"
     mv /usr/bin/theharvester /usr/bin/theHarvester
     echo
fi

if [ -d /opt/veil/.git ]; then
     echo -e "\e[1;33mInstalling Veil-Evasion suite.\e[0m"
     unlink /usr/bin/veil
     rm -rf /opt/veil
     apt-get -y install veil-evasion veil-catapult
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

