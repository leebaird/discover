#!/bin/bash

clear
echo
echo

echo -e "\e[1;33mInstalling Veil-evasion.\e[0m"
apt-get -y install veil-evasion
echo
echo
echo -e "\e[1;33mInstalling Filezilla.\e[0m"
apt-get -y install filezilla
echo
echo -e "\e[1;33mInstalling gedit.\e[0m"
apt-get -y install gedit
echo
echo -e "\e[1;33mInstalling xdotool.\e[0m"
apt-get -y install xdotool
echo
echo -e "\e[1;33mUpdating repositories.\e[0m"
echo "# Regular repos" > /etc/apt/sources.list
echo "deb http://http.kali.org/kali kali main non-free contrib" >> /etc/apt/sources.list
echo "deb http://security.kali.org/kali-security kali/updates main contrib non-free" >> /etc/apt/sources.list
echo >> /etc/apt/sources.list

echo "# Source repos" >> /etc/apt/sources.list
echo "deb-src http://http.kali.org/kali kali main non-free contrib" >> /etc/apt/sources.list
echo "deb-src http://security.kali.org/kali-security kali/updates main contrib non-free" >> /etc/apt/sources.list
echo >> /etc/apt/sources.list

echo "# Bleeding Edge repos" >> /etc/apt/sources.list
echo "deb http://repo.kali.org/kali kali-bleeding-edge main" >> /etc/apt/sources.list
echo
echo

