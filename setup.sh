#!/bin/bash

clear
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
echo
echo -e "\e[1;33mChecking if goofile is installed, if not installing.\e[0m"
echo

which goofile >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo ""
else
    echo ""
    wget https://goofile.googlecode.com/files/goofilev1.5.zip
    unzip goofilev1.5.zip
    rm goofilev1.5.zip
    echo -e "\e[01;34m[+]\e[00m Goofile Downloaded, Run python goofilev1.5/goofile.py"
    echo ""
    exit 1
fi
