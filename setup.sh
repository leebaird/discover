#!/bin/bash

clear
echo
echo

echo -e "\e[1;33mInstalling Filezilla.\e[0m"

if [ -n "$(command -v apt-get)" ]; then
    apt-get -y install filezilla

elif [ -n "$(command -v pacman)" ]; then
    pacman -S filezilla

fi

echo
echo -e "\e[1;33mInstalling gedit.\e[0m"

if [ -n "$(command -v apt-get)" ]; then
    apt-get -y install gedit

elif [ -n "$(command -v pacman)" ]; then
    pacman -S gedit   
fi

echo
echo -e "\e[1;33mInstalling xdotool.\e[0m"

if [ -n "$(command -v apt-get)" ]; then
    apt-get -y install xdotool

elif [ -n "$(command -v pacman)" ]; then
    pacman -S xdotool	
fi

echo
echo -e "\e[1;33mChecking if goofile is installed, if not installing.\e[0m"

which goofile >/dev/null 2>&1

if [ $? -eq 0 ]; then
     echo
elif [ -n "$(command -v apt-get)" ]; then
     echo
     apt-get -y install goofile
     echo
     exit 1
elif [ -n "$(command -v pacman)" ]; then
     echo "Installing needed dependecies for Arch goofile."
     echo
     pacman -S wget
     echo 
     pacman -S gnupg
     echo
     pacman -S grep
     echo
     wget http://blackarch.org/keyring/blackarch-keyring.pkg.tar.xz{,.sig}
     echo
     gpg --keyserver hkp://pgp.mit.edu --recv 4345771566D76038C7FEB43863EC0ADBEA87E4E3
     echo
     gpg --keyserver-o no-auto-key-retrieve --with-f blackarch-keyring.pkg.tar.xz.sig
     echo
     pacman-key --init
     echo
     rm blackarch-keyring.pkg.tar.xz.sig
     echo
     pacman --noc -U blackarch-keyring.pkg.tar.xz
     echo '[blackarch]' >> /etc/pacman.conf
     echo 'Server = http://www.blackarch.org/blackarch/$repo/os/$arch' >> /etc/pacman.conf
     echo
     pacman -Syyu
     echo
     pacman -S goofile
     echo
     exit 1
fi

echo
echo
