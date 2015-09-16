#!/bin/bash

clear
echo
echo

echo -e "\e[1;33mInstalling Filezilla.\e[0m"
if [ -n "$(command -v apt-get)" ]; then
    apt-get -y install filezilla

elif [ -n "$(command -v pacman)" ]; then
	pacman -S filezilla
else
	echo "apt-get and pacman aren't package managers?"
	exit 1;
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
	echo
     pacman -S goofile
     echo
     exit 1
     
fi

echo
echo