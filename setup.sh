#!/bin/bash

## Global variables
bdate=$(date +"%m-%d-%Y"-%R:%S)
user=$(whoami)

clear
echo
echo

##############################################################################################################

f_inst_tools(){
echo -e "\e[1;33mInstalling Veil-evasion.\e[0m"
apt-get -y --force-yes install veil-evasion
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
}

##############################################################################################################

f_vrfy_repos(){
if [[ `grep -q kali-bleeding-edge /etc/apt/sources.list && grep -q kali-security /etc/apt/sources.list; echo $?` == 0 ]]; then
     echo -e "\e[1;34mOur repos already exist.\e[0m"
     echo
else
     echo -e "\e[1;33mNeed to add our repos.\e[0m"
     f_inst_repos
     echo
fi
}

##############################################################################################################

f_inst_repos(){
## Backup sources.list
cp -p /etc/apt/sources.list /etc/apt/sources.list.$bdate.bak

## Remove all previous kali.org repo lines as well as ours in case of running setup multiple times 
sed -i '/^#.$/d' /etc/apt/sources.list
sed -i '/Security updates/d' /etc/apt/sources.list
sed -i '/cdrom/d' /etc/apt/sources.list
sed -i '/Regular repos/d' /etc/apt/sources.list
sed -i '/Source repos/d' /etc/apt/sources.list
sed -i '/Bleeding Edge repos/d' /etc/apt/sources.list
sed -i '/kali.org/d' /etc/apt/sources.list

## Add remaining sources from sources.list after cleaning to temp file
cat /etc/apt/sources.list > /tmp/sources.leftover

## Add our repo lines to new temp file
echo > /tmp/sources.discoversetup
echo "# Regular repos" >> /tmp/sources.discoversetup
echo "deb http://repo.kali.org/kali kali main non-free contrib" >> /tmp/sources.discoversetup
echo "deb http://security.kali.org/kali-security kali/updates main contrib non-free" >> /tmp/sources.discoversetup
echo >> /tmp/sources.discoversetup

echo "# Source repos" >> /tmp/sources.discoversetup
echo "deb-src http://repo.kali.org/kali kali main non-free contrib" >> /tmp/sources.discoversetup
echo "deb-src http://security.kali.org/kali-security kali/updates main contrib non-free" >> /tmp/sources.discoversetup
echo >> /tmp/sources.discoversetup

echo "# Bleeding Edge repos" >> /tmp/sources.discoversetup
echo "deb http://repo.kali.org/kali kali-bleeding-edge main" >> /tmp/sources.discoversetup
echo >> /tmp/sources.discoversetup

## Remove empty lines from top and merge file contents
sed -i '/./,$!d' /tmp/sources.leftover
olddata=$(cat /tmp/sources.leftover)
newdata=$(cat /tmp/sources.discoversetup)
echo -en "$newdata\n\n$olddata\n" > /etc/apt/sources.list
echo -e "\e[1;33mDone installing repos.\e[0m"
echo
echo
}

##############################################################################################################

f_datadir(){
if [ -d /$user/data ]; then
     echo -e "\e[1;34mUser data directory already exists.\e[0m"
     echo
else
     echo -e "\e[1;33mCreating data directory.\e[0m"
     mkdir -p /$user/data
     echo
fi
}

##############################################################################################################

f_inst_tools
f_vrfy_repos
f_datadir

