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
echo -e "\e[1;33mUpdating repositories.\e[0m"

## Backup sources.list
cp -p /etc/apt/sources.list /etc/apt/sources.list.before.setup.bak

## Remove all previous kali.org repo lines as well as ours in case of multiple times running setup
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

## Cut empty lines from top and merge file contents
sed -i '/./,$!d' /tmp/sources.leftover
olddata=$(cat /tmp/sources.leftover)
newdata=$(cat /tmp/sources.discoversetup)
echo -en "$newdata\n\n$olddata\n" > /etc/apt/sources.list
echo
echo

## Create data directory
echo -e "\e[1;33mCreating Data Directory.\e[0m"
mkdir -p /$user/discoveries
echo

