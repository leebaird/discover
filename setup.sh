#!/bin/bash

clear
echo
echo

echo
echo -e "\e[1;33mInstalling arp-scan.\e[0m"
apt-get -y install arp-scan ; echo

echo -e "\e[1;33mInstalling Filezilla.\e[0m"
apt-get -y install filezilla ; echo

echo -e "\e[1;33mInstalling xdotool.\e[0m"
apt-get -y install xdotool ; echo

distro=$(uname -n)

if [ $distro = kali ]; then
     echo -ne "\e[1;33mDo you want to use the bleeding edge repos? [y/n].\e[0m "
     read repo

     if [ $repo = 'y' ]; then
          echo -e "\e[1;33mSetting up bleeding edge repos.\e[0m"
          echo deb http://repo.kali.org/kali kali-bleeding-edge main >> /etc/apt/sources.list
          echo
          echo -e "\e[1;33mUpdating Repositories.\e[0m"
          apt-get -y update ; apt-get -y upgrade; apt-get -y dist-upgrade
     fi

     echo
     echo -ne "\e[1;33mDo you want to enable the postgresql and metasploit at startup? [y/n].\e[0m "
     read startup

     if [ $startup = 'y' ]; then
          echo -e "\e[1;33mSetting up postgresql and metasploit.\e[0m"
          sleep 3
          update-rc.d postgresql enable && update-rc.d metasploit enable
     fi

     echo -e "\e[1;33mInstalling gedit.\e[0m"
     apt-get -y install gedit ; echo ; echo
     exit
fi

echo
echo -e "\e[1;34mUpdating .bashrc.\e[0m"
grep -v "export PATH=\$PATH:/etc/alternatives/gem-bin" /root/.bashrc > /root/tmp
mv /root/tmp /root/.bashrc

echo
echo

