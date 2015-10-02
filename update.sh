#!/bin/bash

clear
echo
echo

x=$(uname -a | awk '{print $3}' | cut -d '.' -f1)

if [[ $x > 3 ]]; then
     echo -e "\e[1;34mUpdating Kali 2.0.\e[0m"
     apt-get update ; apt-get -y upgrade ; echo

     if [ ! -d /usr/bin/goofile ]; then
          echo -e "\e[1;33mInstalling goofile.\e[0m"
          wget "https://goofile.googlecode.com/files/goofilev1.5.zip"
          unzip -p goofilev1.5.zip goofilev1.5/goofile.py > /usr/bin/goofile
          chmod +x /usr/bin/goofile
          rm goofilev1.5.zip
     fi

     if [ -d /opt/discover/.git ]; then
          echo -e "\e[1;34mUpdating Discover scripts.\e[0m"
          cd /opt/discover/ ; git pull
          cp /opt/discover/alias /root/.bash_aliases ; source /root/.bash_aliases
          echo
     fi

else
     echo -e "\e[1;34mUpdating Kali.\e[0m"
     apt-get update ; apt-get -y upgrade ; apt-get -y dist-upgrade ; apt-get -y autoremove ; apt-get -y autoclean ; echo

     if [ -d /opt/discover/.git ]; then
          echo -e "\e[1;34mUpdating Discover scripts.\e[0m"
          cd /opt/discover/ ; git pull
          cp /opt/discover/alias /root/.bash_aliases ; source /root/.bash_aliases
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
     fi

     if [ ! -f /opt/google/chrome/google-chrome ]; then
          echo -e "\e[1;33mInstalling Google Chrome.\e[0m"
          wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
          dpkg -i google-chrome-stable_current_amd64.deb
          head -n -1 /opt/google/chrome/google-chrome > temp.txt ; mv temp.txt /opt/google/chrome/google-chrome
          echo 'exec -a "$0" "$HERE/chrome"  "$@" --user-data-dir' >> /opt/google/chrome/google-chrome
          chmod +x /opt/google/chrome/google-chrome
          rm google-chrome-stable_current_amd64.deb
          echo
     fi

     if [ ! -f /usr/bin/i586-mingw32msvc-c++ ]; then
          echo -e "\e[1;33mInstalling Ming C Compiler.\e[0m"
          apt-get -y install mingw32
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

     if [ -d /opt/veil/.git ]; then
          echo -e "\e[1;33mInstalling Veil-Evasion suite.\e[0m"
          unlink /usr/bin/veil
          rm -rf /opt/veil
          apt-get -y install veil-evasion veil-catapult
          echo
     fi

     if [ ! -f /usr/share/windows-binaries/wce.exe ]; then
          echo -e "\e[1;33mInstalling Windows Credential Editor.\e[0m"
          wget http://www.ampliasecurity.com/research/wce_v1_4beta_universal.zip
          unzip wce_v1_4beta_universal.zip
          chmod 755 wce.exe
          mv wce.exe /usr/share/windows-binaries/
          rm Changelog LICENSE.txt README wce_v1_4beta_universal.zip
          echo
     fi
fi

echo -e "\e[1;34mUpdating locate database.\e[0m" ; updatedb

echo
echo

