#!/bin/bash

clear
echo
echo

# Fix for errors from URLCrazy file tld.rb lines 81,89,91
# since project is not actively supported.

tlddir=$(locate homophones.rb | sed 's%/[^/]*$%/%')
cd $tlddir

if [ ! -f tld.rb.bak ]; then
    cp tld.rb tld.rb.bak
    cat tld.rb | grep '"bd"=>' -v | grep '"bn"=>' -v | grep '"br"=>' -v > tld_tmp.rb
    mv tld_tmp.rb tld.rb
fi

#########################################################

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

if [ -d /opt/Empire/.git ]; then
     echo -e "\e[1;34mUpdating Empire.\e[0m"
     cd /opt/Empire/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling Empire.\e[0m"
     git clone https://github.com/PowerShellEmpire/Empire.git /opt/Empire
     /opt/Empire/setup/install.sh
     echo
fi

if [ -d /opt/EyeWitness/.git ]; then
     echo -e "\e[1;34mUpdating EyeWitness.\e[0m"
     cd /opt/EyeWitness/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling EyeWitness.\e[0m"
     git clone https://github.com/ChrisTruncer/EyeWitness.git /opt/EyeWitness
     /opt/EyeWitness/setup/setup.sh
fi

if [ ! -f /usr/bin/ssconvert ]; then
     echo -e "\e[1;33mInstalling gnumeric.\e[0m"
     apt-get install -y gnumeric
     echo
fi

if [ ! -f /usr/bin/goofile ]; then
     echo -e "\e[1;33mInstalling goofile.\e[0m"
     apt-get install -y goofile
     echo
fi

if [ ! -f /usr/bin/xmllint ]; then
     echo -e "\e[1;33mInstalling libxml2-utils.\e[0m"
     apt-get install -y libxml2-utils
     echo
fi

if [ -d /opt/prowl/.git ]; then
     echo -e "\e[1;34mUpdating Prowl.\e[0m"
     cd /opt/prowl/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling Prowl.\e[0m"
     git clone https://github.com/Pickfordmatt/Prowl /opt/prowl
     chmod 755 /opt/prowl/prowl.py
     apt-get install python-pip python-lxml
     pip install dnspython Beautifulsoup4 Gitpython
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

if [ -d /opt/Responder/.git ]; then
     echo -e "\e[1;33mRemoving Responder.\e[0m"
     rm -rf /opt/Responder/
     echo
fi

if [[  -d /opt/theHarvester/.git ]]; then
    echo -e "\e[1;33mDeleting theHarvester.\e[0m"
    rm -rf /opt/theHarvester
    rm /usr/share/theHarvester
    echo
fi

if [ ! -f /usr/bin/xdotool ]; then
     echo -e "\e[1;33mInstalling xdotool.\e[0m"
     apt-get install -y xdotool
     echo
fi

if [ -d /opt/Veil-Evasion/.git ]; then
     echo -e "\e[1;34mUpdating Veil-Evasion.\e[0m"
     cd /opt/Veil-Evasion/ ; git pull
     echo
else
     echo -e "\e[1;33mInstalling Veil-Evasion.\e[0m"
     git clone https://github.com/Veil-Framework/Veil-Evasion /opt/Veil-Evasion
     echo
fi

if [ ! -f /usr/bin/xml_grep ]; then
     echo -e "\e[1;33mInstalling xml_grep.\e[0m"
     apt-get install -y xml-twig-tools
     echo
fi

echo -e "\e[1;34mUpdating locate database.\e[0m" ; updatedb

echo
echo

