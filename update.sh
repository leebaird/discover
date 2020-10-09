#!/bin/bash

# Global variables
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

###############################################################################################################################

clear
echo

if [ -d /pentest ]; then
    echo -e "${BLUE}Updating Discover.${NC}"
    git pull
    echo
    echo
    exit
fi

echo -e "${BLUE}Updating Kali.${NC}"
apt update ; apt -y upgrade ; apt -y dist-upgrade ; apt -y autoremove ; apt -y autoclean ; updatedb
echo

if [ -d /opt/BloodHound-v3/.git ]; then
     echo -e "${BLUE}Updating BloodHound.${NC}"
     cd /opt/BloodHound-v3/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Neo4j.${NC}"
     echo "deb http://httpredir.debian.org/debian stretch-backports main" | sudo tee -a /etc/apt/sources.list.d/stretch-backports.list
     apt-get update
     wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
     echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
     apt-get update
     apt-get install apt-transport-https
     apt-get -y install neo4j
     systemctl stop neo4j
     echo
     echo -e "${YELLOW}Installing BloodHound.${NC}"
     git clone https://github.com/BloodHoundAD/BloodHound.git /opt/BloodHound-v3
     apt -y install npm
     cd /opt/BloodHound-v3/
     npm install
     npm run linuxbuild
     echo
fi

if [ -d /opt/Cobalt-Strike ]; then
     if [ -d /opt/Cobalt-Strike/third-party/chryzsh-scripts/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike aggressor scripts - chryzsh.${NC}"
          cd /opt/Cobalt-Strike/third-party/chryzsh-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike aggressor scripts - chryzsh.${NC}"
          git clone https://github.com/chryzsh/Aggressor-Scripts.git /opt/Cobalt-Strike/third-party/chryzsh-scripts
          echo
     fi

     if [ -d /opt/Cobalt-Strike/third-party/mgeeky-scripts/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike aggressor scripts - mgeeky.${NC}"
          cd /opt/Cobalt-Strike/third-party/mgeeky-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike aggressor scripts - mgeeky.${NC}"
          git clone https://github.com/mgeeky/cobalt-arsenal.git /opt/Cobalt-Strike/third-party/mgeeky-scripts
          echo
     fi

     if [ -d /opt/Cobalt-Strike/third-party/profiles/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike profiles.${NC}"
          cd /opt/Cobalt-Strike/third-party/profiles/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike profiles.${NC}"
          git clone https://github.com/rsmudge/Malleable-C2-Profiles.git /opt/Cobalt-Strike/third-party/profiles
          echo
     fi

     if [ -d /opt/Cobalt-Strike/third-party/taowu-scripts/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike aggressor scripts - taowu.${NC}"
          cd /opt/Cobalt-Strike/third-party/taowu-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike aggressor scripts - taowu.${NC}"
          git clone https://github.com/pandasec888/taowu-cobalt-strike.git /opt/Cobalt-Strike/third-party/taowu-scripts
          echo
     fi
fi

if [ -d /opt/Covenant/.git ]; then
     echo -e "${BLUE}Updating Covenant.${NC}"
     cd /opt/Covenant/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Covenant.${NC}"
     git clone --recurse-submodules https://github.com/cobbr/Covenant.git /opt/Covenant
     echo
fi

if [ -d /opt/CrackMapExec/.git ]; then
     echo -e "${BLUE}Updating CrackMapExec.${NC}"
     cd /opt/CrackMapExec/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing CrackMapExec.${NC}"
     apt-get install -y libssl-dev libffi-dev python-dev build-essential
     pip install --user pipenv
     git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec /opt/CrackMapExec
     cd CrackMapExec && pipenv install
     pipenv shell
     python setup.py install
     echo
fi

if [ -d /opt/discover/.git ]; then
     echo -e "${BLUE}Updating Discover.${NC}"
     cd /opt/discover ; git pull
     echo
fi

if [ -d /opt/DNSRecon/.git ]; then
     echo -e "${BLUE}Updating DNSRecon.${NC}"
     cd /opt/DNSRecon/ ; git pull
     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing DNSRecon.${NC}"
     git clone https://github.com/darkoperator/dnsrecon.git /opt/DNSRecon
     cd /opt/DNSRecon/
     pip3 install -r requirements.txt
     echo
fi

if [ -d /opt/dnstwist/.git ]; then
     echo -e "${BLUE}Updating dnstwist.${NC}"
     cd /opt/dnstwist/ ; git pull
     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing dnstwist.${NC}"
     git clone https://github.com/elceef/dnstwist.git /opt/dnstwist
     apt install python3-dnspython python3-geoip python3-whois python3-requests python3-ssdeep
     cd /opt/dnstwist/
     pip3 install -r requirements.txt
     echo
fi

if [ -d /opt/Domain-Hunter/.git ]; then
     echo -e "${BLUE}Updating Domain Hunter.${NC}"
     cd /opt/Domain-Hunter/ ; git pull
     #pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing Domain Hunter.${NC}"
     git clone https://github.com/threatexpress/domainhunter.git /opt/Domain-Hunter
     cd /opt/Domain-Hunter/
     pip3 install -r requirements.txt
     chmod 755 domainhunter.py
     echo
fi

if [ -d /opt/DomainPasswordSpray/.git ]; then
     echo -e "${BLUE}Updating DomainPasswordSpray.${NC}"
     cd /opt/DomainPasswordSpray/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing DomainPasswordSpray.${NC}"
     git clone https://github.com/dafthack/DomainPasswordSpray.git /opt/DomainPasswordSpray
     echo
fi

if [ -d /opt/Donut/.git ]; then
     echo -e "${BLUE}Updating Donut.${NC}"
     cd /opt/Donut/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Donut.${NC}"
     git clone https://github.com/TheWover/donut.git /opt/Donut
     echo
fi

if [ -d /opt/droopescan/.git ]; then
     echo -e "${BLUE}Updating droopescan.${NC}"
     cd /opt/droopescan/ ; git pull
     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing droopescan.${NC}"
     git clone https://github.com/droope/droopescan.git /opt/droopescan
     cd /opt/droopescan/
     pip3 install -r requirements.txt
     echo
fi

if [ -d /opt/Egress-Assess/.git ]; then
     echo -e "${BLUE}Updating Egress-Assess.${NC}"
     cd /opt/Egress-Assess/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Egress-Assess.${NC}"
     git clone https://github.com/ChrisTruncer/Egress-Assess.git /opt/Egress-Assess
     cd /opt/Egress-Assess/setup/
     ./setup.sh
     mv server.pem ../Egress-Assess/
     rm impacket*
     echo
fi

if [ -d /opt/Empire/.git ]; then
     echo -e "${BLUE}Updating Empire.${NC}"
     cd /opt/Empire/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Empire.${NC}"
     git clone https://github.com/BC-SECURITY/Empire/ /opt/Empire
     cd /opt/Empire/setup/
     ./install.sh
fi

if [ -d /opt/EyeWitness/.git ]; then
     echo -e "${BLUE}Updating EyeWitness.${NC}"
     cd /opt/EyeWitness/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing EyeWitness.${NC}"
     git clone https://github.com/ChrisTruncer/EyeWitness.git /opt/EyeWitness
     cd /opt/EyeWitness/Python/setup/
     ./setup.sh
fi

if [ ! -f /usr/bin/xmllint ]; then
     echo -e "${YELLOW}Installing libxml2-utils.${NC}"
     apt-get install -y libxml2-utils
fi

if [ -d /opt/Nishang/.git ]; then
     echo -e "${BLUE}Updating Nishang.${NC}"
     cd /opt/Nishang/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Nishang.${NC}"
     git clone https://github.com/samratashok/nishang.git /opt/Nishang
     echo
fi

echo -e "${BLUE}Updating Nmap scripts.${NC}"
nmap --script-updatedb | egrep -v '(Starting|seconds)' | sed 's/NSE: //'
echo

if [ -d /opt/PowerUpSQL/.git ]; then
     echo -e "${BLUE}Updating PowerUpSQL.${NC}"
     cd /opt/PowerUpSQL/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PowerUpSQL.${NC}"
     git clone https://github.com/NetSPI/PowerUpSQL.git /opt/PowerUpSQL
     echo
fi

if [ -d /opt/PS-Attack/.git ]; then
     echo -e "${BLUE}Updating PS>Attack.${NC}"
     cd /opt/PS-Attack/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PS>Attack.${NC}"
     git clone https://github.com/jaredhaight/PSAttack.git /opt/PS-Attack
     echo
fi


if [ -d /opt/Seatbelt/.git ]; then
     echo -e "${BLUE}Updating Seatbelt.${NC}"
     cd /opt/Seatbelt/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Seatbelt.${NC}"
     git clone https://github.com/GhostPack/Seatbelt.git /opt/Seatbelt
     echo
fi


if [ -d /opt/SecLists/.git ]; then
     echo -e "${BLUE}Updating SecLists.${NC}"
     cd /opt/SecLists/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing SecLists.${NC}"
     git clone https://github.com/danielmiessler/SecLists /opt/SecLists
     echo
fi

if [ -d /opt/SharpShooter/.git ]; then
     echo -e "${BLUE}Updating SharpShooter.${NC}"
     cd /opt/SharpShooter/ ; git pull
     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing SharpShooter.${NC}"
     git clone https://github.com/mdsecactivebreach/SharpShooter.git /opt/SharpShooter
     cd /opt/SharpShooter/
     pip3 install -r requirements.txt
     echo
fi

if [ -d /opt/spoofcheck/.git ]; then
     echo -e "${BLUE}Updating spoofcheck.${NC}"
     cd /opt/spoofcheck/ ; git pull
     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing spoofcheck.${NC}"
     git clone https://github.com/BishopFox/spoofcheck.git /opt/spoofcheck
     cd /opt/spoofcheck/
     pip3 install -r requirements.txt
     echo
fi

if [ -d /opt/SprayingToolkit/.git ]; then
     echo -e "${BLUE}Updating SprayingToolkit.${NC}"
     cd /opt/SprayingToolkit/ ; git pull
#     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing SprayingToolkit.${NC}"
     git clone https://github.com/byt3bl33d3r/SprayingToolkit.git /opt/SprayingToolkit
     cd /opt/SprayingToolkit/
     pip3 install -r requirements.txt
     echo
fi

if [ -d /opt/theHarvester/.git ]; then
     echo -e "${BLUE}Updating theHarvester.${NC}"
     cd /opt/theHarvester/ ; git pull
     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing theHarvester.${NC}"
     git clone https://github.com/laramies/theHarvester.git /opt/theHarvester
     cd /opt/theHarvester/
     pip3 install -r requirements.txt
     echo
fi

if [ ! -e /usr/lib/python3/dist-packages/texttable.py ]; then
     echo -e "${YELLOW}Installing Texttable.${NC}"
     apt install -y python3-texttable
     echo
fi

if [ -d /opt/unicorn/.git ]; then
     echo -e "${BLUE}Updating unicorn.${NC}"
     cd /opt/unicorn/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing unicorn.${NC}"
     git clone https://github.com/trustedsec/unicorn.git /opt/unicorn
     echo
fi

if [ -d /opt/Veil/.git ]; then
     echo -e "${BLUE}Updating Veil.${NC}"
     cd /opt/Veil/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Veil.${NC}"
     git clone https://github.com/Veil-Framework/Veil /opt/Veil
     cd /opt/Veil/config/
     ./setup.sh --force --silent
fi

if [ -d /opt/Windows-Exploit-Suggester/.git ]; then
     echo -e "${BLUE}Updating Windows-Exploit-Suggester.${NC}"
     cd /opt/Windows-Exploit-Suggester/ ; git pull
     rm *.xls 2>/dev/null
     ./windows-exploit-suggester.py --update
     echo
else
     echo -e "${YELLOW}Installing Windows-Exploit-Suggester.${NC}"
     git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester /opt/Windows-Exploit-Suggester
     cd /opt/Windows-Exploit-Suggester/
     pip install xlrd --upgrade
     ./windows-exploit-suggester.py --update
     echo
fi

if [ -d /opt/WitnessMe/.git ]; then
     echo -e "${BLUE}Updating WitnessMe.${NC}"
     cd /opt/WitnessMe/ ; git pull
#     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing WitnessMe.${NC}"
     git clone https://github.com/byt3bl33d3r/WitnessMe.git /opt/WitnessMe
     cd /opt/WitnessMe/
     pip3 install -r requirements.txt
     echo
fi

if [ ! -f /usr/bin/xdotool ]; then
     echo -e "${YELLOW}Installing xdotool.${NC}"
     apt-get install -y xdotool
     echo
fi

if [ ! -f /usr/bin/xlsx2csv ]; then
     echo -e "${YELLOW}Installing xlsx2csv.${NC}"
     apt-get install -y xlsx2csv
     echo
fi

if [ ! -f /usr/bin/xml_grep ]; then
     echo -e "${YELLOW}Installing xml_grep.${NC}"
     apt-get install -y xml-twig-tools
     echo
fi

echo -e "${BLUE}Updating locate database.${NC}"
updatedb

echo
echo
exit

