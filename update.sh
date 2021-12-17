#!/bin/bash

# Global variables
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check for root
if [[ $EUID -ne 0 ]]; then
     echo
     echo "[!] This script must be ran as root."
     exit
fi

###############################################################################################################################

# Clean up

if [ -d /opt/SharpShooter/.git ]; then
     rm -rf /opt/SharpShooter/
fi

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

if [ ! -e /usr/bin/amass ]; then
     echo -e "${YELLOW}Installing Amass.${NC}"
     apt install -y amass
     echo
fi

if [ -d /opt/BloodHound-v4/.git ]; then
     echo -e "${BLUE}Updating BloodHound.${NC}"
     cd /opt/BloodHound-v4/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Neo4j.${NC}"
     apt -y install neo4j
     echo
     echo -e "${YELLOW}Installing BloodHound.${NC}"
     apt -y install npm
     npm install -g electron-packager
     git clone https://github.com/BloodHoundAD/BloodHound /opt/BloodHound-v4
     cd /opt/BloodHound-v4/
     npm install
     npm run linuxbuild
     echo
fi

if [ -d /opt/cobaltstrike ]; then
     echo -e "${BLUE}Updating Cobalt Strike.${NC}"
     cd /opt/cobaltstrike ; ./update
     echo

     if [ -d /opt/cobaltstrike/third-party/chryzsh-scripts/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike aggressor scripts - chryzsh.${NC}"
          cd /opt/cobaltstrike/third-party/chryzsh-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike aggressor scripts - chryzsh.${NC}"
          git clone https://github.com/chryzsh/Aggressor-Scripts /opt/cobaltstrike/third-party/chryzsh-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/mgeeky-scripts/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike aggressor scripts - mgeeky.${NC}"
          cd /opt/cobaltstrike/third-party/mgeeky-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike aggressor scripts - mgeeky.${NC}"
          git clone https://github.com/mgeeky/cobalt-arsenal /opt/cobaltstrike/third-party/mgeeky-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/taowu-scripts/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike aggressor scripts - taowu.${NC}"
          cd /opt/cobaltstrike/third-party/taowu-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike aggressor scripts - taowu.${NC}"
          git clone https://github.com/pandasec888/taowu-cobalt-strike /opt/cobaltstrike/third-party/taowu-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/trustedsec-bof/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike BOF - trustedsec.${NC}"
          cd /opt/cobaltstrike/third-party/trustedsec-bof/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike BOF - trustedsec.${NC}"
          git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF /opt/cobaltstrike/third-party/trustedsec-bof
          echo
     fi

     if [ -d /opt/cobaltstrike/elevatekit/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike ElevateKit.${NC}"
          cd /opt/cobaltstrike/elevatekit/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike ElevateKit.${NC}"
          git clone https://github.com/rsmudge/ElevateKit /opt/cobaltstrike/elevatekit
          echo
     fi

     if [ -d /opt/cobaltstrike/malleable-c2-profiles/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike Malleable C2 profiles.${NC}"
          cd /opt/cobaltstrike/malleable-c2-profiles/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike Malleable C2 profiles.${NC}"
          git clone https://github.com/Cobalt-Strike/Malleable-C2-Profiles /opt/cobaltstrike/malleable-c2-profiles
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike misc - bluescreenofjeff.${NC}"
          cd /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike misc - bluescreenofjeff.${NC}"
          git clone https://github.com/bluscreenofjeff/Malleable-C2-Randomizer /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike misc - DidierStevens.${NC}"
          cd /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/ ; git pull
          mv cs-dns-stager.py cs-dns-stager.tmp
          rm *.def *.md *.py *.txt *.yaml 2>/dev/null
          mv cs-dns-stager.tmp cs-dns-stager.py
          chmod 755 cs-dns-stager.py
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike misc - DidierStevens.${NC}"
          git clone https://github.com/DidierStevens/Beta /opt/cobaltstrike/third-party/DidierStevens-DNS-stager
          cd /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/
          mv cs-dns-stager.py cs-dns-stager.tmp
          rm *.def *.md *.py *.txt *.yaml 2>/dev/null
          mv cs-dns-stager.tmp cs-dns-stager.py
          chmod 755 cs-dns-stager.py
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike misc - FortyNorthSecurity.${NC}"
          cd /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike misc - FortyNorthSecurity.${NC}"
          git clone https://github.com/FortyNorthSecurity/C2concealer /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/outflanknl-helpcolor/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike misc - outflanknl.${NC}"
          cd /opt/cobaltstrike/third-party/outflanknl-helpcolor/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike misc - outflanknl.${NC}"
          git clone https://github.com/outflanknl/HelpColor /opt/cobaltstrike/third-party/outflanknl-helpcolor
          echo
     fi
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
     git clone https://github.com/darkoperator/dnsrecon /opt/DNSRecon
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
     git clone https://github.com/elceef/dnstwist /opt/dnstwist
     apt install python3-dnspython python3-geoip python3-whois python3-requests python3-ssdeep
     cd /opt/dnstwist/
     pip3 install -r requirements.txt
     echo
fi

if [ -d /opt/Domain-Hunter/.git ]; then
     echo -e "${BLUE}Updating Domain Hunter.${NC}"
     cd /opt/Domain-Hunter/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Domain Hunter.${NC}"
     git clone https://github.com/threatexpress/domainhunter /opt/Domain-Hunter
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
     git clone https://github.com/dafthack/DomainPasswordSpray /opt/DomainPasswordSpray
     echo
fi

if [ -d /opt/Donut/.git ]; then
     echo -e "${BLUE}Updating Donut.${NC}"
     cd /opt/Donut/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Donut.${NC}"
     git clone https://github.com/TheWover/donut /opt/Donut
     echo
fi

if [ -d /opt/droopescan/.git ]; then
     echo -e "${BLUE}Updating droopescan.${NC}"
     cd /opt/droopescan/ ; git pull
     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing droopescan.${NC}"
     git clone https://github.com/droope/droopescan /opt/droopescan
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
     git clone https://github.com/ChrisTruncer/Egress-Assess /opt/Egress-Assess
     cd /opt/Egress-Assess/setup/
     ./setup.sh
     mv server.pem ../Egress-Assess/
     rm impacket*
     echo
fi

if [ -d /opt/egressbuster/.git ]; then
     echo -e "${BLUE}Updating egressbuster.${NC}"
     cd /opt/egressbuster/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing egressbuster.${NC}"
     git clone https://github.com/trustedsec/egressbuster /opt/egressbuster
     echo
fi

if [ -d /opt/EyeWitness/.git ]; then
     echo -e "${BLUE}Updating EyeWitness.${NC}"
     cd /opt/EyeWitness/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing EyeWitness.${NC}"
     git clone https://github.com/ChrisTruncer/EyeWitness /opt/EyeWitness
     cd /opt/EyeWitness/Python/setup/
     ./setup.sh
fi

if [ -d /opt/impacket/.git ]; then
     echo -e "${BLUE}Updating impacket.${NC}"
     cd /opt/impacket/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing impacket.${NC}"
     git clone https://github.com/SecureAuthCorp/impacket /opt/impacket
     echo
fi

if [ -d /opt/krbrelayx/.git ]; then
     echo -e "${BLUE}Updating krbrelayx.${NC}"
     cd /opt/krbrelayx/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing krbrelayx.${NC}"
     git clone https://github.com/dirkjanm/krbrelayx /opt/krbrelayx
     echo
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
     git clone https://github.com/samratashok/nishang /opt/Nishang
     echo
fi

echo -e "${BLUE}Updating Nmap scripts.${NC}"
nmap --script-updatedb | egrep -v '(Starting|seconds)' | sed 's/NSE: //'
echo

if [ -d /opt/PEASS-ng/.git ]; then
     echo -e "${BLUE}Updating PEASS-ng.${NC}"
     cd /opt/PEASS-ng/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PEASS-ng.${NC}"
     git clone https://github.com/carlospolop/PEASS-ng /opt/PEASS-ng
     echo
fi

if [ -d /opt/PowerUpSQL/.git ]; then
     echo -e "${BLUE}Updating PowerUpSQL.${NC}"
     cd /opt/PowerUpSQL/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PowerUpSQL.${NC}"
     git clone https://github.com/NetSPI/PowerUpSQL /opt/PowerUpSQL
     echo
fi

if [ -d /opt/PrivescCheck/.git ]; then
     echo -e "${BLUE}Updating PrivescCheck.${NC}"
     cd /opt/PrivescCheck/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PrivescCheck.${NC}"
     git clone https://github.com/itm4n/PrivescCheck /opt/PrivescCheck
     echo
fi

if [ -d /opt/Responder/.git ]; then
     echo -e "${BLUE}Updating Responder.${NC}"
     cd /opt/Responder/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Responder.${NC}"
     git clone https://github.com/lgandx/Responder /opt/Responder
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

if [ -d /opt/SharpCollection/.git ]; then
     echo -e "${BLUE}Updating SharpCollection.${NC}"
     cd /opt/SharpCollection/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing SharpCollection.${NC}"
     git clone https://github.com/Flangvik/SharpCollection /opt/SharpCollection
     echo
fi

if [ -d /opt/spoofcheck/.git ]; then
     echo -e "${BLUE}Updating spoofcheck.${NC}"
     cd /opt/spoofcheck/ ; git pull
     pip3 install -r requirements.txt -q
     echo
else
     echo -e "${YELLOW}Installing spoofcheck.${NC}"
     git clone https://github.com/BishopFox/spoofcheck /opt/spoofcheck
     cd /opt/spoofcheck/
     pip3 install -r requirements.txt
     echo
fi

if [ -d /opt/SprayingToolkit/.git ]; then
     echo -e "${BLUE}Updating SprayingToolkit.${NC}"
     cd /opt/SprayingToolkit/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing SprayingToolkit.${NC}"
     git clone https://github.com/byt3bl33d3r/SprayingToolkit /opt/SprayingToolkit
     cd /opt/SprayingToolkit/
     pip3 install -r requirements.txt
     echo
fi

if [ -d /opt/theHarvester/.git ]; then
     echo -e "${BLUE}Updating theHarvester.${NC}"
     cd /opt/theHarvester/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing theHarvester.${NC}"
     git clone https://github.com/laramies/theHarvester /opt/theHarvester
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
     git clone https://github.com/trustedsec/unicorn /opt/unicorn
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

if [ -d /opt/Windows-Exploit-Suggester-NG/.git ]; then
     echo -e "${BLUE}Updating Windows Exploit Suggester NG.${NC}"
     cd /opt/Windows-Exploit-Suggester-NG/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Windows Exploit Suggester NG.${NC}"
     git clone https://github.com/bitsadmin/wesng /opt/Windows-Exploit-Suggester-NG
     echo
fi

if [ -d /opt/WitnessMe/.git ]; then
     echo -e "${BLUE}Updating WitnessMe.${NC}"
     cd /opt/WitnessMe/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing WitnessMe.${NC}"
     git clone https://github.com/byt3bl33d3r/WitnessMe /opt/WitnessMe
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

exit

