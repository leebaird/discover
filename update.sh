#!/usr/bin/bash

# Global variables
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check for root
if [ $EUID -ne 0 ]; then
     echo
     echo "[!] This script must be ran as root."
     exit
fi

clear
echo

echo -e "${BLUE}Updating Kali.${NC}"
apt update ; apt -y upgrade ; apt -y dist-upgrade ; apt -y autoremove ; apt -y autoclean
echo

if [ ! -d /usr/share/doc/golang-go ]; then
     echo -e "${YELLOW}Installing Go.${NC}"
     apt install -y golang-go
     mv /root/go /opt/
     echo
fi

if [ ! -f /usr/bin/bloodhound ]; then
     echo -e "${YELLOW}Installing BloodHound and Neo4j.${NC}"
     apt install -y bloodhound
     echo
fi

if [ -d /opt/cobaltstrike ]; then
     if [ -d /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer/.git ]; then
          echo -e "${BLUE}Updating CS - bluescreenofjeff malleable C2 randomizer.${NC}"
          cd /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - bluescreenofjeff malleable C2 randomizer.${NC}"
          git clone https://github.com/bluscreenofjeff/Malleable-C2-Randomizer /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/bokuloader/.git ]; then
          echo -e "${BLUE}Updating CS - BokuLoader.${NC}"
          cd /opt/cobaltstrike/third-party/bokuloader/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - BokuLoader.${NC}"
          git clone https://github.com/boku7/BokuLoader /opt/cobaltstrike/third-party/bokuloader
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/chryzsh-scripts/.git ]; then
          echo -e "${BLUE}Updating CS - chryzsh aggressor scripts.${NC}"
          cd /opt/cobaltstrike/third-party/chryzsh-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - chryzsh aggressor scripts.${NC}"
          git clone https://github.com/chryzsh/Aggressor-Scripts /opt/cobaltstrike/third-party/chryzsh-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/.git ]; then
          echo -e "${BLUE}Updating CS - Didier Stevens DNS stager.${NC}"
          cd /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/ ; git pull
          mv cs-dns-stager.py cs-dns-stager.tmp
          rm *.def *.md *.py *.txt *.yaml 2>/dev/null
          mv cs-dns-stager.tmp cs-dns-stager.py
          chmod 755 cs-dns-stager.py
          echo
     else
          echo -e "${YELLOW}Installing CS - Didier Stevens DNS stager.${NC}"
          git clone https://github.com/DidierStevens/Beta /opt/cobaltstrike/third-party/DidierStevens-DNS-stager
          cd /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/
          mv cs-dns-stager.py cs-dns-stager.tmp
          rm *.def *.md *.py *.txt *.yaml 2>/dev/null
          mv cs-dns-stager.tmp cs-dns-stager.py
          chmod 755 cs-dns-stager.py
          echo
     fi

     if [ -d /opt/cobaltstrike/elevatekit/.git ]; then
          echo -e "${BLUE}Updating CS - ElevateKit.${NC}"
          cd /opt/cobaltstrike/elevatekit/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - ElevateKit.${NC}"
          git clone https://github.com/rsmudge/ElevateKit /opt/cobaltstrike/elevatekit
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer/.git ]; then
          echo -e "${BLUE}Updating CS - FortyNorthSecurity C2concealer.${NC}"
          cd /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - FortyNorthSecurity C2concealer.${NC}"
          git clone https://github.com/FortyNorthSecurity/C2concealer /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer
          echo
     fi

     if [ -d /opt/cobaltstrike/malleable-c2-profiles/.git ]; then
          echo -e "${BLUE}Updating CS - Malleable C2 profiles.${NC}"
          cd /opt/cobaltstrike/malleable-c2-profiles/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - Malleable C2 profiles.${NC}"
          git clone https://github.com/Cobalt-Strike/Malleable-C2-Profiles /opt/cobaltstrike/malleable-c2-profiles
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/mgeeky-scripts/.git ]; then
          echo -e "${BLUE}Updating CS - mgeeky aggressor scripts.${NC}"
          cd /opt/cobaltstrike/third-party/mgeeky-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - mgeeky aggressor scripts.${NC}"
          git clone https://github.com/mgeeky/cobalt-arsenal /opt/cobaltstrike/third-party/mgeeky-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/outflanknl-helpcolor/.git ]; then
          echo -e "${BLUE}Updating CS - Outflanknl HelpColor.${NC}"
          cd /opt/cobaltstrike/third-party/outflanknl-helpcolor/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - Outflanknl HelpColor.${NC}"
          git clone https://github.com/outflanknl/HelpColor /opt/cobaltstrike/third-party/outflanknl-helpcolor
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/taowu-scripts/.git ]; then
          echo -e "${BLUE}Updating CS - taowu aggressor scripts.${NC}"
          cd /opt/cobaltstrike/third-party/taowu-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - taowu aggressor scripts.${NC}"
          git clone https://github.com/pandasec888/taowu-cobalt-strike /opt/cobaltstrike/third-party/taowu-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/trustedsec-bof/.git ]; then
          echo -e "${BLUE}Updating CS - TrustedSec SA BOF.${NC}"
          cd /opt/cobaltstrike/third-party/trustedsec-bof/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - TrustedSec SA BOF.${NC}"
          git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF /opt/cobaltstrike/third-party/trustedsec-bof
          echo
     fi
fi

if [ -d /opt/discover/.git ]; then
     echo -e "${BLUE}Updating Discover.${NC}"
     cd /opt/discover ; git pull
     echo
fi

if [ -d /opt/DNSRecon/.git -a -d /opt/DNSRecon-venv ]; then
     echo -e "${BLUE}Updating DNSRecon.${NC}"
     cd /opt/DNSRecon/ ; git pull
     source /opt/DNSRecon-venv/bin/activate
     pip3 install -r requirements.txt --upgrade
     deactivate
     echo
else
     echo -e "${YELLOW}Installing DNSRecon.${NC}"
     git clone https://github.com/darkoperator/dnsrecon /opt/DNSRecon
     echo
     echo -e "${YELLOW}Setting up DNSRecon virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/DNSRecon-venv
     source /opt/DNSRecon-venv/bin/activate
     cd /opt/DNSRecon/
     pip3 install -r requirements.txt
     deactivate
     echo
fi

if [ ! -f /usr/bin/dnstwist ]; then
     echo -e "${YELLOW}Installing dnstwist.${NC}"
     apt install -y dnstwist
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
     pip3 install pytesseract
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

if [ -d /opt/Egress-Assess/.git -a -d /opt/Egress-Assess-venv ]; then
     echo -e "${BLUE}Updating Egress-Assess.${NC}"
     cd /opt/Egress-Assess/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Egress-Assess.${NC}"
     git clone https://github.com/ChrisTruncer/Egress-Assess /opt/Egress-Assess
     echo
     echo -e "${YELLOW}Setting up Egress-Assess virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/Egress-Assess-venv
     source /opt/Egress-Assess-venv/bin/activate
     cd /opt/Egress-Assess
     pip3 install -r requirements.txt
     deactivate
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

if [ -d /opt/gobuster/.git ]; then
     echo -e "${BLUE}Updating gobuster.${NC}"
     cd /opt/gobuster/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing gobuster.${NC}"
     git clone https://github.com/OJ/gobuster.git /opt/gobuster
     cd /opt/gobuster/
     go get && go build
     make
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

if [ -d /opt/PowerSharpPack/.git ]; then
     echo -e "${BLUE}Updating PowerSharpPack.${NC}"
     cd /opt/PowerSharpPack/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PowerSharpPack.${NC}"
     git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack /opt/PowerSharpPack
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

if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
     echo -e "${YELLOW}Expanding Rockyou list.${NC}"
     zcat /usr/share/wordlists/rockyou.txt.gz > /usr/share/wordlists/rockyou.txt
     rm /usr/share/wordlists/rockyou.txt.gz
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

if [ -d /opt/spoofcheck/.git -a -d /opt/spoofcheck-venv ]; then
     echo -e "${BLUE}Updating spoofcheck.${NC}"
     cd /opt/spoofcheck/ ; git pull
     source /opt/spoofcheck-venv/bin/activate
     pip3 install -r requirements.txt --upgrade
     deactivate
     echo
else
     echo -e "${YELLOW}Installing spoofcheck.${NC}"
     git clone https://github.com/BishopFox/spoofcheck /opt/spoofcheck
     echo
     echo -e "${YELLOW}Setting up spoofcheck virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/spoofcheck-venv
     source /opt/spoofcheck-venv/bin/activate
     cd /opt/spoofcheck/
     pip3 install -r requirements.txt
     deactivate
     echo
fi

if [ -d /opt/theHarvester/.git -a -d /opt/theHarvester-venv ]; then
     echo -e "${BLUE}Updating theHarvester.${NC}"
     cd /opt/theHarvester/ ; git pull
     source /opt/theHarvester-venv/bin/activate
     pip3 install -r requirements.txt --upgrade
     deactivate
     echo
else
     echo -e "${YELLOW}Installing theHarvester.${NC}"
     git clone https://github.com/laramies/theHarvester /opt/theHarvester
     echo
     echo -e "${YELLOW}Setting up theHarvester virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/theHarvester-venv
     source /opt/theHarvester-venv/bin/activate
     cd /opt/theHarvester/
     pip3 install -r requirements.txt
     deactivate
     echo
fi

if [ ! -f /usr/bin/veil ]; then
     echo -e "${YELLOW}Installing Veil.${NC}"
     apt install -y veil
     echo
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

if [ -d /opt/xspy/.git ]; then
     echo -e "${BLUE}Updating xspy.${NC}"
     cd /opt/xspy/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing xspy.${NC}"
     git clone https://github.com/mnp/xspy /opt/xspy
     cd /opt/xspy/
     apt install -y build-essential libx11-dev
     apt install -y x11-utils xutils-dev imagemagick libxext-dev
     make
     echo
fi

if [ ! -f /opt/xwatchwin/xwatchwin ]; then
     echo -e "${YELLOW}Installing xwatchwin.${NC}"
     apt install -y imagemagick libxext-dev xutils-dev
     wget http://www.ibiblio.org/pub/X11/contrib/utilities/xwatchwin.tar.gz
     tar zxvf xwatchwin.tar.gz
     rm xwatchwin.tar.gz
     mv xwatchwin/ /opt/
     cd /opt/xwatchwin/
     xmkmf && make && make install
     echo
fi

echo -e "${BLUE}Updating locate database.${NC}"
updatedb

exit
