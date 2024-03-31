#!/usr/bin/bash

# Check for root
if [ $EUID -ne 0 ]; then
     echo
     echo "[!] This script must be ran as root."
     exit
fi

# Global variables
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

# -----------------------------------------------------------------------------------------------

# Clean up
if [ -d /opt/C2-stuff/ ]; then
     rm -rf /opt/C2-stuff/
fi

if [ -d /opt/cobaltstrike/third-party/outflanknl-helpcolor/ ]; then
     rm -rf /opt/cobaltstrike/third-party/outflanknl-helpcolor/
fi

# -----------------------------------------------------------------------------------------------

clear
echo

echo -e "${BLUE}Updating Kali.${NC}"
apt update ; apt -y upgrade ; apt -y dist-upgrade ; apt -y autoremove ; apt -y autoclean
echo

if [ ! -f /usr/bin/ansible ]; then
     echo -e "${YELLOW}Installing Ansible.${NC}"
     apt install -y ansible-core
     echo
fi

if [ ! -f /usr/bin/aws ]; then
     echo -e "${YELLOW}Installing AWS.${NC}"
     apt install -y awscli
     echo
fi

if [ ! -f /usr/bin/bloodhound ]; then
     echo -e "${YELLOW}Installing BloodHound and Neo4j.${NC}"
     apt install -y bloodhound
     echo
fi

if [ ! -f /usr/bin/certbot ]; then
     echo -e "${YELLOW}Installing Certbot.${NC}"
     apt install -y certbot letsencrypt python3-certbot-apache
     echo
fi

if [ ! -f /usr/bin/go ]; then
     echo -e "${YELLOW}Installing Go.${NC}"
     apt install -y gccgo-go golang-go
     echo >> ~/.zshrc
     echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
     echo 'export GOPATH=/opt/go' >> ~/.zshrc
     echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc
     echo
fi

if [ ! -f /usr/bin/raven ]; then
     echo -e "${YELLOW}Installing Raven.${NC}"
     apt install -y raven
     echo
fi

# -----------------------------------------------------------------------------------------------

if [ -d /opt/BOFs/anthemtotheego-inlineExecute-assembly/.git ]; then
     echo -e "${BLUE}Updating anthemtotheego InlineExecute Assembly BOF.${NC}"
     cd /opt/BOFs/anthemtotheego-inlineExecute-assembly/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing anthemtotheego InlineExecute Assembly BOF.${NC}"
     git clone https://github.com/anthemtotheego/InlineExecute-Assembly /opt/BOFs/anthemtotheego-inlineExecute-assembly
     echo
fi

if [ -d /opt/BOFs/outflanknl-c2-tool-collection/.git ]; then
     echo -e "${BLUE}Updating Outflanknl C2 Tool Collection BOF.${NC}"
     cd /opt/BOFs/outflanknl-c2-tool-collection/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Outflanknl C2 Tool Collection BOF.${NC}"
     git clone https://github.com/outflanknl/C2-Tool-Collection /opt/BOFs/outflanknl-c2-tool-collection
     echo
fi

if [ -d /opt/BOFs/outflanknl-helpcolor/.git ]; then
     echo -e "${BLUE}Updating Outflanknl HelpColor BOF.${NC}"
     cd /opt/BOFs/outflanknl-helpcolor/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Outflanknl HelpColor BOF.${NC}"
     git clone https://github.com/outflanknl/HelpColor /opt/BOFs/outflanknl-helpcolor
     echo
fi

if [ -d /opt/BOFs/trustedsec-remote-ops/.git ]; then
     echo -e "${BLUE}Updating TrustedSec Remote OPs BOF.${NC}"
     cd /opt/BOFs/trustedsec-remote-ops/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing TrustedSec Remote OPs BOF.${NC}"
     git clone https://github.com/trustedsec/CS-Remote-OPs-BOF /opt/BOFs/trustedsec-remote-ops
     echo
fi

if [ -d /opt/BOFs/trustedsec-sa/.git ]; then
     echo -e "${BLUE}Updating TrustedSec Situational Awareness BOF.${NC}"
     cd /opt/BOFs/trustedsec-sa/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing TrustedSec Situational Awareness BOF.${NC}"
     git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF /opt/BOFs/trustedsec-sa
     echo
fi

# -----------------------------------------------------------------------------------------------

if [ -d /opt/cobaltstrike/ ]; then
     if [ -d /opt/cobaltstrike/elevatekit/.git ]; then
          echo -e "${BLUE}Updating CS - ElevateKit.${NC}"
          cd /opt/cobaltstrike/elevatekit/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - ElevateKit.${NC}"
          git clone https://github.com/rsmudge/ElevateKit /opt/cobaltstrike/elevatekit
          echo
     fi

     if [ -d /opt/cobaltstrike/RedSiege-C2concealer/.git ]; then
          echo -e "${BLUE}Updating CS - RedSiege C2concealer.${NC}"
          cd /opt/cobaltstrike/RedSiege-C2concealer/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - RedSiege C2concealer.${NC}"
          git clone https://github.com/RedSiege/C2concealer /opt/cobaltstrike/RedSiege-C2concealer
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

     if [ -d /opt/cobaltstrike/mgeeky-scripts/.git ]; then
          echo -e "${BLUE}Updating CS - mgeeky cobalt arsenal.${NC}"
          cd /opt/cobaltstrike/mgeeky-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - mgeeky cobalt arsenal.${NC}"
          git clone https://github.com/mgeeky/cobalt-arsenal /opt/cobaltstrike/mgeeky-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/tylous-sourcepoint/.git ]; then
          echo -e "${BLUE}Updating CS - Tylous SourcePoint.${NC}"
          cd /opt/cobaltstrike/tylous-sourcepoint/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - Tylous SourcePoint.${NC}"
          git clone https://github.com/Tylous/SourcePoint /opt/cobaltstrike/tylous-sourcepoint
          cd /opt/cobaltstrike/tylous-sourcepoint/
          go get gopkg.in/yaml.v2
          go build SourcePoint.go
          echo
     fi
fi

# -----------------------------------------------------------------------------------------------

if [ -d /opt/discover/.git ]; then
     echo -e "${BLUE}Updating Discover.${NC}"
     cd /opt/discover ; git pull
     echo
fi

if [ -d /opt/DNSRecon/.git -a -d /opt/DNSRecon-venv ]; then
     echo -e "${BLUE}Updating DNSRecon.${NC}"
     cd /opt/DNSRecon/ ; git pull
     source /opt/DNSRecon-venv/bin/activate
     pip3 install -r requirements.txt --upgrade | grep -v 'already satisfied'
     # If you are in a corp env that is doing MITM with SSL use the following line instead.
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade | grep -v 'already satisfied'
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
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
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
     echo
     echo -e "${YELLOW}Setting up Domain Hunter virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/Domain-Hunter-venv
     source /opt/Domain-Hunter-venv/bin/activate
     cd /opt/Domain-Hunter/
     pip3 install pytesseract
     chmod 755 domainhunter.py
     deactivate
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

if [ -d /opt/Egress-Assess/.git -a -d /opt/Egress-Assess-venv ]; then
     echo -e "${BLUE}Updating Egress-Assess.${NC}"
     cd /opt/Egress-Assess/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Egress-Assess.${NC}"
     git clone https://github.com/RedSiege/Egress-Assess /opt/Egress-Assess
     echo
     echo -e "${YELLOW}Setting up Egress-Assess virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/Egress-Assess-venv
     source /opt/Egress-Assess-venv/bin/activate
     cd /opt/Egress-Assess
     pip3 install -r requirements.txt
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
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

if [ ! -f /usr/bin/feroxbuster ]; then
     echo -e "${YELLOW}Installing feroxbuster.${NC}"
     apt install -y feroxbuster
     echo
fi

if [ -d /opt/Freeze/.git ]; then
     echo -e "${BLUE}Updating Freeze.${NC}"
     cd /opt/Freeze/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Freeze.${NC}"
     git clone https://github.com/optiv/Freeze /opt/Freeze
     echo
fi

if [ ! -f /usr/bin/gobuster ]; then
     echo -e "${YELLOW}Installing gobuster.${NC}"
     apt install -y gobuster
     echo
fi

if [ -d /opt/Havoc/.git ]; then
     echo -e "${BLUE}Updating Havoc.${NC}"
     cd /opt/Havoc/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Havoc.${NC}"
     apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm
     git clone https://github.com/HavocFramework/Havoc /opt/Havoc
     cd /opt/Havoc/teamserver/
     go mod download golang.org/x/sys
     go mod download github.com/ugorji/go
     cd ..
     make all
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

if [ -d /opt/manspider/.git ]; then
     echo -e "${BLUE}Updating MAN-SPIDER.${NC}"
     cd /opt/manspider/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing MAN-SPIDER.${NC}"
     git clone https://github.com/blacklanternsecurity/MANSPIDER /opt/manspider
     apt install -y antiword tesseract-ocr
     echo
fi

if [ ! -f /usr/bin/nishang ]; then
     echo -e "${YELLOW}Installing nishang.${NC}"
     apt install -y nishang
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

if [ -d /opt/PowerSploit/.git ]; then
     echo -e "${BLUE}Updating PowerSploit.${NC}"
     cd /opt/PowerSploit/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PowerSploit.${NC}"
     git clone https://github.com/0xe7/PowerSploit /opt/PowerSploit
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

if [ ! -f /usr/bin/rustc ]; then
     echo -e "${YELLOW}Installing Rust.${NC}"
     apt install -y rustc
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
     pip3 install -r requirements.txt --upgrade | grep -v 'already satisfied'
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade | grep -v 'already satisfied'
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
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
     deactivate
     echo
fi

if [ -d /opt/subfinder/.git ]; then
     echo -e "${BLUE}Updating subfinder.${NC}"
     cd /opt/subfinder/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing subfinder.${NC}"
     git clone https://github.com/projectdiscovery/subfinder /opt/subfinder
     cd /opt/subfinder/v2/cmd/subfinder
     go build
     echo
fi

if [ $(lsb_release -si) == "Parrot" -a ! -d /usr/share/doc/python3-ujson ]; then
     echo -e "${YELLOW}Installing theHarvester Deps For Parrot.${NC}"
     apt install -yqq python3-ujson
fi

if [ -d /opt/theHarvester/.git -a -d /opt/theHarvester-venv ]; then
     echo -e "${BLUE}Updating theHarvester.${NC}"
     cd /opt/theHarvester/ ; git pull
     source /opt/theHarvester-venv/bin/activate
     /opt/theHarvester-venv/bin/pip3 install -r requirements.txt --upgrade | grep -v 'already satisfied'
#     /opt/theHarvester-venv/bin/pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade | grep -v 'already satisfied'
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
     /opt/theHarvester-venv/bin/pip3 install -r requirements.txt
#     /opt/theHarvester-venv/bin/pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
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

if [ ! -f /usr/bin/xspy ]; then
     echo -e "${YELLOW}Installing xspy.${NC}"
     apt install -y xspy
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
