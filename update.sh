#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

# Variables
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo
echo -e "${BLUE}Updating the operating system.${NC}"
apt update ; apt -y upgrade ; apt -y dist-upgrade ; apt -y autoremove ; apt -y autoclean ; updatedb
echo

if ! command -v 7z &> /dev/null; then
    echo -e "${YELLOW}Installing 7-Zip.${NC}"
    apt install -y 7zip
    echo
fi

if ! command -v ansible &> /dev/null; then
    echo -e "${YELLOW}Installing Ansible.${NC}"
    apt install -y ansible-core
    echo
fi

if ! command -v arp-scan &> /dev/null; then
    echo -e "${YELLOW}Installing arpscan.${NC}"
    apt install -y arp-scan/questing
    echo
fi

f_go_bin() {
    command -v go 2>/dev/null || { [ -x /usr/local/go/bin/go ] && echo /usr/local/go/bin/go; }
}

f_go_install_tool() {
    local module=$1
    local name=$2
    local go_bin
    go_bin=$(f_go_bin) || return 1
    GO111MODULE=on "$go_bin" install "$module"
    install -m 755 "$("$go_bin" env GOPATH)/bin/$name" /usr/local/bin/"$name" 2>/dev/null || true
}

if command -v asnmap &> /dev/null; then
    echo -e "${BLUE}Updating asnmap.${NC}"
    asnmap_out=$(NO_COLOR=1 asnmap -up -silent 2>&1) || true
    if echo "$asnmap_out" | grep -qi 'already updated'; then
        echo "Already up to date."
    elif echo "$asnmap_out" | grep -qE '^\[INF\]'; then
        echo "Updated."
    else
        f_go_install_tool github.com/projectdiscovery/asnmap/cmd/asnmap@latest asnmap
    fi
    echo
elif [ -n "$(f_go_bin)" ]; then
    echo -e "${YELLOW}Installing asnmap.${NC}"
    f_go_install_tool github.com/projectdiscovery/asnmap/cmd/asnmap@latest asnmap
    echo
fi

if ! command -v aws &> /dev/null; then
    echo -e "${YELLOW}Installing awscli.${NC}"
    apt install -y awscli
    echo
fi

if ! command -v az &> /dev/null; then
    echo -e "${YELLOW}Installing azure-cli.${NC}"
    if ! apt install -y azure-cli 2>/dev/null || ! command -v az &> /dev/null; then
        curl -sL https://aka.ms/InstallAzureCLIDeb | bash
    fi
    echo
fi

if ! command -v chromium &> /dev/null && \
   ! command -v chromium-browser &> /dev/null && \
   ! command -v google-chrome &> /dev/null && \
   ! command -v google-chrome-stable &> /dev/null; then
    echo -e "${YELLOW}Installing chromium.${NC}"
    if ! apt install -y chromium 2>/dev/null || ! command -v chromium &> /dev/null; then
        apt install -y chromium-browser 2>/dev/null || true
    fi
    echo
fi

if ! command -v curl &> /dev/null; then
    echo -e "${YELLOW}Installing curl.${NC}"
    apt install -y curl
    echo
fi

f_dnsrecon_working() {
    command -v dnsrecon >/dev/null 2>&1 && dnsrecon --version >/dev/null 2>&1
}

if [ -x /opt/dnsrecon-venv/bin/dnsrecon ]; then
    echo -e "${BLUE}Updating DNSRecon.${NC}"
    cd /opt/dnsrecon/ || exit
    git pull
    /opt/dnsrecon-venv/bin/python -m pip install -q /opt/dnsrecon
    ln -sf /opt/dnsrecon-venv/bin/dnsrecon /usr/local/bin/dnsrecon
    echo
elif f_dnsrecon_working; then
    :
elif python3 -c 'import sys; exit(0 if sys.version_info >= (3, 13) else 1)' 2>/dev/null; then
    echo -e "${YELLOW}Installing DNSRecon from upstream (apt package is incompatible with Python 3.13+).${NC}"
    apt remove -y dnsrecon 2>/dev/null
    if ! python3 -m venv /tmp/dnsrecon-venv-check 2>/dev/null; then
        apt install -y python3-venv
        rm -rf /tmp/dnsrecon-venv-check
    fi
    if [ -d /opt/dnsrecon/.git ]; then
        cd /opt/dnsrecon/ || exit
        git pull
    else
        git clone https://github.com/darkoperator/dnsrecon /opt/dnsrecon
    fi
    python3 -m venv /opt/dnsrecon-venv
    /opt/dnsrecon-venv/bin/python -m pip install -q -U pip
    /opt/dnsrecon-venv/bin/python -m pip install -q /opt/dnsrecon
    ln -sf /opt/dnsrecon-venv/bin/dnsrecon /usr/local/bin/dnsrecon
    echo
else
    echo -e "${YELLOW}Installing dnsrecon.${NC}"
    apt install -y dnsrecon
    echo
fi

if ! command -v dnstwist &> /dev/null; then
    echo -e "${YELLOW}Installing dnstwist.${NC}"
    apt install -y dnstwist
    echo
fi

if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Installing docker.${NC}"
    apt install -y docker.io
    echo
fi

if [ -d /opt/Domain-Hunter/.git ]; then
    echo -e "${BLUE}Updating Domain Hunter.${NC}"
    cd /opt/Domain-Hunter/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing Domain Hunter.${NC}"
    git clone https://github.com/threatexpress/domainhunter /opt/Domain-Hunter
    echo
    echo -e "${YELLOW}Setting up Domain Hunter virtual environment.${NC}"
    python3 -m venv /opt/Domain-Hunter-venv
    /opt/Domain-Hunter-venv/bin/python -m pip install pytesseract
#    /opt/Domain-Hunter-venv/bin/pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org pytesseract
    chmod 755 /opt/Domain-Hunter/domainhunter.py
    echo
fi

if [ -d /opt/DomainPasswordSpray/.git ]; then
    echo -e "${BLUE}Updating DomainPasswordSpray.${NC}"
    cd /opt/DomainPasswordSpray/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing DomainPasswordSpray.${NC}"
    git clone https://github.com/dafthack/DomainPasswordSpray /opt/DomainPasswordSpray
    echo
fi

# shellcheck disable=SC2166
if [ -d /opt/Egress-Assess/.git -a -d /opt/Egress-Assess-venv ]; then
    echo -e "${BLUE}Updating Egress-Assess.${NC}"
    cd /opt/Egress-Assess/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing Egress-Assess.${NC}"
    git clone https://github.com/RedSiege/Egress-Assess /opt/Egress-Assess
    echo
    echo -e "${YELLOW}Setting up Egress-Assess virtualenv.${NC}"
    python3 -m venv /opt/Egress-Assess-venv
    /opt/Egress-Assess-venv/bin/python -m pip install -r /opt/Egress-Assess/requirements.txt
    # If you are in a corp env that is doing MiTM with SSL, use the following line instead. Do the same for all Python repos.
#    pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade | grep -v 'already satisfied'
    echo
fi

if [ -d /opt/egressbuster/.git ]; then
    echo -e "${BLUE}Updating egressbuster.${NC}"
    cd /opt/egressbuster/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing egressbuster.${NC}"
    git clone https://github.com/trustedsec/egressbuster /opt/egressbuster
    echo
fi

if grep -qi '^ID=ubuntu' /etc/os-release; then
    if ! command -v feroxbuster >/dev/null; then
        echo -e "${YELLOW}Installing feroxbuster.${NC}"
        curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
        mv feroxbuster /usr/local/bin/
        echo
    fi
else
    if ! command -v feroxbuster >/dev/null; then
        echo -e "${YELLOW}Installing feroxbuster.${NC}"
        apt install -y feroxbuster
        echo
    fi
fi

if ! command -v ffuf &> /dev/null; then
    echo -e "${YELLOW}Installing ffuf.${NC}"
    apt install -y ffuf
    echo
fi

if ! command -v gitleaks &> /dev/null; then
    echo -e "${YELLOW}Installing gitleaks.${NC}"
    apt install -y gitleaks
    echo
fi

if ! command -v go &> /dev/null && [ ! -x /usr/local/go/bin/go ]; then
    echo -e "${YELLOW}Go is not installed. Install manually: https://go.dev/doc/install${NC}"
    echo
fi

if ! command -v gobuster &> /dev/null; then
    echo -e "${YELLOW}Installing gobuster.${NC}"
    apt install -y gobuster
    echo
fi

if ! command -v gcloud &> /dev/null || ! command -v gsutil &> /dev/null; then
    echo -e "${YELLOW}Installing google-cloud-cli.${NC}"
    if ! apt install -y google-cloud-cli 2>/dev/null || ! command -v gcloud &> /dev/null; then
        apt install -y apt-transport-https ca-certificates gnupg
        curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
        echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list
        apt update
        apt install -y google-cloud-cli
    fi
    echo
fi

if command -v gowitness &> /dev/null; then
    echo -e "${BLUE}Updating gowitness.${NC}"
    gowitness_before=$(sha256sum "$(command -v gowitness)" 2>/dev/null | awk '{print $1}')
    if f_go_install_tool github.com/sensepost/gowitness@latest gowitness; then
        gowitness_after=$(sha256sum "$(command -v gowitness)" 2>/dev/null | awk '{print $1}')
        if [ -n "$gowitness_before" ] && [ "$gowitness_before" = "$gowitness_after" ]; then
            echo "Already up to date."
        else
            echo "Updated."
        fi
    fi
    echo
elif [ -n "$(f_go_bin)" ]; then
    echo -e "${YELLOW}Installing gowitness.${NC}"
    f_go_install_tool github.com/sensepost/gowitness@latest gowitness
    echo
fi

if command -v httpx &> /dev/null; then
    echo -e "${BLUE}Updating httpx.${NC}"
    httpx_out=$(NO_COLOR=1 httpx -up -silent 2>&1) || true
    if echo "$httpx_out" | grep -qi 'already updated'; then
        echo "Already up to date."
    elif echo "$httpx_out" | grep -qE '^\[INF\]'; then
        echo "Updated."
    else
        f_go_install_tool github.com/projectdiscovery/httpx/cmd/httpx@latest httpx
    fi
    echo
elif [ -n "$(f_go_bin)" ]; then
    echo -e "${YELLOW}Installing httpx.${NC}"
    f_go_install_tool github.com/projectdiscovery/httpx/cmd/httpx@latest httpx
    echo
fi

if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Installing jq.${NC}"
    apt install -y jq
    echo
fi

if [ -d /opt/krbrelayx/.git ]; then
    echo -e "${BLUE}Updating krbrelayx.${NC}"
    cd /opt/krbrelayx/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing krbrelayx.${NC}"
    git clone https://github.com/dirkjanm/krbrelayx /opt/krbrelayx
    echo
fi

if ! command -v kubectl &> /dev/null; then
    echo -e "${YELLOW}Installing kubectl.${NC}"
    if command -v snap &> /dev/null; then
        snap install kubectl --classic 2>/dev/null || true
    fi
    if ! command -v kubectl &> /dev/null; then
        KUBECTL_VERSION=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
        curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl
        chmod +x /usr/local/bin/kubectl
    fi
    echo
fi

if [ -d /opt/manspider/.git ]; then
    echo -e "${BLUE}Updating MAN-SPIDER.${NC}"
    cd /opt/manspider/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing MAN-SPIDER.${NC}"
    git clone https://github.com/blacklanternsecurity/MANSPIDER /opt/manspider
    apt install -y antiword tesseract-ocr
    echo
fi

if ! command -v msfconsole &> /dev/null; then
    echo -e "${YELLOW}Installing Metasploit.${NC}"
    snap install metasploit-framework
    echo
fi

if ! command -v nikto &> /dev/null; then
    echo -e "${YELLOW}Installing nikto.${NC}"
    apt install -y nikto
    echo
fi

if [ -d /usr/share/nmap/scripts/custom/.git ]; then
    echo -e "${BLUE}Updating custom Nmap scripts.${NC}"
    cd /usr/share/nmap/scripts/custom/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing custom Nmap scripts.${NC}"
    git clone https://github.com/ibrahmsql/Custom-Nse /usr/share/nmap/scripts/custom/
    echo
fi

if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}Installing nmap.${NC}"
    apt install -y nmap
    echo
fi

echo -e "${BLUE}Updating Nmap scripts.${NC}"
nmap --script-updatedb | grep -Eiv '(starting|seconds)' | sed 's/NSE: //'
echo

if [ -d /opt/PowerSharpPack/.git ]; then
    echo -e "${BLUE}Updating PowerSharpPack.${NC}"
    cd /opt/PowerSharpPack/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing PowerSharpPack.${NC}"
    git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack /opt/PowerSharpPack
    echo
fi

if [ -d /opt/PowerSploit/.git ]; then
    echo -e "${BLUE}Updating PowerSploit.${NC}"
    cd /opt/PowerSploit/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing PowerSploit.${NC}"
    git clone https://github.com/0xe7/PowerSploit /opt/PowerSploit
    echo
fi

if [ -d /opt/PowerUpSQL/.git ]; then
    echo -e "${BLUE}Updating PowerUpSQL.${NC}"
    cd /opt/PowerUpSQL/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing PowerUpSQL.${NC}"
    git clone https://github.com/NetSPI/PowerUpSQL /opt/PowerUpSQL
    echo
fi

if [ -d /opt/PrivescCheck/.git ]; then
    echo -e "${BLUE}Updating PrivescCheck.${NC}"
    cd /opt/PrivescCheck/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing PrivescCheck.${NC}"
    git clone https://github.com/itm4n/PrivescCheck /opt/PrivescCheck
    echo
fi

if ! python3 -c 'import requests' &> /dev/null; then
    echo -e "${YELLOW}Installing python3-requests.${NC}"
    apt install -y python3-requests
    echo
fi

if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    echo -e "${YELLOW}Expanding Rockyou list.${NC}"
    zcat /usr/share/wordlists/rockyou.txt.gz > /usr/share/wordlists/rockyou.txt
    rm /usr/share/wordlists/rockyou.txt.gz
    echo
fi

if ! command -v rustc &> /dev/null; then
    echo -e "${YELLOW}Installing Rust.${NC}"
    apt install -y rustc
    echo
fi

if [ -d /usr/share/wordlists/seclists/.git ]; then
    echo -e "${BLUE}Updating SecLists.${NC}"
    cd /usr/share/wordlists/seclists/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing SecLists.${NC}"
    git clone https://github.com/danielmiessler/seclists /usr/share/wordlists/seclists
    echo
fi

if [ -d /opt/SharpCollection/.git ]; then
    echo -e "${BLUE}Updating SharpCollection.${NC}"
    cd /opt/SharpCollection/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing SharpCollection.${NC}"
    git clone https://github.com/Flangvik/SharpCollection /opt/SharpCollection
    echo
fi

if ! command -v sqlmap &> /dev/null; then
    echo -e "${YELLOW}Installing sqlmap.${NC}"
    apt install -y sqlmap
    echo
fi

if ! command -v sslscan &> /dev/null; then
    echo -e "${YELLOW}Installing sslscan.${NC}"
    apt install -y sslscan
    echo
fi

if command -v subfinder &> /dev/null; then
    echo -e "${BLUE}Updating subfinder.${NC}"
    subfinder_out=$(NO_COLOR=1 subfinder -up -silent 2>&1) || true
    if echo "$subfinder_out" | grep -qi 'already updated'; then
        echo "Already up to date."
    elif echo "$subfinder_out" | grep -qE '^\[INF\]'; then
        echo "Updated."
    else
        f_go_install_tool github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest subfinder
    fi
    echo
elif [ -n "$(f_go_bin)" ]; then
    echo -e "${YELLOW}Installing subfinder.${NC}"
    f_go_install_tool github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest subfinder
    echo
fi

f_sublist3r_patch() {
    sed -i \
        -e 's/class enumratorBaseThreaded(multiprocessing.Process, enumratorBase)/class enumratorBaseThreaded(threading.Thread, enumratorBase)/' \
        -e 's/multiprocessing.Process.__init__(self)/threading.Thread.__init__(self)/' \
        -e 's/subdomains_queue = multiprocessing.Manager().list()/subdomains_queue = list()/' \
        /opt/Sublist3r/sublist3r.py
}

f_sublist3r_working() {
    command -v sublist3r >/dev/null 2>&1 && sublist3r -d example.com 2>&1 | grep -q 'Total Unique Subdomains Found'
}

if [ -x /opt/Sublist3r-venv/bin/python ] && [ -f /opt/Sublist3r/sublist3r.py ]; then
    echo -e "${BLUE}Updating Sublist3r.${NC}"
    cd /opt/Sublist3r/ || exit
    git pull
    f_sublist3r_patch
    /opt/Sublist3r-venv/bin/python -m pip install -q -r requirements.txt
    echo '#!/bin/bash' > /usr/local/bin/sublist3r
    echo 'exec /opt/Sublist3r-venv/bin/python /opt/Sublist3r/sublist3r.py "$@"' >> /usr/local/bin/sublist3r
    chmod 755 /usr/local/bin/sublist3r
    echo
elif f_sublist3r_working; then
    :
elif python3 -c 'import sys; exit(0 if sys.version_info >= (3, 13) else 1)' 2>/dev/null; then
    echo -e "${YELLOW}Installing Sublist3r from upstream (apt package is incompatible with Python 3.13+).${NC}"
    apt remove -y sublist3r 2>/dev/null
    if ! python3 -m venv /tmp/sublist3r-venv-check 2>/dev/null; then
        apt install -y python3-venv
        rm -rf /tmp/sublist3r-venv-check
    fi
    if [ -d /opt/Sublist3r/.git ]; then
        cd /opt/Sublist3r/ || exit
        git pull
    else
        git clone https://github.com/aboul3la/Sublist3r /opt/Sublist3r
    fi
    f_sublist3r_patch
    python3 -m venv /opt/Sublist3r-venv
    /opt/Sublist3r-venv/bin/python -m pip install -q -U pip
    /opt/Sublist3r-venv/bin/python -m pip install -q -r /opt/Sublist3r/requirements.txt
    echo '#!/bin/bash' > /usr/local/bin/sublist3r
    echo 'exec /opt/Sublist3r-venv/bin/python /opt/Sublist3r/sublist3r.py "$@"' >> /usr/local/bin/sublist3r
    chmod 755 /usr/local/bin/sublist3r
    echo
else
    echo -e "${YELLOW}Installing Sublist3r.${NC}"
    apt install -y sublist3r
    echo
fi

if ! command -v trivy &> /dev/null; then
    echo -e "${YELLOW}Installing trivy.${NC}"
    if ! apt install -y trivy 2>/dev/null || ! command -v trivy &> /dev/null; then
        apt install -y wget gnupg apt-transport-https
        wget -qO- https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg
        echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list
        apt update
        apt install -y trivy
    fi
    echo
fi

if ! command -v trufflehog &> /dev/null; then
    echo -e "${YELLOW}Installing trufflehog.${NC}"
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
    echo
fi

if ! command -v wafw00f &> /dev/null; then
    echo -e "${YELLOW}Installing wafw00f.${NC}"
    apt install -y wafw00f
    echo
fi

if ! command -v whatweb &> /dev/null; then
    echo -e "${YELLOW}Installing whatweb.${NC}"
    apt install -y whatweb
    echo
fi

if [ -d /opt/Windows-Exploit-Suggester-NG/.git ]; then
    echo -e "${BLUE}Updating Windows Exploit Suggester NG.${NC}"
    cd /opt/Windows-Exploit-Suggester-NG/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing Windows Exploit Suggester NG.${NC}"
    git clone https://github.com/bitsadmin/wesng /opt/Windows-Exploit-Suggester-NG
    echo
fi

if ! command -v xdotool >/dev/null 2>&1; then
    echo -e "${YELLOW}Installing xdotool.${NC}"
    apt install -y xdotool
    echo
fi

if ! command -v xml_grep &> /dev/null; then
    echo -e "${YELLOW}Installing xml_grep.${NC}"
    apt install -y xml-twig-tools
    echo
fi

if ! command -v xmllint &> /dev/null; then
    echo -e "${YELLOW}Installing xmllint.${NC}"
    apt install -y libxml2-utils
    echo
fi

if grep -qi '^ID=ubuntu' /etc/os-release; then
    if ! command -v ydotool >/dev/null 2>&1 || ! command -v ydotoold >/dev/null 2>&1; then
        echo -e "${YELLOW}Installing ydotool.${NC}"
        apt install -y ydotool
        echo
    fi
fi

###############################################################################################################################

if [ -d /opt/bruteratel/ ] || [ -d /opt/cobaltstrike/ ]; then
    if [ -d /opt/BOFs/anthemtotheego-inlineExecute-assembly/.git ]; then
        echo -e "${BLUE}Updating anthemtotheego InlineExecute Assembly BOF.${NC}"
        cd /opt/BOFs/anthemtotheego-inlineExecute-assembly/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing anthemtotheego InlineExecute Assembly BOF.${NC}"
        git clone https://github.com/anthemtotheego/InlineExecute-Assembly /opt/BOFs/anthemtotheego-inlineExecute-assembly
        echo
    fi

    if [ -d /opt/BOFs/outflanknl-c2-tool-collection/.git ]; then
        echo -e "${BLUE}Updating Outflank C2 Tool Collection BOF.${NC}"
        cd /opt/BOFs/outflanknl-c2-tool-collection/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing Outflank C2 Tool Collection BOF.${NC}"
        git clone https://github.com/outflanknl/C2-Tool-Collection /opt/BOFs/outflanknl-c2-tool-collection
        echo
    fi

    if [ -d /opt/BOFs/outflanknl-helpcolor/.git ]; then
        echo -e "${BLUE}Updating Outflank HelpColor BOF.${NC}"
        cd /opt/BOFs/outflanknl-helpcolor/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing Outflank HelpColor BOF.${NC}"
        git clone https://github.com/outflanknl/HelpColor /opt/BOFs/outflanknl-helpcolor
        echo
    fi

    if [ -d /opt/BOFs/trustedsec-remote-ops/.git ]; then
        echo -e "${BLUE}Updating TrustedSec Remote OPs BOF.${NC}"
        cd /opt/BOFs/trustedsec-remote-ops/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing TrustedSec Remote OPs BOF.${NC}"
        git clone https://github.com/trustedsec/CS-Remote-OPs-BOF /opt/BOFs/trustedsec-remote-ops
        echo
    fi

    if [ -d /opt/BOFs/trustedsec-sa/.git ]; then
        echo -e "${BLUE}Updating TrustedSec Situational Awareness BOF.${NC}"
        cd /opt/BOFs/trustedsec-sa/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing TrustedSec Situational Awareness BOF.${NC}"
        git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF /opt/BOFs/trustedsec-sa
        echo
    fi
fi
###############################################################################################################################

if [ -d /opt/cobaltstrike/ ]; then
    if [ -d /opt/cobaltstrike/elevatekit/.git ]; then
        echo -e "${BLUE}Updating CS - ElevateKit.${NC}"
        cd /opt/cobaltstrike/elevatekit/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing CS - ElevateKit.${NC}"
        git clone https://github.com/rsmudge/ElevateKit /opt/cobaltstrike/elevatekit
        echo
    fi

    if [ -d /opt/cobaltstrike/RedSiege-C2concealer/.git ]; then
        echo -e "${BLUE}Updating CS - RedSiege C2concealer.${NC}"
        cd /opt/cobaltstrike/RedSiege-C2concealer/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing CS - RedSiege C2concealer.${NC}"
        git clone https://github.com/RedSiege/C2concealer /opt/cobaltstrike/RedSiege-C2concealer
        echo
    fi

    if [ -d /opt/cobaltstrike/malleable-c2-profiles/.git ]; then
        echo -e "${BLUE}Updating CS - Malleable C2 profiles.${NC}"
        cd /opt/cobaltstrike/malleable-c2-profiles/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing CS - Malleable C2 profiles.${NC}"
        git clone https://github.com/Cobalt-Strike/Malleable-C2-Profiles /opt/cobaltstrike/malleable-c2-profiles
        echo
    fi

    if [ -d /opt/cobaltstrike/mgeeky-scripts/.git ]; then
        echo -e "${BLUE}Updating CS - mgeeky cobalt arsenal.${NC}"
        cd /opt/cobaltstrike/mgeeky-scripts/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing CS - mgeeky cobalt arsenal.${NC}"
        git clone https://github.com/mgeeky/cobalt-arsenal /opt/cobaltstrike/mgeeky-scripts
    echo
    fi

    if [ -d /opt/cobaltstrike/tylous-sourcepoint/.git ]; then
        echo -e "${BLUE}Updating CS - Tylous SourcePoint.${NC}"
        cd /opt/cobaltstrike/tylous-sourcepoint/ || exit ; git pull
        echo
    else
        echo -e "${YELLOW}Installing CS - Tylous SourcePoint.${NC}"
        git clone https://github.com/Tylous/SourcePoint /opt/cobaltstrike/tylous-sourcepoint
        cd /opt/cobaltstrike/tylous-sourcepoint/ || exit
        go get gopkg.in/yaml.v2
        go build SourcePoint.go
        echo
    fi
fi
###############################################################################################################################

# Get the original user's home directory even if run with sudo
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME="$HOME"
fi

# Delete folder if it is empty
if [ -d "$USER_HOME/data/" ] && [ -z "$(ls -A "$USER_HOME/data/" 2>/dev/null)" ]; then
    rm -rf "$USER_HOME/data/"
fi

echo -e "${BLUE}Updating locate database.${NC}"
updatedb
echo

exit
