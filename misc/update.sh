#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

# Variables
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'
# Discover install root (parent of misc/) — reliable when this script is executed directly
DISCOVER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

f_disable_auto_updates(){
    local marker=/etc/apt/apt.conf.d/99discover-no-auto-updates

    # Only run (and print) once — marker file means this machine was already configured.
    if [ -f "$marker" ] && grep -q 'Managed by Discover update.sh' "$marker" 2>/dev/null; then
        return 0
    fi

    echo -e "${BLUE}Disabling automatic OS update checks.${NC}"

    cat > "$marker" <<'EOF'
// Managed by Discover update.sh — manual updates only
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
EOF

    local unit
    for unit in unattended-upgrades apt-daily.timer apt-daily-upgrade.timer \
        update-notifier-download.timer update-notifier-motd.timer \
        fwupd-refresh.timer motd-news.timer ua-timer.timer snapd.snap-repair.timer; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done

    mkdir -p /etc/xdg/autostart
    local desktop
    for desktop in update-notifier ubuntu-advantage-notification ubuntu-report-on-upgrade; do
        cat > "/etc/xdg/autostart/${desktop}.desktop" <<EOF
[Desktop Entry]
Hidden=true
EOF
    done

    if command -v snap &> /dev/null; then
        snap set system refresh.hold="$(date -u --date='+90 days' +%Y-%m-%dT%H:%M:%SZ)" \
            >/dev/null 2>&1 || true
    fi

    echo
}

f_disable_auto_updates

# OS packages — quiet when nothing to do; one upgrade pass (no upgrade+dist-upgrade double chatter).
f_update_os(){
    local held
    export DEBIAN_FRONTEND=noninteractive

    echo -e "${BLUE}Updating the operating system.${NC}"
    # -qq: no Hit:/Get: spam or Ubuntu Pro walls of text
    if ! apt-get update -qq 2>/dev/null; then
        apt-get update 2>&1 | tail -20 || true
    fi

    # Always include phased updates so Ubuntu does not leave packages "held".
    # dist-upgrade alone covers normal upgrades; avoids a second Summary block.
    local apt_phase=(-o APT::Get::Always-Include-Phased-Updates=true)
    if ! apt-get -y -qq \
        "${apt_phase[@]}" \
        -o APT::Get::Show-User-Simulation-Note=false \
        -o Dpkg::Use-Pty=0 \
        -o APT::Color=0 \
        dist-upgrade 2>/dev/null; then
        apt-get -y "${apt_phase[@]}" dist-upgrade 2>&1 | tail -30 || true
    fi
    apt-get -y -qq autoremove >/dev/null 2>&1 || true
    apt-get -y -qq autoclean >/dev/null 2>&1 || true
    updatedb 2>/dev/null || true

    held=$(apt list --upgradable 2>/dev/null | awk 'NR > 1 && $0 ~ /\// { n++ } END { print n+0 }')
    if [ "${held:-0}" -gt 0 ]; then
        echo "OS: ${held} package(s) still upgradable."
    else
        echo "OS packages up to date."
    fi
    echo
}
f_update_os
unset -f f_update_os

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

# CISA Known Exploited Vulnerabilities catalog (used by Active CVSS / Top CVE)
# Stored under Discover's resource/ folder. Alphabetical order: after chromium, before curl.
# curl is installed just below; use it if already present, otherwise soft-fail until curl installs.
f_update_cisa_kev(){
    local kev_dir="$DISCOVER_ROOT/resource"
    local kev_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    local kev_file="$kev_dir/known_exploited_vulnerabilities.json"
    local tmp_file
    local count

    echo -e "${BLUE}Updating CISA KEV catalog.${NC}"
    if ! command -v curl &> /dev/null; then
        echo -e "${YELLOW}curl not installed yet; skipping CISA KEV until curl is available.${NC}"
        echo
        return 0
    fi
    mkdir -p "$kev_dir" || {
        echo -e "${YELLOW}Could not create $kev_dir; skipping CISA KEV update.${NC}"
        echo
        return 0
    }

    tmp_file=$(mktemp) || {
        echo -e "${YELLOW}Could not create temp file; skipping CISA KEV update.${NC}"
        echo
        return 0
    }

    if curl -fsSL --connect-timeout 30 --max-time 180 \
        -A "Discover-update/1.0 (https://github.com/leebaird/discover)" \
        -o "$tmp_file" "$kev_url"; then
        if python3 -c "import json,sys; json.load(open(sys.argv[1], encoding='utf-8'))" "$tmp_file" 2>/dev/null; then
            mv "$tmp_file" "$kev_file"
            chmod 644 "$kev_file" 2>/dev/null || true
            if [ -n "$SUDO_USER" ]; then
                chown "$SUDO_USER:" "$kev_file" 2>/dev/null || true
            fi
            count=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1], encoding='utf-8')).get('count', '?'))" "$kev_file" 2>/dev/null || echo "?")
            echo "Saved $kev_file"
            echo "$count vulnerabilities."
        else
            rm -f "$tmp_file"
            echo -e "${YELLOW}CISA KEV download was not valid JSON; keeping previous catalog if any.${NC}"
        fi
    else
        rm -f "$tmp_file"
        echo -e "${YELLOW}Failed to download CISA KEV catalog; keeping previous catalog if any.${NC}"
    fi
    echo
    # Engagement trees are not walked here (Desktop/external paths). Import
    # rewrites tools/shodan/kev-ids.js for the report the operator opens.
}

f_update_cisa_kev

# Refresh Microsoft Edge User-Agent for scanners (Nikto, Nmap, ffuf, Active, scripts).
# Primary source: jnrbsn user-agents JSON; backup: microlink top desktop list.
# Soft-fail: keep existing resource/user-agent.txt if download fails.
f_update_user_agent(){
    local ua_dir="$DISCOVER_ROOT/resource"
    local ua_file="$ua_dir/user-agent.txt"
    local primary_url="https://jnrbsn.github.io/user-agents/user-agents.json"
    local backup_url="https://raw.githubusercontent.com/microlinkhq/top-user-agents/master/src/desktop.json"
    local tmp_file
    local ua=""
    # Prefer GitHub Nikto install; fall back to legacy apt paths.
    local nikto_cfg=""
    for candidate in /opt/nikto/program/nikto.conf /etc/nikto/config.txt /etc/nikto.conf; do
        if [ -f "$candidate" ]; then
            nikto_cfg="$candidate"
            break
        fi
    done
    local nmap_http=/usr/share/nmap/nselib/http.lua

    echo -e "${BLUE}Updating scanner User-Agent (Microsoft Edge).${NC}"

    if ! command -v curl &> /dev/null; then
        echo -e "${YELLOW}curl not installed yet; skipping User-Agent refresh until curl is available.${NC}"
        echo
        return 0
    fi

    mkdir -p "$ua_dir" || {
        echo -e "${YELLOW}Could not create $ua_dir; skipping User-Agent refresh.${NC}"
        echo
        return 0
    }

    tmp_file=$(mktemp) || {
        echo -e "${YELLOW}Could not create temp file; skipping User-Agent refresh.${NC}"
        echo
        return 0
    }

    f_ua_from_json(){
        local json_path="$1"
        python3 - "$json_path" <<'PY'
import json, sys

path = sys.argv[1]
try:
    data = json.load(open(path, encoding="utf-8"))
except Exception:
    sys.exit(1)

items = data if isinstance(data, list) else []
if isinstance(data, dict):
    for value in data.values():
        if isinstance(value, list):
            items = value
            break

chosen = ""
for entry in items:
    if not isinstance(entry, str):
        continue
    if "Edg/" not in entry:
        continue
    if "Windows NT" not in entry and "Windows" not in entry:
        continue
    if not entry.startswith("Mozilla/"):
        continue
    chosen = entry.strip()
    break

if not chosen:
    sys.exit(1)
print(chosen)
PY
    }

    if curl -fsSL --connect-timeout 20 --max-time 60 \
        -A "Discover-update/1.0 (https://github.com/leebaird/discover)" \
        -o "$tmp_file" "$primary_url"; then
        ua=$(f_ua_from_json "$tmp_file" 2>/dev/null || true)
    fi

    if [ -z "$ua" ]; then
        if curl -fsSL --connect-timeout 20 --max-time 60 \
            -A "Discover-update/1.0 (https://github.com/leebaird/discover)" \
            -o "$tmp_file" "$backup_url"; then
            ua=$(f_ua_from_json "$tmp_file" 2>/dev/null || true)
        fi
    fi
    rm -f "$tmp_file"

    if [ -z "$ua" ] || [[ "$ua" != Mozilla/* ]]; then
        if [ -f "$ua_file" ]; then
            echo -e "${YELLOW}Could not refresh User-Agent; keeping existing $ua_file.${NC}"
        else
            echo -e "${YELLOW}Could not refresh User-Agent; tools will use built-in Edge fallback.${NC}"
        fi
        echo
        return 0
    fi

    {
        echo "# Discover scanner User-Agent (Microsoft Edge on Windows)."
        echo "# Refreshed by misc/update.sh — do not commit secrets here."
        echo "# Primary: $primary_url"
        echo "$ua"
    } > "$ua_file"
    chmod 644 "$ua_file" 2>/dev/null || true
    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER:" "$ua_file" 2>/dev/null || true
    fi
    echo "Saved $ua_file"
    echo "$ua"

    # Nikto — USERAGENT= when present (2.5+ also accepts -useragent CLI).
    if [ -n "$nikto_cfg" ] && [ -f "$nikto_cfg" ] && [ -w "$nikto_cfg" ]; then
        if grep -qE '^USERAGENT=' "$nikto_cfg"; then
            # Use | delimiter; UA has no pipes.
            sed -i "s|^USERAGENT=.*|USERAGENT=$ua|" "$nikto_cfg"
        else
            printf '\nUSERAGENT=%s\n' "$ua" >> "$nikto_cfg"
        fi
        echo "Updated Nikto USERAGENT in $nikto_cfg"
    elif [ -n "$nikto_cfg" ] && [ -f "$nikto_cfg" ]; then
        echo -e "${YELLOW}Nikto config not writable: $nikto_cfg${NC}"
    fi

    # Nmap NSE http library default User-Agent (best-effort across upgrades).
    if [ -f "$nmap_http" ] && [ -w "$nmap_http" ]; then
        if python3 - "$nmap_http" "$ua" <<'PY'
import re, sys

path, new_ua = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8", errors="replace").read()
# stdnse.get_script_args('http.useragent') or "...."
pattern = re.compile(
    r"(stdnse\.get_script_args\(\s*['\"]http\.useragent['\"]\s*\)\s*or\s*)([\"'])(.*?)\2",
    re.DOTALL,
)
match = pattern.search(text)
if not match:
    sys.exit(1)
quote = match.group(2)
escaped = new_ua.replace("\\", "\\\\").replace(quote, "\\" + quote)
new_text, count = pattern.subn(r"\1" + quote + escaped + quote, text, count=1)
if count != 1:
    sys.exit(1)
open(path, "w", encoding="utf-8").write(new_text)
PY
        then
            echo "Updated Nmap default User-Agent in $nmap_http"
        else
            echo -e "${YELLOW}Could not patch Nmap http.lua User-Agent (pattern mismatch).${NC}"
        fi
    elif [ -f "$nmap_http" ]; then
        echo -e "${YELLOW}Nmap http.lua not writable: $nmap_http${NC}"
    fi

    # ffuf — per-user default headers in ~/.config/ffuf/ffufrc (no system-wide default).
    # When Update runs under sudo, patch the invoking user's config (and root if needed).
    f_patch_ffuf_ua(){
        local home_dir="$1"
        local owner="$2"
        local conf_dir conf_file

        [ -n "$home_dir" ] && [ -d "$home_dir" ] || return 1
        conf_dir="$home_dir/.config/ffuf"
        conf_file="$conf_dir/ffufrc"
        mkdir -p "$conf_dir" || return 1

        if python3 - "$conf_file" "$ua" <<'PY'
import re, sys
from pathlib import Path

path = Path(sys.argv[1])
new_ua = sys.argv[2]
header_line = f'        "User-Agent: {new_ua}"'

if path.is_file():
    text = path.read_text(encoding="utf-8", errors="replace")
else:
    text = ""

# Replace existing User-Agent entry in headers list if present.
ua_hdr = re.compile(
    r'^([ \t]*"[Uu]ser-[Aa]gent:\s*)([^"]*)(")',
    re.MULTILINE,
)
if ua_hdr.search(text):
    text = ua_hdr.sub(r'\1' + new_ua.replace("\\", "\\\\") + r'\3', text, count=1)
    path.write_text(text, encoding="utf-8")
    sys.exit(0)

# Insert into existing headers = [ ... ] block under [http] if possible.
headers_block = re.compile(
    r'(headers\s*=\s*\[)(.*?)(\n[ \t]*\])',
    re.DOTALL | re.IGNORECASE,
)
m = headers_block.search(text)
if m:
    inner = m.group(2).rstrip()
    if inner and not inner.rstrip().endswith(","):
        # last entry may need trailing comma before new line
        inner = inner.rstrip() + ","
    insertion = inner + "\n" + header_line
    text = text[: m.start(2)] + insertion + text[m.end(2) :]
    path.write_text(text, encoding="utf-8")
    sys.exit(0)

# Ensure [http] section exists, then append headers list.
if re.search(r'^\[http\]', text, re.MULTILINE):
    text = text.rstrip() + "\n\n    headers = [\n" + header_line + "\n    ]\n"
else:
    prefix = text.rstrip()
    block = (
        "# User-Agent managed by Discover update.sh\n"
        "[http]\n"
        "    headers = [\n"
        f"{header_line}\n"
        "    ]\n"
    )
    text = (prefix + "\n\n" + block) if prefix else block

path.write_text(text, encoding="utf-8")
PY
        then
            if [ -n "$owner" ] && [ "$owner" != "root" ]; then
                chown -R "$owner:" "$conf_dir" 2>/dev/null || true
            fi
            echo "Updated ffuf User-Agent in $conf_file"
            return 0
        fi
        echo -e "${YELLOW}Could not update ffuf config: $conf_file${NC}"
        return 1
    }

    if [ -n "$SUDO_USER" ]; then
        sudo_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        f_patch_ffuf_ua "$sudo_home" "$SUDO_USER" || true
    fi
    # Also patch the effective home (root when Update is run with sudo).
    if [ -z "$SUDO_USER" ] || [ "$(id -u)" -eq 0 ]; then
        # Avoid double-writing the same path when not using sudo.
        if [ -z "$SUDO_USER" ] || [ "${sudo_home:-}" != "$HOME" ]; then
            f_patch_ffuf_ua "$HOME" "$(id -un)" || true
        fi
    fi

    echo
}

f_update_user_agent

if ! command -v curl &> /dev/null; then
    echo -e "${YELLOW}Installing curl.${NC}"
    apt install -y curl
    echo
    # Retry KEV now that curl is available (first-time installs).
    f_update_cisa_kev
    f_update_user_agent
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
    systemctl disable docker docker.socket containerd >/dev/null 2>&1 || true
    systemctl stop docker docker.socket containerd >/dev/null 2>&1 || true
    echo -e "${YELLOW}Docker/containerd installed but not enabled at boot (start manually or via container scanner).${NC}"
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

# droopescan — CMS scanner (Drupal, WordPress, …); pipx under /opt/pipx → /usr/local/bin.
# Python 3.12+ needs cement/setuptools patch after install or upgrade (re-run is quiet if already applied).
if ! command -v pipx &> /dev/null; then
    echo -e "${YELLOW}Installing pipx (required for droopescan).${NC}"
    apt install -y pipx
    echo
fi

_ds_pipx(){
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx "$@"
}

if [ -d /opt/pipx/venvs/droopescan ]; then
    # Same look as DomainPasswordSpray / Egress-Assess: blue header + plain status line.
    echo -e "${BLUE}Updating droopescan.${NC}"
    _ds_out=$(_ds_pipx upgrade -q droopescan 2>&1) || true
    if [ -n "$_ds_out" ] && ! echo "$_ds_out" | grep -qiE 'already at latest|already installed'; then
        echo "$_ds_out"
    else
        echo "Already up to date."
    fi
    unset _ds_out
    echo
elif command -v droopescan &> /dev/null; then
    # Binary on PATH but not under /opt/pipx — install Discover's copy
    echo -e "${YELLOW}Installing droopescan.${NC}"
    mkdir -p /opt/pipx
    _ds_pipx install droopescan
    echo
else
    echo -e "${YELLOW}Installing droopescan.${NC}"
    mkdir -p /opt/pipx
    _ds_pipx install droopescan
    echo
fi
unset -f _ds_pipx

# Py3.12+ cement/imp patch — silent when already applied; prints only if it changes files.
if [ -x "$DISCOVER_ROOT/misc/patch-droopescan-py314.sh" ]; then
    _ds_patch="$DISCOVER_ROOT/misc/patch-droopescan-py314.sh"
    if [ -d /opt/pipx/venvs/droopescan ]; then
        if ! bash "$_ds_patch" /opt/pipx/venvs/droopescan; then
            echo -e "${YELLOW}[!] System droopescan patch failed:${NC}"
            echo "    sudo $_ds_patch -v /opt/pipx/venvs/droopescan"
        fi
    fi
    # User pipx (PATH often prefers ~/.local/bin over /usr/local/bin)
    _ds_user_home="$HOME"
    if [ -n "${SUDO_USER:-}" ]; then
        _ds_user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi
    if [ -d "$_ds_user_home/.local/pipx/venvs/droopescan" ]; then
        bash "$_ds_patch" "$_ds_user_home/.local/pipx/venvs/droopescan" || true
    fi
    unset _ds_user_home _ds_patch
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

# Nikto from GitHub (sullo/nikto) — apt 2.1.5 is years behind (2.6.x has TLS SNI,
# current tests DBs, -useragent / -nointeractive). Install under /opt/nikto.
f_install_nikto_github(){
    local nikto_root=/opt/nikto
    local nikto_prog="$nikto_root/program"
    local nikto_pl="$nikto_prog/nikto.pl"
    local nikto_conf="$nikto_prog/nikto.conf"
    local nikto_default="$nikto_prog/nikto.conf.default"
    local wrapper=/usr/local/bin/nikto
    local repo=https://github.com/sullo/nikto.git

    # Drop distro package so /usr/bin/nikto cannot shadow GitHub install.
    if dpkg -l nikto 2>/dev/null | grep -q '^ii'; then
        echo -e "${YELLOW}Removing apt nikto (stale 2.1.x) in favor of GitHub.${NC}"
        apt remove -y nikto 2>/dev/null || true
        # Optional system LW2 only used by old apt Nikto.
        apt remove -y libwhisker2-perl 2>/dev/null || true
        echo
    fi

    # Perl modules required by Nikto 2.5+/2.6 (see upstream Dockerfile).
    # Only apt-install what's missing so Update stays quiet on repeat runs.
    local pkg missing=()
    for pkg in \
        libnet-ssleay-perl \
        libio-socket-ssl-perl \
        libwww-perl \
        libjson-perl \
        libxml-writer-perl \
        libtimedate-perl
    do
        if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
            missing+=("$pkg")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo -e "${YELLOW}Installing Nikto Perl deps: ${missing[*]}${NC}"
        apt install -y "${missing[@]}" || true
        echo
    fi

    if [ -d "$nikto_root/.git" ]; then
        # Same pattern as MAN-SPIDER / custom Nmap scripts:
        # blue header + git pull ("Already up to date." or real pull).
        echo -e "${BLUE}Updating Nikto.${NC}"
        git -C "$nikto_root" fetch --force --prune origin >/dev/null 2>&1 || true
        git -C "$nikto_root" checkout -q main 2>/dev/null \
            || git -C "$nikto_root" checkout -q master 2>/dev/null || true
        git -C "$nikto_root" pull --ff-only origin main 2>/dev/null \
            || git -C "$nikto_root" pull --ff-only 2>/dev/null || true
        echo
    else
        echo -e "${YELLOW}Installing Nikto.${NC}"
        rm -rf "$nikto_root"
        if ! git clone "$repo" "$nikto_root"; then
            echo -e "${YELLOW}Nikto git clone failed.${NC}"
            echo
            return 1
        fi
        git -C "$nikto_root" checkout -q main 2>/dev/null || true
        echo
    fi

    if [ ! -f "$nikto_pl" ]; then
        echo -e "${YELLOW}Nikto install incomplete: missing $nikto_pl${NC}"
        echo
        return 1
    fi
    chmod 755 "$nikto_pl" 2>/dev/null || true

    # Discover-owned site config — rewrite only when content changes (silent).
    if [ -f "$nikto_default" ]; then
        python3 - "$nikto_default" "$nikto_conf" <<'PY' >/dev/null
import sys
from pathlib import Path

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
base = src.read_text(encoding="utf-8", errors="replace")
force = {
    "PROMPTS": "no",
    "UPDATES": "no",
    "DEFAULTHTTPVER": "1.1",
    "CHECKMETHODS": "GET",
}
comment_keys = {"RFIURL"}
seen = set()
lines = []
for raw in base.splitlines():
    stripped = raw.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        key = stripped.split("=", 1)[0].strip()
        if key in comment_keys:
            lines.append("#" + raw if not raw.lstrip().startswith("#") else raw)
            continue
        if key in force:
            if key not in seen:
                lines.append(f"{key}={force[key]}")
                seen.add(key)
            continue
    lines.append(raw)
for key, value in force.items():
    if key not in seen:
        lines.append(f"{key}={value}")
new = "\n".join(lines) + "\n"
old = dst.read_text(encoding="utf-8", errors="replace") if dst.is_file() else None
if old != new:
    dst.write_text(new, encoding="utf-8")
PY
    fi

    # Wrapper (silent unless missing).
    if [ ! -x "$wrapper" ] || ! grep -q '/opt/nikto/program/nikto.pl' "$wrapper" 2>/dev/null; then
        cat > "$wrapper" <<'WRAP'
#!/usr/bin/env bash
# Discover wrapper — GitHub Nikto (sullo/nikto) under /opt/nikto
exec perl /opt/nikto/program/nikto.pl "$@"
WRAP
        chmod 755 "$wrapper"
    fi
    hash -r 2>/dev/null || true
}
f_install_nikto_github

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

if command -v nuclei &> /dev/null; then
    echo -e "${BLUE}Updating nuclei.${NC}"
    nuclei_out=$(NO_COLOR=1 nuclei -up -silent 2>&1) || true
    if echo "$nuclei_out" | grep -qi 'already updated'; then
        echo "Already up to date."
    elif echo "$nuclei_out" | grep -qE '^\[INF\]'; then
        echo "Updated."
    else
        f_go_install_tool github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest nuclei
    fi
    echo
elif [ -n "$(f_go_bin)" ]; then
    echo -e "${YELLOW}Installing nuclei.${NC}"
    f_go_install_tool github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest nuclei
    echo
fi

if [ -d /opt/PEASS-ng/.git ]; then
    echo -e "${BLUE}Updating PEASS-ng.${NC}"
    cd /opt/PEASS-ng/ || exit ; git pull
    echo
else
    echo -e "${YELLOW}Installing PEASS-ng.${NC}"
    git clone https://github.com/peass-ng/PEASS-ng /opt/PEASS-ng
    echo
fi

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

# TigerVNC client (vncviewer) — lightweight VNC viewer for operator desktops.
if ! command -v vncviewer >/dev/null 2>&1 && ! command -v xtigervncviewer >/dev/null 2>&1; then
    echo -e "${YELLOW}Installing TigerVNC viewer.${NC}"
    apt install -y tigervnc-viewer
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

f_ruby_bin() {
    local ruby_bin

    for ruby_bin in \
        "$(command -v ruby 2>/dev/null)" \
        /opt/metasploit-framework/embedded/bin/ruby \
        /snap/metasploit-framework/current/opt/metasploit-framework/embedded/bin/ruby; do
        if [ -n "$ruby_bin" ] && [ -x "$ruby_bin" ]; then
            printf '%s\n' "$ruby_bin"
            return 0
        fi
    done

    return 1
}

f_whatweb_ensure_deps() {
    local ruby_bin

    if ruby_bin=$(f_ruby_bin); then
        if "$ruby_bin" -e 'require "addressable"' >/dev/null 2>&1; then
            return 0
        fi
    fi

    if ! command -v ruby >/dev/null 2>&1; then
        echo -e "${YELLOW}Installing Ruby for WhatWeb.${NC}"
        apt install -y ruby
    fi
    if ! ruby -e 'require "addressable"' >/dev/null 2>&1; then
        apt install -y ruby-addressable 2>/dev/null || true
    fi
}

f_whatweb_restore_script() {
    if [ ! -f /opt/WhatWeb/whatweb ]; then
        return 1
    fi

    if head -1 /opt/WhatWeb/whatweb | grep -q '^#!/usr/bin/env ruby'; then
        return 0
    fi

    if [ ! -d /opt/WhatWeb/.git ]; then
        return 1
    fi

    echo -e "${YELLOW}Restoring WhatWeb script from git.${NC}"
    git -C /opt/WhatWeb checkout -- whatweb
}

f_whatweb_install_wrapper() {
    rm -f /usr/local/bin/whatweb /usr/bin/whatweb

    cat > /usr/local/bin/whatweb <<'EOF'
#!/bin/bash
RUBY=""
for candidate in \
    "$(command -v ruby 2>/dev/null)" \
    /opt/metasploit-framework/embedded/bin/ruby \
    /snap/metasploit-framework/current/opt/metasploit-framework/embedded/bin/ruby; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        RUBY=$candidate
        break
    fi
done
if [ -z "$RUBY" ]; then
    echo "[!] Ruby not found. Run Discover update to install dependencies." >&2
    exit 1
fi
exec "$RUBY" /opt/WhatWeb/whatweb "$@"
EOF
    chmod 755 /usr/local/bin/whatweb
    ln -sf /usr/local/bin/whatweb /usr/bin/whatweb
}

f_whatweb_working() {
    command -v whatweb >/dev/null 2>&1 && whatweb --version >/dev/null 2>&1
}

f_whatweb_remove_apt_package() {
    if dpkg-query -W -f='${Status}' whatweb 2>/dev/null | grep -q 'install ok installed'; then
        apt remove -y -qq whatweb
    fi
}

if [ -d /opt/WhatWeb/.git ]; then
    echo -e "${BLUE}Updating WhatWeb.${NC}"
    f_whatweb_ensure_deps
    f_whatweb_restore_script
    cd /opt/WhatWeb/ || exit
    whatweb_pull=$(git pull 2>&1) || true
    if echo "$whatweb_pull" | grep -qi 'already up to date'; then
        echo "Already up to date."
    else
        echo "Updated."
    fi
    f_whatweb_restore_script
    f_whatweb_install_wrapper
    echo
elif f_whatweb_working; then
    :
else
    echo -e "${YELLOW}Installing WhatWeb from upstream (apt package is broken).${NC}"
    f_whatweb_remove_apt_package
    f_whatweb_ensure_deps
    git clone https://github.com/urbanadventurer/WhatWeb /opt/WhatWeb
    f_whatweb_install_wrapper
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

# WPScan — WordPress security scanner (Ruby gem). Alphabetical: after Windows…, before xdotool.
# https://github.com/wpscanteam/wpscan
f_install_wpscan(){
    local pkg missing=()
    local out

    # Build deps for native gem extensions (nokogiri, etc.)
    for pkg in ruby ruby-dev build-essential libcurl4-openssl-dev libxml2-dev libxslt1-dev zlib1g-dev; do
        if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
            missing+=("$pkg")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo -e "${YELLOW}Installing WPScan build deps: ${missing[*]}${NC}"
        apt install -y "${missing[@]}" || true
        echo
    fi

    if ! command -v gem >/dev/null 2>&1; then
        echo -e "${YELLOW}gem not available; skipping WPScan install.${NC}"
        echo
        return 0
    fi

    if command -v wpscan >/dev/null 2>&1; then
        echo -e "${BLUE}Updating wpscan.${NC}"
        out=$(gem update wpscan 2>&1) || true
        if echo "$out" | grep -qiE 'Nothing to update|already|up to date|latest|Gems already up-to-date'; then
            echo "Already up to date."
        elif echo "$out" | grep -qiE 'Successfully installed|Updating|updated|Fetching'; then
            echo "$out" | grep -iE 'Successfully installed|Updating|updated|Fetching' | head -5 \
                || echo "Updated."
        else
            echo "Already up to date."
        fi
    else
        echo -e "${YELLOW}Installing wpscan.${NC}"
        # -n /usr/local/bin so the binary is on PATH without gem env setup
        if ! gem install -n /usr/local/bin wpscan; then
            gem install wpscan || {
                echo -e "${YELLOW}WPScan gem install failed.${NC}"
                echo
                return 0
            }
        fi
    fi

    # Local DB refresh (quiet when already current)
    if command -v wpscan >/dev/null 2>&1; then
        wpscan --update >/dev/null 2>&1 || true
    fi
    echo
}
f_install_wpscan
unset -f f_install_wpscan

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

# Register discover-cve: handler so Active report Top CVE links open
# NVD + Rapid7 + Tenable via Firefox CLI (same method as recon/domain.sh).
f_install_discover_cve_handler(){
    local apps_dir="$USER_HOME/.local/share/applications"
    local desktop="$apps_dir/discover-cve.desktop"
    local mimeapps="$USER_HOME/.config/mimeapps.list"
    local opener="$DISCOVER_ROOT/misc/open-cve-tabs.sh"
    local owner="${SUDO_USER:-$USER}"

    [ -x "$opener" ] || chmod +x "$opener" 2>/dev/null || true
    [ -f "$opener" ] || return 0

    mkdir -p "$apps_dir" "$USER_HOME/.config"
    cat > "$desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Discover CVE Tabs
Comment=Open NVD, Rapid7, Tenable, Exploit-DB, and GitHub for a CVE (Discover)
Exec=$opener %u
Terminal=false
Categories=Network;Security;
MimeType=x-scheme-handler/discover-cve;
NoDisplay=true
EOF

    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER:" "$desktop" 2>/dev/null || true
    fi

    if [ -f "$mimeapps" ]; then
        if grep -q 'x-scheme-handler/discover-cve=' "$mimeapps" 2>/dev/null; then
            sed -i 's|x-scheme-handler/discover-cve=.*|x-scheme-handler/discover-cve=discover-cve.desktop|' "$mimeapps"
        elif grep -q '^\[Default Applications\]' "$mimeapps"; then
            sed -i '/^\[Default Applications\]/a x-scheme-handler/discover-cve=discover-cve.desktop' "$mimeapps"
        else
            printf '\n[Default Applications]\nx-scheme-handler/discover-cve=discover-cve.desktop\n' >> "$mimeapps"
        fi
    else
        printf '[Default Applications]\nx-scheme-handler/discover-cve=discover-cve.desktop\n' > "$mimeapps"
    fi

    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER:" "$mimeapps" 2>/dev/null || true
        sudo -u "$SUDO_USER" xdg-mime default discover-cve.desktop x-scheme-handler/discover-cve >/dev/null 2>&1 || true
        sudo -u "$SUDO_USER" update-desktop-database "$apps_dir" >/dev/null 2>&1 || true
    else
        xdg-mime default discover-cve.desktop x-scheme-handler/discover-cve >/dev/null 2>&1 || true
        update-desktop-database "$apps_dir" >/dev/null 2>&1 || true
    fi

    unset owner
}

f_install_discover_cve_handler

# discover-scan: — operator host scans (nikto/nuclei/ffuf) from filtered Subdomains.
f_install_discover_scan_handler(){
    local apps_dir="$USER_HOME/.local/share/applications"
    local desktop="$apps_dir/discover-scan.desktop"
    local mimeapps="$USER_HOME/.config/mimeapps.list"
    local opener="$DISCOVER_ROOT/misc/discover-scan-handler.sh"

    [ -x "$opener" ] || chmod +x "$opener" 2>/dev/null || true
    [ -f "$opener" ] || return 0
    chmod +x "$DISCOVER_ROOT/misc/run-host-scan.sh" 2>/dev/null || true

    mkdir -p "$apps_dir" "$USER_HOME/.config"
    cat > "$desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Discover Host Scan
Comment=Run nuclei/droopescan/wpscan/nikto/ffuf from Discover reports (operator)
Exec=$opener %u
Terminal=true
Categories=Network;Security;
MimeType=x-scheme-handler/discover-scan;
NoDisplay=true
EOF

    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER:" "$desktop" 2>/dev/null || true
    fi

    if [ -f "$mimeapps" ]; then
        if grep -q 'x-scheme-handler/discover-scan=' "$mimeapps" 2>/dev/null; then
            sed -i 's|x-scheme-handler/discover-scan=.*|x-scheme-handler/discover-scan=discover-scan.desktop|' "$mimeapps"
        elif grep -q '^\[Default Applications\]' "$mimeapps"; then
            sed -i '/^\[Default Applications\]/a x-scheme-handler/discover-scan=discover-scan.desktop' "$mimeapps"
        else
            printf '\n[Default Applications]\nx-scheme-handler/discover-scan=discover-scan.desktop\n' >> "$mimeapps"
        fi
    else
        printf '[Default Applications]\nx-scheme-handler/discover-scan=discover-scan.desktop\n' > "$mimeapps"
    fi

    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER:" "$mimeapps" 2>/dev/null || true
        sudo -u "$SUDO_USER" xdg-mime default discover-scan.desktop x-scheme-handler/discover-scan >/dev/null 2>&1 || true
        sudo -u "$SUDO_USER" update-desktop-database "$apps_dir" >/dev/null 2>&1 || true
    else
        xdg-mime default discover-scan.desktop x-scheme-handler/discover-scan >/dev/null 2>&1 || true
        update-desktop-database "$apps_dir" >/dev/null 2>&1 || true
    fi
}

f_install_discover_scan_handler

# discover-ffuf: — open each ffuf finding URL in Firefox from Audit / Subdomains.
f_install_discover_ffuf_handler(){
    local apps_dir="$USER_HOME/.local/share/applications"
    local desktop="$apps_dir/discover-ffuf.desktop"
    local mimeapps="$USER_HOME/.config/mimeapps.list"
    local opener="$DISCOVER_ROOT/misc/open-ffuf-tabs.sh"

    [ -x "$opener" ] || chmod +x "$opener" 2>/dev/null || true
    [ -f "$opener" ] || return 0

    mkdir -p "$apps_dir" "$USER_HOME/.config"
    cat > "$desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Discover ffuf Tabs
Comment=Open each ffuf finding URL in Firefox (Discover)
Exec=$opener %u
Terminal=false
Categories=Network;Security;
MimeType=x-scheme-handler/discover-ffuf;
NoDisplay=true
EOF

    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER:" "$desktop" 2>/dev/null || true
    fi

    if [ -f "$mimeapps" ]; then
        if grep -q 'x-scheme-handler/discover-ffuf=' "$mimeapps" 2>/dev/null; then
            sed -i 's|x-scheme-handler/discover-ffuf=.*|x-scheme-handler/discover-ffuf=discover-ffuf.desktop|' "$mimeapps"
        elif grep -q '^\[Default Applications\]' "$mimeapps"; then
            sed -i '/^\[Default Applications\]/a x-scheme-handler/discover-ffuf=discover-ffuf.desktop' "$mimeapps"
        else
            printf '\n[Default Applications]\nx-scheme-handler/discover-ffuf=discover-ffuf.desktop\n' >> "$mimeapps"
        fi
    else
        printf '[Default Applications]\nx-scheme-handler/discover-ffuf=discover-ffuf.desktop\n' > "$mimeapps"
    fi

    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER:" "$mimeapps" 2>/dev/null || true
        sudo -u "$SUDO_USER" xdg-mime default discover-ffuf.desktop x-scheme-handler/discover-ffuf >/dev/null 2>&1 || true
        sudo -u "$SUDO_USER" update-desktop-database "$apps_dir" >/dev/null 2>&1 || true
    else
        xdg-mime default discover-ffuf.desktop x-scheme-handler/discover-ffuf >/dev/null 2>&1 || true
        update-desktop-database "$apps_dir" >/dev/null 2>&1 || true
    fi
}

f_install_discover_ffuf_handler

# Delete folder if it is empty
if [ -d "$USER_HOME/data/" ] && [ -z "$(ls -A "$USER_HOME/data/" 2>/dev/null)" ]; then
    rm -rf "$USER_HOME/data/"
fi

if command -v snap &> /dev/null; then
    echo -e "${BLUE}Refreshing snaps.${NC}"
    snap refresh 2>/dev/null || true
    echo
fi

echo -e "${BLUE}Updating locate database.${NC}"
updatedb
echo

exit
