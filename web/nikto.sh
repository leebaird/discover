#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

trap 'pkill -f nikto; exit' INT TERM

# Check for regular user
if [ "$EUID" == 0 ]; then
    echo
    echo "[!] This option cannot be ran as root."
    echo
    exit 1
fi

if grep -q 'Nikto/@VERSION' /etc/nikto/config.txt; then
    echo
    echo -e "[!] Remove the default user agent string located at ${YELLOW}/etc/nikto/config.txt${NC}"
    echo
    exit 1
fi

if grep -q '^RFIURL=http://cirt.net/rfiinc.txt?' /etc/nikto/config.txt; then
    echo
    echo -e "[!] Comment out RFIURL checks located at ${YELLOW}/etc/nikto/config.txt${NC}"
    echo
    exit 1
fi

f_nikto_select_tool(){
    if command -v ydotool >/dev/null 2>&1 && pgrep ydotoold >/dev/null 2>&1; then
        XDOTOOL="sudo ydotool"
        ENTER="enter"
        return 0
    fi

    if command -v xdotool >/dev/null 2>&1; then
        XDOTOOL="xdotool"
        ENTER="Return"
        return 0
    fi

    echo
    if command -v ydotool >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] ydotool is installed but ydotoold is not running.${NC}"
        echo -e "${YELLOW}[!] Start the daemon (sudo ydotoold &) or install xdotool via Discover Update.${NC}"
    else
        echo -e "${YELLOW}[!] Neither xdotool nor ydotool is installed.${NC}"
        echo -e "${YELLOW}[!] Run the Update option from the main menu.${NC}"
    fi
    echo
    return 1
}

# Same Edge UA as host-scan / Update (resource/user-agent.txt or Discover export).
f_nikto_user_agent(){
    local ua=""

    if [ -n "${USER_AGENT:-}" ]; then
        printf '%s' "$USER_AGENT"
        return 0
    fi

    if declare -F f_discover_user_agent >/dev/null 2>&1; then
        ua=$(f_discover_user_agent)
    elif [ -n "${DISCOVER:-}" ] && [ -f "$DISCOVER/resource/user-agent.txt" ]; then
        ua=$(grep -v '^[[:space:]]*#' "$DISCOVER/resource/user-agent.txt" | sed '/^[[:space:]]*$/d' | head -n 1)
    elif [ -f "$(dirname "${BASH_SOURCE[0]}")/../resource/user-agent.txt" ]; then
        ua=$(grep -v '^[[:space:]]*#' "$(dirname "${BASH_SOURCE[0]}")/../resource/user-agent.txt" | sed '/^[[:space:]]*$/d' | head -n 1)
    fi

    ua="${ua#"${ua%%[![:space:]]*}"}"
    ua="${ua%"${ua##*[![:space:]]}"}"

    if [ -z "$ua" ] || [[ "$ua" != Mozilla/* ]]; then
        ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"
    fi

    printf '%s' "$ua"
}

f_nikto_complete(){
    local mode="$1"
    local port="${2:-}"

    echo
    echo "$MEDIUM"
    echo
    echo "[*] Scan complete."
    echo

    if [ "$mode" = "1" ]; then
        echo -e "New report located at ${YELLOW}$HOME/data/nikto-$port/${NC}"
    else
        echo -e "New report located at ${YELLOW}$HOME/data/nikto/${NC}"
    fi

    echo
}

clear
f_banner

f_nikto_select_tool || exit 1

NIKTO_UA=$(f_nikto_user_agent)

# Nikto 2.1.x has no CLI -useragent; set USERAGENT= in a Discover-owned config.
# Also shadow LW2 with TLS SNI (Azure ALB / modern HTTPS require it).
NIKTO_CONF="$HOME/data/nikto-discover.conf"
mkdir -p "$HOME/data"
NIKTO_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NIKTO_DISCOVER_ROOT="$(cd "$NIKTO_SCRIPT_DIR/.." && pwd)"
NIKTO_LW2_LIB="${XDG_CACHE_HOME:-$HOME/.cache}/discover/perl5"
if [ -f "$NIKTO_DISCOVER_ROOT/misc/patch-lw2-sni.py" ] && [ -f /usr/share/perl5/LW2.pm ]; then
    if [ ! -f "$NIKTO_LW2_LIB/LW2.pm" ] || [ /usr/share/perl5/LW2.pm -nt "$NIKTO_LW2_LIB/LW2.pm" ] \
        || ! grep -q 'Discover: TLS SNI' "$NIKTO_LW2_LIB/LW2.pm" 2>/dev/null; then
        python3 "$NIKTO_DISCOVER_ROOT/misc/patch-lw2-sni.py" /usr/share/perl5/LW2.pm "$NIKTO_LW2_LIB/LW2.pm" \
            || true
    fi
    if [ -f "$NIKTO_LW2_LIB/LW2.pm" ] && grep -q 'set_tlsext_host_name' "$NIKTO_LW2_LIB/LW2.pm" 2>/dev/null; then
        export PERL5LIB="${NIKTO_LW2_LIB}${PERL5LIB:+:$PERL5LIB}"
        # New xdotool tabs may not inherit this shell; prefix typed commands.
        NIKTO_ENV_PREFIX="PERL5LIB=${NIKTO_LW2_LIB}:\$PERL5LIB "
    fi
fi
NIKTO_ENV_PREFIX="${NIKTO_ENV_PREFIX:-}"
python3 - "$NIKTO_CONF" "$NIKTO_UA" <<'PY'
import sys
from pathlib import Path

out = Path(sys.argv[1])
ua = sys.argv[2]
base = ""
for candidate in (Path("/etc/nikto/config.txt"), Path("/etc/nikto.conf")):
    if candidate.is_file():
        base = candidate.read_text(encoding="utf-8", errors="replace")
        break
force = {
    "USERAGENT": ua,
    "PROMPTS": "no",
    "UPDATES": "no",
    "DEFAULTHTTPVER": "1.1",
    "CHECKMETHODS": "GET",
}
seen: set[str] = set()
new_lines: list[str] = []
for raw in base.splitlines() if base else []:
    stripped = raw.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        key = stripped.split("=", 1)[0].strip()
        if key in force:
            if key not in seen:
                new_lines.append(f"{key}={force[key]}")
                seen.add(key)
            continue
        new_lines.append(raw)
        continue
    new_lines.append(raw)
for key, value in force.items():
    if key not in seen:
        new_lines.append(f"{key}={value}")
out.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
PY

echo -e "${BLUE}Run multiple instances of Nikto in parallel.${NC}"
echo
echo -e "User-Agent: ${YELLOW}$NIKTO_UA${NC}"
echo -e "Config:     ${YELLOW}$NIKTO_CONF${NC}"
echo
echo "1.  List of IPs"
echo "2.  List of IP:port"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read -r CHOICE

case "$CHOICE" in
    1)
        f_location

        echo
        echo -n "Port (default 80): "
        read -r PORT
        echo

        if [ -z "$PORT" ]; then
            PORT=80
        fi

        if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
            f_return_main
        fi

        mkdir -p "$HOME/data/nikto-$PORT"

        while IFS= read -r LINE; do
            [ -z "$LINE" ] && continue
            $XDOTOOL key ctrl+shift+t
            $XDOTOOL type "${NIKTO_ENV_PREFIX}nikto -config $NIKTO_CONF -h $LINE -port $PORT -no404 -maxtime 15m -Format htm --output $HOME/data/nikto-$PORT/$LINE.htm ; exit"
            sleep 2
            $XDOTOOL key $ENTER
        done < "$LOCATION"

        f_nikto_complete 1 "$PORT"
        exit 0
        ;;

    2)
        f_location

        mkdir -p "$HOME/data/nikto"

        while IFS=: read -r HOST PORT; do
            [ -z "$HOST" ] || [ -z "$PORT" ] && continue
            $XDOTOOL key ctrl+shift+t
            sleep 2
            $XDOTOOL type "${NIKTO_ENV_PREFIX}nikto -config $NIKTO_CONF -h $HOST -port $PORT -no404 -maxtime 15m -Format htm --output $HOME/data/nikto/$HOST-$PORT.htm ; exit"
            sleep 2
            $XDOTOOL key $ENTER
        done < "$LOCATION"

        f_nikto_complete 2
        exit 0
        ;;

    3)
        f_return_main
        ;;

    *)
        f_invalid
        exit
        ;;
esac