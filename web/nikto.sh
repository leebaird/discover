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

# Prefer GitHub install from Discover Update.
f_nikto_bin(){
    if [ -x /usr/local/bin/nikto ]; then
        echo /usr/local/bin/nikto
        return 0
    fi
    if [ -f /opt/nikto/program/nikto.pl ]; then
        echo /opt/nikto/program/nikto.pl
        return 0
    fi
    command -v nikto 2>/dev/null || true
}

NIKTO_BIN=$(f_nikto_bin)
if [ -z "$NIKTO_BIN" ]; then
    echo
    echo -e "[!] Nikto not found. Run Discover ${YELLOW}Update${NC} (installs sullo/nikto from GitHub)."
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

# Per-run Discover config (PROMPTS/UPDATES/no RFI); UA also via -useragent.
NIKTO_CONF="$HOME/data/nikto-discover.conf"
mkdir -p "$HOME/data"
python3 - "$NIKTO_CONF" "$NIKTO_UA" <<'PY'
import sys
from pathlib import Path

out = Path(sys.argv[1])
ua = sys.argv[2]
base = ""
for candidate in (
    Path("/opt/nikto/program/nikto.conf"),
    Path("/opt/nikto/program/nikto.conf.default"),
    Path("/etc/nikto/config.txt"),
    Path("/etc/nikto.conf"),
):
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
comment_keys = {"RFIURL"}
seen: set[str] = set()
new_lines: list[str] = []
for raw in base.splitlines() if base else []:
    stripped = raw.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        key = stripped.split("=", 1)[0].strip()
        if key in comment_keys:
            new_lines.append("#" + raw if not raw.lstrip().startswith("#") else raw)
            continue
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
echo -e "Binary:     ${YELLOW}$NIKTO_BIN${NC}"
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
            $XDOTOOL type "$NIKTO_BIN -config $NIKTO_CONF -host $LINE -port $PORT -useragent '$NIKTO_UA' -nointeractive -nocheck -maxtime 15m -Format htm -output $HOME/data/nikto-$PORT/$LINE.htm ; exit"
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
            $XDOTOOL type "$NIKTO_BIN -config $NIKTO_CONF -host $HOST -port $PORT -useragent '$NIKTO_UA' -nointeractive -nocheck -maxtime 15m -Format htm -output $HOME/data/nikto/$HOST-$PORT.htm ; exit"
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
        f_return_main
        ;;
esac
