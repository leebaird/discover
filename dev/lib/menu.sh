# Shared interactive menu helpers for dev scanners.
# Requires exported helpers from discover.sh: f_dev_die, f_dev_previous.

f_dev_trim(){
    local value="$1"
    value="${value//$'\r'/}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

f_dev_read_choice(){
    local __var="$1"
    local __value

    read -r __value
    __value=$(f_dev_trim "$__value")
    printf -v "$__var" '%s' "$__value"
    echo
}

f_dev_menu_validate(){
    local choice="$1"

    if [ -z "$choice" ]; then
        f_dev_die "Invalid choice or entry."
    fi
}

f_dev_read_url(){
    local __var="$1"
    local __prompt="$2"
    local __value

    echo -n "$__prompt"
    read -r __value
    __value=$(f_dev_trim "$__value")

    if [ -z "$__value" ]; then
        f_dev_die "No target URL provided."
    fi
    if [[ ! "$__value" =~ ^https?:// ]]; then
        f_dev_die "Invalid URL."
    fi

    printf -v "$__var" '%s' "$__value"
    echo
}

f_dev_read_required(){
    local __var="$1"
    local __prompt="$2"
    local __message="$3"
    local __value

    echo -n "$__prompt"
    read -r __value
    __value=$(f_dev_trim "$__value")

    if [ -z "$__value" ]; then
        f_dev_die "$__message"
    fi

    printf -v "$__var" '%s' "$__value"
    echo
}

f_dev_read_path(){
    local __var="$1"
    local __prompt="$2"
    local __message="$3"
    local __value

    echo -n "$__prompt"
    read -r __value
    __value=$(f_dev_trim "$__value")
    __value="${__value/#\~/$HOME}"

    if [ -z "$__value" ] || [ ! -e "$__value" ]; then
        f_dev_die "$__message"
    fi

    printf -v "$__var" '%s' "$__value"
    echo
}

f_dev_read_file(){
    local __var="$1"
    local __prompt="$2"
    local __message="$3"
    local __value

    echo -n "$__prompt"
    read -r __value
    __value=$(f_dev_trim "$__value")
    __value="${__value/#\~/$HOME}"

    if [ -z "$__value" ] || [ ! -f "$__value" ]; then
        f_dev_die "$__message"
    fi

    printf -v "$__var" '%s' "$__value"
    echo
}

f_dev_read_dir(){
    local __var="$1"
    local __prompt="$2"
    local __message="$3"
    local __value

    echo -n "$__prompt"
    read -r __value
    __value=$(f_dev_trim "$__value")
    __value="${__value/#\~/$HOME}"

    if [ -z "$__value" ] || [ ! -d "$__value" ]; then
        f_dev_die "$__message"
    fi

    printf -v "$__var" '%s' "$__value"
    echo
}

f_dev_read_scan_mode(){
    local __var="$1"
    local __choice

    echo
    echo -n "Choice: "
    f_dev_read_choice __choice

    case "$__choice" in
        1) printf -v "$__var" '%s' "quick" ;;
        2) printf -v "$__var" '%s' "full" ;;
        *) f_dev_die "Invalid choice or entry." ;;
    esac
}

f_dev_read_optional(){
    local __var="$1"
    local __prompt="$2"
    local __value

    echo -n "$__prompt"
    read -r __value
    __value=$(f_dev_trim "$__value")
    __value="${__value/#\~/$HOME}"
    printf -v "$__var" '%s' "$__value"
    echo
}

f_dev_read_jwt(){
    local __var="$1"
    local __value

    echo -n "Enter JWT token: "
    read -r __value
    __value=$(f_dev_trim "$__value")

    if [ -z "$__value" ]; then
        f_dev_die "No JWT token provided."
    fi
    if [[ ! "$__value" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
        f_dev_die "Invalid JWT."
    fi

    printf -v "$__var" '%s' "$__value"
    echo
}

f_dev_read_optional_jwt(){
    local __var="$1"
    local __prompt="$2"
    local __value

    echo -n "$__prompt"
    read -r __value
    __value=$(f_dev_trim "$__value")

    if [ -n "$__value" ] && [[ ! "$__value" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
        f_dev_die "Invalid JWT."
    fi

    printf -v "$__var" '%s' "$__value"
    echo
}