#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

DIR=$HOME/compare-sites
DIFFONLY=false
MEDIUM='=================================================================='

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo
echo -e "${YELLOW}Compare Changes to Home Pages\n\nby Lee Baird\n${NC}"

# If no arguments, print usage
if [ $# -eq 0 ]; then
    echo
    echo "Where file contains a list of URLs to be compared."
    echo "Usage: $0 [options] file"
    echo
    echo "Options:"
    echo " -c Compare versions without downloading new ones."
    echo " -o Output directory. Default: ~/compare-sites"
    echo
    exit 1
fi

# Assign FILE and FILEHASH after confirming FILE is set
FILE="$1"
FILEHASH=$(sha256sum "$FILE" | awk '{print $1}')
HDIR="$DIR/$FILEHASH"
VERSION=1

ts2date(){
    date -d "1970-01-01 $1 sec"
}

while getopts "o:c" OPTION; do
    case $OPTION in
        o) DIR="$OPTARG" ;;
        c) DIFFONLY=true ;;
        *) usage && exit ;;
    esac
done

shift $((OPTIND - 1))

if [ ! -f "$FILE" ]; then
    echo
    echo "$MEDIUM"
    echo
    echo -e "${RED}[!] Invalid choice or entry.${NC}"
    echo
    exit 1
fi

# Ensure the main directory and hash directory exist
if [ ! -d "$DIR" ]; then
    mkdir -p "$DIR"
fi

if [ ! -d "$HDIR" ]; then
    mkdir -p "$HDIR"
fi

while [ -f "$HDIR/$VERSION" ]; do
    VERSION=$((VERSION + 1))
done

if ! "$DIFFONLY"; then
    date +%s > "$HDIR/$VERSION"
    echo
    echo
    echo "Downloading:"

    while IFS= read -r URL; do
        HASH=$(echo -n "$URL" | sha256sum | tr -d " -")
        echo "[*] $URL"
        if ! wget -q "$URL" -O "$HDIR/$URL-$HASH-$VERSION"; then
            echo
            echo -e "${RED}[!] Failed to download $URL${NC}"
            echo
            exit 1
        fi
    done < "$FILE"

    echo
    echo "$MEDIUM"
else
    VERSION=$((VERSION - 1))
fi

if [ "$VERSION" -gt 1 ]; then
    echo
    echo "Versions:"

    for ((i=1; i<=VERSION; i++)); do
        echo "$i - $(ts2date "$(cat "$HDIR/$i")")"
    done

    echo
    echo -n "Base version: "
    read -r A
    echo -n "Compare with: "
    read -r B

    [ -z "$A" ] && A="1"
    [ -z "$B" ] && B="$VERSION"

    # Check if selected versions are valid
    if [ "$A" -gt "$VERSION" ] || [ "$B" -gt "$VERSION" ]; then
        echo
        echo -e "${RED}[!] Selected versions exceed the available versions.${NC}"
        echo
        exit 1
    fi

    while IFS= read -r URL; do
        echo
        echo "$MEDIUM"
        echo
        echo -e "\e[1;34m$URL\e[0m"
        HASH=$(echo -n "$URL" | sha256sum | tr -d " -")
        diff "$HDIR/$URL-$HASH-$A" "$HDIR/$URL-$HASH-$B" | grep '<iframe src='
    done < "$FILE"
fi
