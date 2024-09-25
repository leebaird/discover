#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

clear

DIR=$HOME/compare-sites
DIFFONLY=false
medium='=================================================================='

usage(){
echo
echo "Compare changes to home pages."
echo
echo
echo "Where file contains a list of URLs to be compared."
echo "Usage: $0 [options] file"
echo
echo "Options:"
echo " -c Compare versions without downloading new ones."
echo " -o Output directory. Default: ~/compare-sites"
echo
echo
}

ts2date(){
date -d "1970-01-01 $1 sec"
}

while getopts "o:c" OPTION; do
    case $OPTION in
        o) DIR="$OPTARG";;
        c) DIFFONLY=true;;
        *) usage && exit;;
    esac
done

shift $((OPTIND - 1))

# Check if a file is passed, if not, show usage
if [ $# -eq 0 ]; then
    echo
    usage
    echo
    exit 1
fi

FILE="$1"

if [ ! -f "$FILE" ]; then
    echo
    echo $medium
    echo
    echo "[!] File does not exist."
    echo
    exit 1
fi

if [ ! -d "$DIR" ]; then
    mkdir -p "$DIR"
fi

FILEHASH=$(sha256sum "$FILE" | awk '{print $1}')
HDIR="$DIR/$FILEHASH"
VERSION=1

while [ -f "$HDIR/$VERSION" ]; do
    VERSION=$((VERSION + 1))
done

if ! $DIFFONLY; then
    date +%s > "$HDIR/$VERSION"
    echo
    echo
    echo "Downloading:"

    while IFS= read -r URL; do
        HASH=$(echo -n "$URL" | sha256sum | tr -d " -")
        echo "[*] $URL"
        if ! wget -q "$URL" -O "$HDIR/$URL-$HASH-$VERSION"; then
            echo
            echo "[!] Failed to download $URL"
            echo
            exit 1
        fi
    done < "$FILE"

    echo
    echo $medium
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
    [ -z "$B" ] && B=$VERSION

    # Check if selected versions are valid
    if [ "$A" -gt "$VERSION" ] || [ "$B" -gt "$VERSION" ]; then
        echo
        echo "[!] Error: Selected versions exceed the available versions."
        echo
        exit 1
    fi

    while IFS= read -r URL; do
        echo
        echo $medium
        echo
        echo -e "\e[1;34m$URL\e[0m"
        HASH=$(echo -n "$URL" | sha256sum | tr -d " -")
        diff "$HDIR/$URL-$HASH-$A" "$HDIR/$URL-$HASH-$B" | grep '<iframe src='
    done < "$FILE"
fi
