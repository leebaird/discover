#!/usr/bin/env bash

# by ibrahimsql - Open Redirect Scanner Wrapper
# Discover framework compatibility module

# Global variables from discover.sh
CWD=$(pwd)
# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MYIP=$(ip addr | grep 'global' | grep -Eiv '(:|docker)' | cut -d '/' -f1 | awk '{print $2}')
RUNDATE=$(date +%B' '%d,' '%Y)

LARGE='==============================================================================================================================='
MEDIUM='=================================================================='
SMALL='========================================'

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
NC='\033[0m'

f_banner(){
    echo
    echo -e "${YELLOW}
  _____  ______ _______ ______      ______  _______ _____   _ ______  _______ ______ _______   
 / ___ \(_____ (_______)  ___ \    (_____ \(_______|____ \ (_|_____ \(_______) _____|_______)  
| |   | |_____) )____  | |   | |___ _____) )_____   _   \ \ _ _____) )_____ | /      _         
| |   | |  ____/  ___) | |   | (___|_____ (|  ___) | |   | | (_____ (|  ___)| |     | |        
| |___| | |    | |_____| |   | |         | | |_____| |__/ /| |     | | |____| \_____| |_____   
 \_____/|_|    |_______)_|   |_|         |_|_______)_____/ |_|     |_|_______)______)\______) 

              
By ibrahimsql & Lee Baird ${NC}"
    echo
    echo
}

f_error(){
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] Invalid choice or entry.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    exit 1
}

f_single_target() {
    echo -n "Enter the target URL or domain: "
    read -r TARGET
    
    # Check for no answer
    if [ -z "$TARGET" ]; then
        f_error
    fi
    
    # Make sure the target has a schema
    if [[ ! $TARGET =~ ^https?:// ]]; then
        # Ask if HTTP or HTTPS should be used
        echo
        echo -n "Use HTTPS? (y/n): "
        read -r USE_HTTPS
        
        if [[ $USE_HTTPS =~ ^[Yy]$ ]]; then
            TARGET="https://$TARGET"
        else
            TARGET="http://$TARGET"
        fi
    fi
    
    # Run the Python script
    echo
    echo -e "[*] Running Open Redirect Scanner on: ${BLUE}$TARGET${NC}"
    echo
    python3 "$SCRIPT_DIR"/openredirect-scanner.py -u "$TARGET"
}

f_domain_target() {
    echo -n "Enter the domain name: "
    read -r DOMAIN
    
    # Check for no answer
    if [ -z "$DOMAIN" ]; then
        f_error
    fi
    
    # Run the Python script
    echo
    echo -e "[*] Running Open Redirect Scanner on domain: ${BLUE}$DOMAIN${NC}"
    echo
    python3 "$SCRIPT_DIR"/openredirect-scanner.py -d "$DOMAIN"
}

f_file_target() {
    echo -n "Enter the path to the file containing URLs: "
    read -r FILE_PATH
    
    # Check for no answer
    if [ -z "$FILE_PATH" ]; then
        f_error
    fi
    
    # Check if file exists
    if [ ! -f "$FILE_PATH" ]; then
        echo
        echo -e "${RED}[!] File not found: $FILE_PATH${NC}"
        f_error
    fi
    
    # Ask for output format
    echo
    echo "Select output format:"
    echo "1. All formats (txt, json, csv)"
    echo "2. Text only"
    echo "3. JSON only"
    echo "4. CSV only"
    echo
    echo -n "Choice (1-4): "
    read -r FORMAT_CHOICE
    
    case "$FORMAT_CHOICE" in
        1) FORMAT="all" ;;
        2) FORMAT="txt" ;;
        3) FORMAT="json" ;;
        4) FORMAT="csv" ;;
        *) FORMAT="all" ;;
    esac
    
    # Run the Python script
    echo
    echo -e "[*] Running Open Redirect Scanner on URLs from file: ${BLUE}$FILE_PATH${NC}"
    echo -e "[*] Output format: ${BLUE}$FORMAT${NC}"
    echo
    python3 "$SCRIPT_DIR"/openredirect-scanner.py -f "$FILE_PATH" -o "$FORMAT"
}

f_advanced_options() {
    echo -n "Enter the target URL or domain: "
    read -r TARGET
    
    # Check for no answer
    if [ -z "$TARGET" ]; then
        f_error
    fi
    
    # Make sure the target has a schema
    if [[ ! $TARGET =~ ^https?:// ]]; then
        echo
        echo -n "Use HTTPS? (y/n): "
        read -r USE_HTTPS
        
        if [[ $USE_HTTPS =~ ^[Yy]$ ]]; then
            TARGET="https://$TARGET"
        else
            TARGET="http://$TARGET"
        fi
    fi
    
    # Ask for custom parameter wordlist
    echo
    echo -n "Enter path to custom parameter wordlist (leave empty to use default): "
    read -r WORDLIST
    
    # Ask for output format
    echo
    echo "Select output format:"
    echo "1. All formats (txt, json, csv)"
    echo "2. Text only"
    echo "3. JSON only"
    echo "4. CSV only"
    echo
    echo -n "Choice (1-4): "
    read -r FORMAT_CHOICE
    
    case "$FORMAT_CHOICE" in
        1) FORMAT="all" ;;
        2) FORMAT="txt" ;;
        3) FORMAT="json" ;;
        4) FORMAT="csv" ;;
        *) FORMAT="all" ;;
    esac
    
    # Build the command
    CMD="python3 $SCRIPT_DIR/openredirect-scanner.py -u $TARGET -o $FORMAT"
    
    if [ -n "$WORDLIST" ]; then
        CMD="$CMD -w $WORDLIST"
    fi
    
    # Run the Python script
    echo
    echo -e "[*] Running Open Redirect Scanner with custom options"
    echo -e "[*] Command: ${BLUE}$CMD${NC}"
    echo
    eval "$CMD"
}

f_main() {
    clear
    f_banner
    
    echo -e "${BLUE}OPEN REDIRECT SCANNER${NC}"
    echo "1. Scan a single URL"
    echo "2. Scan a domain"
    echo "3. Scan multiple URLs from a file"
    echo "4. Advanced options"
    echo "5. Exit"
    echo
    
    echo -n "Choice: "
    read -r CHOICE
    
    case "$CHOICE" in
        1)
            f_single_target
            ;;
        2)
            f_domain_target
            ;;
        3)
            f_file_target
            ;;
        4)
            f_advanced_options
            ;;
        5)
            echo
            exit 0
            ;;
        *)
            echo
            echo -e "${RED}[!] Invalid choice, try again.${NC}"
            echo
            sleep 2
            f_main
            ;;
    esac
}

# Run the script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    f_main
fi
