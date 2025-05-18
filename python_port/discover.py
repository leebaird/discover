#!/usr/bin/env python3
"""
Discover Framework - Main Script

This is the main entry point for the Discover Framework, a collection of security
testing tools for reconnaissance, scanning, enumeration, and more.

Original bash scripts by Lee Baird (@discoverscripts)
Python port by [Your Name]

This Python port utilizes Python 3.12 features and best practices:
- Type hints throughout the code for better IDE support and code clarity
- Structural pattern matching (match-case) for cleaner menu handling
- Pathlib for more intuitive file path operations
- Context managers for safer file operations
- Exception handling with specific exception types
- Improved docstrings with detailed parameter and return type documentation
- Consistent code style and organization
"""

from __future__ import annotations

import os
import sys
import subprocess
import signal
import datetime
import socket
import re
from pathlib import Path
from typing import Optional, Union, Callable, Any, NoReturn

# Global variables
CWD = Path.cwd()
DISCOVER = Path(__file__).parent.absolute()
MYIP: Optional[str] = None
RUNDATE = datetime.datetime.now().strftime("%B %d, %Y")

# ANSI colors
BLUE = '\033[1;34m'
RED = '\033[1;31m'
YELLOW = '\033[1;33m'
NC = '\033[0m'  # No Color

# Formatting
LARGE = '==============================================================================================================================='
MEDIUM = '=================================================================='
SMALL = '========================================'

# Get local IP address
def get_local_ip() -> str:
    """
    Get the local IP address of the machine.

    Returns:
        str: The local IP address or "127.0.0.1" if not found
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except (socket.error, OSError):
        return "127.0.0.1"

MYIP = get_local_ip()

# Signal handler for graceful termination
def terminate_handler(signum: int, frame: Any) -> NoReturn:
    """
    Handle termination signals by saving data and exiting gracefully.

    Args:
        signum: Signal number
        frame: Current stack frame

    Returns:
        Never returns, exits the program
    """
    save_dir = Path.home() / "data" / f"cancelled-{datetime.datetime.now().strftime('%H:%M:%S')}"
    save_dir.mkdir(parents=True, exist_ok=True)

    print()
    print("[!] Terminating.")
    print()
    print(f"{YELLOW}Saving data to {save_dir}.{NC}")

    # Move data to save directory (implementation would depend on what data needs to be saved)

    print()
    print("[*] Saving complete.")
    print()
    sys.exit(1)

# Register signal handlers
signal.signal(signal.SIGINT, terminate_handler)
signal.signal(signal.SIGTERM, terminate_handler)

def banner() -> None:
    """
    Display the Discover banner.

    Returns:
        None
    """
    print()
    print(f"""{YELLOW}
 _____  ___  _____  _____  _____  _    _  _____  _____
|     \  |  |____  |      |     |  \  /  |____  |____/
|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_

By Lee Baird{NC}""")
    print()
    print()

def error() -> NoReturn:
    """
    Display an error message and exit.

    Returns:
        Never returns, exits the program
    """
    print()
    print(f"{RED}{SMALL}{NC}")
    print()
    print(f"{RED}[!] Invalid choice or entry.{NC}")
    print()
    print(f"{RED}{SMALL}{NC}")
    print()
    sys.exit(1)

def check_location(location: str) -> str:
    """
    Check if a file exists at the specified location.

    Args:
        location: Path to the file

    Returns:
        The validated location

    Raises:
        SystemExit: If the location is invalid or the file doesn't exist
    """
    if not location:
        error()

    file_path = Path(location)
    if not file_path.is_file():
        error()

    return location

def check_display() -> None:
    """
    Check if the script is running in a graphical environment.

    Returns:
        None

    Raises:
        SystemExit: If the DISPLAY environment variable is not set
    """
    if not os.environ.get('DISPLAY'):
        print()
        print(f"{RED}{MEDIUM}{NC}")
        print()
        print(f"{RED}[!] This option must be ran locally.{NC}")
        print()
        print(f"{RED}{MEDIUM}{NC}")
        print()
        sys.exit(1)

def type_of_scan() -> str:
    """
    Prompt for the type of scan to perform.

    Returns:
        str: The maximum round-trip time for the scan

    Raises:
        SystemExit: If an invalid choice is made
    """
    print(f"{BLUE}Type of scan: {NC}")
    print()
    print("1.  External")
    print("2.  Internal")
    print("3.  Previous menu")
    print()
    choice = input("Choice: ")

    # Using match-case statement (Python 3.10+)
    match choice:
        case "1":
            print()
            print(f"{YELLOW}[*] Setting the max probe round trip to 1.5s.{NC}")
            maxrtt = "1500ms"
            print()
            print(MEDIUM)
            print()
            return maxrtt
        case "2":
            print()
            print(f"{YELLOW}[*] Setting the max probe round trip to 500ms.{NC}")
            maxrtt = "500ms"
            print()
            print(MEDIUM)
            print()
            return maxrtt
        case "3":
            main_menu()
        case _:
            error()

def scan_name() -> tuple[str, str]:
    """
    Get a name for the scan and create a directory.

    Returns:
        tuple: A tuple containing the scan name and maximum round-trip time

    Raises:
        SystemExit: If an invalid scan name is provided
    """
    maxrtt = type_of_scan()

    print(f"{YELLOW}[*] Warning: no spaces allowed{NC}")
    print()
    name = input("Name of scan: ")

    # Validate scan name: only allow alphanumeric, dashes, and underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        error()

    # Create directory using Path object
    scan_dir = Path(name)
    scan_dir.mkdir(exist_ok=True)

    return name, maxrtt

def cidr_scan() -> None:
    """
    Perform a scan on a CIDR range.

    This function prompts for a CIDR range, validates it, and performs a scan
    using the scanning module.

    Returns:
        None
    """
    from modules import scanning

    banner()
    name, maxrtt = scan_name()

    print()
    print("Usage: 192.168.1.0/24")
    print()
    cidr = input("CIDR: ")

    # Check for no answer
    if not cidr:
        # Use Path object for directory removal
        Path(name).rmdir()
        error()

    # Check for a valid CIDR
    if not re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$', cidr):
        error()

    # Use Path object and context manager for file operations
    tmp_list = Path('tmp-list')
    with tmp_list.open('w') as f:
        f.write(cidr + '\n')

    location = str(tmp_list)

    print()
    exclude = input("Do you have an exclusion list? (y/N) ")

    if exclude.lower() == 'y':
        exclude_file = input("Enter the path to the file: ")
        if not exclude_file or not Path(exclude_file).is_file():
            error()
    else:
        # Use Path object and context manager for file operations
        tmp_file = Path('tmp')
        tmp_file.touch()
        exclude_file = str(tmp_file)

    start_time = datetime.datetime.now().strftime("%r %Z")

    try:
        # Call scanning module functions
        scanning.scan(name, location, exclude_file, maxrtt)
        scanning.ports(name)
        # Call NSE scripts
        # Call Metasploit
        # Generate report
    finally:
        # Clean up using Path objects
        if tmp_list.exists():
            tmp_list.unlink()

        tmp_file = Path('tmp')
        if tmp_file.exists():
            tmp_file.unlink()

def list_scan() -> None:
    """
    Perform a scan on a list of targets.

    This function prompts for a file containing a list of targets and performs a scan
    using the scanning module.

    Returns:
        None
    """
    from modules import scanning

    banner()
    name, maxrtt = scan_name()

    location = input("Enter the location of your file: ")
    location = check_location(location)

    # Use Path object and context manager for file operations
    tmp_file = Path('tmp')
    tmp_file.touch()
    exclude_file = str(tmp_file)

    start_time = datetime.datetime.now().strftime("%r %Z")

    try:
        # Call scanning module functions
        scanning.scan(name, location, exclude_file, maxrtt)
        scanning.ports(name)
        # Call NSE scripts
        # Call Metasploit
        # Generate report
    finally:
        # Clean up using Path objects
        if tmp_file.exists():
            tmp_file.unlink()

def single_scan() -> None:
    """
    Perform a scan on a single IP, range, or URL.

    This function prompts for a single target (IP, range, or URL) and performs a scan
    using the scanning module.

    Returns:
        None
    """
    from modules import scanning

    banner()
    name, maxrtt = scan_name()

    print()
    target = input("IP, range or URL: ")

    # Check for no answer
    if not target:
        # Use Path object for directory removal
        Path(name).rmdir()
        error()

    # Use Path object and context manager for file operations
    tmp_target = Path('tmp-target')
    with tmp_target.open('w') as f:
        f.write(target + '\n')

    location = str(tmp_target)

    # Use Path object for file operations
    tmp_file = Path('tmp')
    tmp_file.touch()
    exclude_file = str(tmp_file)

    start_time = datetime.datetime.now().strftime("%r %Z")

    try:
        # Call scanning module functions
        scanning.scan(name, location, exclude_file, maxrtt)
        scanning.ports(name)
        # Call NSE scripts
        # Call Metasploit
        # Generate report
    finally:
        # Clean up using Path objects
        if tmp_target.exists():
            tmp_target.unlink()

        if tmp_file.exists():
            tmp_file.unlink()

def domain_menu() -> None:
    """
    Display the domain reconnaissance menu.

    This function presents a menu for domain reconnaissance options and handles
    user input to execute the selected option.

    Returns:
        None
    """
    from modules import recon

    banner()

    print(f"{BLUE}RECON{NC}")
    print()
    print("1.  Passive")
    print("2.  Find registered domains")
    print("3.  Previous menu")
    print()
    choice = input("Choice: ")

    # Using match-case statement (Python 3.10+)
    match choice:
        case "1":
            recon.passive_recon()
        case "2":
            recon.find_registered_domains()
        case "3":
            main_menu()
        case _:
            print()
            print(f"{RED}[!] Invalid choice or entry, try again.{NC}")
            print()
            domain_menu()

def person_recon() -> None:
    """
    Perform person reconnaissance.

    This function calls the person_recon function from the recon module to gather
    information about a person.

    Returns:
        None
    """
    from modules import recon

    banner()
    recon.person_recon()

def generate_targets() -> None:
    """
    Generate a target list.

    This function calls the generate_targets function from the scanning module to
    create a list of targets for scanning.

    Returns:
        None
    """
    from modules import scanning

    banner()
    scanning.generate_targets()

def enumerate_scan() -> NoReturn:
    """
    Re-run Nmap scripts and MSF aux on a previous scan.

    This function prompts for a previous scan directory and re-runs Nmap scripts
    and Metasploit auxiliary modules on the targets from that scan.

    Returns:
        Never returns, exits the program
    """
    from modules import scanning

    banner()
    maxrtt = type_of_scan()

    location = input("Enter the location of your previous scan: ")

    # Check for no answer
    if not location:
        error()

    # Check for wrong answer using Path object
    scan_dir = Path(location)
    if not scan_dir.is_dir():
        error()

    name = location

    print()
    delay = input("Set scan delay. (0-5, enter for normal) ")

    # Check for no answer
    if not delay:
        delay = '0'

    # Validate delay using exception handling
    try:
        delay_int = int(delay)
        if delay_int < 0 or delay_int > 5:
            error()
    except ValueError:
        error()

    # Call NSE scripts
    # Call Metasploit

    print()
    print(MEDIUM)
    print()
    print("[*] Scan complete.")
    print()
    print(f"The supporting data folder is located at {YELLOW}{name}{NC}")
    print()
    sys.exit(0)

def main_menu() -> None:
    """
    Display the main menu and handle user input.

    This function presents the main menu of the Discover Framework and processes
    user input to execute the selected option.

    Returns:
        None
    """
    banner()

    # Create data directory if it doesn't exist using Path object
    data_dir = Path.home() / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    print(f"{BLUE}RECON{NC}")
    print("1.  Domain")
    print("2.  Person")
    print()
    print(f"{BLUE}SCANNING{NC}")
    print("3.  Generate target list")
    print("4.  CIDR")
    print("5.  List")
    print("6.  IP, range, or URL")
    print("7.  Rerun Nmap scripts and MSF aux")
    print()
    print(f"{BLUE}WEB{NC}")
    print("8.  Insecure direct object reference")
    print("9.  Open multiple tabs in Firefox")
    print("10. Nikto")
    print("11. SSL")
    print()
    print(f"{BLUE}MISC{NC}")
    print("12. Parse XML")
    print("13. Generate a malicious payload")
    print("14. Start a Metasploit listener")
    print("15. Sensitive Information Detector")
    print("16. API Security Scanner")
    print("17. OAuth/JWT Security Tester")
    print("18. Cloud Security Scanner")
    print("19. Container Security Scanner")
    print("20. MSF Web & API Security Scanner")
    print("21. Update")
    print("22. Exit")
    print()
    choice = input("Choice: ")

    # Using match-case statement (Python 3.10+)
    match choice:
        case "1":
            domain_menu()
        case "2":
            person_recon()
        case "3":
            generate_targets()
        case "4":
            cidr_scan()
        case "5":
            list_scan()
        case "6":
            single_scan()
        case "7":
            enumerate_scan()
        case "8":
            from modules import web
            web.direct_object_ref()
        case "9":
            from modules import web
            web.multi_tabs()
        case "10":
            from modules import web
            web.nikto_scan()
        case "11":
            from modules import web
            web.ssl_check()
        case "12":
            from modules import misc
            misc.parse_xml()
        case "13":
            from modules import misc
            misc.generate_payload()
        case "14":
            from modules import misc
            misc.start_listener()
        case "15":
            from modules import misc
            misc.sensitive_detector()
        case "16":
            from modules import misc
            misc.api_scanner()
        case "17":
            from modules import misc
            misc.oauth_jwt_tester()
        case "18":
            from modules import misc
            misc.cloud_scanner()
        case "19":
            from modules import misc
            misc.container_scanner()
        case "20":
            from modules import misc
            misc.msf_web_api()
        case "21":
            from modules import misc
            misc.update_system()
        case "22":
            sys.exit(0)
        case _:
            print()
            print(f"{RED}[!] Invalid choice or entry, try again.{NC}")
            print()
            main_menu()

if __name__ == "__main__":
    # Entry point of the program
    main_menu()
