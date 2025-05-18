"""
Discover Framework - Scanning Module

This module contains functions for scanning targets, including CIDR ranges,
lists of targets, and single IPs or URLs.
"""

import ipaddress
import os
import re
import subprocess

# Global variables
SIP = 'sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'


def scan(name, location, exclude_file, maxrtt, vdetection=False, full_scan=False, delay=0, run_msf=False):
    """
    Perform a scan on the targets specified in the location file.

    Args:
        name (str): Name of the scan (directory where results will be stored)
        location (str): Path to the file containing targets
        exclude_file (str): Path to the file containing exclusions
        maxrtt (str): Maximum round-trip time for packets
        vdetection (bool): Whether to perform version detection
        full_scan (bool): Whether to perform a full TCP port scan
        delay (int): Scan delay (0-5)
        run_msf (bool): Whether to run matching Metasploit auxiliaries
    """
    # Define port ranges
    custom_tcp = '1-1040,1050,1080,1099,1158,1344,1352,1414,1433,1521,1720,1723,1883,1911,1962,2049,2202,2375,2628,2947,3000,3031,3050,3260,3306,3310,3389,3500,3632,4369,4786,5000,5019,5040,5060,5432,5560,5631,5632,5666,5672,5850,5900,5920,5984,5985,6000,6001,6002,6003,6004,6005,6379,6666,7210,7634,7777,8000,8009,8080,8081,8091,8140,8222,8332,8333,8400,8443,8834,9000,9084,9100,9160,9600,9999,10000,10443,10809,11211,12000,12345,13364,19150,20256,27017,28784,30718,35871,37777,46824,49152,50000,50030,50060,50070,50075,50090,60010,60030'
    full_tcp = '1-65535'
    udp_ports = '53,67,123,137,161,407,500,523,623,1434,1604,1900,2302,2362,3478,3671,4800,5353,5683,6481,17185,31337,44818,47808'

    # Determine TCP port range
    tcp_ports = full_tcp if full_scan else custom_tcp

    # Determine scan type
    scan_type = 'sTV' if vdetection else 'sT'
    udp_type = 'sUV' if vdetection else 'sU'

    # Run nmap scan
    cmd = [
        'sudo',
        'nmap',
        '--randomize-hosts',
        '-iL',
        location,
        '--excludefile',
        exclude_file,
        '--privileged',
        '-n',
        '-PE',
        '-PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
        '-PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,49152',
        f'-{scan_type}',
        f'-{udp_type}',
        '-p',
        f'T:{tcp_ports},U:{udp_ports}',
        '-O',
        '--osscan-guess',
        '--max-os-tries',
        '1',
        '--max-retries',
        '2',
        '--min-rtt-timeout',
        '100ms',
        '--max-rtt-timeout',
        maxrtt,
        '--initial-rtt-timeout',
        '500ms',
        '--defeat-rst-ratelimit',
        '--min-rate',
        '450',
        '--max-rate',
        '15000',
        '--open',
        '--stats-every',
        '30s',
        '--scan-delay',
        str(delay),
        '-oA',
        f'{name}/nmap',
    ]

    print()
    print('Running Nmap scan...')
    subprocess.run(cmd)

    # Check if any hosts were found
    with open(f'{name}/nmap.nmap') as f:
        if '(0 hosts up)' in f.read():
            # Clean up and exit
            import shutil

            shutil.rmtree(name)
            if os.path.exists('tmp'):
                os.remove('tmp')
            if os.path.exists('tmp-list'):
                os.remove('tmp-list')
            if os.path.exists('tmp-target'):
                os.remove('tmp-target')
            print()
            print('=' * 50)
            print()
            print('[*] Scan complete.')
            print()
            print('\033[1;33m[*] No live hosts were found.\033[0m')
            print()
            return False

    # Process nmap output
    process_nmap_output(name)

    return True


def process_nmap_output(name):
    """
    Process the nmap output files to extract useful information.

    Args:
        name (str): Name of the scan (directory where results are stored)
    """
    # Clean up nmap.nmap file
    with open(f'{name}/nmap.nmap') as f:
        content = f.read()

    # Filter out unnecessary lines
    filtered_content = []
    for line in content.splitlines():
        if not re.search(
            r'(0000:|0010:|0020:|0030:|0040:|0050:|0060:|0070:|0080:|0090:|00a0:|00b0:|00c0:|00d0:|1 hop|closed|guesses|guessing|filtered|fingerprint|general purpose|initiated|latency|network distance|no exact os|no os matches|os cpe|please report|rttvar|scanned in|unreachable|warning)',
            line,
            re.IGNORECASE,
        ):
            filtered_content.append(line.replace('Nmap scan report for ', ''))

    # Remove OS: lines
    filtered_content = [line for line in filtered_content if not line.startswith('OS:')]

    # Write cleaned content
    with open(f'{name}/nmap.txt', 'w') as f:
        f.write('\n'.join(filtered_content))

    # Extract hosts
    with open(f'{name}/nmap.nmap') as f:
        content = f.read()

    # Find all IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, content)

    # Sort IPs
    sorted_ips = sorted(set(ips), key=lambda ip: [int(octet) for octet in ip.split('.')])

    # Write hosts file
    with open(f'{name}/hosts.txt', 'w') as f:
        f.write('\n'.join(sorted_ips))

    # Extract open ports
    with open(f'{name}/nmap.txt') as f:
        content = f.read()

    # Find all open ports
    open_ports = []
    for line in content.splitlines():
        if 'open' in line and 'WARNING' not in line:
            port = line.split()[0]
            open_ports.append(port)

    # Write ports file
    with open(f'{name}/ports.txt', 'w') as f:
        f.write('\n'.join(sorted(set(open_ports))))

    # Separate TCP and UDP ports
    tcp_ports = []
    udp_ports = []
    for port in open_ports:
        if 'tcp' in port:
            tcp_ports.append(port.split('/')[0])
        elif 'udp' in port:
            udp_ports.append(port.split('/')[0])

    # Write TCP and UDP port files
    with open(f'{name}/ports-tcp.txt', 'w') as f:
        f.write('\n'.join(sorted(set(tcp_ports), key=int)))

    with open(f'{name}/ports-udp.txt', 'w') as f:
        f.write('\n'.join(sorted(set(udp_ports), key=int)))

    # Extract banners
    banners = []
    for line in content.splitlines():
        if 'open' in line and 'really open' not in line:
            parts = line.split()
            if len(parts) > 3:
                banner = ' '.join(parts[3:])
                banners.append(banner)

    # Write banners file
    with open(f'{name}/banners.txt', 'w') as f:
        f.write('\n'.join(sorted(set(banners))))

    # Extract HTTP and HTTPS services
    http_services = []
    https_services = []

    with open(f'{name}/nmap.gnmap') as f:
        gnmap_content = f.read()

    for tcp_port in tcp_ports:
        # HTTP services
        http_pattern = f' {tcp_port}/open/tcp//appserv-http/| {tcp_port}/open/tcp//http/| {tcp_port}/open/tcp//http-alt/| {tcp_port}/open/tcp//http-proxy/| {tcp_port}/open/tcp//snet-sensor-mgmt/| {tcp_port}/open/tcp//sun-answerbook/| {tcp_port}/open/tcp//vnc-http/| {tcp_port}/open/tcp//wbem-http/| {tcp_port}/open/tcp//wsman/'
        for line in gnmap_content.splitlines():
            if any(pattern in line for pattern in http_pattern.split('|')):
                host = line.split('Host: ')[1].split()[0]
                http_services.append(f'http://{host}:{tcp_port}')

        # HTTPS services
        https_pattern = f' {tcp_port}/open/tcp//compaq-https/| {tcp_port}/open/tcp//https/| {tcp_port}/open/tcp//https-alt/| {tcp_port}/open/tcp//ssl|giop/| {tcp_port}/open/tcp//ssl|http/| {tcp_port}/open/tcp//tungsten-https/| {tcp_port}/open/tcp//ssl|unknown/| {tcp_port}/open/tcp//wsmans/'
        for line in gnmap_content.splitlines():
            if any(pattern in line for pattern in https_pattern.split('|')):
                host = line.split('Host: ')[1].split()[0]
                https_services.append(f'https://{host}:{tcp_port}')

    # Write HTTP and HTTPS service files
    with open(f'{name}/http.txt', 'w') as f:
        f.write('\n'.join(sorted(set(http_services))))

    with open(f'{name}/https.txt', 'w') as f:
        f.write('\n'.join(sorted(set(https_services))))

    # Remove empty files
    for file in os.listdir(name):
        file_path = os.path.join(name, file)
        if os.path.isfile(file_path) and os.path.getsize(file_path) == 0:
            os.remove(file_path)


def ports(name):
    """
    Locate high value ports from the nmap scan results.

    Args:
        name (str): Name of the scan (directory where results are stored)
    """
    print()
    print('=' * 50)
    print()
    print('\033[1;34mLocating high value ports.\033[0m')
    print('     TCP')

    # Define high value TCP ports
    tcp_ports = [
        13,
        19,
        21,
        22,
        23,
        25,
        37,
        69,
        70,
        79,
        80,
        102,
        110,
        111,
        119,
        135,
        139,
        143,
        389,
        433,
        443,
        445,
        465,
        502,
        512,
        513,
        514,
        523,
        524,
        548,
        554,
        563,
        587,
        623,
        631,
        636,
        771,
        831,
        873,
        902,
        993,
        995,
        998,
        1050,
        1080,
        1099,
        1158,
        1344,
        1352,
        1414,
        1433,
        1521,
        1720,
        1723,
        1883,
        1911,
        1962,
        2049,
        2202,
        2375,
        2628,
        2947,
        3000,
        3031,
        3050,
        3260,
        3306,
        3310,
        3389,
        3500,
        3632,
        4369,
        4786,
        5000,
        5019,
        5040,
        5060,
        5432,
        5560,
        5631,
        5632,
        5666,
        5672,
        5850,
        5900,
        5920,
        5984,
        5985,
        6000,
        6001,
        6002,
        6003,
        6004,
        6005,
        6379,
        6666,
        7210,
        7634,
        7777,
        8000,
        8009,
        8080,
        8081,
        8091,
        8140,
        8222,
        8332,
        8333,
        8400,
        8443,
        8834,
        9000,
        9084,
        9100,
        9160,
        9600,
        9999,
        10000,
        10443,
        10809,
        11211,
        12000,
        12345,
        13364,
        19150,
        20256,
        27017,
        28784,
        30718,
        35871,
        37777,
        46824,
        49152,
        50000,
        50030,
        50060,
        50070,
        50075,
        50090,
        60010,
        60030,
    ]

    # Extract hosts with each TCP port
    for port in tcp_ports:
        with open(f'{name}/nmap.gnmap') as f:
            gnmap_content = f.read()

        hosts = []
        for line in gnmap_content.splitlines():
            if f'{port}/open/tcp' in line:
                host = line.split('Host: ')[1].split()[0]
                hosts.append(host)

        if hosts:
            with open(f'{name}/{port}.txt', 'w') as f:
                f.write('\n'.join(sorted(set(hosts), key=lambda ip: [int(octet) for octet in ip.split('.')])))

    # Special case for port 523
    if os.path.exists(f'{name}/523.txt'):
        os.rename(f'{name}/523.txt', f'{name}/523-tcp.txt')

    # Special case for port 5060
    if os.path.exists(f'{name}/5060.txt'):
        os.rename(f'{name}/5060.txt', f'{name}/5060-tcp.txt')

    print('     UDP')

    # Define high value UDP ports
    udp_ports = [
        53,
        67,
        123,
        137,
        161,
        407,
        500,
        523,
        623,
        1434,
        1604,
        1900,
        2302,
        2362,
        3478,
        3671,
        4800,
        5353,
        5683,
        6481,
        17185,
        31337,
        44818,
        47808,
    ]

    # Extract hosts with each UDP port
    for port in udp_ports:
        with open(f'{name}/nmap.gnmap') as f:
            gnmap_content = f.read()

        hosts = []
        for line in gnmap_content.splitlines():
            if f'{port}/open/udp' in line:
                host = line.split('Host: ')[1].split()[0]
                hosts.append(host)

        if hosts:
            with open(f'{name}/{port}.txt', 'w') as f:
                f.write('\n'.join(sorted(set(hosts), key=lambda ip: [int(octet) for octet in ip.split('.')])))

    # Special case for port 523
    if os.path.exists(f'{name}/523.txt'):
        os.rename(f'{name}/523.txt', f'{name}/523-udp.txt')

    # Combine Apache HBase ports and sort
    combine_ports(name, ['60010', '60030'], 'apache-hbase.txt')

    # Combine Bitcoin ports and sort
    combine_ports(name, ['8332', '8333'], 'bitcoin.txt')

    # Combine DB2 ports and sort
    combine_ports(name, ['523-tcp', '523-udp'], 'db2.txt')

    # Combine Hadoop ports and sort
    combine_ports(name, ['50030', '50060', '50070', '50075', '50090'], 'hadoop.txt')

    # Combine NNTP ports and sort
    combine_ports(name, ['119', '433', '563'], 'nntp.txt')

    # Combine SMTP ports and sort
    combine_ports(name, ['25', '465', '587'], 'smtp.txt')

    # Combine X11 ports and sort
    combine_ports(name, ['6000', '6001', '6002', '6003', '6004', '6005'], 'x11.txt')

    # Remove empty files
    for file in os.listdir(name):
        file_path = os.path.join(name, file)
        if os.path.isfile(file_path) and os.path.getsize(file_path) == 0:
            os.remove(file_path)


def combine_ports(name, port_files, output_file):
    """
    Combine multiple port files into a single file.

    Args:
        name (str): Name of the scan (directory where results are stored)
        port_files (list): List of port file names to combine
        output_file (str): Name of the output file
    """
    all_hosts = set()

    for port_file in port_files:
        file_path = os.path.join(name, f'{port_file}.txt')
        if os.path.exists(file_path):
            with open(file_path) as f:
                hosts = f.read().splitlines()
                all_hosts.update(hosts)

    if all_hosts:
        # Sort hosts by IP address
        sorted_hosts = sorted(all_hosts, key=lambda ip: [int(octet) for octet in ip.split('.')])

        with open(os.path.join(name, output_file), 'w') as f:
            f.write('\n'.join(sorted_hosts))


def generate_targets():
    """Generate a target list using various methods."""
    print('\033[1;34mGenerate target list\033[0m')
    print()
    print('1.  ARP scan')
    print('2.  Ping sweep')
    print('3.  Previous menu')
    print()
    choice = input('Choice: ')

    if choice == '1':
        # ARP scan
        print()
        print('Running ARP scan...')

        # Get the network interface
        interfaces = []
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if 'state UP' in line:
                interface = line.split(':')[1].strip()
                interfaces.append(interface)

        if not interfaces:
            print('No active network interfaces found.')
            return

        # If multiple interfaces, let user choose
        interface = interfaces[0]
        if len(interfaces) > 1:
            print('Multiple interfaces found:')
            for i, iface in enumerate(interfaces):
                print(f'{i + 1}. {iface}')
            print()
            choice = input('Select interface (1): ') or '1'
            try:
                interface = interfaces[int(choice) - 1]
            except (ValueError, IndexError):
                print('Invalid choice. Using first interface.')
                interface = interfaces[0]

        # Run arp-scan
        result = subprocess.run(['sudo', 'arp-scan', '--interface', interface, '--localnet'], capture_output=True, text=True)

        # Parse results
        ips = []
        for line in result.stdout.splitlines():
            if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line):
                ip = line.split()[0]
                ips.append(ip)

        # Save results
        if ips:
            os.makedirs(os.path.expanduser('~/data'), exist_ok=True)
            with open(os.path.expanduser('~/data/targets.txt'), 'w') as f:
                f.write('\n'.join(ips))

            print()
            print('ARP scan complete.')
            print(f'Found {len(ips)} hosts.')
            print('Results saved to ~/data/targets.txt')
        else:
            print('No hosts found.')

    elif choice == '2':
        # Ping sweep
        print()
        network = input('Enter network (e.g., 192.168.1.0/24): ')

        try:
            # Validate network
            ipaddress.ip_network(network)

            # Run ping sweep
            print('Running ping sweep...')
            result = subprocess.run(['sudo', 'nmap', '-sn', network], capture_output=True, text=True)

            # Parse results
            ips = []
            for line in result.stdout.splitlines():
                if 'Nmap scan report for' in line:
                    ip = line.split()[-1]
                    # Remove parentheses if hostname was found
                    if '(' in ip:
                        ip = ip.strip('()')
                    ips.append(ip)

            # Save results
            if ips:
                os.makedirs(os.path.expanduser('~/data'), exist_ok=True)
                with open(os.path.expanduser('~/data/targets.txt'), 'w') as f:
                    f.write('\n'.join(ips))

                print()
                print('Ping sweep complete.')
                print(f'Found {len(ips)} hosts.')
                print('Results saved to ~/data/targets.txt')
            else:
                print('No hosts found.')

        except ValueError:
            print('Invalid network format. Please use CIDR notation (e.g., 192.168.1.0/24).')

    elif choice == '3':
        # Return to main menu
        return

    else:
        print()
        print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
        print()
        generate_targets()
