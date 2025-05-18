"""
Discover Framework - Web Module

This module contains functions for web-related testing, including insecure direct
object reference testing, opening multiple tabs in Firefox, Nikto scanning, and SSL checking.
"""

import os
import re
import subprocess
import time


def direct_object_ref():
    """
    Test for insecure direct object references.

    Using Burp, authenticate to a site, map & Spider, then log out.
    Target > Site map > select the URL > right click > Copy URLs in
    this host. Paste the results into a new file.
    """
    print('\033[1;34mInsecure Direct Object Reference Testing\033[0m')
    print()
    print('Using Burp, authenticate to a site, map & Spider, then log out.')
    print('Target > Site map > select the URL > right click > Copy URLs in')
    print('this host. Paste the results into a new file.')
    print()

    # Get the location of the file
    location = input('Enter the location of your file: ')
    if not location or not os.path.isfile(location):
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        print('\033[1;31m[!] Invalid choice or entry.\033[0m')
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        return

    # Read URLs from file
    with open(location) as f:
        urls = f.read().splitlines()

    # Filter out empty lines and comments
    urls = [url.strip() for url in urls if url.strip() and not url.strip().startswith('#')]

    if not urls:
        print('No valid URLs found in the file.')
        return

    # Create output directory
    output_dir = os.path.join(os.path.expanduser('~'), 'data', 'direct-object-ref')
    os.makedirs(output_dir, exist_ok=True)

    # Create a file with the original URLs
    with open(os.path.join(output_dir, 'original-urls.txt'), 'w') as f:
        f.write('\n'.join(urls))

    # Extract parameters from URLs
    params = set()
    for url in urls:
        if '?' in url:
            query_string = url.split('?', 1)[1]
            for param_pair in query_string.split('&'):
                if '=' in param_pair:
                    param = param_pair.split('=')[0]
                    params.add(param)

    # Write parameters to file
    if params:
        with open(os.path.join(output_dir, 'parameters.txt'), 'w') as f:
            f.write('\n'.join(sorted(params)))

    # Extract paths from URLs
    paths = set()
    for url in urls:
        parsed_url = url.split('?')[0]  # Remove query string
        if '://' in parsed_url:
            path = '/'.join(parsed_url.split('/')[3:])  # Remove scheme and domain
            if path:
                paths.add(path)

    # Write paths to file
    if paths:
        with open(os.path.join(output_dir, 'paths.txt'), 'w') as f:
            f.write('\n'.join(sorted(paths)))

    # Look for potential IDOR patterns in parameters
    idor_patterns = ['id', 'user', 'account', 'num', 'order', 'no', 'doc', 'key', 'email', 'group', 'profile', 'edit', 'report']
    potential_idors = []

    for url in urls:
        if '?' in url:
            query_string = url.split('?', 1)[1]
            for param_pair in query_string.split('&'):
                if '=' in param_pair:
                    param, value = param_pair.split('=', 1)
                    if any(pattern in param.lower() for pattern in idor_patterns):
                        if value.isdigit() or (len(value) < 20 and re.match(r'^[a-zA-Z0-9_-]+$', value)):
                            potential_idors.append(f'{url} (Parameter: {param}, Value: {value})')

    # Write potential IDORs to file
    if potential_idors:
        with open(os.path.join(output_dir, 'potential-idors.txt'), 'w') as f:
            f.write('\n'.join(potential_idors))

    print()
    print('Analysis complete.')
    print(f'Found {len(urls)} URLs, {len(params)} unique parameters, and {len(potential_idors)} potential IDOR vulnerabilities.')
    print(f'Results saved to {output_dir}')
    print()


def multi_tabs():
    """
    Open multiple tabs in Firefox with URLs from various sources.

    Options:
    1. List of URLs
    2. Files in a directory
    3. Directories in robots.txt
    """
    # Check if running in a graphical environment
    if not os.environ.get('DISPLAY'):
        print()
        print('\033[1;31m' + '=' * 50 + '\033[0m')
        print()
        print('\033[1;31m[!] This option must be ran locally.\033[0m')
        print()
        print('\033[1;31m' + '=' * 50 + '\033[0m')
        print()
        return

    print('\033[1;34mOpen multiple tabs in Firefox with:\033[0m')
    print()
    print('1.  List')
    print('2.  Files in a directory')
    print('3.  Directories in robots.txt')
    print('4.  Previous menu')
    print()

    choice = input('Choice: ')

    if choice == '1':
        # Open tabs from a list
        print()
        location = input('Enter the location of your file: ')
        if not location or not os.path.isfile(location):
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            print('\033[1;31m[!] Invalid choice or entry.\033[0m')
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            return

        # Read URLs from file
        with open(location) as f:
            urls = f.read().splitlines()

        # Filter out empty lines and comments
        urls = [url.strip() for url in urls if url.strip() and not url.strip().startswith('#')]

        if not urls:
            print('No valid URLs found in the file.')
            return

        # Open URLs in Firefox
        for url in urls:
            # Add http:// prefix if not present
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            subprocess.run(['firefox', '--new-tab', url])
            time.sleep(1)  # Delay to prevent overwhelming the browser

        print()
        print(f'Opened {len(urls)} tabs in Firefox.')

    elif choice == '2':
        # Open tabs for files in a directory
        print()
        location = input('Enter the directory path: ')
        if not location or not os.path.isdir(location):
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            print('\033[1;31m[!] Invalid choice or entry.\033[0m')
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            return

        # Get all files in the directory
        files = [os.path.join(location, f) for f in os.listdir(location) if os.path.isfile(os.path.join(location, f))]

        if not files:
            print('No files found in the directory.')
            return

        # Open files in Firefox
        for file in files:
            subprocess.run(['firefox', '--new-tab', f'file://{os.path.abspath(file)}'])
            time.sleep(1)  # Delay to prevent overwhelming the browser

        print()
        print(f'Opened {len(files)} tabs in Firefox.')

    elif choice == '3':
        # Open tabs for directories in robots.txt
        print()
        url = input('Enter the URL (e.g., example.com): ')
        if not url:
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            print('\033[1;31m[!] Invalid choice or entry.\033[0m')
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            return

        # Add http:// prefix if not present
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Download robots.txt
        try:
            result = subprocess.run(['wget', '-q', f'{url}/robots.txt', '-O', 'robots.txt'], check=True)

            if not os.path.exists('robots.txt') or os.path.getsize('robots.txt') == 0:
                print(f'No robots.txt found at {url}')
                return

            # Extract directories from robots.txt
            directories = []
            with open('robots.txt') as f:
                for line in f:
                    if line.lower().startswith(('allow:', 'disallow:')):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/' and not path.startswith('#'):
                            directories.append(path)

            if not directories:
                print('No directories found in robots.txt')
                return

            # Open directories in Firefox
            for directory in directories:
                full_url = url + directory
                subprocess.run(['firefox', '--new-tab', full_url])
                time.sleep(1)  # Delay to prevent overwhelming the browser

            print()
            print(f'Opened {len(directories)} tabs in Firefox.')

            # Clean up
            os.remove('robots.txt')

        except subprocess.CalledProcessError:
            print(f'Failed to download robots.txt from {url}')

    elif choice == '4':
        # Return to previous menu
        return

    else:
        print()
        print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
        print()
        multi_tabs()


def nikto_scan():
    """
    Run multiple instances of Nikto in parallel.

    Options:
    1. List of IPs
    2. List of IP:port
    """
    # Check if running as root
    if os.geteuid() == 0:
        print()
        print('This option cannot be ran as root.')
        print()
        return

    print('\033[1;34mRun multiple instances of Nikto in parallel.\033[0m')
    print()
    print('1.  List of IPs')
    print('2.  List of IP:port')
    print('3.  Previous menu')
    print()

    choice = input('Choice: ')

    if choice == '1':
        # Scan list of IPs
        print()
        location = input('Enter the location of your file: ')
        if not location or not os.path.isfile(location):
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            print('\033[1;31m[!] Invalid choice or entry.\033[0m')
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            return

        # Read IPs from file
        with open(location) as f:
            ips = f.read().splitlines()

        # Filter out empty lines and comments
        ips = [ip.strip() for ip in ips if ip.strip() and not ip.strip().startswith('#')]

        if not ips:
            print('No valid IPs found in the file.')
            return

        # Create output directory
        output_dir = os.path.join(os.path.expanduser('~'), 'data', 'nikto')
        os.makedirs(output_dir, exist_ok=True)

        # Run Nikto for each IP
        processes = []
        for ip in ips:
            output_file = os.path.join(output_dir, f'{ip.replace(".", "_")}.htm')
            cmd = ['nikto', '-h', ip, '-o', output_file, '-Format', 'htm']
            process = subprocess.Popen(cmd)
            processes.append((process, ip))
            time.sleep(1)  # Delay to prevent overwhelming the system

        # Wait for all processes to complete
        print()
        print(f'Running Nikto on {len(ips)} targets...')
        print('This may take a while. Press Ctrl+C to terminate.')
        print()

        try:
            for process, ip in processes:
                process.wait()
                print(f'Completed scan for {ip}')
        except KeyboardInterrupt:
            print()
            print('Terminating scans...')
            for process, _ in processes:
                process.terminate()

        print()
        print('Nikto scans complete.')
        print(f'Results saved to {output_dir}')

    elif choice == '2':
        # Scan list of IP:port
        print()
        location = input('Enter the location of your file: ')
        if not location or not os.path.isfile(location):
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            print('\033[1;31m[!] Invalid choice or entry.\033[0m')
            print()
            print('\033[1;31m' + '=' * 40 + '\033[0m')
            print()
            return

        # Read IP:port from file
        with open(location) as f:
            targets = f.read().splitlines()

        # Filter out empty lines and comments
        targets = [target.strip() for target in targets if target.strip() and not target.strip().startswith('#')]

        if not targets:
            print('No valid targets found in the file.')
            return

        # Create output directory
        output_dir = os.path.join(os.path.expanduser('~'), 'data', 'nikto')
        os.makedirs(output_dir, exist_ok=True)

        # Run Nikto for each target
        processes = []
        for target in targets:
            if ':' not in target:
                print(f'Skipping invalid target: {target} (missing port)')
                continue

            ip, port = target.split(':', 1)
            output_file = os.path.join(output_dir, f'{ip.replace(".", "_")}_{port}.htm')
            cmd = ['nikto', '-h', ip, '-p', port, '-o', output_file, '-Format', 'htm']
            process = subprocess.Popen(cmd)
            processes.append((process, target))
            time.sleep(1)  # Delay to prevent overwhelming the system

        # Wait for all processes to complete
        print()
        print(f'Running Nikto on {len(targets)} targets...')
        print('This may take a while. Press Ctrl+C to terminate.')
        print()

        try:
            for process, target in processes:
                process.wait()
                print(f'Completed scan for {target}')
        except KeyboardInterrupt:
            print()
            print('Terminating scans...')
            for process, _ in processes:
                process.terminate()

        print()
        print('Nikto scans complete.')
        print(f'Results saved to {output_dir}')

    elif choice == '3':
        # Return to previous menu
        return

    else:
        print()
        print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
        print()
        nikto_scan()


def ssl_check():
    """
    Check for SSL certificate issues.

    Uses sslscan, sslyze, and Nmap to check for SSL/TLS certificate issues.
    """
    print('\033[1;34mCheck for SSL certificate issues.\033[0m')
    print()
    print('List of IP:port.')
    print()

    # Get the location of the file
    location = input('Enter the location of your file: ')
    if not location or not os.path.isfile(location):
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        print('\033[1;31m[!] Invalid choice or entry.\033[0m')
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        return

    # Read IP:port from file
    with open(location) as f:
        targets = f.read().splitlines()

    # Filter out empty lines and comments
    targets = [target.strip() for target in targets if target.strip() and not target.strip().startswith('#')]

    if not targets:
        print('No valid targets found in the file.')
        return

    # Create output directory
    output_dir = os.path.join(os.path.expanduser('~'), 'data', 'ssl')
    os.makedirs(output_dir, exist_ok=True)

    # Run SSL checks for each target
    for target in targets:
        if ':' not in target:
            print(f'Skipping invalid target: {target} (missing port)')
            continue

        ip, port = target.split(':', 1)
        target_dir = os.path.join(output_dir, f'{ip.replace(".", "_")}_{port}')
        os.makedirs(target_dir, exist_ok=True)

        print()
        print(f'Checking SSL/TLS for {target}...')

        # Run sslscan
        try:
            print('Running sslscan...')
            sslscan_output = os.path.join(target_dir, 'sslscan.txt')
            subprocess.run(['sslscan', '--no-colour', target], stdout=open(sslscan_output, 'w'), stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f'Error running sslscan: {e}')

        # Run sslyze
        try:
            print('Running sslyze...')
            sslyze_output = os.path.join(target_dir, 'sslyze.txt')
            subprocess.run(['sslyze', target], stdout=open(sslyze_output, 'w'), stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f'Error running sslyze: {e}')

        # Run Nmap SSL scripts
        try:
            print('Running Nmap SSL scripts...')
            nmap_output = os.path.join(target_dir, 'nmap_ssl')
            subprocess.run(
                [
                    'nmap',
                    '-sV',
                    '--script',
                    'ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-ccs-injection',
                    '-p',
                    port,
                    ip,
                    '-oA',
                    nmap_output,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f'Error running Nmap SSL scripts: {e}')

    print()
    print('SSL checks complete.')
    print(f'Results saved to {output_dir}')
    print()

    # Generate summary report
    summary_file = os.path.join(output_dir, 'summary.txt')
    with open(summary_file, 'w') as f:
        f.write('SSL/TLS Check Summary\n')
        f.write('=' * 50 + '\n\n')

        for target in targets:
            if ':' not in target:
                continue

            ip, port = target.split(':', 1)
            target_dir = os.path.join(output_dir, f'{ip.replace(".", "_")}_{port}')

            f.write(f'Target: {target}\n')
            f.write('-' * 30 + '\n')

            # Check for common issues
            issues = []

            # Check sslscan output
            sslscan_output = os.path.join(target_dir, 'sslscan.txt')
            if os.path.exists(sslscan_output):
                with open(sslscan_output) as scan_file:
                    content = scan_file.read()
                    if 'SSLv2' in content and 'enabled' in content:
                        issues.append('SSLv2 is enabled (Insecure)')
                    if 'SSLv3' in content and 'enabled' in content:
                        issues.append('SSLv3 is enabled (POODLE vulnerability)')
                    if 'Heartbleed' in content and 'vulnerable' in content:
                        issues.append('Vulnerable to Heartbleed')

            # Check Nmap output
            nmap_output = os.path.join(target_dir, 'nmap_ssl.nmap')
            if os.path.exists(nmap_output):
                with open(nmap_output) as scan_file:
                    content = scan_file.read()
                    if 'ssl-poodle' in content and 'vulnerable' in content:
                        issues.append('Vulnerable to POODLE')
                    if 'ssl-ccs-injection' in content and 'vulnerable' in content:
                        issues.append('Vulnerable to CCS Injection')
                    if 'ssl-heartbleed' in content and 'vulnerable' in content:
                        issues.append('Vulnerable to Heartbleed')

            if issues:
                f.write('Issues Found:\n')
                for issue in issues:
                    f.write(f'- {issue}\n')
            else:
                f.write('No major issues found.\n')

            f.write('\n')

    print(f'Summary report generated: {summary_file}')
