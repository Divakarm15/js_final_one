#!/usr/bin/env python3
"""
JS Scout Pro v5 — Selenium + Chromium Edition
==============================================
JavaScript security recon tool with real browser crawling.

Install deps:
    pip install requests selenium webdriver-manager

On Linux (Kali/Ubuntu):
    apt install chromium chromium-driver
    pip install selenium webdriver-manager

On Windows/Mac:
    pip install selenium webdriver-manager
    (chromedriver auto-downloaded via webdriver-manager)

Usage:
    python3 jsscout.py https://target.com
    python3 jsscout.py https://target.com --threads 10 --depth 4
    python3 jsscout.py https://target.com --no-selenium   # requests-only mode
    python3 server.py  ->  http://localhost:7331  (Web UI)
"""

import re, sys, os, json, time, hashlib, argparse, threading, traceback
from pathlib import Path
from queue import Queue, Empty
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from html.parser import HTMLParser

# =============================================================================
# NEW v7 MODULES — Import with graceful fallback for standalone usage
# =============================================================================
try:
    from endpoint_extractor import EndpointCollector
    ENDPOINT_EXTRACTOR_OK = True
except ImportError:
    ENDPOINT_EXTRACTOR_OK = False

try:
    from vulnerability_checks import VulnerabilityChecker
    VULN_CHECKS_OK = True
except ImportError:
    VULN_CHECKS_OK = False

try:
    from xss_detector import XSSDetector
    XSS_DETECTOR_OK = True
except ImportError:
    XSS_DETECTOR_OK = False

try:
    from report_generator import ReportGenerator
    REPORT_GEN_OK = True
except ImportError:
    REPORT_GEN_OK = False

try:
    from advanced_vulns import AdvancedVulnChecker
    ADVANCED_VULNS_OK = True
except ImportError:
    ADVANCED_VULNS_OK = False

try:
    from advanced_scanner import AdvancedScanner
    ADVANCED_SCANNER_OK = True
except ImportError:
    ADVANCED_SCANNER_OK = False

try:
    from auth_checks import AuthChecker
    AUTH_CHECKS_OK = True
except ImportError:
    AUTH_CHECKS_OK = False

try:
    from burp_integration import BurpManager
    BURP_OK = True
except ImportError:
    BURP_OK = False

try:
    from external_tools_integration import ExternalToolsOrchestrator
    EXTERNAL_TOOLS_OK = True
except ImportError:
    EXTERNAL_TOOLS_OK = False

try:
    from logger import make_logger
    LOGGER_OK = True
except ImportError:
    LOGGER_OK = False



try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

# Selenium — optional but strongly recommended
SELENIUM_OK = False
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import (
        TimeoutException, WebDriverException, NoSuchElementException,
        StaleElementReferenceException, JavascriptException
    )
    SELENIUM_OK = True
except ImportError:
    pass

# webdriver-manager for auto chromedriver download
WDM_OK = False
try:
    from webdriver_manager.chrome import ChromeDriverManager
    WDM_OK = True
except ImportError:
    pass


# =============================================================================
# SECURITY PATTERNS
# =============================================================================

SECRET_PATTERNS = [
    (re.compile(r'(?:api[_\-]?key|apikey|api_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', re.I), "api_key", "HIGH"),
    (re.compile(r'(?:access[_\-]?token|auth[_\-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.I), "access_token", "HIGH"),
    (re.compile(r'["\']eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}["\']'), "jwt_token", "HIGH"),
    (re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "password", "CRITICAL"),
    (re.compile(r'(?:secret|client_secret|private_key)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "secret", "HIGH"),
    (re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'), "aws_access_key", "CRITICAL"),
    (re.compile(r'AIza[a-zA-Z0-9_\-]{35}'), "google_api_key", "HIGH"),
    (re.compile(r'["\']pk_(?:test|live)_[a-zA-Z0-9]{24,}["\']'), "stripe_pk", "CRITICAL"),
    (re.compile(r'["\']sk_(?:test|live)_[a-zA-Z0-9]{24,}["\']'), "stripe_sk", "CRITICAL"),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'), "slack_token", "HIGH"),
    (re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}'), "github_token", "HIGH"),
    (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'), "private_key", "CRITICAL"),
    (re.compile(r'(?:firebase|firebaseConfig)[^{]{0,50}apiKey\s*:\s*["\']([^"\']{10,})["\']', re.I), "firebase_key", "HIGH"),
    (re.compile(r'(?:mongodb|postgres|mysql|redis)://[^\s"\'<>]{10,}', re.I), "db_connection", "CRITICAL"),
    (re.compile(r'"type"\s*:\s*"service_account"'), "gcp_service_account", "CRITICAL"),
    (re.compile(r'(?:authorization|x-api-key)\s*:\s*["\']([^"\']{10,})["\']', re.I), "auth_header", "HIGH"),
]

ENDPOINT_PATTERNS = [
    re.compile(r'["\'`](/api/v?\d+/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/api/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/graphql[a-zA-Z0-9/_\-]*)["\'`]'),
    re.compile(r'["\'`](/rest/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`](/v[1-9]\d*/[a-zA-Z0-9/_\-\.{}:]+)["\'`]'),
    re.compile(r'["\'`]([a-zA-Z0-9/_\-\.{}:]+\.(?:json|xml|yaml))["\'`]'),
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|xhr\.open)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'(?:url|endpoint|baseURL|apiUrl|API_URL)\s*[:=]\s*["\'`]([^"\'`]{5,100})["\'`]', re.I),
]

XSS_SINKS = [
    (re.compile(r'\.innerHTML\s*=\s*(?!["\'\s]*["\']|`[^`$]*`\s*;|\s*(?:""|\'\'|``)\s*)', re.I), "innerHTML", "HIGH"),
    (re.compile(r'\.outerHTML\s*=\s*', re.I), "outerHTML", "HIGH"),
    (re.compile(r'document\.write\s*\(', re.I), "document.write", "HIGH"),
    (re.compile(r'document\.writeln\s*\(', re.I), "document.writeln", "HIGH"),
    (re.compile(r'\.insertAdjacentHTML\s*\(', re.I), "insertAdjacentHTML", "CRITICAL"),
    (re.compile(r'(?<!\.)(?<!typeof\s)\beval\s*\(', re.I), "eval", "CRITICAL"),
    (re.compile(r'\bnew\s+Function\s*\(', re.I), "new Function()", "CRITICAL"),
    (re.compile(r'setTimeout\s*\(\s*(?:["\']|[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+)', re.I), "setTimeout(str)", "HIGH"),
    (re.compile(r'setInterval\s*\(\s*(?:["\']|[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+)', re.I), "setInterval(str)", "HIGH"),
    (re.compile(r'window\.location(?:\.href)?\s*=\s*(?!["\'](?:#|/|https?:)[^"\']*["\'])', re.I), "location.href=", "HIGH"),
    (re.compile(r'location\.(?:replace|assign)\s*\(', re.I), "location.replace/assign", "HIGH"),
    (re.compile(r'\$\([^)]+\)\.html\s*\(\s*(?!\s*\))[^"\'`)]', re.I), "$.html()", "HIGH"),
    (re.compile(r'\$\([^)]+\)\.(?:append|prepend|after|before)\s*\(\s*(?!\s*["\']<[^<]*>["\'])', re.I), "$.append/prepend", "MEDIUM"),
    (re.compile(r'\.attr\s*\(\s*["\'`](?:href|src|action)["\'`]\s*,', re.I), "$.attr(href/src)", "HIGH"),
    (re.compile(r'dangerouslySetInnerHTML\s*=', re.I), "dangerouslySetInnerHTML", "CRITICAL"),
    (re.compile(r'\.srcdoc\s*=', re.I), "iframe.srcdoc", "HIGH"),
    (re.compile(r'createContextualFragment\s*\(', re.I), "createContextualFragment", "CRITICAL"),
    (re.compile(r'addEventListener\s*\(\s*["\'`]message["\'`]', re.I), "postMessage listener", "MEDIUM"),
    (re.compile(r'\.setAttributeNS?\s*\(\s*(?:null,\s*)?["\'`](?:href|src|action)["\'`]', re.I), "setAttribute(href/src)", "HIGH"),
]

XSS_SOURCES = [
    (re.compile(r'location\.(?:search|hash|href|pathname)', re.I), "location.*"),
    (re.compile(r'document\.(?:URL|documentURI|referrer)', re.I), "document.URL"),
    (re.compile(r'(?:URLSearchParams|searchParams)\.(?:get|getAll)\s*\(', re.I), "URLSearchParams"),
    (re.compile(r'document\.getElementById\([^)]+\)\.value', re.I), "DOM input value"),
    (re.compile(r'document\.querySelector\([^)]+\)\.value', re.I), "DOM input value"),
    (re.compile(r'window\.name', re.I), "window.name"),
    (re.compile(r'document\.cookie', re.I), "document.cookie"),
    (re.compile(r'postMessage', re.I), "postMessage"),
]

XSS_SANITIZERS = [
    'DOMPurify.sanitize', 'sanitizeHtml', 'sanitize_html', 'escapeHtml',
    'escape_html', 'bleach.clean', 'he.encode', 'he.escape',
    'createTextNode', 'innerText', 'encodeURIComponent', 'htmlspecialchars',
    'htmlentities', 'stripTags', 'xss(', 'filterXSS',
]

KEYWORDS = {
    'todo_fixme':    re.compile(r'\b(?:TODO|FIXME|HACK|XXX|BUG|TEMP)\b'),
    'debug_logging': re.compile(r'\bconsole\.(log|debug|warn|error|info)\s*\(', re.I),
    'hardcoded_url': re.compile(r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)'),
    'disabled_security': re.compile(r'(?:verify\s*=\s*False|SSL_VERIFY|checkServerIdentity|rejectUnauthorized\s*:\s*false)', re.I),
    'cors_wildcard': re.compile(r'Access-Control-Allow-Origin["\s:]+\*'),
    'admin_path':    re.compile(r'["\'`]/(?:admin|administrator|wp-admin|manage|dashboard|control)[/"\'`]', re.I),
    'jwt_nosig':     re.compile(r'algorithm[s]?\s*[=:]\s*["\'](?:none|NONE)["\']'),
}

XSS_PAYLOADS = {
    "basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'><script>alert(1)</script>",
        '"><script>alert(1)</script>',
    ],
    "attribute": [
        '" onmouseover=alert(1) x="',
        "' onmouseover=alert(1) x='",
        '" autofocus onfocus=alert(1) x="',
        "' autofocus onfocus=alert(1) x='",
    ],
    "javascript_context": [
        '";alert(1)//',
        "';alert(1)//",
        "`;alert(1)//",
        '\\";alert(1)//',
        "</script><script>alert(1)</script>",
    ],
    "href_src": [
        "javascript:alert(1)",
        "javascript:alert`1`",
        "data:text/html,<script>alert(1)</script>",
    ],
    "filter_bypass": [
        "<sCript>alert(1)</sCript>",
        "<img/src=x/onerror=alert(1)>",
        "<svg/onload=alert(1)//>",
        "<audio src onerror=alert(1)>",
        "<img src=x onerror=alert`1`>",
    ],
    "dom": [
        "javascript:alert(1)",
        "#<img src=x onerror=alert(1)>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ],
}

# Context-aware payloads — used by the XSS prober
# Key = reflection context detected in the page
CONTEXT_PAYLOADS = {
    'html': [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<script>alert(1)</script>',
        '<body onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
    ],
    'attr': [
        '" onmouseover=alert(1) x="',
        "' onmouseover=alert(1) x='",
        '" autofocus onfocus=alert(1) x="',
        '" onblur=alert(1) x="',
    ],
    'attr_href': [
        'javascript:alert(1)',
        'javascript:alert`1`',
        'JaVaScRiPt:alert(1)',
    ],
    'attr_src': [
        'x onerror=alert(1)',
        'x" onerror="alert(1)',
    ],
    'js_str_dq': [
        '";alert(1)//',
        '";alert(1);x="',
        '\\";alert(1)//',
        '"+(alert(1))+"',
    ],
    'js_str_sq': [
        "';alert(1)//",
        "';alert(1);x='",
        "\\';alert(1)//",
        "'+(alert(1))+'",
    ],
    'js_str_bt': [
        '`;alert(1)//',
        '${alert(1)}',
        '`+(alert(1))+`',
    ],
    'js_comment': [
        '\nalert(1)\n//',
        '\nalert(1)/*',
    ],
    'url': [
        'javascript:alert(1)',
        '%22><img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
    ],
    'unknown': [
        '<img src=x onerror=alert(1)>',
        '" onmouseover=alert(1) x="',
        "';alert(1)//",
        '";alert(1)//',
        'javascript:alert(1)',
        '"><img src=x onerror=alert(1)>',
    ],
}

# =============================================================================
# JS URL EXTRACTION — comprehensive, handles webpack/vite/AMD/chunks
# =============================================================================

SKIP_EXTS = {
    '.css','.png','.jpg','.jpeg','.gif','.svg','.ico',
    '.woff','.woff2','.ttf','.eot','.otf',
    '.pdf','.zip','.gz','.tar','.rar',
    '.mp4','.mp3','.webm','.ogg','.wav',
    '.webp','.avif','.bmp','.map',
}

MANIFEST_PATHS = [
    '/asset-manifest.json', '/static/asset-manifest.json',
    '/assets/asset-manifest.json', '/manifest.json',
    '/webpack-manifest.json', '/mix-manifest.json',
    '/assets.json', '/precache-manifest.js',
    '/_next/static/development/_buildManifest.js',
    '/service-worker.js', '/sw.js',
]

# Basic patterns: quoted JS references
JS_REGEXES = [
    re.compile(r'src\s*=\s*["\']([^"\']+\.m?js(?:\?[^"\']*)?)["\']', re.I),
    re.compile(r'src\s*=\s*([^\s"\'>/]+\.m?js(?:\?[^\s"\'>/]*)?)', re.I),
    re.compile(r'(?:import|require)\s*\(\s*["\'`]([^"\'`]+\.m?js(?:\?[^"\'`]*)?)["\'`]\s*\)', re.I),
    re.compile(r'import\s+[^"\'`]*["\'`]([^"\'`]+\.m?js)["\'`]', re.I),
    re.compile(r'["\'`](https?://[^\s"\'`<>]+\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    re.compile(r'["\'`](/_next/static/[^\s"\'`<>]+\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    re.compile(r'["\'`](/(?:assets|static/js|static/chunks|dist|build|js)/[a-zA-Z0-9._/\-]+\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    re.compile(r'["\'`](/[a-zA-Z0-9._/\-]{4,300}\.m?js(?:\?[^\s"\'`<>]*)?)["\'`]'),
    re.compile(r'https?://[^\s"\'<>]+\.m?js(?:\?[^\s"\'<>]*)?(?=[\s,;>])'),
    re.compile(r'data-(?:src|main)\s*=\s*["\']([^"\']+\.m?js)["\']', re.I),
    # RequireJS / AMD
    re.compile(r'require\s*\(\s*\[([^\]]+)\]', re.I),
    re.compile(r'define\s*\(\s*\[([^\]]+)\]', re.I),
]

# Webpack patterns
_WP_PUBPATH    = re.compile(r'__webpack_require__\.p\s*=\s*["\'`]([^"\'`]+)["\'`]')
_WP_PUBPATH2   = re.compile(r'publicPath\s*[=:]\s*["\'`]([^"\'`]{1,100})["\'`]')

# Webpack 4: {0:"abc123", 1:"def456"} — chunk id to hash
_WP4_CHUNK_MAP = re.compile(r'\{(?:\s*\d+\s*:\s*"[a-f0-9]{4,}"(?:\s*,\s*\d+\s*:\s*"[a-f0-9]{4,}")*\s*)\}')
_WP4_CHUNK_ID  = re.compile(r'(\d+)\s*:\s*"([a-f0-9]{4,})"')

# Webpack 4 named: {0:"home", 1:"about"} — chunk id to name (no hash)
_WP4_NAMED_MAP = re.compile(r'\{(?:\s*\d+\s*:\s*"[a-zA-Z0-9_\-\.]+"(?:\s*,\s*\d+\s*:\s*"[a-zA-Z0-9_\-\.]+")*\s*)\}')
_WP4_NAMED_ID  = re.compile(r'(\d+)\s*:\s*"([a-zA-Z0-9_\-\.]+)"')

# Webpack 5: (self["webpackChunk..."] = self["webpackChunk..."] || []).push
_WP5_CHUNK     = re.compile(r'self\[["\'`]webpackChunk[^"\'`]*["\'`]\]')

# Webpack chunk filename template: e => e + ".js" or e + ".chunk.js"
_WP_CHUNK_TMPL = re.compile(r'function\s*\w*\s*\(\s*\w+\s*\)\s*\{\s*return\s*\w+\s*\+\s*["\']([^"\']+)["\']')
_WP_CHUNK_EXT  = re.compile(r'\.push\(\[(\d+)\]\)')

# Next.js
_NEXT_BUILD    = re.compile(r'"buildId"\s*:\s*"([a-zA-Z0-9_\-]{4,})"')

# Vite: dynamic import("/assets/Name.hash.js")
_VITE_IMPORT   = re.compile(r'import\s*\(\s*["\']([^"\']+\.m?js)["\']')
_VITE_ENTRY    = re.compile(r'"([a-zA-Z0-9/_\-\.]+\.m?js)"\s*:')

# AMD require array strings: require(["./a","./b"])
_AMD_DEPS      = re.compile(r'["\'](\./[a-zA-Z0-9/_\-\.]+)["\']')


def extract_js_urls(content: str, base_url: str) -> set:
    """
    Extract ALL JS URLs from HTML or JS content.
    Handles: plain src/import/require, Webpack 4+5, Next.js, Vite, AMD/RequireJS.
    """
    found = set()
    parsed_base = urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    def add(raw: str):
        if not raw or raw.startswith(('data:', 'blob:')):
            return
        raw = raw.strip().split('#')[0]
        if raw.startswith('//'):
            raw = parsed_base.scheme + ':' + raw
        elif not raw.startswith('http'):
            raw = urljoin(base_url, raw)
        if raw.startswith(('http://', 'https://')):
            found.add(raw)

    # ── Basic regex sweep ────────────────────────────────────────────────────
    for pat in JS_REGEXES:
        for m in pat.finditer(content):
            group = m.group(1) if m.lastindex else m.group(0)
            # AMD array: extract each quoted path from ["a","b","c"]
            if group.startswith('[') or ',' in group:
                for dep in _AMD_DEPS.findall(group):
                    if dep.endswith('.js') or '/' in dep:
                        add(dep)
            else:
                add(group)

    # ── Detect publicPath ────────────────────────────────────────────────────
    pub_path = '/'
    for pat in [_WP_PUBPATH, _WP_PUBPATH2]:
        m = pat.search(content)
        if m:
            pp = m.group(1).strip()
            if pp.startswith('/') or pp.startswith('http'):
                pub_path = pp if pp.startswith('http') else origin + pp
                break

    pub_base = pub_path.rstrip('/')

    # ── Webpack 4: hash chunk maps  {0:"abc123", 1:"def456"} ────────────────
    chunk_tmpl = '.chunk.js'  # default
    tmpl_m = _WP_CHUNK_TMPL.search(content)
    if tmpl_m:
        chunk_tmpl = tmpl_m.group(1)  # e.g. ".chunk.js" or ".js"

    for cm in _WP4_CHUNK_MAP.finditer(content):
        for m in _WP4_CHUNK_ID.finditer(cm.group(0)):
            cid, chash = m.group(1), m.group(2)
            for tmpl in [
                f'/static/js/{cid}.{chash}.chunk.js',
                f'/static/js/{cid}.{chash}.js',
                f'/static/chunks/{cid}.{chash}.js',
                f'/js/{cid}.{chash}.chunk.js',
                f'/_next/static/chunks/{cid}-{chash}.js',
                f'/{cid}.{chash}{chunk_tmpl}',
            ]:
                add(pub_base + tmpl if not pub_base.startswith('http') else pub_base + tmpl)

    # ── Webpack 4: named chunk maps {0:"home", 1:"about"} ───────────────────
    for cm in _WP4_NAMED_MAP.finditer(content):
        for m in _WP4_NAMED_ID.finditer(cm.group(0)):
            cid, cname = m.group(1), m.group(2)
            # Skip if looks like a hash (already caught above)
            if re.match(r'^[a-f0-9]{6,}$', cname):
                continue
            for tmpl in [
                f'/static/js/{cname}.{cid}.chunk.js',
                f'/static/js/{cid}.{cname}.chunk.js',
                f'/static/chunks/{cname}.js',
                f'/js/{cname}.js',
                f'/{cid}.{cname}.js',
            ]:
                add(pub_base + tmpl)

    # ── Next.js build ID ─────────────────────────────────────────────────────
    nm = _NEXT_BUILD.search(content)
    if nm:
        bid = nm.group(1)
        for path in [
            f'/_next/static/{bid}/_buildManifest.js',
            f'/_next/static/{bid}/_ssgManifest.js',
            '/_next/static/chunks/main.js',
            '/_next/static/chunks/webpack.js',
            '/_next/static/chunks/framework.js',
            '/_next/static/chunks/pages/_app.js',
        ]:
            add(origin + path)

    # ── Vite dynamic imports ─────────────────────────────────────────────────
    for m in _VITE_IMPORT.finditer(content):
        add(m.group(1))
    for m in _VITE_ENTRY.finditer(content):
        path = m.group(1)
        if not path.startswith('/'):
            path = '/' + path
        add(urljoin(base_url, path))

    return found


# =============================================================================
# REFLECTION CONTEXT DETECTION
# =============================================================================

def detect_reflection_context(html: str, marker: str) -> list:
    """
    Find every position where marker appears in html/JS.
    For each, determine the syntactic context so we can pick the right payload.

    Returns list of context strings (may have multiple if reflected in several places):
        'html'        — raw HTML body between tags
        'attr'        — inside an HTML attribute value (generic)
        'attr_href'   — inside href/src/action/formaction attribute
        'attr_src'    — inside src/data/background attribute
        'js_str_dq'   — inside JS double-quoted string
        'js_str_sq'   — inside JS single-quoted string
        'js_str_bt'   — inside JS template literal
        'js_comment'  — inside // or /* comment
        'url'         — inside a URL value
        'unknown'     — can't determine
    """
    contexts = []
    start = 0

    while True:
        pos = html.find(marker, start)
        if pos == -1:
            break
        start = pos + 1

        # Look at surrounding ~300 chars on each side
        before = html[max(0, pos - 300):pos]
        after  = html[pos:min(len(html), pos + 300)]

        ctx = _classify_context(before, after, marker)
        if ctx not in contexts:
            contexts.append(ctx)

    return contexts if contexts else ['unknown']


def _classify_context(before: str, after: str, marker: str) -> str:
    """Classify the HTML/JS context based on surrounding text."""

    before_lower = before.lower()

    # ── Check if inside a <script> block ────────────────────────────────────
    last_script_open  = before_lower.rfind('<script')
    last_script_close = before_lower.rfind('</script')
    in_script = last_script_open > last_script_close and last_script_open != -1

    if in_script:
        # What kind of JS string context?
        # Count unescaped quotes after last newline or semicolon
        code_segment = before[last_script_open:]

        # Track quote state (simplistic but effective for most cases)
        dq = code_segment.count('"') - code_segment.count('\\"')
        sq = code_segment.count("'") - code_segment.count("\\'")
        bt = code_segment.count('`') - code_segment.count('\\`')

        # Check for comment
        last_line = code_segment.split('\n')[-1]
        if '//' in last_line and last_line.index('//') < len(last_line) - 2:
            return 'js_comment'
        if '/*' in code_segment and '*/' not in code_segment[code_segment.rfind('/*'):]:
            return 'js_comment'

        if dq % 2 == 1:
            return 'js_str_dq'
        if sq % 2 == 1:
            return 'js_str_sq'
        if bt % 2 == 1:
            return 'js_str_bt'

        return 'js_str_dq'  # fallback: assume double-quoted

    # ── Check if inside an HTML attribute ───────────────────────────────────
    # Find the last unclosed tag
    last_tag_open  = before.rfind('<')
    last_tag_close = before.rfind('>')
    in_tag = last_tag_open > last_tag_close and last_tag_open != -1

    if in_tag:
        tag_content = before[last_tag_open:]

        # Identify the attribute name
        attr_match = re.search(
            r'(href|src|action|formaction|data|background|poster|code)\s*=\s*["\']?$',
            tag_content, re.I
        )
        if attr_match:
            attr_name = attr_match.group(1).lower()
            if attr_name in ('href', 'action', 'formaction'):
                return 'attr_href'
            if attr_name in ('src', 'data', 'background', 'poster', 'code'):
                return 'attr_src'

        return 'attr'

    # ── Check if inside a URL value ──────────────────────────────────────────
    url_indicators = ['url(', 'href=', 'src=', 'action=', 'redirect=', 'next=', 'return=']
    if any(ind in before_lower[-100:] for ind in url_indicators):
        return 'url'

    # ── Default: raw HTML ────────────────────────────────────────────────────
    return 'html'


# =============================================================================
# HTML PARSERS
# =============================================================================

class PageParser(HTMLParser):
    """Extracts JS URLs, page links, inline scripts from HTML."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url       = base_url
        self.base_domain    = urlparse(base_url).netloc
        self.js_urls        : set  = set()
        self.page_links     : set  = set()
        self.inline_scripts : list = []
        self._in_script     = False
        self._script_buf    = []

    def handle_starttag(self, tag: str, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}

        if tag == 'script':
            self._in_script = True
            self._script_buf = []
            src = a.get('src', '').strip()
            if src:
                url = self._abs(src)
                if url:
                    self.js_urls.add(url)

        elif tag == 'link':
            href = a.get('href', '').strip()
            rel  = a.get('rel', '').lower()
            as_  = a.get('as', '').lower()
            if href:
                url = self._abs(href)
                if url:
                    is_js = href.endswith(('.js', '.mjs')) or '.js?' in href
                    if 'modulepreload' in rel or ('preload' in rel and as_ == 'script') or is_js:
                        self.js_urls.add(url)

        elif tag == 'a':
            href = a.get('href', '').strip()
            if href and not href.startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:')):
                url = self._abs(href)
                if url and self._same_domain(url):
                    clean = url.split('#')[0].rstrip('/')
                    if clean:
                        self.page_links.add(clean)

    def handle_endtag(self, tag: str):
        if tag == 'script':
            self._in_script = False
            body = ''.join(self._script_buf).strip()
            if body:
                self.inline_scripts.append(body)
            self._script_buf = []

    def handle_data(self, data: str):
        if self._in_script:
            self._script_buf.append(data)

    def _abs(self, url: str) -> str:
        if not url:
            return ''
        try:
            result = urljoin(self.base_url, url.strip())
            if result.startswith(('http://', 'https://')):
                return result
        except Exception:
            pass
        return ''

    def _same_domain(self, url: str) -> bool:
        try:
            nl = urlparse(url).netloc
            return nl == self.base_domain or nl.endswith('.' + self.base_domain)
        except Exception:
            return False


class FormParser(HTMLParser):
    """
    Proper HTMLParser-based form extractor.
    Collects all forms, their fields, action, method.
    Also collects <a href> params and <button> names.
    """

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url    = base_url
        self.base_domain = urlparse(base_url).netloc
        self.forms       : list = []
        self.href_params : dict = {}   # base_url -> set of param names
        self._cur_form   = None

    def handle_starttag(self, tag: str, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}

        if tag == 'form':
            action = urljoin(self.base_url, a.get('action', '') or self.base_url)
            method = a.get('method', 'GET').upper()
            self._cur_form = {
                'action': action,
                'method': method,
                'fields': [],
            }

        elif tag in ('input', 'textarea', 'select', 'button') and self._cur_form is not None:
            name  = a.get('name', '').strip()
            ftype = a.get('type', 'text').lower()
            value = a.get('value', '')
            if name and ftype not in ('submit', 'reset', 'image', 'button'):
                self._cur_form['fields'].append({
                    'name':  name,
                    'type':  ftype,
                    'value': value,
                })

        elif tag == 'a':
            href = a.get('href', '').strip()
            if href and not href.startswith(('javascript:', 'mailto:', '#')):
                try:
                    full   = urljoin(self.base_url, href)
                    parsed = urlparse(full)
                    if parsed.netloc == self.base_domain or not parsed.netloc:
                        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        params = list(parse_qs(parsed.query).keys())
                        if params:
                            if base not in self.href_params:
                                self.href_params[base] = set()
                            self.href_params[base].update(params)
                except Exception:
                    pass

    def handle_endtag(self, tag: str):
        if tag == 'form' and self._cur_form is not None:
            # Only keep same-domain forms
            parsed = urlparse(self._cur_form['action'])
            if not parsed.netloc or parsed.netloc == self.base_domain:
                self.forms.append(self._cur_form)
            self._cur_form = None


# =============================================================================
# SELENIUM BROWSER MANAGER
# =============================================================================

class BrowserManager:
    """
    Manages a headless Chromium instance via Selenium.
    Provides JS-rendered page fetching, network request interception,
    and XSS payload injection.
    """

    def __init__(self, timeout: int = 15, log_fn=None):
        self.timeout = timeout
        self.log     = log_fn or print
        self.driver  = None
        self._lock   = threading.Lock()

    def start(self) -> bool:
        """Launch headless Chromium. Returns True on success."""
        if not SELENIUM_OK:
            self.log("[!] Selenium not installed — browser mode disabled")
            self.log("    pip install selenium webdriver-manager")
            return False

        opts = ChromeOptions()
        opts.add_argument('--headless=new')
        opts.add_argument('--no-sandbox')
        opts.add_argument('--disable-dev-shm-usage')
        opts.add_argument('--disable-gpu')
        opts.add_argument('--disable-web-security')
        opts.add_argument('--allow-running-insecure-content')
        opts.add_argument('--ignore-certificate-errors')
        opts.add_argument('--disable-blink-features=AutomationControlled')
        opts.add_argument('--window-size=1920,1080')
        opts.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36')
        opts.add_experimental_option('excludeSwitches', ['enable-automation'])
        opts.add_experimental_option('useAutomationExtension', False)

        # Enable performance logging to capture network requests
        opts.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

        try:
            # Try system chromedriver first
            try:
                service = ChromeService()
                self.driver = webdriver.Chrome(service=service, options=opts)
                self.log("[+] Chromium started (system chromedriver)")
                return True
            except Exception:
                pass

            # Try webdriver-manager auto-download
            if WDM_OK:
                service = ChromeService(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=service, options=opts)
                self.log("[+] Chromium started (webdriver-manager)")
                return True

            # Try common paths
            for path in ['/usr/bin/chromedriver', '/usr/local/bin/chromedriver',
                         'chromedriver.exe', '/snap/bin/chromium.chromedriver']:
                if os.path.exists(path):
                    service = ChromeService(executable_path=path)
                    self.driver = webdriver.Chrome(service=service, options=opts)
                    self.log(f"[+] Chromium started ({path})")
                    return True

            self.log("[!] chromedriver not found. Install: apt install chromium-driver")
            return False

        except Exception as e:
            self.log(f"[!] Failed to start Chromium: {e}")
            return False

    def stop(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    def get_page(self, url: str, wait_for_js: bool = True) -> dict:
        """
        Load URL in browser. Returns:
        {
            'html'          : str,      # final rendered HTML
            'js_urls'       : set,      # all JS URLs loaded by browser
            'page_links'    : set,      # all href links found
            'xhr_urls'      : set,      # XHR/fetch requests made
            'inline_scripts': list,     # inline script bodies
            'title'         : str,
            'final_url'     : str,
        }
        """
        if not self.driver:
            return {}

        result = {
            'html': '', 'js_urls': set(), 'page_links': set(),
            'xhr_urls': set(), 'inline_scripts': [], 'title': '', 'final_url': url
        }

        try:
            self.driver.set_page_load_timeout(self.timeout)
            self.driver.get(url)

            # Wait for page to stabilize
            if wait_for_js:
                try:
                    WebDriverWait(self.driver, min(self.timeout, 8)).until(
                        lambda d: d.execute_script('return document.readyState') == 'complete'
                    )
                    time.sleep(0.8)  # Extra wait for async JS
                except TimeoutException:
                    pass

            result['final_url'] = self.driver.current_url
            result['title']     = self.driver.title
            result['html']      = self.driver.page_source

            # ── Extract all loaded JS files from performance log ─────────────
            try:
                logs = self.driver.get_log('performance')
                for entry in logs:
                    try:
                        msg  = json.loads(entry['message'])['message']
                        meth = msg.get('method', '')
                        if meth == 'Network.requestWillBeSent':
                            req_url  = msg['params']['request']['url']
                            req_type = msg['params'].get('type', '')
                            if req_type == 'Script' or req_url.endswith(('.js', '.mjs')):
                                result['js_urls'].add(req_url)
                            elif req_type in ('XHR', 'Fetch'):
                                result['xhr_urls'].add(req_url)
                    except Exception:
                        pass
            except Exception:
                pass

            # ── Get all script src from DOM ───────────────────────────────────
            try:
                scripts = self.driver.find_elements(By.TAG_NAME, 'script')
                for s in scripts:
                    try:
                        src = s.get_attribute('src')
                        if src and src.startswith('http'):
                            result['js_urls'].add(src)
                        txt = s.get_attribute('innerHTML') or ''
                        if txt.strip():
                            result['inline_scripts'].append(txt)
                    except StaleElementReferenceException:
                        pass
            except Exception:
                pass

            # ── Get all links from DOM ────────────────────────────────────────
            try:
                links = self.driver.find_elements(By.TAG_NAME, 'a')
                base_domain = urlparse(url).netloc
                for link in links:
                    try:
                        href = link.get_attribute('href') or ''
                        if href.startswith('http'):
                            p = urlparse(href)
                            if p.netloc == base_domain or p.netloc.endswith('.' + base_domain):
                                result['page_links'].add(href.split('#')[0])
                    except StaleElementReferenceException:
                        pass
            except Exception:
                pass

            return result

        except WebDriverException as e:
            if 'net::ERR' not in str(e):
                pass  # silently ignore network errors
            return result
        except Exception:
            return result

    def get_all_network_js(self) -> set:
        """Return all JS URLs captured from browser network log."""
        js_urls = set()
        if not self.driver:
            return js_urls
        try:
            logs = self.driver.get_log('performance')
            for entry in logs:
                try:
                    msg = json.loads(entry['message'])['message']
                    if msg.get('method') == 'Network.requestWillBeSent':
                        url      = msg['params']['request']['url']
                        req_type = msg['params'].get('type', '')
                        if req_type == 'Script' or url.endswith(('.js', '.mjs')):
                            js_urls.add(url)
                except Exception:
                    pass
        except Exception:
            pass
        return js_urls

    def inject_xss(self, url: str, param: str, payload: str) -> dict:
        """
        Load URL with XSS payload injected into param.
        Checks if an alert/confirm/prompt dialog fires (= XSS confirmed).
        Also checks if payload appears raw in DOM.

        Returns: {'triggered': bool, 'in_dom': bool, 'final_url': str}
        """
        if not self.driver:
            return {'triggered': False, 'in_dom': False, 'final_url': url}

        test_url = f"{url}?{urlencode({param: payload})}"
        result   = {'triggered': False, 'in_dom': False, 'final_url': test_url}

        try:
            self.driver.set_page_load_timeout(self.timeout)

            # Dismiss any existing alert first
            try:
                self.driver.switch_to.alert.dismiss()
            except Exception:
                pass

            self.driver.get(test_url)

            # Wait briefly for JS to execute
            try:
                WebDriverWait(self.driver, 4).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                result['triggered'] = True
                alert.dismiss()
            except TimeoutException:
                pass

            # Also check DOM for unescaped payload markers
            try:
                dom = self.driver.page_source
                if '<img src=x' in dom or '<svg onload' in dom or 'onerror=alert' in dom:
                    result['in_dom'] = True
            except Exception:
                pass

        except Exception:
            pass

        return result

    def scroll_and_click(self, url: str) -> set:
        """
        Load page, scroll down to trigger lazy-loaded content,
        click ALL interactive elements (nav links, buttons, tabs, dropdowns)
        to discover more JS chunks.
        Returns set of new JS URLs discovered.
        """
        if not self.driver:
            return set()

        js_urls = set()
        visited_in_session = {url}

        try:
            self.driver.get(url)
            time.sleep(1.5)

            # Scroll to bottom in steps to trigger lazy loading
            for scroll_pct in [20, 40, 60, 80, 100]:
                self.driver.execute_script(
                    f"window.scrollTo(0, document.body.scrollHeight * {scroll_pct/100});"
                )
                time.sleep(0.4)

            js_urls.update(self.get_all_network_js())

            # Click all nav links, buttons, tabs — collect new JS each time
            clickable_selectors = [
                'nav a', 'header a', '.nav a', '.menu a', '.navbar a',
                '[role="tab"]', '[role="menuitem"]', '[role="button"]',
                'button:not([type="submit"])', '.tab', '.tab-item',
                '.dropdown-toggle', '.accordion-button', '.collapse-toggle',
                'a[href^="#"]',  # anchor links that trigger JS
                '.sidebar a', '.sidebar-menu a',
            ]

            for selector in clickable_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for elem in elements[:12]:  # limit per selector
                        try:
                            if not elem.is_displayed():
                                continue
                            self.driver.execute_script("arguments[0].click();", elem)
                            time.sleep(0.5)
                            js_urls.update(self.get_all_network_js())
                        except Exception:
                            pass
                except Exception:
                    pass

            # Also try clicking <a> links that stay on same domain (up to 15 unique paths)
            try:
                base_domain = urlparse(url).netloc
                links = self.driver.find_elements(By.TAG_NAME, 'a')
                clicked = 0
                for link in links:
                    if clicked >= 15:
                        break
                    try:
                        href = link.get_attribute('href') or ''
                        if not href or href.startswith(('javascript:', 'mailto:', '#')):
                            continue
                        parsed = urlparse(href)
                        if parsed.netloc != base_domain:
                            continue
                        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if clean in visited_in_session:
                            continue
                        visited_in_session.add(clean)
                        self.driver.execute_script("arguments[0].click();", link)
                        time.sleep(1.0)
                        js_urls.update(self.get_all_network_js())
                        clicked += 1
                        # Go back
                        self.driver.back()
                        time.sleep(0.8)
                    except Exception:
                        try:
                            self.driver.get(url)
                            time.sleep(1)
                        except Exception:
                            pass
            except Exception:
                pass

        except Exception:
            pass

        return js_urls


# =============================================================================
# CORE SCANNER
# =============================================================================

class JSScout:
    BASE_HEADERS = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/122.0.0.0 Safari/537.36'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }

    def __init__(self, target: str, output_dir: str,
                 threads: int = 10, timeout: int = 15,
                 max_pages: int = 200, depth: int = 3,
                 cookies: str = None, extra_headers: dict = None,
                 use_selenium: bool = True, log_fn=None):

        if '://' not in target:
            target = 'https://' + target
        parsed           = urlparse(target)
        self.base_url    = f"{parsed.scheme}://{parsed.netloc}"
        self.base_domain = parsed.netloc
        self.output_dir  = Path(output_dir)
        self.threads     = threads
        self.timeout     = timeout
        self.max_pages   = max_pages
        self.depth       = depth
        self.use_selenium= use_selenium
        self.log_fn      = log_fn or print
        self._lock       = threading.Lock()

        self.visited_pages   : set = set()
        self._html_page_cache: dict = {}  # url -> html for Phase 13
        self.found_js_urls   : set = set()
        self._dl_hashes      : set = set()
        self._inline_scripts : list = []  # (source_url, script_body)
        self._js_url_map     : dict = {}  # filename -> source_url

        self.session = requests.Session()
        self.session.headers.update(self.BASE_HEADERS)
        self.session.verify = False
        self.session.max_redirects = 5
        if cookies:
            for pair in cookies.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    k, _, v = pair.partition('=')
                    self.session.cookies.set(k.strip(), v.strip())
        if extra_headers:
            self.session.headers.update(extra_headers)

        # Selenium browser
        self.browser = BrowserManager(timeout=timeout, log_fn=self.log_fn) if use_selenium else None

        self.results = {
            'target':        self.base_url,
            'js_files':      [],
            'endpoints':     {},
            'secrets':       [],
            'xss_findings':  [],
            'poc_findings':  [],
            'dom_clobber':   [],
            'proto_pollution': [],
            'keywords':      {},
            'external_urls': [],
            'payload_library': XSS_PAYLOADS,
        }
        self._page_texts  = []   # accumulate page HTML for auth checks
        self._all_forms   = []   # accumulate forms for auth checks
        self.skip_auth    = False
        self.skip_advanced = False

    def log(self, msg: str):
        self.log_fn(msg)

    # =========================================================================
    # PUBLIC ENTRY
    # =========================================================================

    def run(self) -> dict:
        t0 = time.time()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'js').mkdir(exist_ok=True)

        # ── Start Selenium ────────────────────────────────────────────────────
        browser_active = False
        if self.use_selenium and self.browser:
            self.log("[*] Starting Chromium browser...")
            browser_active = self.browser.start()
            if browser_active:
                self.log("[+] Chromium ready — JS rendering enabled")
            else:
                self.log("[!] Falling back to requests-only mode")

        # ── Phase 1: Crawl ────────────────────────────────────────────────────
        self.log(f"[*] Phase 1: Crawling {self.base_url}  (max_pages={self.max_pages}, depth={self.depth})")
        self._crawl(browser_active)
        self.log(f"[+] Crawl done: {len(self.visited_pages)} pages | {len(self.found_js_urls)} JS URLs | {len(self._inline_scripts)} inline scripts")

        # ── Phase 2: Manifest probing ─────────────────────────────────────────
        self.log(f"[*] Phase 2: Probing {len(MANIFEST_PATHS)} manifest paths...")
        self._probe_manifests()
        self.log(f"[+] After manifests: {len(self.found_js_urls)} JS URLs")

        # ── Phase 3: Download JS files ────────────────────────────────────────
        self.log(f"[*] Phase 3: Downloading {len(self.found_js_urls)} JS files...")
        self._download_all(list(self.found_js_urls))
        dl = len(list((self.output_dir / 'js').glob('*.js')))
        self.log(f"[+] Downloaded {dl} unique JS files")

        # ── Phase 4: Deep JS crawl (recursive until fixed point) ──────────────
        self.log("[*] Phase 4: Deep crawl — JS→JS reference chain resolution...")
        new = self._js_deep_crawl()
        dl  = len(list((self.output_dir / 'js').glob('*.js')))
        self.log(f"[+] Deep crawl done: {len(new)} new URLs | {dl} total JS files")

        # ── Phase 4b: Browser scroll on main page to trigger lazy chunks ──────
        if browser_active:
            self.log("[*] Phase 4b: Browser scroll + interact to trigger lazy-loaded JS...")
            extra = self.browser.scroll_and_click(self.base_url)
            truly_new = extra - self.found_js_urls
            if truly_new:
                self.found_js_urls.update(truly_new)
                self.log(f"  [browser] {len(truly_new)} additional JS URLs from browser interaction")
                self._download_all(list(truly_new))
                # One more deep crawl pass
                self._js_deep_crawl()

        # ── Phase 5: Analysis ─────────────────────────────────────────────────
        js_files = sorted((self.output_dir / 'js').glob('*.js'))
        self.log(f"[*] Phase 5: Analyzing {len(js_files)} JS files + {len(self._inline_scripts)} inline scripts...")
        self._analyze_all(js_files)

        # ── Phase 6: XSS Probing ──────────────────────────────────────────────
        self.log("[*] Phase 6: Context-aware XSS parameter probing...")
        self._probe_params(browser_active)
        poc_count = len(self.results.get('poc_findings', []))
        self.log(f"[+] {poc_count} confirmed reflected XSS PoC(s) found")

        # ── Stop browser ──────────────────────────────────────────────────────
        if browser_active:
            self.browser.stop()

        # ── Phase 7: Enhanced Endpoint Extraction ─────────────────────────────
        if ENDPOINT_EXTRACTOR_OK:
            self.log("\n[*] Phase 7: Enhanced endpoint extraction from HTML + JS...")
            self._run_endpoint_extraction()
            ep_count = len(self.results.get('all_endpoints', {}).get('same_domain', []))
            self.log(f"[+] Endpoint extraction: {ep_count} same-domain endpoints discovered")
        else:
            self.log("[!] endpoint_extractor.py not found — skipping enhanced extraction")

        # ── Phase 8: Additional Vulnerability Checks ──────────────────────────
        if VULN_CHECKS_OK:
            self.log("\n[*] Phase 8: Running CORS / Redirect / Host Header / Sensitive Path checks...")
            self._run_vulnerability_checks()
            vc = self.results.get('vuln_data', {})
            cors_n  = len(vc.get('cors', []))
            redir_n = len(vc.get('open_redirect', []))
            host_n  = len(vc.get('host_header', []))
            html_n  = len(vc.get('html_injection', []))
            sens_n  = len(vc.get('sensitive_endpoints', []))
            self.log(f"[+] Vuln checks: CORS={cors_n}  Redirect={redir_n}  "
                     f"HostInject={host_n}  HTMLInject={html_n}  SensitivePaths={sens_n}")
            if cors_n or redir_n or host_n or html_n:
                self.log("")
            for f in vc.get('cors', []):
                self.log(f"  [CORS]        [{f['severity']}] {f['type']} @ {f['url'][:80]}")
                self.log(f"                {f['description']}")
                self.log(f"                Evidence: {str(f.get('evidence',''))[:120]}")
            for f in vc.get('open_redirect', []):
                self.log(f"  [REDIRECT]    [{f['severity']}] param={f['param']} @ {f['base_url'][:70]}")
                self.log(f"                PoC: {f['url'][:120]}")
                self.log(f"                Evidence: {str(f.get('evidence',''))[:120]}")
            for f in vc.get('host_header', []):
                self.log(f"  [HOST INJECT] [{f['severity']}] {f['header'][:60]} @ {f['url'][:70]}")
                self.log(f"                {f['description']}")
                self.log(f"                Evidence: {str(f.get('evidence',''))[:120]}")
            for f in vc.get('html_injection', []):
                self.log(f"  [HTML INJECT] [{f['severity']}] param={f['param']} @ {f['base_url'][:70]}")
                self.log(f"                PoC: {f['url'][:120]}")
                self.log(f"                Evidence: {str(f.get('evidence',''))[:120]}")
        else:
            self.log("[!] vulnerability_checks.py not found — skipping vuln checks")

        # ── Phase 9: Enhanced XSS Detection ───────────────────────────────────
        if XSS_DETECTOR_OK:
            self.log("\n[*] Phase 9: Running enhanced XSS detection (DOM + Reflected + Stored)...")
            self._run_xss_detection()
            xd = self.results.get('xss_data', {})
            self.log(f"[+] XSS detection: DOM={len(xd.get('dom_xss',[]))}  "
                     f"Reflected={len(xd.get('reflected_xss',[]))}  "
                     f"Stored={len(xd.get('stored_xss',[]))}")
        else:
            self.log("[!] xss_detector.py not found — skipping enhanced XSS detection")

        # ── Phase 11: Advanced Vulnerability Checks ──────────────────────────
        if ADVANCED_VULNS_OK:
            self.log("\n[*] Phase 11: Advanced scan — SQLi, SSTI, CMDi, LFI, XXE, SSRF, JWT, GraphQL,")
            self.log("                            Security Headers, CRLF, IDOR, Clickjacking,")
            self.log("                            Request Smuggling, Cache Poisoning, File Upload, Subdomain Takeover...")
            self._run_advanced_checks()
            adv = self.results.get('advanced_data', {})
            sev_map = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
            for cat, items in sorted(adv.items()):
                if not isinstance(items, list) or not items:
                    continue
                self.log(f"  [{cat.upper()}] {len(items)} finding(s):")
                for f in items:
                    icon = sev_map.get(f.get('severity',''), '⚪')
                    self.log(f"    {icon} [{f.get('severity','?')}] {f.get('type','?')}")
                    self.log(f"       URL: {str(f.get('url', f.get('base_url','')))[:100]}")
                    if f.get('param'):
                        self.log(f"       Param: {f['param']}")
                    self.log(f"       {f.get('description','')[:120]}")
                    self.log(f"       Evidence: {str(f.get('evidence',''))[:120]}")
        else:
            self.log("[!] advanced_vulns.py not found — skipping advanced checks")

        # ── Phase 12: Auth / Session / OAuth / Directory Listing / Param Discovery ──
        if AUTH_CHECKS_OK and not getattr(self, 'skip_auth', False):
            self.log("\n[*] Phase 12: Auth & Session checks (OAuth, Access Control, Dir Listing, Params)...")
            self._run_auth_checks()
            auth = self.results.get('auth_data', {})
            for cat, items in auth.items():
                if items:
                    self.log(f"  [+] {cat}: {len(items)} finding(s)")
        else:
            self.log("[!] auth_checks.py not found — skipping auth checks")

        # ── Phase 10: Report ──────────────────────────────────────────────────
        # ── Phase 13: External Tools Integration ─────────────────────────────
        if EXTERNAL_TOOLS_OK and not getattr(self, 'skip_external', False):
            try:
                orchestrator = ExternalToolsOrchestrator(
                    base_url=self.base_url,
                    output_dir=self.output_dir,
                    session=getattr(self, 'session', None),
                    log_fn=self.log,
                )
                ext_results = orchestrator.run(
                    js_dir=self.output_dir / 'js',
                    html_pages=getattr(self, '_html_page_cache', {}),
                )
                self.results['external_tools'] = ext_results
                for ep in ext_results.get('all_endpoints', []):
                    if ep not in self.results.get('endpoints', []):
                        self.results.setdefault('endpoints', []).append(ep)
                for sec in ext_results.get('all_secrets', []):
                    val = sec.get('value', sec.get('context', ''))
                    existing_vals = {s if isinstance(s, str) else s.get('value', s.get('match', ''))
                                     for s in self.results.get('secrets', [])}
                    if val not in existing_vals:
                        self.results.setdefault('secrets', []).append(sec)
            except Exception as e:
                self.log(f"[!] Phase 13 external tools error: {e}")
        else:
            self.log("[!] external_tools_integration.py not found — skipping Phase 13")

        self.log("\n[*] Phase 10: Writing comprehensive vulnerability report...")
        rp = self._write_report()
        if REPORT_GEN_OK:
            self._write_enhanced_report()

        elapsed = time.time() - t0
        poc_count = len(self.results.get('poc_findings', []))
        self.log(f"\n[✓] Done in {elapsed:.1f}s")
        adv_data = self.results.get('advanced_data', {})
        adv_total = sum(len(v) for v in adv_data.values() if isinstance(v, list))
        adv_crit  = sum(1 for fl in adv_data.values() if isinstance(fl, list)
                        for f in fl if f.get('severity') == 'CRITICAL')
        adv_high  = sum(1 for fl in adv_data.values() if isinstance(fl, list)
                        for f in fl if f.get('severity') == 'HIGH')
        vc_data   = self.results.get('vuln_data', {})
        vc_total  = sum(len(v) for v in vc_data.values() if isinstance(v, list))

        self.log(f"\n{'='*60}")
        self.log(f"  JS Scout Pro — Final Results")
        self.log(f"{'='*60}")
        self.log(f"    JS files        : {len(self.results['js_files'])}")
        self.log(f"    Endpoints       : {len(self.results['endpoints'])}")
        self.log(f"    Secrets         : {len(self.results['secrets'])}")
        self.log(f"    XSS sinks       : {len(self.results['xss_findings'])}")
        self.log(f"    Reflected XSS   : {poc_count} {'⚡' * min(poc_count,5)}")
        self.log(f"    Vuln checks     : {vc_total} findings (CORS/Redirect/HostInj/HTMLInj)")
        self.log(f"    Advanced vulns  : {adv_total} findings ({adv_crit} CRITICAL, {adv_high} HIGH)")
        if adv_crit:
            self.log(f"    🔴 CRITICAL vulns found — immediate action required!")
        self.log(f"{'='*60}")
        self.log(f"    Report          : {rp}")
        # Phase 13 summary
        ext = self.results.get('external_tools', {})
        if ext:
            ts = ext.get('tool_summary', {})
            self.log(f"{'='*60}")
            self.log(f"  Phase 13 — External Tools Summary")
            self.log(f"{'='*60}")
            self.log(f"    JS-Scan keywords      : {ts.get('js_scan_keywords', 0)}")
            self.log(f"    GoLinkFinder eps      : {ts.get('golinkfinder_eps', 0)}")
            self.log(f"    BurpJSLinkFinder eps  : {ts.get('burpjslf_eps', 0)}")
            self.log(f"    getJS JS files        : {ts.get('getjs_js_files', 0)}")
            self.log(f"    linx obfuscated       : {ts.get('linx_obfuscated', 0)}")
            self.log(f"    waybackurls total     : {ts.get('waybackurls_total', 0)}")
            self.log(f"    gau total             : {ts.get('gau_total', 0)}")
            self.log(f"    waymore JS URLs       : {ts.get('waymore_js', 0)}")
            self.log(f"    jsleak secrets        : {ts.get('jsleak_secrets', 0)}")
            self.log(f"    jsfinder subdomains   : {ts.get('jsfinder_subdomains', 0)}")
            self.log(f"    jsluice secrets       : {ts.get('jsluice_secrets', 0)}")
            self.log(f"    ── Combined endpoints : {len(ext.get('all_endpoints', []))}")
            self.log(f"    ── Combined secrets   : {len(ext.get('all_secrets', []))}")
            self.log(f"{'='*60}")
        return self.results

    # =========================================================================
    # PHASE 1: BFS CRAWLER
    # =========================================================================

    def _crawl(self, browser_active: bool):
        q             = Queue()
        self._active  = 0
        self._alock   = threading.Lock()

        def enqueue(url, depth):
            with self._alock:
                self._active += 1
            q.put((url, depth))

        def done_one():
            with self._alock:
                self._active -= 1

        self.visited_pages.add(self.base_url)
        enqueue(self.base_url, 0)

        def worker():
            while True:
                try:
                    url, depth = q.get(timeout=2.0)
                except Empty:
                    with self._alock:
                        if self._active == 0:
                            return
                    continue
                try:
                    new_pages = self._crawl_page(url, depth, browser_active)
                    if depth < self.depth:
                        for link in new_pages:
                            with self._lock:
                                if link not in self.visited_pages and len(self.visited_pages) < self.max_pages:
                                    self.visited_pages.add(link)
                                    enqueue(link, depth + 1)
                finally:
                    done_one()

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = [pool.submit(worker) for _ in range(self.threads)]
            for f in futs:
                f.result()

    def _crawl_page(self, url: str, depth: int, browser_active: bool) -> set:
        """Fetch one page. Returns new page links."""
        new_js    = set()
        new_pages = set()

        # ── Try Selenium first for JS-rendered content ────────────────────────
        html_content = None
        if browser_active and self.browser and depth <= 1:
            try:
                bres = self.browser.get_page(url, wait_for_js=True)
                if bres.get('html'):
                    html_content = bres['html']
                    # Collect JS URLs the browser actually loaded
                    new_js.update(bres.get('js_urls', set()))
                    new_js.update(bres.get('xhr_urls', set()))
                    # Collect inline scripts
                    for inline in bres.get('inline_scripts', []):
                        if inline.strip():
                            with self._lock:
                                self._inline_scripts.append((url, inline))
                            new_js.update(extract_js_urls(inline, url))
                    # Page links from browser
                    for link in bres.get('page_links', set()):
                        ext = Path(urlparse(link).path).suffix.lower()
                        if ext not in SKIP_EXTS:
                            new_pages.add(link)
                    self.log(f"  [browser] {url[:75]}  +{len(new_js)} JS  +{len(new_pages)} links")
            except Exception as e:
                html_content = None

        # ── Fallback / supplement with requests ───────────────────────────────
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code >= 400:
                with self._lock:
                    self.found_js_urls.update(js for js in new_js if js.endswith(('.js','.mjs')))
                return new_pages
        except Exception as e:
            self.log(f"  [!] {url[:70]} — {type(e).__name__}")
            return new_pages

        ct      = resp.headers.get('content-type', '').lower()
        content = resp.text[:5_000_000]

        # If Selenium already got HTML, only use requests for regex sweep
        if not html_content:
            html_content = content

        if 'html' in ct and html_content:
            parser = PageParser(url)
            try:
                parser.feed(html_content)
            except Exception:
                pass
            new_js.update(parser.js_urls)
            for inline in parser.inline_scripts:
                with self._lock:
                    self._inline_scripts.append((url, inline))
                new_js.update(extract_js_urls(inline, url))
            for link in parser.page_links:
                ext = Path(urlparse(link).path).suffix.lower()
                if ext not in SKIP_EXTS:
                    new_pages.add(link)

        new_js.update(extract_js_urls(content, url))

        with self._lock:
            added = len(new_js - self.found_js_urls)
            self.found_js_urls.update(new_js)

        if not browser_active:
            self.log(f"  [page] {resp.status_code} {url[:75]}  +{len(new_js)} JS")

        return new_pages

    # =========================================================================
    # PHASE 2: MANIFEST PROBING
    # =========================================================================

    def _probe_manifests(self):
        def probe(path: str):
            url = self.base_url + path
            try:
                resp = self.session.get(url, timeout=min(self.timeout, 5))
                if resp.status_code != 200:
                    return
                ct = resp.headers.get('content-type', '').lower()
                if 'json' in ct:
                    try:
                        data = resp.json()
                        self._extract_js_from_json(data, url)
                    except Exception:
                        pass
                new_js = extract_js_urls(resp.text, url)
                with self._lock:
                    added = len(new_js - self.found_js_urls)
                    if added:
                        self.found_js_urls.update(new_js)
                        self.log(f"  [manifest] {path}  +{added}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            list(pool.map(probe, MANIFEST_PATHS))

    def _extract_js_from_json(self, data, base_url: str):
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, str) and (v.endswith('.js') or '.js?' in v):
                    url = urljoin(base_url, v)
                    if url.startswith('http'):
                        with self._lock:
                            self.found_js_urls.add(url)
                elif isinstance(v, (dict, list)):
                    self._extract_js_from_json(v, base_url)
        elif isinstance(data, list):
            for item in data:
                self._extract_js_from_json(item, base_url)

    # =========================================================================
    # PHASE 3: DOWNLOAD
    # =========================================================================

    def _download_all(self, urls: list):
        js_dir         = self.output_dir / 'js'
        existing_names : set = {f.name for f in js_dir.glob('*.js')}

        def dl(url: str):
            # Only download same-domain or CDN JS
            parsed = urlparse(url)
            if not url.startswith(('http://', 'https://')):
                return
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code != 200:
                    return
                data = resp.content
                if not data or len(data) < 10:
                    return

                h = hashlib.sha256(data).hexdigest()[:16]
                with self._lock:
                    if h in self._dl_hashes:
                        return
                    self._dl_hashes.add(h)

                path = urlparse(url).path
                name = os.path.basename(path) or 'script.js'
                if not name.endswith(('.js', '.mjs')):
                    name += '.js'
                name = re.sub(r'[^\w.\-]', '_', name)[:120]
                if not name or name in ('.js', '_.js'):
                    name = 'script.js'

                with self._lock:
                    if name in existing_names:
                        stem = name[:-3]
                        i = 1
                        while f'{stem}_{i}.js' in existing_names:
                            i += 1
                        name = f'{stem}_{i}.js'
                    existing_names.add(name)

                (js_dir / name).write_bytes(data)
                with self._lock:
                    self._js_url_map[name] = url
                self.log(f"  [dl] {name}  {len(data)/1024:.1f}KB  <- {url[:70]}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            pool.map(dl, urls)

    # =========================================================================
    # PHASE 4: RECURSIVE JS DEEP CRAWL
    # =========================================================================

    def _js_deep_crawl(self) -> set:
        """
        Iteratively scan downloaded JS files for references to more JS.
        Continues until no new URLs found (fixed-point convergence).
        """
        all_new: set = set()
        already_scanned: set = set()

        for iteration in range(1, 11):
            newly_discovered: set = set()

            for js_file in list((self.output_dir / 'js').glob('*.js')):
                if js_file.name in already_scanned:
                    continue
                already_scanned.add(js_file.name)
                try:
                    js_content = js_file.read_text(encoding='utf-8', errors='replace')
                    found = extract_js_urls(js_content, self.base_url)
                    with self._lock:
                        truly_new = found - self.found_js_urls
                        if truly_new:
                            self.found_js_urls.update(truly_new)
                            newly_discovered.update(truly_new)
                            all_new.update(truly_new)
                except Exception:
                    pass

            if not newly_discovered:
                self.log(f"  [deep crawl] Fixed point after {iteration} pass(es) — {len(all_new)} extra URLs found")
                break

            self.log(f"  [deep crawl] Pass {iteration}: {len(newly_discovered)} new JS URLs — downloading...")
            self._download_all(list(newly_discovered))

        return all_new

    # =========================================================================
    # PHASE 5: ANALYSIS
    # =========================================================================

    def _analyze_all(self, js_files: list):
        endpoints = {}
        secrets   = []
        xss       = []
        dom_cb    = []
        proto     = []
        keywords  = defaultdict(list)
        ext_urls  = set()
        stats     = []

        # Analyze downloaded JS files
        for js_file in js_files:
            try:
                content = js_file.read_text(encoding='utf-8', errors='replace')
                fname   = js_file.name

                for ep in self._find_endpoints(content):
                    if ep not in endpoints:
                        endpoints[ep] = []
                    if fname not in endpoints[ep]:
                        endpoints[ep].append(fname)

                fs = self._find_secrets(content, fname);   secrets.extend(fs)
                fx = self._find_xss(content, fname);       xss.extend(fx)
                fd = self._find_dom_clobber(content, fname); dom_cb.extend(fd)
                fp = self._find_proto(content, fname);     proto.extend(fp)

                lines = content.split('\n')
                for kw, pat in KEYWORDS.items():
                    for i, line in enumerate(lines, 1):
                        if pat.search(line):
                            keywords[kw].append({'file': fname, 'line': i, 'content': line.strip()[:200]})
                            if len(keywords[kw]) >= 15:
                                break

                for m in re.finditer(r'["\'`](https?://[a-zA-Z0-9._\-/:%?#=&+@\[\]{}]+)["\'`]', content):
                    u = m.group(1)
                    if urlparse(u).netloc != self.base_domain:
                        ext_urls.add(u)

                n_ep = sum(1 for files in endpoints.values() if fname in files)
                n_sec = len(fs); n_xss = len(fx)
                stats.append({'name': fname, 'size': js_file.stat().st_size,
                              'endpoints': n_ep, 'secrets': n_sec,
                              'xss_sinks': n_xss, 'minified': self._is_minified(content),
                              'source_url': self._js_url_map.get(fname, '')})
                self.log(f"  [analyze] {fname}: {n_ep} eps  {n_sec} secrets  {n_xss} XSS sinks")

            except Exception as e:
                self.log(f"  [!] {js_file.name}: {e}")

        # Also analyze inline scripts captured during crawl
        inline_xss_count = 0
        seen_inline: set = set()
        for source_url, script_body in self._inline_scripts:
            h = hashlib.md5(script_body.encode()).hexdigest()[:12]
            if h in seen_inline:
                continue
            seen_inline.add(h)
            fx = self._find_xss(script_body, f'inline@{urlparse(source_url).path}')
            if fx:
                xss.extend(fx)
                inline_xss_count += len(fx)
                # Add endpoints from inline scripts too
                for ep in self._find_endpoints(script_body):
                    if ep not in endpoints:
                        endpoints[ep] = []
                    endpoints[ep].append(f'inline@{urlparse(source_url).path}')

        if inline_xss_count:
            self.log(f"  [inline scripts] {inline_xss_count} additional XSS sinks found in inline scripts")

        self.results.update({
            'endpoints':     endpoints, 'secrets':        secrets,
            'xss_findings':  xss,       'dom_clobber':    dom_cb,
            'proto_pollution': proto,   'keywords':       dict(keywords),
            'external_urls': list(ext_urls), 'js_files':  stats,
            'total_js':      len(js_files),
            'visited_pages': sorted(self.visited_pages),
        })

    def _find_endpoints(self, content: str) -> set:
        found = set()
        for pat in ENDPOINT_PATTERNS:
            for m in pat.finditer(content):
                ep = m.group(1).strip()
                if 3 < len(ep) < 200:
                    found.add(ep)
        return found

    def _find_secrets(self, content: str, fname: str) -> list:
        found = []; seen = set()
        SKIP = {'placeholder','example','changeme','your_api_key','your_secret',
                'your_token','undefined','null','true','false','test','demo','xxx'}
        for pat, stype, severity in SECRET_PATTERNS:
            for m in pat.finditer(content):
                val = (m.group(1) if m.lastindex else m.group(0)).strip()
                if val.lower() in SKIP or len(val) < 4:
                    continue
                key = f'{fname}:{stype}:{val[:20]}'
                if key in seen: continue
                seen.add(key)
                line = content[:m.start()].count('\n') + 1
                ctx  = content[max(0,m.start()-60):m.end()+60].replace('\n',' ').strip()
                found.append({'file': fname, 'type': stype, 'severity': severity,
                              'value': val[:120], 'line': line, 'context': ctx[:250]})
        return found

    def _is_xss_false_positive(self, match_text: str, line: str, nearby: str, sink: str) -> tuple:
        """Returns (is_fp: bool, reason: str)."""
        # 1. Inside single-line comment
        comment_pos = line.find('//')
        if comment_pos != -1:
            match_pos = line.find(match_text[:30])
            if match_pos != -1 and match_pos > comment_pos:
                return True, "inside comment"

        # 2. Inside block comment
        if '/*' in nearby and '*/' not in nearby.split('/*')[-1]:
            return True, "inside block comment"

        # 3. Sanitizer nearby
        for san in XSS_SANITIZERS:
            if san in nearby:
                return True, f"sanitizer present: {san}"

        # 4. innerHTML with static string
        if sink == 'innerHTML' and re.search(r'\.innerHTML\s*=\s*["\']', line):
            return True, "innerHTML assigned static string"

        # 5. eval in typeof check
        if sink == 'eval' and 'typeof' in line and 'eval' in line:
            return True, "typeof eval check"

        # 6. eval on string literal
        if sink == 'eval' and re.search(r"eval\s*\(\s*['\"]", line):
            return True, "eval of string literal"

        # 7. setTimeout/setInterval with function reference (not string)
        if sink in ('setTimeout(str)', 'setInterval(str)'):
            m = re.search(r'(?:setTimeout|setInterval)\s*\(\s*([^,\)]+)', line)
            if m:
                arg = m.group(1).strip()
                if not (arg.startswith(("'", '"')) or '+' in arg):
                    return True, "timeout with fn reference"

        # 8. location.href with static URL
        if sink == 'location.href=':
            if re.search(r'location(?:\.href)?\s*=\s*["\'](?:/|https?:)', line):
                return True, "location assigned static URL"

        # 9. $.html() getter (no args)
        if sink == '$.html()':
            if re.search(r'\.html\s*\(\s*\)', line):
                return True, "$.html() getter call"

        # 10. innerHTML with template literal (no ${})
        if sink == 'innerHTML' and re.search(r'\.innerHTML\s*=\s*`[^`$]*`', line):
            return True, "innerHTML with static template literal"

        # 11. Safe variable names
        safe_names = ['template', 'staticHtml', 'safeHtml', 'sanitized', 'purified',
                      'escaped', 'STATIC_', 'TEMPLATE_', 'SVG_', 'defaultHtml']
        for sv in safe_names:
            if sv.lower() in match_text.lower():
                return True, f"safe variable name: {sv}"

        # 12. postMessage with origin check nearby
        if sink == 'postMessage listener':
            origin_checks = ['event.origin', 'e.origin', 'origin ===', 'origin !==',
                             'trustedOrigins', 'allowedOrigins', 'ALLOWED_ORIGINS']
            if any(oc in nearby for oc in origin_checks):
                return True, "postMessage has origin check"

        return False, ""

    def _find_xss(self, content: str, fname: str) -> list:
        found = []; seen = set()
        lines = content.split('\n')
        fp_count = 0

        for pat, sink, severity in XSS_SINKS:
            for m in pat.finditer(content):
                line_no = content[:m.start()].count('\n') + 1
                line    = lines[line_no - 1] if line_no <= len(lines) else ''
                nearby  = content[max(0, m.start()-200):m.end()+200]

                is_fp, reason = self._is_xss_false_positive(m.group(0), line, nearby, sink)
                if is_fp:
                    fp_count += 1
                    continue

                key = f'{sink}:{line_no}'
                if key in seen: continue
                seen.add(key)

                # Check for source→sink flow
                confirmed = any(src_pat.search(nearby) for src_pat, _ in XSS_SOURCES)

                found.append({
                    'file':           fname,
                    'sink':           sink,
                    'severity':       severity,
                    'line':           line_no,
                    'match':          m.group(0)[:120],
                    'context':        line.strip()[:200],
                    'confirmed_flow': confirmed,
                })

        if fp_count:
            self.log(f"  ↳ {fp_count} XSS false positive(s) suppressed in {fname}")

        return found

    def _find_dom_clobber(self, content: str, fname: str) -> list:
        found = []
        DOM_CLOBBER_PATS = [
            re.compile(r'document\[["\'`](\w+)["\'`]\]', re.I),
            re.compile(r'window\[["\'`](\w+)["\'`]\]', re.I),
            re.compile(r'getElementById\s*\(\s*["\'`](\w+)["\'`]\s*\)(?!\.value)', re.I),
        ]
        SAFE_IDS = {'getElementById', 'body', 'head', 'html', 'title', 'location',
                    'cookie', 'domain', 'referrer', 'URL', 'characterSet'}
        seen = set()
        for pat in DOM_CLOBBER_PATS:
            for m in pat.finditer(content):
                name = m.group(1) if m.lastindex else m.group(0)
                if name in SAFE_IDS: continue
                key = f'{fname}:{name}'
                if key in seen: continue
                seen.add(key)
                line = content[:m.start()].count('\n') + 1
                found.append({'file': fname, 'name': name, 'line': line,
                              'context': m.group(0)[:150]})
        return found

    def _find_proto(self, content: str, fname: str) -> list:
        PROTO_PATS = [
            re.compile(r'__proto__\s*\[', re.I),
            re.compile(r'constructor\s*\[\s*["\']prototype["\']', re.I),
            re.compile(r'Object\.assign\s*\(\s*\w+\.prototype', re.I),
            re.compile(r'merge\s*\(\s*\w+\s*,\s*JSON\.parse', re.I),
        ]
        found = []
        for pat in PROTO_PATS:
            for m in pat.finditer(content):
                line = content[:m.start()].count('\n') + 1
                found.append({'file': fname, 'line': line, 'context': m.group(0)[:150]})
        return found

    def _is_minified(self, content: str) -> bool:
        lines = content.split('\n')
        if not lines: return False
        avg_len = sum(len(l) for l in lines) / len(lines)
        return avg_len > 200

    # =========================================================================
    # PHASE 6: CONTEXT-AWARE XSS PARAMETER PROBING
    # =========================================================================

    _PROBE_CANARY  = 'jsSc0utXxZ99'   # alphanumeric — never filtered
    _PROBE_MARKER  = 'JSSCOUT_XSS_7x9z'

    def _probe_params(self, browser_active: bool):
        """
        Phase 6: Full context-aware reflected XSS detection.

        For each (url, param):
          1. Send canary → if not reflected → skip
          2. detect_reflection_context() → find WHERE it's reflected
          3. Pick payloads from CONTEXT_PAYLOADS matching that context
          4. Send each payload → check raw reflection
          5. If browser active: also actually load in browser to confirm alert fires
          6. Store confirmed PoC with exact URL, param, payload, context, evidence
        """

        COMMON_PARAMS = [
            'q','s','search','query','keyword','term','name','user','username',
            'input','text','msg','message','data','value','comment','content',
            'url','redirect','next','return','ref','from','to','back',
            'email','title','body','subject','description','id','page','p',
            'token','action','type','category','tag','filter','sort','order',
            'lang','locale','format','view','mode','tab','section','code','key',
            'file','path','dir','target','dest','redir','error','err','status',
            't','k','v','n','c','r','i','j','m','x','y','z',
        ]

        # probe_targets: base_url -> {'real': set(), 'common': set()}
        probe_targets: dict = {}

        def add_target(base: str, real=None, common=None):
            if base not in probe_targets:
                probe_targets[base] = {'real': set(), 'common': set()}
            if real:
                probe_targets[base]['real'].update(p for p in real if p)
            if common:
                probe_targets[base]['common'].update(p for p in common if p)

        # ── Collect from visited pages ────────────────────────────────────────
        for url in list(self.visited_pages):
            parsed = urlparse(url)
            if parsed.netloc != self.base_domain:
                continue
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            real = list(parse_qs(parsed.query).keys())
            add_target(base, real=real, common=COMMON_PARAMS)

        # ── Collect from JS endpoints ─────────────────────────────────────────
        for ep in list(self.results.get('endpoints', {}).keys()):
            if ep.startswith('/') or ep.startswith(self.base_url):
                full = urljoin(self.base_url, ep) if ep.startswith('/') else ep
                p    = urlparse(full)
                if p.netloc and p.netloc != self.base_domain:
                    continue
                base = f"{p.scheme or 'http'}://{p.netloc or self.base_domain}{p.path}"
                real = list(parse_qs(p.query).keys())
                add_target(base, real=real, common=COMMON_PARAMS)

        # ── Form extraction: fetch ALL same-domain pages ───────────────────────
        pages_to_scan = [
            u for u in list(self.visited_pages)
            if urlparse(u).netloc == self.base_domain
        ][:80]

        self.log(f"  [probe] Extracting forms from {len(pages_to_scan)} pages...")
        page_cache: dict = {}

        def fetch_page(url: str):
            try:
                r = self.session.get(url, timeout=min(self.timeout, 8))
                if r.status_code < 400 and 'html' in r.headers.get('content-type', '').lower():
                    page_cache[url] = r.text
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=min(self.threads, 8)) as pool:
            pool.map(fetch_page, pages_to_scan)

        for page_url, html in page_cache.items():
            parser = FormParser(page_url)
            try:
                parser.feed(html)
            except Exception:
                pass

            # Forms
            for form in parser.forms:
                base   = form['action'].split('?')[0]
                fields = [f['name'] for f in form['fields']]
                real_params = list(parse_qs(urlparse(form['action']).query).keys()) + fields
                add_target(base, real=real_params, common=COMMON_PARAMS[:25])

            # href params
            for base, params in parser.href_params.items():
                add_target(base, real=list(params))

            # Also scan inline JS on the page for param patterns
            for m in re.finditer(r'["\'/]([^"\']+)\?([a-zA-Z_]\w{0,30})=', html):
                path  = m.group(1)
                param = m.group(2)
                if '/' in path or path.endswith(('.php', '.asp', '.html', '.jsp')):
                    full = urljoin(page_url, path)
                    p    = urlparse(full)
                    if p.netloc == self.base_domain or not p.netloc:
                        base = f"{p.scheme or 'http'}://{p.netloc or self.base_domain}{p.path}"
                        add_target(base, real=[param])

        # ── Build flat probe list — real params FIRST ─────────────────────────
        all_pairs: list = []
        for base, psets in probe_targets.items():
            ordered = list(psets['real']) + [
                p for p in psets['common'] if p not in psets['real']
            ]
            for param in ordered[:60]:
                all_pairs.append((base, param))

        self.log(f"  [probe] {len(all_pairs)} (url,param) pairs across {len(probe_targets)} URLs")
        self.log(f"  [probe] Strategy: canary→context-detect→context-matched payloads" +
                 (" + browser XSS confirmation" if browser_active else ""))

        all_poc  = []
        poc_lock = threading.Lock()
        seen_poc : set = set()

        def probe_pair(args):
            base, param = args
            pt = min(self.timeout, 8)

            # ── Get baseline response for existing params ──────────────────────
            existing_params = {}
            try:
                p = urlparse(base)
                existing_params = {k: v[0] for k, v in parse_qs(p.query).items()}
            except Exception:
                pass

            # ── Stage 1: canary check ─────────────────────────────────────────
            canary_params = dict(existing_params)
            canary_params[param] = self._PROBE_CANARY
            canary_url = f"{base}?{urlencode(canary_params)}"
            try:
                cr = self.session.get(canary_url, timeout=pt, allow_redirects=True)
                if self._PROBE_CANARY not in cr.text:
                    return   # Not reflected at all — skip
                canary_body = cr.text
            except Exception:
                return

            # ── Stage 2: detect WHERE it's reflected ──────────────────────────
            contexts = detect_reflection_context(canary_body, self._PROBE_CANARY)
            self.log(f"  [canary] REFLECTED {base}?{param}=... → context: {contexts}")

            # ── Stage 3: send context-matched payloads ────────────────────────
            for ctx in contexts:
                payloads = CONTEXT_PAYLOADS.get(ctx, CONTEXT_PAYLOADS['unknown'])
                for payload in payloads:
                    # Embed a detectable marker in payload
                    marked_payload = payload.replace('alert(1)', f'alert("{self._PROBE_MARKER}")')
                    if self._PROBE_MARKER not in marked_payload:
                        # Payload doesn't use alert(1) — use as-is but check for raw reflection
                        marked_payload = payload

                    test_params = dict(existing_params)
                    test_params[param] = marked_payload
                    test_url = f"{base}?{urlencode(test_params)}"

                    try:
                        resp = self.session.get(test_url, timeout=pt, allow_redirects=True)
                        body = resp.text

                        # Check raw reflection of the payload (not escaped)
                        raw_payload_reflected = False
                        # Check some key parts of payload appear unescaped
                        payload_parts = [p for p in [
                            '<img', '<svg', '<script', 'onerror=', 'onload=',
                            'javascript:', 'alert(', 'onmouseover='
                        ] if p in payload]

                        if payload_parts:
                            raw_payload_reflected = any(part in body for part in payload_parts)
                        elif self._PROBE_MARKER in body:
                            raw_payload_reflected = True

                        # Extra: check MARKER is not escaped
                        if self._PROBE_MARKER in body:
                            pos    = body.find(self._PROBE_MARKER)
                            nearby = body[max(0, pos-80):pos+120]
                            if any(esc in nearby for esc in ['&lt;', '&gt;', '&amp;', '%3C', '%3E', '\\u003c']):
                                raw_payload_reflected = False

                        if not raw_payload_reflected:
                            continue

                        dedup_key = f"{base}:{param}:{ctx}"
                        confirmed_by_browser = False

                        # ── Stage 4: Browser confirmation ──────────────────────
                        if browser_active and self.browser:
                            try:
                                bres = self.browser.inject_xss(base, param, payload)
                                confirmed_by_browser = bres.get('triggered', False) or bres.get('in_dom', False)
                            except Exception:
                                pass

                        with poc_lock:
                            if dedup_key in seen_poc:
                                break
                            seen_poc.add(dedup_key)
                            poc = {
                                'url':                  test_url,
                                'base':                 base,
                                'param':                param,
                                'payload':              marked_payload,
                                'context':              ctx,
                                'browser_confirmed':    confirmed_by_browser,
                                'status':               resp.status_code,
                                'evidence':             body[max(0, body.find(payload[:20]) - 80): body.find(payload[:20]) + 160].strip()[:300] if payload[:20] in body else '',
                            }
                            all_poc.append(poc)

                        conf_str = " [BROWSER CONFIRMED ✓]" if confirmed_by_browser else ""
                        self.log(f"  [⚡ XSS FOUND] {base}  param={param}  ctx={ctx}{conf_str}")
                        self.log(f"    PoC: {test_url[:120]}")
                        break  # One confirmed payload per context is enough

                    except Exception:
                        pass

        with ThreadPoolExecutor(max_workers=min(self.threads, 8)) as pool:
            pool.map(probe_pair, all_pairs)

        self.log(f"  [probe] Complete — {len(all_poc)} XSS PoC(s)")
        self.results['poc_findings'] = all_poc
        for finding in self.results['xss_findings']:
            finding['poc_urls'] = all_poc[:5]

    # =========================================================================
    # PHASE 7: ENHANCED ENDPOINT EXTRACTION
    # =========================================================================

    def _run_endpoint_extraction(self):
        """
        Phase 7: Run comprehensive endpoint extraction using the EndpointCollector.
        Processes all visited pages (HTML) and downloaded JS files.
        Saves structured endpoint data to endpoints.json and endpoints.txt.
        """
        if not ENDPOINT_EXTRACTOR_OK:
            return

        collector = EndpointCollector(
            target_url=self.base_url,
            session=self.session,
            base_url=self.base_url,
        )

        # Process HTML pages already visited during crawl
        pages_list = list(self.visited_pages)[:80]  # Limit to avoid re-fetching too many
        self.log(f"  [endpoints] Processing {len(pages_list)} crawled pages for endpoint extraction...")

        def fetch_and_collect(url):
            try:
                r = self.session.get(url, timeout=min(self.timeout, 8), allow_redirects=True)
                if r.status_code < 400 and 'html' in r.headers.get('content-type', '').lower():
                    collector.collect_from_html(r.text, url)
            except Exception:
                pass

        from concurrent.futures import ThreadPoolExecutor as _TPE
        with _TPE(max_workers=min(self.threads, 8)) as pool:
            pool.map(fetch_and_collect, pages_list)

        # Process downloaded JS files
        js_dir = self.output_dir / 'js'
        if js_dir.exists():
            collector.collect_from_js_dir(js_dir)

        # Save the endpoint report
        ep_summary = collector.save_report(self.output_dir)
        self.results['all_endpoints'] = ep_summary

        # Merge JS-discovered endpoints into existing results
        js_ep = ep_summary.get('js_endpoints', [])
        for item in js_ep:
            url = item.get('url', '')
            if url and url not in self.results['endpoints']:
                self.results['endpoints'][url] = [item.get('source', '')]

        # Store param_map for use by vulnerability checks
        self.results['param_map'] = ep_summary.get('param_map', {})

        self.log(f"  [endpoints] Total unique endpoints: {ep_summary['stats']['total']}")
        self.log(f"  [endpoints] Same-domain: {ep_summary['stats']['same_domain']}")
        self.log(f"  [endpoints] JS-discovered: {ep_summary['stats']['js_endpoints']}")
        self.log(f"  [endpoints] Forms found: {ep_summary['stats']['forms']}")
        self.log(f"  [endpoints] Dynamic patterns: {ep_summary['stats']['dynamic']}")

    # =========================================================================
    # PHASE 8: ADDITIONAL VULNERABILITY CHECKS
    # =========================================================================

    def _run_vulnerability_checks(self):
        """
        Phase 8: Run CORS, Open Redirect, Host Header Injection,
        and Sensitive Endpoint Discovery checks.
        """
        if not VULN_CHECKS_OK:
            return

        checker = VulnerabilityChecker(
            target_url=self.base_url,
            session=self.session,
            threads=self.threads,
            timeout=self.timeout,
            log_fn=self.log,
        )

        # Collect URLs to check — same-domain URLs from endpoints
        all_ep = self.results.get('all_endpoints', {})
        same_domain_urls = all_ep.get('same_domain', [])[:40]

        # Param map for redirect testing
        param_map = self.results.get('param_map', {})

        vuln_findings = checker.run_all(
            urls_to_check=same_domain_urls,
            param_map=param_map,
        )
        self.results['vuln_data'] = vuln_findings

        # Save vulnerability findings JSON
        (self.output_dir / 'vulnerability_findings.json').write_text(
            json.dumps(vuln_findings, indent=2, default=str),
            encoding='utf-8',
        )

    # =========================================================================
    # PHASE 12: AUTH / SESSION / OAUTH / ACCESS CONTROL
    # =========================================================================

    def _run_auth_checks(self):
        """Phase 12: OAuth, session fixation, broken access control, dir listing, param discovery."""
        if not AUTH_CHECKS_OK:
            return

        # Collect JS content for param discovery
        js_content = ''
        js_dir = self.output_dir / 'js'
        if js_dir.exists():
            for jf in list(js_dir.glob('*.js'))[:10]:
                try:
                    js_content += jf.read_text(encoding='utf-8', errors='replace')[:30000]
                except Exception:
                    pass

        # Collect all page content
        page_content = ' '.join(getattr(self, '_page_texts', [])[:5])

        # Find login URL
        login_url = None
        for url in self.visited_pages:
            if re.search(r'/(login|signin|auth|account)', url, re.I):
                login_url = url
                break

        checker = AuthChecker(
            session=self.session,
            timeout=self.timeout,
            log_fn=self.log,
        )

        all_ep = self.results.get('all_endpoints', {})
        all_urls = (all_ep.get('same_domain', []) +
                    list(self.visited_pages))[:80]

        auth_findings = checker.run_all(
            base_url=self.base_url,
            page_content=page_content,
            all_urls=all_urls,
            forms=getattr(self, '_all_forms', []),
            js_content=js_content,
            login_url=login_url,
        )

        self.results['auth_data'] = auth_findings

        # Save to disk
        (self.output_dir / 'auth_findings.json').write_text(
            json.dumps(auth_findings, indent=2, default=str),
            encoding='utf-8',
        )

    # =========================================================================
    # PHASE 11: ADVANCED VULNERABILITY CHECKS
    # =========================================================================

    def _run_advanced_checks(self):
        """
        Phase 11: Run comprehensive advanced vulnerability detection.
        Covers: SQLi, SSTI, CMDi, LFI/Path Traversal, XXE, SSRF,
                JWT, GraphQL, Security Headers, CRLF, IDOR, Clickjacking,
                Request Smuggling, Cache Poisoning, File Upload, Subdomain Takeover,
                Information Disclosure.
        """
        if not ADVANCED_VULNS_OK:
            return

        checker = AdvancedVulnChecker(
            target_url=self.base_url,
            session=self.session,
            threads=self.threads,
            timeout=self.timeout,
            log_fn=self.log,
        )

        # Build inputs from crawler results
        all_ep       = self.results.get('all_endpoints', {})
        same_domain  = all_ep.get('same_domain', [])[:60]
        param_map    = self.results.get('param_map', {})
        forms        = self.results.get('forms', [])
        cookies      = dict(self.session.cookies)

        # Collect response bodies for JWT token hunting
        response_bodies = []
        for url in ([self.base_url] + same_domain[:10]):
            try:
                r = self.session.get(url, timeout=self.timeout, verify=False)
                response_bodies.append(r.text)
            except Exception:
                pass

        adv_findings = checker.run_all(
            urls_to_check=same_domain,
            param_map=param_map,
            forms=forms,
            cookies=cookies,
            response_bodies=response_bodies,
        )

        self.results['advanced_data'] = adv_findings

        # Persist to disk
        (self.output_dir / 'advanced_findings.json').write_text(
            json.dumps(adv_findings, indent=2, default=str),
            encoding='utf-8',
        )

    # =========================================================================
    # PHASE 9: ENHANCED XSS DETECTION
    # =========================================================================

    def _run_xss_detection(self):
        """
        Phase 9: Run comprehensive XSS detection:
        - DOM-based XSS static analysis on JS files
        - Reflected XSS probing on URL parameters
        - Stored XSS probing via forms
        """
        if not XSS_DETECTOR_OK:
            return

        detector = XSSDetector(
            target_url=self.base_url,
            session=self.session,
            timeout=self.timeout,
            threads=self.threads,
            use_browser=self.use_selenium,
            log_fn=self.log,
        )

        # 1. DOM XSS analysis on downloaded JS files
        js_files = sorted((self.output_dir / 'js').glob('*.js'))
        if js_files:
            detector.analyze_js_files([str(f) for f in js_files])

        # 2. Reflected XSS probing
        # Collect (url, param) pairs from all sources
        url_param_pairs = []
        seen_pairs = set()

        # From visited pages with query params
        for url in self.visited_pages:
            parsed = urlparse(url)
            if parsed.netloc == self.base_domain:
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                for param in parse_qs(parsed.query).keys():
                    key = f"{base}:{param}"
                    if key not in seen_pairs:
                        seen_pairs.add(key)
                        url_param_pairs.append((base, param))

        # From param_map (forms + href params)
        for base, params in self.results.get('param_map', {}).items():
            for param in list(params)[:20]:
                key = f"{base}:{param}"
                if key not in seen_pairs:
                    seen_pairs.add(key)
                    url_param_pairs.append((base, param))

        # Add common params to main URL
        common_params = [
            'q', 'search', 'query', 'id', 'name', 'input', 'text', 'msg',
            'url', 'redirect', 'next', 'page', 'token', 'ref', 'lang', 'keyword',
            'term', 'filter', 'type', 'category', 'sort', 'order', 'view', 'tab',
        ]
        for param in common_params:
            key = f"{self.base_url}:{param}"
            if key not in seen_pairs:
                seen_pairs.add(key)
                url_param_pairs.append((self.base_url, param))

        if url_param_pairs:
            detector.probe_reflected(url_param_pairs[:200])  # Cap at 200 pairs

        # 3. Stored XSS probing via forms
        all_ep = self.results.get('all_endpoints', {})
        forms  = all_ep.get('forms', [])
        if forms:
            detector.probe_stored(forms)

        # Store XSS data in results
        xss_summary = detector.get_summary()
        self.results['xss_data'] = xss_summary['findings']

        # Merge DOM XSS findings into existing xss_findings (de-dup by sink+line+file)
        existing_keys = {f"{f['sink']}:{f['line']}:{f['file']}"
                         for f in self.results.get('xss_findings', [])}
        for f in xss_summary['findings'].get('dom_xss', []):
            key = f"{f['sink']}:{f['line']}:{f['file']}"
            if key not in existing_keys:
                self.results['xss_findings'].append(f)
                existing_keys.add(key)

        # Merge reflected XSS findings into poc_findings
        existing_poc_keys = {f"{f.get('base','')}:{f.get('param','')}"
                              for f in self.results.get('poc_findings', [])}
        for f in xss_summary['findings'].get('reflected_xss', []):
            key = f"{f.get('base_url','')}:{f.get('param','')}"
            if key not in existing_poc_keys:
                self.results['poc_findings'].append(f)
                existing_poc_keys.add(key)

        # Save XSS findings JSON
        (self.output_dir / 'xss_findings.json').write_text(
            json.dumps(xss_summary, indent=2, default=str),
            encoding='utf-8',
        )

    # =========================================================================
    # ENHANCED REPORT (new v7 format using ReportGenerator)
    # =========================================================================

    def _write_enhanced_report(self):
        """Write the enhanced v7 vulnerability report using ReportGenerator."""
        if not REPORT_GEN_OK:
            return
        try:
            gen = ReportGenerator(self.results, self.output_dir)
            paths = gen.generate_all()
            self.log(f"  [report] Enhanced HTML report: {paths.get('html', '')}")
            self.log(f"  [report] Full text report:     {paths.get('text', '')}")
            self.log(f"  [report] JSON report:          {paths.get('json', '')}")
        except Exception as e:
            self.log(f"  [!] Enhanced report generation failed: {e}")

    # =========================================================================
    # PHASE 10 (legacy): ORIGINAL REPORT
    # =========================================================================

    # =========================================================================
    # PHASE 11: ADVANCED VULNERABILITY CHECKS
    # =========================================================================

    def _run_advanced_checks(self):
        """Phase 11: Run AdvancedScanner — 20 attack categories."""
        scanner = AdvancedScanner(
            target_url=self.base_url,
            session=self.session,
            threads=self.threads,
            timeout=self.timeout,
            log_fn=self.log,
        )

        all_ep      = self.results.get('all_endpoints', {})
        same_domain = all_ep.get('same_domain', [])[:60]
        param_map   = self.results.get('param_map', {})

        adv_findings = scanner.run(
            param_map=param_map,
            visited_urls=same_domain,
        )
        self.results['advanced_data'] = adv_findings

        (self.output_dir / 'advanced_findings.json').write_text(
            json.dumps(adv_findings, indent=2, default=str),
            encoding='utf-8',
        )

    def _write_report(self) -> str:
        r   = self.results
        out = self.output_dir
        risk = self._calc_risk(r)

        summary = {
            'target':           r['target'],
            'scan_time':        time.strftime('%Y-%m-%d %H:%M:%S'),
            'risk':             risk,
            'js_files':         len(r['js_files']),
            'endpoints':        len(r['endpoints']),
            'secrets':          len(r['secrets']),
            'xss_sinks':        len(r['xss_findings']),
            'xss_confirmed':    sum(1 for x in r['xss_findings'] if x.get('confirmed_flow')),
            'reflected_xss':    len(r.get('poc_findings', [])),
            'browser_confirmed': sum(1 for p in r.get('poc_findings',[]) if p.get('browser_confirmed')),
            'dom_clobber':      len(r['dom_clobber']),
            'proto_pollution':  len(r['proto_pollution']),
        }

        r_copy = dict(r)
        r_copy['external_urls'] = list(r.get('external_urls', []))
        (out / 'summary.json').write_text(json.dumps(summary, indent=2))
        (out / 'full_results.json').write_text(json.dumps(r_copy, indent=2, default=str))

        # ── Reflected XSS PoCs report ─────────────────────────────────────────
        poc_findings = r.get('poc_findings', [])
        if poc_findings:
            lines = ["=" * 70, "CONFIRMED REFLECTED XSS VULNERABILITIES", "=" * 70, ""]
            for i, poc in enumerate(poc_findings, 1):
                conf = " [BROWSER CONFIRMED]" if poc.get('browser_confirmed') else ""
                lines += [
                    f"[{i}] {poc.get('base', poc.get('url',''))}",
                    f"     Parameter : {poc['param']}",
                    f"     Context   : {poc.get('context', 'unknown')}{conf}",
                    f"     Payload   : {poc['payload']}",
                    f"     PoC URL   : {poc['url']}",
                    f"     Evidence  : {poc.get('evidence','')[:200]}",
                    "",
                ]
            (out / 'reflected_xss.txt').write_text('\n'.join(lines))

        # ── Plain text summary ────────────────────────────────────────────────
        txt_lines = [
            f"JS Scout Pro v5 — Scan Report",
            f"Target  : {r['target']}",
            f"Risk    : {risk}",
            f"Time    : {summary['scan_time']}",
            "",
            f"JS Files      : {summary['js_files']}",
            f"Endpoints     : {summary['endpoints']}",
            f"Secrets       : {summary['secrets']}",
            f"XSS Sinks     : {summary['xss_sinks']} ({summary['xss_confirmed']} source→sink confirmed)",
            f"Reflected XSS : {summary['reflected_xss']} ({summary['browser_confirmed']} browser-confirmed)",
            "",
        ]
        if poc_findings:
            txt_lines.append("REFLECTED XSS PoCs:")
            for poc in poc_findings:
                conf = " ✓ BROWSER" if poc.get('browser_confirmed') else ""
                txt_lines.append(f"  [{poc['param']}] {poc['url'][:100]}{conf}")
        txt_lines.append("")
        if r['secrets']:
            txt_lines.append("SECRETS:")
            for s in r['secrets'][:20]:
                txt_lines.append(f"  [{s['severity']}] {s['type']} in {s['file']}:{s['line']}")
        (out / 'report.txt').write_text('\n'.join(txt_lines))

        # ── HTML Report ────────────────────────────────────────────────────────
        def h(s): return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

        def sev_color(s):
            return {'CRITICAL':'#ff2244','HIGH':'#ff6622','MEDIUM':'#ffcc00','LOW':'#44aaff','INFO':'#888'}.get(s,'#888')

        poc_rows = ''
        for i, poc in enumerate(poc_findings, 1):
            conf = ' <b style="color:#00ff9f">[BROWSER ✓]</b>' if poc.get('browser_confirmed') else ''
            poc_rows += f'''<tr>
              <td>{i}</td>
              <td style="color:#ff2244"><b>{h(poc["param"])}</b></td>
              <td><span style="color:#ffaa00">{h(poc.get("context","?"))}</span>{conf}</td>
              <td><a href="{h(poc["url"])}" target="_blank" style="color:#00d4ff;word-break:break-all">{h(poc["url"])}</a></td>
              <td style="font-family:monospace;font-size:11px">{h(poc["payload"])}</td>
            </tr>'''

        secret_rows = ''
        for s in r.get('secrets', []):
            secret_rows += f'''<tr>
              <td><span style="color:{sev_color(s["severity"])}">{h(s["severity"])}</span></td>
              <td>{h(s["type"])}</td>
              <td>{h(s["file"])}:{s["line"]}</td>
              <td style="font-family:monospace;font-size:11px;max-width:300px;word-break:break-all">{h(s["value"][:120])}</td>
            </tr>'''

        xss_rows = ''
        for x in r.get('xss_findings', []):
            flow = ' <b style="color:#ff2244">⚡ src→sink</b>' if x.get('confirmed_flow') else ''
            xss_rows += f'''<tr>
              <td><span style="color:{sev_color(x["severity"])}">{h(x["severity"])}</span></td>
              <td>{h(x["sink"])}{flow}</td>
              <td>{h(x["file"])}:{x["line"]}</td>
              <td style="font-family:monospace;font-size:11px;max-width:350px;overflow:hidden">{h(x["context"][:120])}</td>
            </tr>'''

        js_file_rows = ''
        for f in sorted(r.get('js_files', []), key=lambda x: -x.get('size',0)):
            src_url = f.get('source_url', '')
            name_cell = f'<a href="{h(src_url)}" target="_blank" style="color:#00d4ff">{h(f["name"])}</a>' if src_url else h(f["name"])
            js_file_rows += f'''<tr>
              <td>{name_cell}</td>
              <td>{(f.get("size",0)/1024):.1f} KB</td>
              <td style="color:{"#ff6622" if f.get("secrets",0) else "#888"}">{f.get("secrets",0)}</td>
              <td style="color:{"#ff2244" if f.get("xss_sinks",0) else "#888"}">{f.get("xss_sinks",0)}</td>
              <td>{"🗜 minified" if f.get("minified") else ""}</td>
            </tr>'''

        ep_rows = ''
        for ep, files in list(r.get('endpoints', {}).items())[:200]:
            ep_rows += f'<tr><td style="color:#00d4ff;font-family:monospace">{h(ep)}</td><td style="color:#888;font-size:11px">{h(", ".join(files[:3]))}</td></tr>'

        # ── Vulnerability finding rows ─────────────────────────────────────────
        vc = r.get('vuln_data', {})

        def vuln_rows(findings, cols):
            rows = ''
            for f in findings:
                sev = f.get('severity','INFO')
                sc  = {'CRITICAL':'#ff2244','HIGH':'#ff6622','MEDIUM':'#ffcc00','LOW':'#44aaff','INFO':'#888'}.get(sev,'#888')
                row = f'<tr><td><span style="color:{sc}">{h(sev)}</span></td>'
                for col in cols:
                    row += f'<td style="font-size:12px;word-break:break-all">{h(str(f.get(col,""))[:200])}</td>'
                row += '</tr>'
                rows += row
            return rows

        cors_rows  = vuln_rows(vc.get('cors',[]),  ['type','url','evidence','remediation'])
        redir_rows = vuln_rows(vc.get('open_redirect',[]), ['param','url','evidence','remediation'])
        host_rows  = vuln_rows(vc.get('host_header',[]),   ['header','url','evidence','remediation'])
        html_inj_rows = vuln_rows(vc.get('html_injection',[]), ['param','url','evidence','remediation'])

        # ── Advanced findings rows ────────────────────────────────────────────
        adv = r.get('advanced_data', {})

        def adv_rows(findings_list, cols):
            rows = ''
            for f in (findings_list or []):
                if not isinstance(f, dict):
                    continue
                sev = f.get('severity', 'INFO')
                sc  = {'CRITICAL':'#ff2244','HIGH':'#ff6622','MEDIUM':'#ffcc00','LOW':'#44aaff','INFO':'#888'}.get(sev,'#888')
                row = f'<tr><td><span style="color:{sc}"><b>{h(sev)}</b></span></td>'
                for col in cols:
                    val = str(f.get(col, ''))[:250]
                    if col in ('url',) and val.startswith('http'):
                        row += f'<td style="font-size:11px"><a href="{h(val)}" target="_blank" style="color:#00d4ff;word-break:break-all">{h(val[:120])}</a></td>'
                    else:
                        row += f'<td style="font-size:11px;word-break:break-all">{h(val)}</td>'
                row += '</tr>'
                rows += row
            return rows

        waf_info    = adv.get('waf', [{}])[0].get('waf_info', {}) if adv.get('waf') else {}
        origin_info = adv.get('waf', [{}])[0].get('origin_info', {}) if adv.get('waf') else {}

        adv_sqli_rows    = adv_rows(adv.get('sqli',[]),    ['param','url','evidence','remediation'])
        adv_ssti_rows    = adv_rows(adv.get('ssti',[]),    ['param','engine','url','evidence','remediation'])
        adv_lfi_rows     = adv_rows(adv.get('path_traversal',[]),     ['param','url','evidence','remediation'])
        adv_ssrf_rows    = adv_rows(adv.get('ssrf',[]),    ['param','url','evidence','remediation'])
        adv_cmdi_rows    = adv_rows(adv.get('command_injection',[]),    ['param','url','evidence','remediation'])
        adv_xxe_rows     = adv_rows(adv.get('xxe',[]),     ['url','evidence','remediation'])
        adv_hdr_rows     = adv_rows(adv.get('security_headers',[]), ['header','description','remediation'])
        adv_ck_rows      = adv_rows(adv.get('cookie_security',[]), ['cookie','description','remediation'])
        adv_jwt_rows     = adv_rows(adv.get('jwt',[]),     ['type','description','evidence','remediation'])
        adv_cj_rows      = adv_rows(adv.get('clickjacking',[]), ['description','evidence','remediation'])
        adv_meth_rows    = adv_rows(adv.get('cache_poisoning',[]), ['method','url','evidence','remediation'])
        adv_info_rows    = adv_rows(adv.get('info_disclosure',[]), ['pattern','url','evidence','remediation'])
        adv_rl_rows      = adv_rows(adv.get('crlf',[]), ['description','url','evidence','remediation'])
        adv_idor_rows    = adv_rows(adv.get('idor',[]),    ['param','url','evidence','remediation'])
        adv_take_rows    = adv_rows(adv.get('subdomain_takeover',[]),      ['url','service','evidence','remediation'])
        adv_graphql_rows = adv_rows(adv.get('graphql',[]),        ['type','url','evidence','remediation'])
        adv_oauth_rows   = adv_rows(adv.get('oauth',[]),          ['type','url','evidence','remediation'])
        adv_proto_rows   = adv_rows(adv.get('proto_pollution',[]),['param','url','evidence','remediation'])
        adv_smug_rows    = adv_rows(adv.get('request_smuggling',[]),       ['type','url','evidence','remediation'])
        adv_deser_rows   = adv_rows(adv.get('deserialization',[]),        ['type','url','evidence','remediation'])
        adv_waf_rows     = adv_rows(adv.get('cache_poisoning',[]),      ['type','url','evidence','remediation'])

        def adv_count(key): return len(adv.get(key, []))

        risk_color = {'CRITICAL':'#ff2244','HIGH':'#ff6622','MEDIUM':'#ffcc00','LOW':'#44aaff','INFO':'#888'}.get(risk,'#888')

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Scout Pro — Report: {h(r["target"])}</title>
<style>
  * {{margin:0;padding:0;box-sizing:border-box}}
  body {{background:#080b0f;color:#c9d8e8;font-family:"Share Tech Mono",monospace;padding:32px 24px}}
  h1 {{font-size:22px;letter-spacing:4px;color:#00ff9f;margin-bottom:4px}}
  h2 {{font-size:13px;letter-spacing:3px;color:#00d4ff;margin:28px 0 12px;border-bottom:1px solid #1e2d3d;padding-bottom:6px}}
  .meta {{color:#3a5068;font-size:12px;margin-bottom:24px}}
  .risk {{display:inline-block;padding:6px 18px;background:{risk_color}22;border:1px solid {risk_color};color:{risk_color};font-size:14px;letter-spacing:3px;margin-bottom:24px}}
  .stats {{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:28px}}
  .stat {{background:#0d1117;border:1px solid #1e2d3d;padding:12px 20px;text-align:center;min-width:120px}}
  .stat-val {{display:block;font-size:28px;font-weight:bold}}
  .stat-label {{font-size:10px;color:#3a5068;letter-spacing:2px}}
  table {{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:12px}}
  th {{background:#0d1117;color:#3a5068;padding:8px 12px;text-align:left;letter-spacing:2px;font-size:10px;border-bottom:1px solid #1e2d3d}}
  td {{padding:8px 12px;border-bottom:1px solid #111720;vertical-align:top}}
  tr:hover td {{background:#0d1117}}
  a {{color:#00d4ff;text-decoration:none}}
  a:hover {{text-decoration:underline}}
  .empty {{color:#3a5068;font-style:italic;padding:16px}}
  code {{background:#0d1117;padding:2px 6px;font-size:11px}}
</style>
</head>
<body>
<h1>⚡ JS SCOUT PRO v5</h1>
<div class="meta">Target: <b style="color:#c9d8e8">{h(r["target"])}</b> &nbsp;|&nbsp; {summary["scan_time"]}</div>
<div class="risk">⚠ RISK: {risk}</div>

<div class="stats">
  <div class="stat"><span class="stat-val" style="color:#00d4ff">{summary["js_files"]}</span><span class="stat-label">JS FILES</span></div>
  <div class="stat"><span class="stat-val" style="color:#00ff9f">{summary["endpoints"]}</span><span class="stat-label">ENDPOINTS</span></div>
  <div class="stat"><span class="stat-val" style="color:{"#ff2244" if summary["secrets"] else "#888"}">{summary["secrets"]}</span><span class="stat-label">SECRETS</span></div>
  <div class="stat"><span class="stat-val" style="color:{"#ff2244" if summary["reflected_xss"] else "#888"}">{summary["reflected_xss"]}</span><span class="stat-label">REFLECTED XSS</span></div>
  <div class="stat"><span class="stat-val" style="color:{"#ff6622" if summary["xss_sinks"] else "#888"}">{summary["xss_sinks"]}</span><span class="stat-label">XSS SINKS</span></div>
  <div class="stat"><span class="stat-val" style="color:{"#00ff9f" if summary["browser_confirmed"] else "#888"}">{summary["browser_confirmed"]}</span><span class="stat-label">BROWSER CONFIRMED</span></div>
  <div class="stat"><span class="stat-val" style="color:#888">{summary["dom_clobber"]}</span><span class="stat-label">DOM CLOBBER</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff6622' if len(vc.get('cors',[])) else '#888'}">{len(vc.get('cors',[]))}</span><span class="stat-label">CORS</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff6622' if len(vc.get('open_redirect',[])) else '#888'}">{len(vc.get('open_redirect',[]))}</span><span class="stat-label">OPEN REDIRECT</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff6622' if len(vc.get('host_header',[])) else '#888'}">{len(vc.get('host_header',[]))}</span><span class="stat-label">HOST INJECT</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff6622' if len(vc.get('html_injection',[])) else '#888'}">{len(vc.get('html_injection',[]))}</span><span class="stat-label">HTML INJECT</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff2244' if adv_count('sqli') else '#888'}">{adv_count('sqli')}</span><span class="stat-label">SQLi</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff2244' if adv_count('ssti') else '#888'}">{adv_count('ssti')}</span><span class="stat-label">SSTI</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff2244' if adv_count('path_traversal') else '#888'}">{adv_count('path_traversal')}</span><span class="stat-label">LFI</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff2244' if adv_count('ssrf') else '#888'}">{adv_count('ssrf')}</span><span class="stat-label">SSRF</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff2244' if adv_count('command_injection') else '#888'}">{adv_count('command_injection')}</span><span class="stat-label">CMDi</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff6622' if adv_count('security_headers') else '#888'}">{adv_count('security_headers')}</span><span class="stat-label">HDR ISSUES</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ffcc00' if waf_info.get('waf') else '#888'}">{waf_info.get('waf') or 'None'}</span><span class="stat-label">WAF</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#00ff9f' if origin_info.get('origin_ip') else '#888'}">{origin_info.get('origin_ip') or '?'}</span><span class="stat-label">ORIGIN IP</span></div>
</div>

<h2>🔴 REFLECTED XSS — CONFIRMED PoCs</h2>
{"<table><thead><tr><th>#</th><th>PARAM</th><th>CONTEXT</th><th>PoC URL (CLICKABLE)</th><th>PAYLOAD</th></tr></thead><tbody>" + poc_rows + "</tbody></table>" if poc_rows else "<div class='empty'>No reflected XSS confirmed.</div>"}

<h2>🔑 SECRETS &amp; CREDENTIALS</h2>
{"<table><thead><tr><th>SEV</th><th>TYPE</th><th>FILE:LINE</th><th>VALUE</th></tr></thead><tbody>" + secret_rows + "</tbody></table>" if secret_rows else "<div class='empty'>No secrets found.</div>"}

<h2>⚠ XSS SINKS (Static Analysis)</h2>
{"<table><thead><tr><th>SEV</th><th>SINK</th><th>FILE:LINE</th><th>CONTEXT</th></tr></thead><tbody>" + xss_rows + "</tbody></table>" if xss_rows else "<div class='empty'>No XSS sinks detected.</div>"}

<h2>📦 JS FILES — Clickable URLs</h2>
{"<table><thead><tr><th>FILE (clickable = source URL)</th><th>SIZE</th><th>SECRETS</th><th>XSS SINKS</th><th>FLAGS</th></tr></thead><tbody>" + js_file_rows + "</tbody></table>" if js_file_rows else "<div class='empty'>No JS files downloaded.</div>"}

<h2>🌍 CORS MISCONFIGURATION</h2>
{"<table><thead><tr><th>SEV</th><th>TYPE</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + cors_rows + "</tbody></table>" if cors_rows else "<div class='empty'>No CORS misconfigurations found.</div>"}

<h2>↪ OPEN REDIRECT</h2>
{"<table><thead><tr><th>SEV</th><th>PARAM</th><th>PoC URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + redir_rows + "</tbody></table>" if redir_rows else "<div class='empty'>No open redirects found.</div>"}

<h2>🖥 HOST HEADER INJECTION</h2>
{"<table><thead><tr><th>SEV</th><th>HEADER</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + host_rows + "</tbody></table>" if host_rows else "<div class='empty'>No host header injection found.</div>"}

<h2>💉 HTML INJECTION</h2>
{"<table><thead><tr><th>SEV</th><th>PARAM</th><th>PoC URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + html_inj_rows + "</tbody></table>" if html_inj_rows else "<div class='empty'>No HTML injection found.</div>"}

<h2>🌐 API ENDPOINTS</h2>
{"<table><thead><tr><th>ENDPOINT</th><th>FOUND IN</th></tr></thead><tbody>" + ep_rows + "</tbody></table>" if ep_rows else "<div class='empty'>No endpoints extracted.</div>"}

<hr style="border-color:#1e2d3d;margin:32px 0">
<h1 style="color:#ff6622;font-size:16px;letter-spacing:3px">⚡ ADVANCED VULNERABILITY SCAN RESULTS</h1>

<h2>🛡 WAF / CDN & ORIGIN IP BYPASS</h2>
<div style="background:#0d1117;border:1px solid #1e2d3d;padding:16px;margin-bottom:24px;font-size:13px">
  <b style="color:#ffcc00">WAF Detected:</b> <span style="color:#ff6622">{waf_info.get('waf') or 'None detected'}</span><br>
  <b style="color:#ffcc00">Evidence:</b> {h(', '.join(waf_info.get('evidence',[])[:3]))}<br>
  <b style="color:#ffcc00">Origin IP:</b> <span style="color:#00ff9f">{origin_info.get('origin_ip') or 'Not found'}</span><br>
  <b style="color:#ffcc00">Bypass URL:</b> <span style="color:#00d4ff">{h(origin_info.get('bypass_url') or 'N/A')}</span><br>
  <b style="color:#ffcc00">Method:</b> {h(origin_info.get('method') or 'N/A')}<br>
  <b style="color:#ffcc00">Candidate IPs:</b> {h(', '.join(origin_info.get('candidate_ips',[])[:10]))}<br>
  <b style="color:#ffcc00">crt.sh Subdomains:</b> {len(origin_info.get('subdomains',[]))} found
  {"<br><details><summary style='color:#3a5068;cursor:pointer'>Show subdomains</summary><pre style='color:#888;font-size:11px'>" + h('\n'.join(origin_info.get('subdomains',[])[:30])) + "</pre></details>" if origin_info.get('subdomains') else ""}
</div>

<h2>💉 SQL INJECTION</h2>
{"<table><thead><tr><th>SEV</th><th>PARAM</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_sqli_rows + "</tbody></table>" if adv_sqli_rows else "<div class='empty'>No SQL injection found.</div>"}

<h2>🧪 SERVER-SIDE TEMPLATE INJECTION (SSTI)</h2>
{"<table><thead><tr><th>SEV</th><th>PARAM</th><th>ENGINE</th><th>URL</th><th>EVIDENCE</th></tr></thead><tbody>" + adv_ssti_rows + "</tbody></table>" if adv_ssti_rows else "<div class='empty'>No SSTI found.</div>"}

<h2>📂 LOCAL FILE INCLUSION / PATH TRAVERSAL</h2>
{"<table><thead><tr><th>SEV</th><th>PARAM</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_lfi_rows + "</tbody></table>" if adv_lfi_rows else "<div class='empty'>No LFI/path traversal found.</div>"}

<h2>🔁 SERVER-SIDE REQUEST FORGERY (SSRF)</h2>
{"<table><thead><tr><th>SEV</th><th>PARAM</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_ssrf_rows + "</tbody></table>" if adv_ssrf_rows else "<div class='empty'>No SSRF found.</div>"}

<h2>💻 COMMAND INJECTION</h2>
{"<table><thead><tr><th>SEV</th><th>PARAM</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_cmdi_rows + "</tbody></table>" if adv_cmdi_rows else "<div class='empty'>No command injection found.</div>"}

<h2>📦 XXE INJECTION</h2>
{"<table><thead><tr><th>SEV</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_xxe_rows + "</tbody></table>" if adv_xxe_rows else "<div class='empty'>No XXE found.</div>"}

<h2>🔐 SECURITY HEADERS</h2>
{"<table><thead><tr><th>SEV</th><th>HEADER</th><th>ISSUE</th><th>REMEDIATION</th></tr></thead><tbody>" + adv_hdr_rows + "</tbody></table>" if adv_hdr_rows else "<div class='empty'>All security headers present.</div>"}

<h2>🍪 COOKIE SECURITY</h2>
{"<table><thead><tr><th>SEV</th><th>COOKIE</th><th>ISSUE</th><th>FIX</th></tr></thead><tbody>" + adv_ck_rows + "</tbody></table>" if adv_ck_rows else "<div class='empty'>No cookie issues found.</div>"}

<h2>🔑 JWT ANALYSIS</h2>
{"<table><thead><tr><th>SEV</th><th>TYPE</th><th>DESCRIPTION</th><th>EVIDENCE</th></tr></thead><tbody>" + adv_jwt_rows + "</tbody></table>" if adv_jwt_rows else "<div class='empty'>No JWT issues found.</div>"}

<h2>🖱 CLICKJACKING</h2>
{"<table><thead><tr><th>SEV</th><th>TYPE</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_cj_rows + "</tbody></table>" if adv_cj_rows else "<div class='empty'>No clickjacking issues found.</div>"}

<h2>⚙ HTTP METHOD TAMPERING</h2>
{"<table><thead><tr><th>SEV</th><th>METHOD</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_meth_rows + "</tbody></table>" if adv_meth_rows else "<div class='empty'>No dangerous HTTP methods allowed.</div>"}

<h2>🔎 INFORMATION DISCLOSURE</h2>
{"<table><thead><tr><th>SEV</th><th>PATTERN</th><th>URL</th><th>EVIDENCE</th></tr></thead><tbody>" + adv_info_rows + "</tbody></table>" if adv_info_rows else "<div class='empty'>No information disclosure found.</div>"}

<h2>🚦 RATE LIMITING</h2>
{"<table><thead><tr><th>SEV</th><th>TYPE</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_rl_rows + "</tbody></table>" if adv_rl_rows else "<div class='empty'>Rate limiting appears to be in place.</div>"}

<h2>🆔 IDOR / PARAMETER TAMPERING</h2>
{"<table><thead><tr><th>SEV</th><th>PARAM</th><th>URL</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_idor_rows + "</tbody></table>" if adv_idor_rows else "<div class='empty'>No IDOR found.</div>"}

<h2>🌐 SUBDOMAIN TAKEOVER</h2>
{"<table><thead><tr><th>SEV</th><th>SUBDOMAIN</th><th>SERVICE</th><th>EVIDENCE</th><th>FIX</th></tr></thead><tbody>" + adv_take_rows + "</tbody></table>" if adv_take_rows else "<div class='empty'>No subdomain takeover found.</div>"}

</body>
</html>'''

        (out / 'report.html').write_text(html, encoding='utf-8')
        return str(out / 'report.txt')

    def _calc_risk(self, r) -> str:
        adv = r.get('advanced_data', {})
        vc  = r.get('vuln_data', {})

        # CRITICAL: RCE-class, credential theft, data exfil
        critical_adv_keys = ['sqli', 'ssti', 'command_injection', 'xxe', 'ssrf', 'path_traversal']
        if any(adv.get(k) for k in critical_adv_keys):
            return 'CRITICAL'
        if any(f.get('severity') == 'CRITICAL' for fl in adv.values() if isinstance(fl, list) for f in fl):
            return 'CRITICAL'
        if any(s['severity'] == 'CRITICAL' for s in r.get('secrets', [])):
            return 'CRITICAL'
        if r.get('poc_findings'):
            return 'CRITICAL'

        # HIGH: significant exploitable vulns
        high_adv_keys = ['jwt', 'idor', 'crlf', 'subdomain_takeover', 'file_upload', 'cache_poisoning']
        if any(adv.get(k) for k in high_adv_keys):
            return 'HIGH'
        if vc.get('cors') or vc.get('open_redirect') or vc.get('host_header'):
            return 'HIGH'
        if r.get('secrets') or any(x.get('confirmed_flow') for x in r.get('xss_findings', [])):
            return 'HIGH'

        # MEDIUM
        if adv.get('graphql') or adv.get('security_headers') or adv.get('info_disclosure'):
            return 'MEDIUM'
        if r.get('xss_findings') or r.get('dom_clobber') or vc.get('html_injection'):
            return 'MEDIUM'

        if r.get('endpoints'):
            return 'LOW'
        return 'INFO'


# =============================================================================
# CLI ENTRY
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description='JS Scout Pro v10 — Full Security Recon + Vulnerability Scanner + 15-Tool External Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 jsscout.py https://target.com
  python3 jsscout.py https://target.com --depth 4 --pages 300
  python3 jsscout.py https://target.com --no-selenium
  python3 jsscout.py https://target.com --skip-vuln-checks
  python3 jsscout.py https://target.com --cookies "session=abc123"
  python3 jsscout.py https://target.com --header "Authorization: Bearer TOKEN"

New in v10 (Phase 13 — External Tools Engine):
  - JS-Scan      : keyword + hardcoded credential scanner
  - LinksDumper  : deep HTML link extraction (href/src/data-*/JS assigns)
  - GoLinkFinder : fast clean endpoint extractor from JS
  - BurpJSLinkFinder : scope-filtered endpoint + param extraction
  - urlgrab      : full URL spider from crawled pages
  - waybackurls  : historical URLs from Wayback Machine CDX
  - gau          : URLs from Wayback + OTX + URLScan
  - getJS        : JS file discovery (script tags, imports, webpack chunks)
  - linx         : obfuscated/encoded link decoder (base64, hex, charcode)
  - waymore      : extended Wayback with MIME/status filtering
  - xnLinkFinder : aggressive JS link extraction (obj keys, templates, arrows)
  - URLFinder    : ProjectDiscovery passive URL discovery engine
  - jsleak       : secret + sensitive path detector
  - jsfinder     : JS file scanner + subdomain extractor
  - jsluice      : BishopFox multi-pass secret + URL extractor

New in v7:
  - Enhanced endpoint extraction (HTML + JS + AJAX/fetch/axios)
  - CORS misconfiguration detection
  - Open redirect detection
  - Host header injection testing
  - Sensitive endpoint discovery (500+ paths)
  - Enhanced XSS detection (Reflected + Stored + DOM-based)
  - Structured vulnerability report with remediation guidance
        """
    )
    ap.add_argument('target')
    ap.add_argument('--output',           default=None)
    ap.add_argument('--threads',          type=int, default=10)
    ap.add_argument('--timeout',          type=int, default=15)
    ap.add_argument('--pages',            type=int, default=200)
    ap.add_argument('--depth',            type=int, default=3)
    ap.add_argument('--cookies',          default=None)
    ap.add_argument('--header',           action='append', dest='headers')
    ap.add_argument('--no-selenium',      action='store_true', help='Disable Selenium/browser mode')
    ap.add_argument('--skip-vuln-checks', action='store_true', help='Skip CORS/redirect/host-header/sensitive-path checks')
    ap.add_argument('--skip-stored-xss',  action='store_true', help='Skip stored XSS form probing')
    ap.add_argument('--json',             action='store_true', help='Output JSON to stdout')
    # ── Burp Suite integration ─────────────────────────────────────────────
    ap.add_argument('--burp',             action='store_true', help='Route requests through Burp proxy')
    ap.add_argument('--burp-host',        default='127.0.0.1', help='Burp proxy host (default: 127.0.0.1)')
    ap.add_argument('--burp-port',        type=int, default=8080, help='Burp proxy port (default: 8080)')
    ap.add_argument('--collab-domain',    default='', help='Burp Collaborator domain for OOB detection')
    ap.add_argument('--export-burp',      action='store_true', help='Export findings as Burp-importable XML')
    # ── Module control ─────────────────────────────────────────────────────
    ap.add_argument('--skip-auth',        action='store_true', help='Skip auth/session/OAuth checks')
    ap.add_argument('--skip-advanced',    action='store_true', help='Skip advanced injection checks')
    ap.add_argument('--verbose',          action='store_true', help='Verbose output')
    # ── Phase 13: External Tools ───────────────────────────────────────────
    ap.add_argument('--skip-external',    action='store_true', help='Skip Phase 13 (external tools engine)')
    ap.add_argument('--ext-sources',      default='wayback,otx,urlscan',
                    help='Comma-separated passive URL sources for gau/waymore (default: wayback,otx,urlscan)')
    args = ap.parse_args()

    target = args.target
    if '://' not in target:
        target = 'http://' + target
    domain = urlparse(target).netloc.replace(':', '_')
    output = args.output or f'jsscout_output/{domain}'

    hdrs = {}
    for h in (args.headers or []):
        if ':' in h:
            k, _, v = h.partition(':')
            hdrs[k.strip()] = v.strip()

    use_selenium = not args.no_selenium

    if use_selenium:
        if not SELENIUM_OK:
            print("[!] Selenium not installed.")
            print("    Install: pip install selenium webdriver-manager")
            print("    Linux:   apt install chromium chromium-driver")
            print("    Continuing in requests-only mode...")
            use_selenium = False
        else:
            print("[+] Selenium available — browser mode ON")
    else:
        print("[*] Browser mode disabled (--no-selenium)")

    scout = JSScout(
        target, output,
        threads=args.threads,
        timeout=args.timeout,
        max_pages=args.pages,
        depth=args.depth,
        cookies=args.cookies,
        extra_headers=hdrs or None,
        use_selenium=use_selenium,
    )

    scout.skip_external = args.skip_external
    results = scout.run()

    if args.json:
        results['external_urls'] = list(results.get('external_urls', []))
        print(json.dumps(results, indent=2, default=str))


if __name__ == '__main__':
    main()
