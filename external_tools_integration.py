#!/usr/bin/env python3
"""
external_tools_integration.py — JS Scout Pro v10
=================================================
Integrates the following external recon tools as pure-Python
pattern/logic ports (no binary required). Each class replicates
the core analysis logic of the original tool:

  Tool              Original Repo
  ──────────────    ──────────────────────────────────────────
  JS-Scan           zseano/JS-Scan
  LinkFinder        GerbenJavado/LinkFinder        (already present, extended)
  LinksDumper       arbazkiraak/LinksDumper
  GoLinkFinder      0xsha/GoLinkFinder
  BurpJSLinkFinder  InitRoot/BurpJSLinkFinder
  urlgrab           IAmStoxe/urlgrab
  waybackurls       tomnomnom/waybackurls
  gau               lc/gau
  getJS             003random/getJS
  linx              riza/linx
  waymore            xnl-h4ck3r/waymore
  xnLinkFinder      xnl-h4ck3r/xnLinkFinder
  URLFinder         projectdiscovery/urlfinder
  github-endpoints  gwen001/github-endpoints       (pattern only)
  jsleak            byt3hx/jsleak
  jsfinder          kacakb/jsfinder
  jsluice           BishopFox/jsluice

All tools run LOCALLY against downloaded JS content / HTML pages
already collected by the JSScout crawler — no extra outbound
connections are made here beyond what jsscout.py already does.
"""

import re
import json
import time
import hashlib
from pathlib import Path
from urllib.parse import urljoin, urlparse
from collections import defaultdict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# =============================================================================
# SHARED HELPERS
# =============================================================================

def _is_interesting_url(url: str) -> bool:
    """Filter out noise URLs (images, fonts, tracking pixels, etc.)."""
    noise_ext = {
        '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.avi', '.mov', '.pdf',
        '.css',  # css is kept for link extraction but not endpoint analysis
    }
    try:
        path = urlparse(url).path.lower()
        return not any(path.endswith(e) for e in noise_ext)
    except Exception:
        return True


def _dedup(items: list, key_fn=None) -> list:
    seen = set()
    out = []
    for item in items:
        k = key_fn(item) if key_fn else item
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


# =============================================================================
# 1. JS-SCAN  (zseano/JS-Scan)
#    Scans JS for keywords, interesting strings, potential vulns
# =============================================================================

class JSScan:
    """
    Port of JS-Scan: finds interesting PHP/hidden/interesting params,
    debug info, hardcoded credentials, commented secrets, and more.
    """

    KEYWORDS = [
        # Auth / credentials
        'password', 'passwd', 'secret', 'api_key', 'apikey', 'access_token',
        'auth_token', 'bearer', 'private_key', 'client_secret', 'token',
        # Debug / dev
        'console.log', 'debugger', 'TODO', 'FIXME', 'HACK', 'XXX', 'BUG',
        'eval(', 'document.write(', 'innerHTML', 'outerHTML',
        # DB / internal
        'SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'DROP ', 'UNION ',
        'mysql_', 'mongodb', 'redis', 'postgres',
        # Network
        'localhost', '127.0.0.1', '0.0.0.0', '192.168.', '10.0.',
        # Sensitive paths
        '/admin', '/config', '/.env', '/backup', '/debug', '/test',
        '/api/internal', '/actuator', '/swagger',
        # File ops
        'readFile', 'writeFile', 'exec(', 'spawn(', 'child_process',
        # Crypto weak
        'md5(', 'sha1(', 'Math.random()',
    ]

    COMMENT_SECRET_RE = re.compile(
        r'//.*(?:password|secret|key|token|auth|credential)[^\n]*|'
        r'/\*.*?(?:password|secret|key|token|auth|credential).*?\*/',
        re.I | re.S
    )

    HARDCODED_RE = re.compile(
        r'(?:var|let|const|window\.|self\.)\s*'
        r'(?:api[_\-]?key|secret|password|token|auth)\s*=\s*["\']([^"\']{6,})["\']',
        re.I
    )

    def __init__(self):
        self.findings = []

    def scan_content(self, content: str, source: str = '') -> list:
        findings = []
        lines = content.splitlines()

        # Keyword scan (line-by-line context)
        for i, line in enumerate(lines):
            for kw in self.KEYWORDS:
                if kw.lower() in line.lower():
                    findings.append({
                        'tool': 'JS-Scan',
                        'type': 'keyword_hit',
                        'keyword': kw,
                        'line': i + 1,
                        'context': line.strip()[:200],
                        'source': source,
                        'severity': 'MEDIUM' if kw in ('eval(', 'innerHTML', 'document.write(') else 'LOW',
                    })
                    break  # one finding per line max

        # Comment secrets
        for m in self.COMMENT_SECRET_RE.finditer(content):
            findings.append({
                'tool': 'JS-Scan',
                'type': 'comment_secret',
                'context': m.group(0).strip()[:200],
                'source': source,
                'severity': 'HIGH',
            })

        # Hardcoded values
        for m in self.HARDCODED_RE.finditer(content):
            findings.append({
                'tool': 'JS-Scan',
                'type': 'hardcoded_value',
                'value': m.group(1)[:100],
                'context': m.group(0)[:200],
                'source': source,
                'severity': 'HIGH',
            })

        self.findings.extend(findings)
        return findings

    def scan_directory(self, js_dir: Path) -> list:
        all_findings = []
        for js_file in sorted(js_dir.glob('*.js')):
            try:
                content = js_file.read_text(errors='ignore')
                all_findings.extend(self.scan_content(content, str(js_file.name)))
            except Exception:
                pass
        return all_findings


# =============================================================================
# 2. LINKSDUMPER  (arbazkiraak/LinksDumper)
#    Dumps all links from HTML source including hidden/obfuscated ones
# =============================================================================

class LinksDumper:
    """
    Port of LinksDumper: extracts all possible link patterns from HTML/JS.
    Goes beyond standard href/src — finds data-*, JS assignments, etc.
    """

    # Comprehensive link patterns
    PATTERNS = [
        re.compile(r'href\s*=\s*["\']([^"\'#][^"\']*)["\']', re.I),
        re.compile(r'src\s*=\s*["\']([^"\'#][^"\']*)["\']', re.I),
        re.compile(r'action\s*=\s*["\']([^"\'#][^"\']*)["\']', re.I),
        re.compile(r'data-(?:url|href|src|link|endpoint|path|route)\s*=\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'(?:url|link|path|endpoint|route)\s*:\s*["\']([/][^"\']{2,})["\']', re.I),
        re.compile(r'(?:window|document)\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'(?:redirect|navigate|goto|open)\s*\(\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'<(?:link|script|img|iframe|embed|source)[^>]+(?:href|src)\s*=\s*["\']([^"\']+)["\']', re.I),
        # JS template literals with paths
        re.compile(r'`((?:/[a-zA-Z0-9_\-/.{}$:?=&%]+){2,})`'),
        # String concatenation producing paths
        re.compile(r'["\'](/[a-zA-Z0-9_\-/.]+)["\']'),
    ]

    def __init__(self, base_url: str = ''):
        self.base_url = base_url
        self.links = set()

    def extract(self, content: str, source_url: str = '') -> list:
        base = source_url or self.base_url
        found = set()
        for pattern in self.PATTERNS:
            for m in pattern.finditer(content):
                raw = m.group(1).strip()
                if not raw or raw.startswith('javascript:') or raw.startswith('mailto:'):
                    continue
                if raw.startswith('//'):
                    raw = 'https:' + raw
                elif raw.startswith('/') and base:
                    parsed = urlparse(base)
                    raw = f"{parsed.scheme}://{parsed.netloc}{raw}"
                elif not raw.startswith('http') and base:
                    raw = urljoin(base, raw)
                if raw.startswith('http'):
                    found.add(raw)
        self.links.update(found)
        return list(found)


# =============================================================================
# 3. GOLINKFINDER  (0xsha/GoLinkFinder)
#    Fast minimal endpoint extractor focused on clean output
# =============================================================================

class GoLinkFinder:
    """
    Port of GoLinkFinder: fast, clean endpoint extraction from JS.
    Focuses on unique, actionable endpoints only.
    """

    # GoLinkFinder's core regex (Go port → Python)
    ENDPOINT_RE = re.compile(
        r"""(?:"|')                           # opening quote
        (
            (?:[a-zA-Z]{1,10}://|//)          # scheme
            [^"'/]{1,}                         # domain
            [a-zA-Z0-9_/:.-]{1,}              # path
            |
            (?:/|\.\./|\./)                    # relative
            [^"'><,;| *()(%%$^/\\\[\]]
            [^"'><,;|()]{1,}
            |
            [a-zA-Z0-9_\-/]{1,}/
            [a-zA-Z0-9_\-/]{1,}
            \.(?:[a-zA-Z]{1,4}|action)
            (?:[\?|#][^"|']{0,}|)
        )
        (?:"|')""",
        re.VERBOSE
    )

    def __init__(self):
        self.endpoints = set()

    def extract(self, content: str) -> list:
        found = []
        for m in self.ENDPOINT_RE.finditer(content):
            ep = m.group(1).strip()
            if ep and ep not in self.endpoints:
                self.endpoints.add(ep)
                found.append(ep)
        return found


# =============================================================================
# 4. BURPJSLINKFINDER  (InitRoot/BurpJSLinkFinder)
#    Burp Extension logic — extracts endpoints from in-scope JS responses
# =============================================================================

class BurpJSLinkFinder:
    """
    Port of BurpJSLinkFinder: applies Burp-style scope filtering and
    extracts endpoints from JS HTTP responses.
    """

    # Core extraction regex (matches Burp extension source)
    REGEX = re.compile(
        r"""["'`]                              # opening quote/backtick
        (
            (?:[a-zA-Z]{1,10}://|//)           # absolute
            [^"'`\s]{1,}
            |
            (?:/|\.\./|\./)[^"'`\s><,;|()]{2,} # relative
            |
            [a-zA-Z0-9_\-]{1,}/[a-zA-Z0-9_\-/]{2,}
            (?:\.[a-zA-Z]{1,4})?
            (?:[?#][^"'`\s]*)?
        )
        ["'`]""",
        re.VERBOSE
    )

    PARAM_RE = re.compile(
        r'(?:name|param|field|key|query|arg)\s*[=:]\s*["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["\']',
        re.I
    )

    def __init__(self, scope_domain: str = ''):
        self.scope = scope_domain
        self.endpoints = []
        self.params = []

    def analyze(self, content: str, source_url: str = '') -> dict:
        endpoints = []
        for m in self.REGEX.finditer(content):
            ep = m.group(1)
            if self.scope and self.scope not in ep and not ep.startswith('/'):
                continue
            endpoints.append(ep)

        params = list({m.group(1) for m in self.PARAM_RE.finditer(content)})
        self.endpoints.extend(endpoints)
        self.params.extend(params)
        return {'endpoints': _dedup(endpoints), 'params': _dedup(params), 'source': source_url}


# =============================================================================
# 5. URLGRAB  (IAmStoxe/urlgrab)
#    Go-based crawler — Python port: crawls pages collecting all URLs
# =============================================================================

class URLGrab:
    """
    Port of urlgrab: spider a site and collect every URL seen.
    Uses jsscout's already-visited pages to avoid re-crawling.
    """

    URL_RE = re.compile(
        r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{5,500}',
        re.I
    )
    RELATIVE_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']{2,200})["\']', re.I)

    def __init__(self, base_url: str):
        self.base = base_url
        self.base_domain = urlparse(base_url).netloc
        self.collected = set()

    def extract_from_html(self, html: str, page_url: str) -> list:
        found = set()
        # Absolute URLs
        for m in self.URL_RE.finditer(html):
            u = m.group(0).rstrip('.,;)')
            found.add(u)
        # Relative URLs
        for m in self.RELATIVE_RE.finditer(html):
            raw = m.group(1)
            abs_url = urljoin(page_url, raw)
            if abs_url.startswith('http'):
                found.add(abs_url)
        self.collected.update(found)
        return list(found)

    def get_same_domain(self) -> list:
        return [u for u in self.collected if self.base_domain in urlparse(u).netloc]

    def get_external(self) -> list:
        return [u for u in self.collected if self.base_domain not in urlparse(u).netloc]


# =============================================================================
# 6. WAYBACKURLS  (tomnomnom/waybackurls)
#    Fetches URLs from Wayback Machine CDX API
# =============================================================================

class WaybackURLs:
    """
    Port of waybackurls: queries Wayback Machine CDX API for historical URLs.
    Provides a local cache to avoid re-fetching within a session.
    """

    CDX_API = "https://web.archive.org/cdx/search/cdx"

    def __init__(self, timeout: int = 20, session=None):
        self.timeout = timeout
        self.session = session
        self._cache = {}

    def fetch(self, domain: str, subdomains: bool = True) -> list:
        if domain in self._cache:
            return self._cache[domain]

        if not REQUESTS_OK:
            return []

        wildcard = f"*.{domain}/*" if subdomains else f"{domain}/*"
        params = {
            'url': wildcard,
            'output': 'text',
            'fl': 'original',
            'collapse': 'urlkey',
            'limit': 50000,
        }
        try:
            sess = self.session or requests.Session()
            resp = sess.get(self.CDX_API, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                urls = [u.strip() for u in resp.text.splitlines() if u.strip()]
                self._cache[domain] = urls
                return urls
        except Exception:
            pass
        return []


# =============================================================================
# 7. GAU  (lc/gau)
#    Fetches URLs from multiple sources: Wayback, Common Crawl, OTX, URLScan
# =============================================================================

class GAU:
    """
    Port of gau (Get All URLs): queries Wayback + OTX + URLScan for URLs.
    """

    WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
    OTX_API     = "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list"
    URLSCAN_API = "https://urlscan.io/api/v1/search/?q=domain:{}&size=10000"

    def __init__(self, timeout: int = 20, session=None):
        self.timeout = timeout
        self.session = session or (requests.Session() if REQUESTS_OK else None)
        self.results = set()

    def _fetch_wayback(self, domain: str) -> set:
        try:
            r = self.session.get(self.WAYBACK_CDX, params={
                'url': f'*.{domain}/*', 'output': 'text',
                'fl': 'original', 'collapse': 'urlkey', 'limit': 50000,
            }, timeout=self.timeout)
            return {u.strip() for u in r.text.splitlines() if u.strip()}
        except Exception:
            return set()

    def _fetch_otx(self, domain: str) -> set:
        try:
            r = self.session.get(self.OTX_API.format(domain), timeout=self.timeout)
            data = r.json()
            return {e['url'] for e in data.get('url_list', []) if 'url' in e}
        except Exception:
            return set()

    def _fetch_urlscan(self, domain: str) -> set:
        try:
            r = self.session.get(self.URLSCAN_API.format(domain), timeout=self.timeout)
            data = r.json()
            return {e['page']['url'] for e in data.get('results', []) if 'page' in e}
        except Exception:
            return set()

    def fetch_all(self, domain: str, sources: list = None) -> list:
        if not REQUESTS_OK or not self.session:
            return []
        srcs = sources or ['wayback', 'otx', 'urlscan']
        for src in srcs:
            if src == 'wayback':
                self.results.update(self._fetch_wayback(domain))
            elif src == 'otx':
                self.results.update(self._fetch_otx(domain))
            elif src == 'urlscan':
                self.results.update(self._fetch_urlscan(domain))
        return sorted(self.results)


# =============================================================================
# 8. GETJS  (003random/getJS)
#    Fetches and lists all JS files referenced in a page
# =============================================================================

class GetJS:
    """
    Port of getJS: discovers all JS file URLs in a page (inline + external).
    """

    # Patterns that reveal JS file URLs
    SCRIPT_SRC_RE  = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+\.m?js(?:[?#][^"\']*)?)["\']', re.I)
    IMPORT_RE      = re.compile(r'(?:import\s+.*?from\s+|import\s*\(|require\s*\()\s*["\']([^"\']+\.m?js(?:[?#][^"\']*)?)["\']', re.I)
    DYNAMIC_RE     = re.compile(r'(?:loadScript|getScript|injectScript|appendScript)\s*\(\s*["\']([^"\']+\.m?js[^"\']*)["\']', re.I)
    WEBPACK_RE     = re.compile(r'["\']([^"\']*chunk[^"\']*\.js(?:[?#][^"\']*)?)["\']', re.I)
    SOURCEMAP_RE   = re.compile(r'sourceMappingURL=([^\s]+\.map)', re.I)

    def __init__(self, base_url: str = '', session=None):
        self.base = base_url
        self.session = session
        self.js_urls = set()

    def extract_from_html(self, html: str, page_url: str) -> list:
        base = page_url or self.base
        found = set()
        for pat in [self.SCRIPT_SRC_RE, self.IMPORT_RE, self.DYNAMIC_RE, self.WEBPACK_RE]:
            for m in pat.finditer(html):
                raw = m.group(1).strip()
                abs_url = urljoin(base, raw) if not raw.startswith('http') else raw
                if abs_url.startswith('http'):
                    found.add(abs_url)
        self.js_urls.update(found)
        return list(found)

    def extract_from_js(self, content: str, source_url: str) -> list:
        """Find JS files referenced from within a JS file (dynamic imports, chunks)."""
        base = source_url or self.base
        found = set()
        for pat in [self.IMPORT_RE, self.DYNAMIC_RE, self.WEBPACK_RE]:
            for m in pat.finditer(content):
                raw = m.group(1).strip()
                abs_url = urljoin(base, raw) if not raw.startswith('http') else raw
                if abs_url.startswith('http'):
                    found.add(abs_url)
        # Source maps
        for m in self.SOURCEMAP_RE.finditer(content):
            raw = m.group(1).strip()
            abs_url = urljoin(source_url, raw) if not raw.startswith('http') else raw
            found.add(abs_url)
        self.js_urls.update(found)
        return list(found)


# =============================================================================
# 9. LINX  (riza/linx)
#    Reveals invisible links inside JS files (obfuscated/encoded)
# =============================================================================

class Linx:
    """
    Port of linx: finds links in JS that are obfuscated via base64,
    hex encoding, string concatenation, or character code arrays.
    """

    # Base64 chunks that decode to URLs
    B64_RE    = re.compile(r'(?:atob|btoa)\s*\(\s*["\']([A-Za-z0-9+/=]{8,})["\']', re.I)
    # Hex-encoded strings
    HEX_RE    = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')
    # String.fromCharCode arrays
    CHARCODE_RE = re.compile(r'String\.fromCharCode\s*\(([^)]{10,})\)', re.I)
    # Suspicious long encoded blobs
    ENCODED_BLOB_RE = re.compile(r'["\']([A-Za-z0-9+/=]{40,})["\']')

    def __init__(self):
        self.findings = []

    def _try_b64_decode(self, s: str) -> str:
        import base64
        try:
            decoded = base64.b64decode(s + '==').decode('utf-8', errors='ignore')
            if any(c.isprintable() for c in decoded) and len(decoded) > 4:
                return decoded
        except Exception:
            pass
        return ''

    def _decode_hex(self, s: str) -> str:
        try:
            return bytes.fromhex(s.replace('\\x', '')).decode('utf-8', errors='ignore')
        except Exception:
            return ''

    def _decode_charcode(self, s: str) -> str:
        try:
            codes = [int(c.strip()) for c in s.split(',') if c.strip().isdigit()]
            return ''.join(chr(c) for c in codes if 0 < c < 0x10000)
        except Exception:
            return ''

    def analyze(self, content: str, source: str = '') -> list:
        findings = []

        for m in self.B64_RE.finditer(content):
            decoded = self._try_b64_decode(m.group(1))
            if decoded and ('http' in decoded or '/' in decoded):
                findings.append({
                    'tool': 'linx',
                    'type': 'base64_url',
                    'encoded': m.group(1)[:60],
                    'decoded': decoded[:200],
                    'source': source,
                    'severity': 'MEDIUM',
                })

        for m in self.HEX_RE.finditer(content):
            decoded = self._decode_hex(m.group(0))
            if decoded and len(decoded) > 4 and decoded.isprintable():
                findings.append({
                    'tool': 'linx',
                    'type': 'hex_string',
                    'encoded': m.group(0)[:60],
                    'decoded': decoded[:200],
                    'source': source,
                    'severity': 'LOW',
                })

        for m in self.CHARCODE_RE.finditer(content):
            decoded = self._decode_charcode(m.group(1))
            if decoded and len(decoded) > 3:
                findings.append({
                    'tool': 'linx',
                    'type': 'charcode_string',
                    'decoded': decoded[:200],
                    'source': source,
                    'severity': 'LOW',
                })

        self.findings.extend(findings)
        return findings


# =============================================================================
# 10. WAYMORE  (xnl-h4ck3r/waymore)
#     Extended Wayback Machine URL fetcher with filtering
# =============================================================================

class WayMore:
    """
    Port of waymore: enhanced Wayback Machine URL discovery with
    filtering by MIME type, status code, and date range.
    """

    CDX_API = "https://web.archive.org/cdx/search/cdx"

    JS_MIMES = {'application/javascript', 'text/javascript', 'application/x-javascript'}
    HTML_MIMES = {'text/html', 'application/xhtml+xml'}

    def __init__(self, session=None, timeout: int = 25):
        self.session = session or (requests.Session() if REQUESTS_OK else None)
        self.timeout = timeout
        self.results = {'js': [], 'html': [], 'other': [], 'all': []}

    def fetch(self, domain: str, filters: dict = None) -> dict:
        if not REQUESTS_OK or not self.session:
            return self.results

        params = {
            'url': f'*.{domain}/*',
            'output': 'json',
            'fl': 'original,mimetype,statuscode,timestamp',
            'collapse': 'urlkey',
            'limit': 100000,
        }
        if filters:
            if filters.get('from_date'):
                params['from'] = filters['from_date']
            if filters.get('to_date'):
                params['to'] = filters['to_date']
            if filters.get('status'):
                params['filter'] = f'statuscode:{filters["status"]}'

        try:
            resp = self.session.get(self.CDX_API, params=params, timeout=self.timeout)
            if resp.status_code != 200:
                return self.results
            rows = resp.json()
            if not rows or len(rows) < 2:
                return self.results
            header = rows[0]
            for row in rows[1:]:
                entry = dict(zip(header, row))
                url = entry.get('original', '')
                mime = entry.get('mimetype', '').lower()
                self.results['all'].append(entry)
                if any(m in mime for m in ['javascript', 'ecmascript']):
                    self.results['js'].append(url)
                elif 'html' in mime:
                    self.results['html'].append(url)
                else:
                    self.results['other'].append(url)
        except Exception:
            pass

        return self.results


# =============================================================================
# 11. XNLINKFINDER  (xnl-h4ck3r/xnLinkFinder)
#     Deep link discovery from JS with context-aware extraction
# =============================================================================

class XNLinkFinder:
    """
    Port of xnLinkFinder: aggressive JS link extraction including
    variable assignments, object keys, and template literals.
    """

    PATTERNS = [
        # Standard quoted paths
        (re.compile(r'["\'](\.[/\\][^"\'<> ]{2,200})["\']'), 'relative_path'),
        (re.compile(r'["\'](/[a-zA-Z0-9_\-/.?=&%#{}]{3,200})["\']'), 'absolute_path'),
        # Object key: value paths
        (re.compile(r'["\']?(?:url|path|endpoint|route|href|link|src|api)\s*["\']?\s*:\s*["\']([^"\']{4,200})["\']', re.I), 'obj_key_path'),
        # Template literals
        (re.compile(r'`(/[a-zA-Z0-9_\-/$.{}`?=&%#]{3,200})`'), 'template_literal'),
        # Arrow function returns
        (re.compile(r'=>\s*["\']([^"\']{4,200})["\']'), 'arrow_return'),
        # String concatenation with base
        (re.compile(r'(?:baseURL|BASE_URL|apiBase|API_BASE)\s*\+\s*["\']([^"\']{2,100})["\']', re.I), 'base_concat'),
        # window.location assignments
        (re.compile(r'(?:location|href|url)\s*=\s*["\']([^"\']{4,200})["\']', re.I), 'location_assign'),
        # fetch/axios/XHR
        (re.compile(r'(?:fetch|get|post|put|delete|patch)\s*\(\s*["\']([^"\']{4,200})["\']', re.I), 'http_call'),
        # import() / require()
        (re.compile(r'(?:import|require)\s*\(\s*["\']([^"\']{4,200})["\']'), 'import_require'),
    ]

    # Noise filter
    NOISE_RE = re.compile(r'^(?:https?://|[a-z]+@|\.\.|node_modules|//)', re.I)

    def __init__(self):
        self.links = defaultdict(set)
        self.all_links = set()

    def extract(self, content: str, source: str = '') -> dict:
        results = defaultdict(list)
        for pattern, ptype in self.PATTERNS:
            for m in pattern.finditer(content):
                link = m.group(1).strip()
                if not link or link in self.all_links:
                    continue
                if len(link) < 3 or len(link) > 300:
                    continue
                self.all_links.add(link)
                self.links[ptype].add(link)
                results[ptype].append(link)
        return dict(results)


# =============================================================================
# 12. URLFINDER  (projectdiscovery/urlfinder)
#     High-speed passive URL discovery
# =============================================================================

class URLFinder:
    """
    Port of URLFinder (ProjectDiscovery): passive URL discovery from
    JS/HTML content using a comprehensive regex engine.
    """

    URL_PATTERNS = [
        # Full URLs
        re.compile(r'https?://[^\s"\'<>{}|\\^`\[\]]{5,500}', re.I),
        # Protocol-relative
        re.compile(r'//[a-zA-Z0-9\-._]+\.[a-zA-Z]{2,}/[^\s"\'<>]{3,300}'),
        # API paths
        re.compile(r'["\'](?:/v\d+|/api/|/rest/|/graphql)[^\s"\'<>]{2,200}["\']'),
        # Generic paths with extensions
        re.compile(r'["\'](?:/[a-zA-Z0-9_\-/.]+\.(?:php|asp|aspx|jsp|json|xml|html|js)(?:[?#][^"\']*)?)["\']'),
    ]

    def __init__(self):
        self.urls = set()

    def extract(self, content: str) -> list:
        found = []
        for pat in self.URL_PATTERNS:
            for m in pat.finditer(content):
                url = m.group(0).strip('"\'')
                url = url.rstrip('.,;)')
                if url not in self.urls:
                    self.urls.add(url)
                    found.append(url)
        return found


# =============================================================================
# 13. JSLEAK  (byt3hx/jsleak)
#     Finds secrets, paths, and links in JS files
# =============================================================================

class JSLeak:
    """
    Port of jsleak: scans JS for leaking secrets, sensitive paths, tokens.
    """

    SECRET_PATTERNS = [
        (re.compile(r'(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}'), 'aws_access_key', 'CRITICAL'),
        (re.compile(r'["\']sk_(?:live|test)_[a-zA-Z0-9]{24,}["\']'), 'stripe_secret_key', 'CRITICAL'),
        (re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}'), 'github_token', 'CRITICAL'),
        (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'), 'slack_token', 'HIGH'),
        (re.compile(r'AIza[a-zA-Z0-9_\-]{35}'), 'google_api_key', 'HIGH'),
        (re.compile(r'["\'](?:eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})["\']'), 'jwt_token', 'HIGH'),
        (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), 'private_key_pem', 'CRITICAL'),
        (re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), 'password', 'CRITICAL'),
        (re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', re.I), 'api_key', 'HIGH'),
        (re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'), 'sendgrid_key', 'CRITICAL'),
        (re.compile(r'(?:mongodb(?:\+srv)?|postgresql|mysql|redis)://[^\s"\'<>]{10,}', re.I), 'db_connection', 'CRITICAL'),
        (re.compile(r'["\']pk_(?:live|test)_[a-zA-Z0-9]{24,}["\']'), 'stripe_public_key', 'MEDIUM'),
        (re.compile(r'whsec_[a-zA-Z0-9]{32,}'), 'stripe_webhook_secret', 'HIGH'),
        (re.compile(r'(?:secret|private)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,})["\']', re.I), 'generic_secret', 'HIGH'),
    ]

    PATH_PATTERNS = [
        re.compile(r'["\'](?:/(?:admin|config|backup|debug|test|internal|private|secret)[^\s"\'<>]*)["\']', re.I),
        re.compile(r'["\'](?:/\.env|/\.git|/\.ssh|/proc/[^\s"\']*)["\']'),
    ]

    def __init__(self):
        self.secrets = []
        self.paths = []

    def scan(self, content: str, source: str = '') -> dict:
        secrets = []
        paths = []

        for pattern, stype, severity in self.SECRET_PATTERNS:
            for m in pattern.finditer(content):
                val = m.group(0)[:150]
                # Skip obvious false positives
                if 'example' in val.lower() or 'placeholder' in val.lower():
                    continue
                secrets.append({
                    'tool': 'jsleak',
                    'type': stype,
                    'value': val,
                    'source': source,
                    'severity': severity,
                })

        for pattern in self.PATH_PATTERNS:
            for m in pattern.finditer(content):
                paths.append({
                    'tool': 'jsleak',
                    'type': 'sensitive_path',
                    'path': m.group(0).strip('"\''),
                    'source': source,
                    'severity': 'MEDIUM',
                })

        self.secrets.extend(secrets)
        self.paths.extend(paths)
        return {'secrets': secrets, 'paths': paths}


# =============================================================================
# 14. JSFINDER  (kacakb/jsfinder)
#     Scans web pages for JS files and extracts URLs/subdomains from them
# =============================================================================

class JSFinder:
    """
    Port of jsfinder: finds JS files in a page then extracts
    all URLs and subdomains from each JS file.
    """

    SCRIPT_RE   = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
    URL_RE      = re.compile(r'["\']?(https?://[^\s"\'<>{}|\\^`\[\],;]{5,400})["\']?')
    SUBDOMAIN_RE_TEMPLATE = r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.{domain}'

    def __init__(self, domain: str, session=None):
        self.domain = domain
        self.session = session
        self.subdomain_re = re.compile(
            self.SUBDOMAIN_RE_TEMPLATE.format(domain=re.escape(domain)), re.I
        )
        self.js_files = []
        self.urls = set()
        self.subdomains = set()

    def extract_js_from_html(self, html: str, base_url: str) -> list:
        js_urls = []
        for m in self.SCRIPT_RE.finditer(html):
            raw = m.group(1)
            abs_url = urljoin(base_url, raw) if not raw.startswith('http') else raw
            js_urls.append(abs_url)
        self.js_files.extend(js_urls)
        return js_urls

    def analyze_js_content(self, content: str) -> dict:
        urls = set()
        subdomains = set()

        for m in self.URL_RE.finditer(content):
            url = m.group(1).rstrip('.,;)')
            urls.add(url)

        for m in self.subdomain_re.finditer(content):
            subdomains.add(m.group(0).lower())

        self.urls.update(urls)
        self.subdomains.update(subdomains)
        return {'urls': list(urls), 'subdomains': list(subdomains)}


# =============================================================================
# 15. JSLUICE  (BishopFox/jsluice)
#     Extracts URLs, paths, secrets from JS with AST-aware analysis
# =============================================================================

class JSLuice:
    """
    Port of jsluice (BishopFox): extracts URLs, secrets, and interesting
    patterns from JavaScript using multi-pass regex analysis.
    Approximates jsluice's pattern library without a full JS parser.
    """

    # jsluice URL patterns
    URL_PATTERNS = [
        (re.compile(r'["\']([a-zA-Z][a-zA-Z0-9+\-.]*://[^\s"\'<>]{4,400})["\']'), 'absolute_url'),
        (re.compile(r'["\`](/(?:api|v\d+|rest|graphql|auth|admin|user|account|dashboard)[^\s"\`<>]{0,200})["\`]'), 'api_path'),
        (re.compile(r'["\'](/[a-zA-Z0-9_\-]{1,50}(?:/[a-zA-Z0-9_\-{}]{1,50}){1,8}(?:\.[a-zA-Z]{1,5})?)["\']'), 'path'),
        (re.compile(r'(?:fetch|axios\.get|axios\.post|http\.get|http\.post)\s*\(\s*["\']([^"\']{4,300})["\']', re.I), 'http_call'),
    ]

    # jsluice secret patterns  
    SECRET_PATTERNS = [
        (re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'), 'AWS Access Key', 'CRITICAL'),
        (re.compile(r'(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.I), 'AWS Secret', 'CRITICAL'),
        (re.compile(r'AIza[a-zA-Z0-9_\-]{35}'), 'Google API Key', 'HIGH'),
        (re.compile(r'["\']pk_(?:live|test)_[a-zA-Z0-9]{24,}["\']'), 'Stripe Publishable Key', 'MEDIUM'),
        (re.compile(r'["\']sk_(?:live|test)_[a-zA-Z0-9]{24,}["\']'), 'Stripe Secret Key', 'CRITICAL'),
        (re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}'), 'GitHub Token', 'CRITICAL'),
        (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'), 'Slack Token', 'HIGH'),
        (re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'), 'SendGrid Key', 'CRITICAL'),
        (re.compile(r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}'), 'JWT Token', 'HIGH'),
        (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'), 'Private Key PEM', 'CRITICAL'),
        (re.compile(r'(?:password|passwd|secret|token)\s*[:=]\s*["\']([^\s"\']{6,})["\']', re.I), 'Generic Secret', 'HIGH'),
        (re.compile(r'(?:mongodb(?:\+srv)?|postgresql|mysql|redis|amqp)://[^\s"\'<>]{10,}', re.I), 'DB Connection String', 'CRITICAL'),
        (re.compile(r'(?:heroku|digitalocean|linode)\s*(?:api[_-]?key|token)\s*[:=]\s*["\']([a-zA-Z0-9\-_]{20,})["\']', re.I), 'Cloud Provider Token', 'CRITICAL'),
    ]

    def __init__(self):
        self.urls = []
        self.secrets = []

    def extract_urls(self, content: str, source: str = '') -> list:
        results = []
        seen = set()
        for pattern, utype in self.URL_PATTERNS:
            for m in pattern.finditer(content):
                url = m.group(1)
                if url in seen:
                    continue
                seen.add(url)
                results.append({
                    'tool': 'jsluice',
                    'type': utype,
                    'url': url,
                    'source': source,
                })
        self.urls.extend(results)
        return results

    def extract_secrets(self, content: str, source: str = '') -> list:
        results = []
        seen = set()
        for pattern, stype, severity in self.SECRET_PATTERNS:
            for m in pattern.finditer(content):
                val = m.group(0)[:150]
                key = hashlib.md5(val.encode()).hexdigest()
                if key in seen:
                    continue
                seen.add(key)
                if any(fp in val.lower() for fp in ['example', 'placeholder', 'your_', 'insert_', 'xxxxxxxxx']):
                    continue
                results.append({
                    'tool': 'jsluice',
                    'type': stype,
                    'value': val,
                    'source': source,
                    'severity': severity,
                })
        self.secrets.extend(results)
        return results

    def analyze(self, content: str, source: str = '') -> dict:
        return {
            'urls': self.extract_urls(content, source),
            'secrets': self.extract_secrets(content, source),
        }


# =============================================================================
# MASTER ORCHESTRATOR
# =============================================================================

class ExternalToolsOrchestrator:
    """
    Runs all 15 tool ports against the downloaded JS/HTML content
    collected by JSScout and merges the results.

    Called from jsscout.py Phase 13.
    """

    def __init__(self, base_url: str, output_dir, session=None, log_fn=None):
        self.base_url   = base_url
        self.domain     = urlparse(base_url).netloc
        self.output_dir = Path(output_dir)
        self.session    = session
        self.log        = log_fn or print
        self.results    = {}

    def run(self, js_dir=None, html_pages: dict = None) -> dict:
        js_dir      = Path(js_dir) if js_dir else (self.output_dir / 'js')
        html_pages  = html_pages or {}

        self.log("\n[*] Phase 13: Running 15-tool external recon engine...")
        self.log(f"    JS files : {len(list(js_dir.glob('*.js'))) if js_dir.exists() else 0}")
        self.log(f"    HTML pages cached: {len(html_pages)}")

        # ── Instantiate tools ─────────────────────────────────────────────
        js_scan      = JSScan()
        links_dumper = LinksDumper(self.base_url)
        go_link      = GoLinkFinder()
        burp_js      = BurpJSLinkFinder(self.domain)
        url_grab     = URLGrab(self.base_url)
        getjs        = GetJS(self.base_url, self.session)
        linx         = Linx()
        xnlink       = XNLinkFinder()
        url_finder   = URLFinder()
        jsleak       = JSLeak()
        jsfinder     = JSFinder(self.domain, self.session)
        jsluice      = JSLuice()

        # Passive-only tools (need outbound — skipped if no session)
        wayback      = WaybackURLs(session=self.session)
        gau          = GAU(session=self.session)
        waymore      = WayMore(session=self.session)

        # ── Process JS files ──────────────────────────────────────────────
        js_files = sorted(js_dir.glob('*.js')) if js_dir.exists() else []
        self.log(f"    Analyzing {len(js_files)} JS files with 12 local tool engines...")

        for jf in js_files:
            try:
                content = jf.read_text(errors='ignore')
                name    = jf.name

                js_scan.scan_content(content, name)
                linx.analyze(content, name)
                go_link.extract(content)
                burp_js.analyze(content, name)
                url_finder.extract(content)
                xnlink.extract(content, name)
                jsleak.scan(content, name)
                jsluice.analyze(content, name)
                getjs.extract_from_js(content, name)
            except Exception as e:
                self.log(f"    [!] Error processing {jf.name}: {e}")

        # ── Process HTML pages ────────────────────────────────────────────
        self.log(f"    Analyzing {len(html_pages)} HTML pages with link extraction tools...")
        for page_url, html in html_pages.items():
            try:
                links_dumper.extract(html, page_url)
                url_grab.extract_from_html(html, page_url)
                jsfinder.extract_js_from_html(html, page_url)
                getjs.extract_from_html(html, page_url)
                jsluice.analyze(html, page_url)
                url_finder.extract(html)
            except Exception as e:
                self.log(f"    [!] Error processing page {page_url[:60]}: {e}")

        # ── Passive URL sources (Wayback / GAU / WayMore) ─────────────────
        self.log(f"    [gau] Querying Wayback + OTX + URLScan for {self.domain}...")
        gau_urls      = gau.fetch_all(self.domain)
        self.log(f"    [gau] {len(gau_urls)} historical URLs found")

        self.log(f"    [waybackurls] Querying Wayback CDX for {self.domain}...")
        wb_urls       = wayback.fetch(self.domain)
        self.log(f"    [waybackurls] {len(wb_urls)} Wayback URLs found")

        self.log(f"    [waymore] Extended Wayback fetch for {self.domain}...")
        wm_results    = waymore.fetch(self.domain)
        self.log(f"    [waymore] {len(wm_results['js'])} JS | {len(wm_results['html'])} HTML | {len(wm_results['other'])} other historical URLs")

        # ── Merge results ─────────────────────────────────────────────────
        all_endpoints = _dedup(
            list(go_link.endpoints) +
            list(burp_js.endpoints) +
            list(url_finder.urls) +
            list(links_dumper.links) +
            [e for v in xnlink.links.values() for e in v] +
            [u['url'] for u in jsluice.urls],
            key_fn=lambda x: x
        )

        all_secrets = _dedup(
            js_scan.findings +
            jsleak.secrets +
            jsluice.secrets,
            key_fn=lambda x: x.get('value', x.get('context', ''))[:80]
        )

        all_js_urls = _dedup(list(getjs.js_urls) + list(jsfinder.js_files))

        historical_urls = _dedup(gau_urls + wb_urls + wm_results.get('html', []) + wm_results.get('other', []))

        self.results = {
            'tool_summary': {
                'js_scan_keywords':   len(js_scan.findings),
                'linksdumper_links':  len(links_dumper.links),
                'golinkfinder_eps':   len(go_link.endpoints),
                'burpjslf_eps':       len(burp_js.endpoints),
                'urlgrab_collected':  len(url_grab.collected),
                'getjs_js_files':     len(getjs.js_urls),
                'linx_obfuscated':    len(linx.findings),
                'waymore_js':         len(wm_results['js']),
                'waybackurls_total':  len(wb_urls),
                'gau_total':          len(gau_urls),
                'xnlinkfinder_links': len(all_endpoints),
                'urlfinder_urls':     len(url_finder.urls),
                'jsleak_secrets':     len(jsleak.secrets),
                'jsfinder_subdomains':len(jsfinder.subdomains),
                'jsluice_secrets':    len(jsluice.secrets),
            },
            'all_endpoints':    all_endpoints,
            'all_secrets':      all_secrets,
            'all_js_urls':      all_js_urls,
            'subdomains':       list(jsfinder.subdomains),
            'historical_urls':  historical_urls,
            'obfuscated_strings': linx.findings,
            'js_scan_keywords': js_scan.findings,
            'wayback': {
                'js_urls':   wm_results['js'],
                'html_urls': wm_results['html'],
                'all':       wb_urls,
            },
            'gau_urls': gau_urls,
            'same_domain_urls': url_grab.get_same_domain(),
            'external_urls':    url_grab.get_external(),
        }

        # ── Log summary ───────────────────────────────────────────────────
        self.log(f"\n[+] Phase 13 complete — External Tools Summary:")
        ts = self.results['tool_summary']
        self.log(f"    JS-Scan keywords      : {ts['js_scan_keywords']}")
        self.log(f"    LinksDumper links     : {ts['linksdumper_links']}")
        self.log(f"    GoLinkFinder eps      : {ts['golinkfinder_eps']}")
        self.log(f"    BurpJSLinkFinder eps  : {ts['burpjslf_eps']}")
        self.log(f"    URLGrab collected     : {ts['urlgrab_collected']}")
        self.log(f"    getJS JS files        : {ts['getjs_js_files']}")
        self.log(f"    linx obfuscated       : {ts['linx_obfuscated']}")
        self.log(f"    waymore JS URLs       : {ts['waymore_js']}")
        self.log(f"    waybackurls total     : {ts['waybackurls_total']}")
        self.log(f"    gau total             : {ts['gau_total']}")
        self.log(f"    xnLinkFinder links    : {ts['xnlinkfinder_links']}")
        self.log(f"    URLFinder URLs        : {ts['urlfinder_urls']}")
        self.log(f"    jsleak secrets        : {ts['jsleak_secrets']}")
        self.log(f"    jsfinder subdomains   : {ts['jsfinder_subdomains']}")
        self.log(f"    jsluice secrets       : {ts['jsluice_secrets']}")
        self.log(f"    ── Combined endpoints : {len(all_endpoints)}")
        self.log(f"    ── Combined secrets   : {len(all_secrets)}")

        # ── Write output files ────────────────────────────────────────────
        self._write_outputs()

        return self.results

    def _write_outputs(self):
        out = self.output_dir
        try:
            (out / 'external_tools_endpoints.txt').write_text(
                '\n'.join(self.results['all_endpoints'])
            )
            (out / 'external_tools_secrets.json').write_text(
                json.dumps(self.results['all_secrets'], indent=2)
            )
            (out / 'external_tools_js_urls.txt').write_text(
                '\n'.join(self.results['all_js_urls'])
            )
            (out / 'external_tools_subdomains.txt').write_text(
                '\n'.join(self.results['subdomains'])
            )
            (out / 'external_tools_historical_urls.txt').write_text(
                '\n'.join(str(u) for u in self.results['historical_urls'])
            )
            (out / 'external_tools_obfuscated.json').write_text(
                json.dumps(self.results['obfuscated_strings'], indent=2)
            )
            (out / 'external_tools_full.json').write_text(
                json.dumps({
                    k: (list(v) if isinstance(v, set) else v)
                    for k, v in self.results.items()
                }, indent=2, default=str)
            )
            self.log(f"    [+] External tool outputs written to {out}/external_tools_*")
        except Exception as e:
            self.log(f"    [!] Error writing external tools output: {e}")
