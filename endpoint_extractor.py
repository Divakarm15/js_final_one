#!/usr/bin/env python3
"""
endpoint_extractor.py — Comprehensive Endpoint Extraction Module
=================================================================
Extracts ALL endpoints from HTML pages and JavaScript files including:
  - HTML href, src, form actions, data-* attributes
  - API endpoints (/api/v1/..., /graphql, /rest/...)
  - URLs inside JavaScript files
  - AJAX / fetch / axios / XHR calls
  - Dynamically constructed endpoints
  - Template literals with path patterns

Outputs results to JSON and text files.

Usage (standalone):
    python3 endpoint_extractor.py https://target.com
    python3 endpoint_extractor.py --js-dir jsscout_output/target.com/js/
"""

import re
import sys
import json
import time
import argparse
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
from html.parser import HTMLParser
from collections import defaultdict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)


# =============================================================================
# ENDPOINT EXTRACTION PATTERNS
# =============================================================================

# HTML tag attribute patterns
HTML_ENDPOINT_ATTRS = {
    'href':         ['a', 'link', 'area', 'base'],
    'src':          ['script', 'img', 'iframe', 'embed', 'source', 'audio', 'video', 'track', 'input'],
    'action':       ['form'],
    'formaction':   ['button', 'input'],
    'data-url':     ['*'],
    'data-href':    ['*'],
    'data-src':     ['*'],
    'data-action':  ['*'],
    'data-endpoint':['*'],
    'data-api':     ['*'],
    'data-path':    ['*'],
    'data-route':   ['*'],
    'content':      ['meta'],   # for og:url, canonical etc.
}

# JavaScript patterns for endpoint extraction
JS_ENDPOINT_PATTERNS = [
    # Quoted REST API paths
    (re.compile(r'["\'\`](/api/v?\d+[/a-zA-Z0-9_\-\.{}:?=&%]*)["\'\`]'), "REST API path"),
    (re.compile(r'["\'\`](/api/[a-zA-Z0-9/_\-\.{}:?=&%]{3,})["\'\`]'), "API path"),

    # GraphQL
    (re.compile(r'["\'\`](/graphql[a-zA-Z0-9/_\-?=&]*)["\'\`]'), "GraphQL endpoint"),
    (re.compile(r'["\'\`](/gql[a-zA-Z0-9/_\-?=&]*)["\'\`]'), "GraphQL short"),

    # REST / versioned paths
    (re.compile(r'["\'\`](/rest/[a-zA-Z0-9/_\-\.{}:?=&%]+)["\'\`]'), "REST path"),
    (re.compile(r'["\'\`](/v[1-9]\d*/[a-zA-Z0-9/_\-\.{}:?=&%]+)["\'\`]'), "Versioned path"),

    # Common auth/user/admin paths
    (re.compile(
        r'["\'\`](/(?:auth|oauth|login|logout|signup|register|token|refresh|verify|'
        r'user|users|me|profile|account|admin|dashboard|settings|config|'
        r'health|status|ping|search|upload|download|export|import|'
        r'webhook|callback|redirect|confirm|reset|invite|payment|order|'
        r'product|cart|checkout|notification|feed|activity|report)'
        r'(?:/[a-zA-Z0-9/_\-\.{}:?=&%]*)?)["\'\`]', re.I
    ), "Auth/common path"),

    # fetch() calls
    (re.compile(r'fetch\s*\(\s*["\'\`]([^"\'`\s]{4,200})["\'\`]', re.I), "fetch()"),
    (re.compile(r'fetch\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*["\'\`][^"\'`]{2,100}["\'\`])', re.I), "fetch() concat"),

    # axios calls
    (re.compile(r'axios\.(?:get|post|put|delete|patch|head|options)\s*\(\s*["\'\`]([^"\'`\s]{4,200})["\'\`]', re.I), "axios call"),
    (re.compile(r'axios\s*\(\s*\{[^}]*url\s*:\s*["\'\`]([^"\'`\s]{4,200})["\'\`]', re.I), "axios({url})"),

    # XMLHttpRequest
    (re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\']\s*,\s*["\'\`]([^"\'`\s]{4,200})["\'\`]', re.I), "XHR.open()"),

    # jQuery AJAX
    (re.compile(r'\$\.(?:ajax|get|post|getJSON|load)\s*\(\s*["\'\`]([^"\'`\s]{4,200})["\'\`]', re.I), "jQuery AJAX"),
    (re.compile(r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\'\`]([^"\'`\s]{4,200})["\'\`]', re.I), "jQuery $.ajax({url})"),

    # URL / endpoint variable assignments
    (re.compile(r'(?:url|endpoint|baseURL|apiUrl|API_URL|base_url|API_BASE|apiBase|baseUrl|API_ENDPOINT|SERVER_URL)\s*[:=]\s*["\'\`]([^"\'`\s]{5,200})["\'\`]', re.I), "URL variable"),

    # Template literals with API paths
    (re.compile(r'`([^`]*?/(?:api|rest|v\d)/[^`]{3,150})`'), "Template literal API"),
    (re.compile(r'`\$\{[^}]+\}(/[a-zA-Z0-9/_\-\.{}:]+)`'), "Template literal path"),

    # Router paths (React Router, Vue Router, Express)
    (re.compile(r'(?:path|route|to)\s*[:=]\s*["\'\`](/[a-zA-Z0-9/_\-\.{}:?=&%]+)["\'\`]', re.I), "Router path"),
    (re.compile(r'app\.(?:get|post|put|delete|patch|use)\s*\(\s*["\'\`](/[^"\'`\s]+)["\'\`]', re.I), "Express route"),

    # Next.js / Nuxt.js API routes
    (re.compile(r'["\'\`](/pages/api/[a-zA-Z0-9/_\-\.]+)["\'\`]'), "Next.js API route"),

    # WebSocket endpoints
    (re.compile(r'(?:ws|wss)://[a-zA-Z0-9._\-/:?=&%]{8,200}'), "WebSocket URL"),

    # Relative paths with common extensions
    (re.compile(r'["\'\`](/[a-zA-Z0-9/_\-]{3,100}\.(?:php|asp|aspx|jsp|json|xml|action)(?:\?[^"\'`\s]*)?)["\'\`]'), "File endpoint"),

    # Dynamic endpoint construction (e.g., baseUrl + '/users/' + id)
    (re.compile(r'["\'\`](https?://[a-zA-Z0-9._\-/:?=&%#@]{8,300})["\'\`]'), "Absolute URL"),

    # AJAX url patterns in object literals
    (re.compile(r'["\'\`]url["\'\`]\s*:\s*["\'\`]([^"\'`\s]{4,200})["\'\`]'), "url key in object"),
]

# Patterns for dynamically constructed endpoints
DYNAMIC_ENDPOINT_PATTERNS = [
    # String concatenation: '/api/' + version + '/users'
    (re.compile(r'["\'\`](/[a-zA-Z0-9/_\-]+/)["\'\`]\s*\+\s*[a-zA-Z_$][a-zA-Z0-9_$]*'), "Dynamic concat prefix"),
    # Template: `/api/${version}/users`
    (re.compile(r'`(/[a-zA-Z0-9/_\-]*\$\{[^}]+\}[a-zA-Z0-9/_\-\.]*)`'), "Template literal dynamic"),
    # Array.join for path construction
    (re.compile(r'\[["\']/*[a-zA-Z]+["\'],\s*["\'][a-zA-Z]+["\']\]\s*\.join\s*\(["\'/]["\']\)'), "Array.join path"),
]


# =============================================================================
# HTML ENDPOINT PARSER
# =============================================================================

class EndpointHTMLParser(HTMLParser):
    """
    Extended HTML parser that extracts endpoints from:
    - All href, src, action attributes
    - data-* attributes with URL patterns
    - form fields with potential endpoints
    - meta tags with URL content
    - script tags (inline JS analyzed separately)
    """

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url    = base_url
        self.base_domain = urlparse(base_url).netloc
        self.endpoints   = defaultdict(set)  # type -> set of URLs
        self.forms       = []
        self._cur_form   = None
        self.inline_scripts = []
        self._in_script  = False
        self._script_buf = []

    def handle_starttag(self, tag: str, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}

        # Script tags
        if tag == 'script':
            self._in_script = True
            self._script_buf = []
            src = a.get('src', '').strip()
            if src:
                url = self._abs(src)
                if url:
                    self.endpoints['script_src'].add(url)

        # Form handling
        elif tag == 'form':
            action = urljoin(self.base_url, a.get('action', '') or self.base_url)
            self._cur_form = {
                'action': action,
                'method': a.get('method', 'GET').upper(),
                'fields': [],
                'enctype': a.get('enctype', 'application/x-www-form-urlencoded'),
            }
            self.endpoints['form_action'].add(action)

        elif tag in ('input', 'textarea', 'select', 'button') and self._cur_form:
            name  = a.get('name', '').strip()
            ftype = a.get('type', 'text').lower()
            if name and ftype not in ('submit', 'reset', 'image', 'button'):
                self._cur_form['fields'].append({'name': name, 'type': ftype, 'value': a.get('value', '')})

        # Anchor tags
        elif tag == 'a':
            href = a.get('href', '').strip()
            if href and not href.startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:')):
                url = self._abs(href)
                if url:
                    self.endpoints['href'].add(url)

        # Link tags
        elif tag == 'link':
            href = a.get('href', '').strip()
            rel  = a.get('rel', '').lower()
            if href and rel not in ('stylesheet', 'icon', 'apple-touch-icon', 'manifest'):
                url = self._abs(href)
                if url:
                    self.endpoints['link_href'].add(url)

        # Image and media src
        elif tag in ('img', 'source', 'audio', 'video', 'track'):
            for attr in ('src', 'srcset', 'data-src', 'data-lazy-src'):
                val = a.get(attr, '').strip()
                if val and not val.startswith('data:'):
                    url = self._abs(val.split(',')[0].strip().split(' ')[0])
                    if url:
                        self.endpoints['media_src'].add(url)

        # IFrame, embed, object
        elif tag in ('iframe', 'embed', 'object'):
            for attr in ('src', 'data'):
                val = a.get(attr, '').strip()
                if val:
                    url = self._abs(val)
                    if url:
                        self.endpoints['embedded_src'].add(url)

        # Meta tags with URL content
        elif tag == 'meta':
            prop = a.get('property', a.get('name', '')).lower()
            content = a.get('content', '').strip()
            if content and prop in ('og:url', 'og:image', 'twitter:url', 'twitter:image'):
                url = self._abs(content)
                if url:
                    self.endpoints['meta_url'].add(url)

        # Scan ALL tags for data-* URL attributes
        for attr_name, attr_val in a.items():
            if attr_name.startswith('data-') and attr_val:
                if attr_val.startswith(('/', 'http://', 'https://')):
                    url = self._abs(attr_val)
                    if url:
                        self.endpoints['data_attr'].add(url)

    def handle_endtag(self, tag: str):
        if tag == 'script':
            self._in_script = False
            body = ''.join(self._script_buf).strip()
            if body:
                self.inline_scripts.append(body)
            self._script_buf = []
        elif tag == 'form' and self._cur_form:
            self.forms.append(self._cur_form)
            self._cur_form = None

    def handle_data(self, data: str):
        if self._in_script:
            self._script_buf.append(data)

    def _abs(self, url: str) -> str:
        if not url:
            return ''
        try:
            result = urljoin(self.base_url, url.strip())
            if result.startswith(('http://', 'https://', 'ws://', 'wss://')):
                return result.split('#')[0]
        except Exception:
            pass
        return ''


# =============================================================================
# JAVASCRIPT ENDPOINT EXTRACTOR
# =============================================================================

class JSEndpointExtractor:
    """
    Extracts endpoints from JavaScript source code including:
    - API paths (REST, GraphQL, etc.)
    - fetch/axios/XHR calls
    - URL variable assignments
    - Router definitions
    - Dynamically constructed endpoints
    """

    def __init__(self, base_url: str = ''):
        self.base_url = base_url

    def extract(self, js_content: str, source_name: str = 'unknown') -> dict:
        """
        Extract all endpoints from JS content.
        Returns dict: { endpoint_type: [{'url': str, 'source': str, 'line': int, 'context': str}] }
        """
        results = defaultdict(list)
        lines   = js_content.split('\n')

        for pattern, ep_type in JS_ENDPOINT_PATTERNS:
            for m in pattern.finditer(js_content):
                url = m.group(1) if m.lastindex else m.group(0)
                url = url.strip()

                # Skip obvious non-endpoints
                if len(url) < 3 or len(url) > 500:
                    continue
                if self._is_false_positive(url):
                    continue

                # Normalize relative paths
                if url.startswith('/') and self.base_url:
                    full_url = urljoin(self.base_url, url)
                elif url.startswith('http'):
                    full_url = url
                else:
                    full_url = url  # keep relative

                line_no = js_content[:m.start()].count('\n') + 1
                line    = lines[line_no - 1].strip()[:200] if line_no <= len(lines) else ''

                results[ep_type].append({
                    'url':     full_url,
                    'raw':     url,
                    'source':  source_name,
                    'line':    line_no,
                    'context': line,
                })

        # Extract dynamically constructed endpoints
        for pattern, ep_type in DYNAMIC_ENDPOINT_PATTERNS:
            for m in pattern.finditer(js_content):
                line_no = js_content[:m.start()].count('\n') + 1
                line    = lines[line_no - 1].strip()[:200] if line_no <= len(lines) else ''
                results[f'dynamic_{ep_type}'].append({
                    'url':     m.group(0)[:200],
                    'raw':     m.group(0)[:200],
                    'source':  source_name,
                    'line':    line_no,
                    'context': line,
                    'note':    'Dynamic construction — needs manual review',
                })

        return dict(results)

    def _is_false_positive(self, url: str) -> bool:
        """Filter out obvious false positives."""
        # Too short
        if len(url) < 3:
            return True
        # Pure JS code fragments
        if any(c in url for c in ['{', '}', '(', ')', ';', '\n', '\\n']):
            if not url.startswith('http'):
                return True
        # JS keywords mistaken for paths
        js_keywords = {'undefined', 'null', 'true', 'false', 'this', 'typeof',
                       'instanceof', 'return', 'function', 'var', 'let', 'const'}
        if url.strip('/') in js_keywords:
            return True
        # CSS/image extensions that aren't endpoints
        non_endpoint_exts = {'.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                             '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map',
                             '.webp', '.avif', '.bmp'}
        for ext in non_endpoint_exts:
            if url.lower().endswith(ext):
                return True
        return False


# =============================================================================
# FULL ENDPOINT COLLECTION
# =============================================================================

class EndpointCollector:
    """
    Comprehensive endpoint collector that combines HTML and JS extraction.
    Fetches pages, parses HTML, analyzes inline JS, and processes JS files.
    """

    def __init__(self, target_url: str, session: requests.Session = None, base_url: str = None):
        if '://' not in target_url:
            target_url = 'https://' + target_url
        self.target_url  = target_url
        self.base_url    = base_url or target_url
        self.base_domain = urlparse(target_url).netloc
        self.session     = session or requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36',
        })
        self.js_extractor = JSEndpointExtractor(base_url=self.base_url)

        # Results store
        self.all_endpoints   = defaultdict(set)    # type -> set of normalized URLs
        self.js_endpoints    = defaultdict(list)   # type -> list of {url, source, line, context}
        self.html_endpoints  = defaultdict(set)    # type -> set of URLs
        self.forms_found     = []
        self.param_map       = defaultdict(set)    # base_url -> set of param names
        self.dynamic_patterns = []                 # dynamically constructed endpoint patterns

    def collect_from_html(self, html_content: str, page_url: str):
        """Extract all endpoints from an HTML page."""
        parser = EndpointHTMLParser(page_url)
        try:
            parser.feed(html_content)
        except Exception:
            pass

        # Merge HTML endpoints
        for ep_type, urls in parser.endpoints.items():
            self.html_endpoints[ep_type].update(urls)
            self.all_endpoints[ep_type].update(urls)

        # Store forms
        self.forms_found.extend(parser.forms)
        for form in parser.forms:
            base = form['action'].split('?')[0]
            for field in form['fields']:
                self.param_map[base].add(field['name'])

        # Extract params from href URLs
        for url in parser.endpoints.get('href', set()):
            parsed = urlparse(url)
            if parsed.netloc == self.base_domain:
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                params = list(parse_qs(parsed.query).keys())
                if params:
                    self.param_map[base].update(params)

        # Analyze inline scripts
        for script_body in parser.inline_scripts:
            js_results = self.js_extractor.extract(script_body, f'inline@{urlparse(page_url).path}')
            for ep_type, findings in js_results.items():
                self.js_endpoints[ep_type].extend(findings)
                if ep_type.startswith('dynamic_'):
                    self.dynamic_patterns.extend(findings)
                else:
                    for f in findings:
                        url = f['url']
                        self.all_endpoints[f'js_{ep_type}'].add(url)

    def collect_from_js_file(self, js_content: str, filename: str):
        """Extract all endpoints from a JS file."""
        js_results = self.js_extractor.extract(js_content, filename)
        for ep_type, findings in js_results.items():
            self.js_endpoints[ep_type].extend(findings)
            if ep_type.startswith('dynamic_'):
                self.dynamic_patterns.extend(findings)
            else:
                for f in findings:
                    url = f['url']
                    self.all_endpoints[f'js_{ep_type}'].add(url)

    def collect_from_js_dir(self, js_dir: Path):
        """Process all JS files in a directory."""
        js_files = list(js_dir.glob('*.js'))
        print(f"[*] Analyzing {len(js_files)} JS files for endpoints...")
        for js_file in js_files:
            try:
                content = js_file.read_text(encoding='utf-8', errors='replace')
                self.collect_from_js_file(content, js_file.name)
            except Exception as e:
                print(f"  [!] Error reading {js_file.name}: {e}")

    def get_summary(self) -> dict:
        """Build structured summary of all discovered endpoints."""
        all_urls = set()
        for urls in self.all_endpoints.values():
            all_urls.update(urls)

        # Categorize by domain
        same_domain = set()
        external    = set()
        for url in all_urls:
            parsed = urlparse(url)
            if parsed.netloc == self.base_domain or not parsed.netloc:
                same_domain.add(url)
            elif parsed.netloc:
                external.add(url)

        # Deduplicated JS endpoint details
        flat_js = []
        seen_js = set()
        for ep_type, findings in self.js_endpoints.items():
            for f in findings:
                key = f"{f['url']}:{f['source']}:{f['line']}"
                if key not in seen_js:
                    seen_js.add(key)
                    flat_js.append({**f, 'type': ep_type})

        return {
            'total_endpoints':    len(all_urls),
            'same_domain':        sorted(same_domain),
            'external':           sorted(external),
            'by_type':            {k: sorted(v) for k, v in self.all_endpoints.items()},
            'js_endpoints':       flat_js,
            'forms':              self.forms_found,
            'param_map':          {k: sorted(v) for k, v in self.param_map.items()},
            'dynamic_patterns':   self.dynamic_patterns[:50],  # cap
            'stats': {
                'total':        len(all_urls),
                'same_domain':  len(same_domain),
                'external':     len(external),
                'forms':        len(self.forms_found),
                'js_endpoints': len(flat_js),
                'dynamic':      len(self.dynamic_patterns),
            }
        }

    def save_report(self, output_dir: Path):
        """Save endpoint extraction results to files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = self.get_summary()

        # JSON output
        json_path = output_dir / 'endpoints.json'
        json_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')
        print(f"[+] Endpoints JSON: {json_path}")

        # Plain text output
        txt_lines = [
            "=" * 60,
            "ENDPOINT EXTRACTION REPORT",
            f"Target: {self.target_url}",
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60,
            "",
            f"Total endpoints found: {summary['stats']['total']}",
            f"Same-domain: {summary['stats']['same_domain']}",
            f"External: {summary['stats']['external']}",
            f"Forms found: {summary['stats']['forms']}",
            f"JS endpoints: {summary['stats']['js_endpoints']}",
            f"Dynamic patterns: {summary['stats']['dynamic']}",
            "",
            "--- SAME-DOMAIN ENDPOINTS ---",
        ]
        for url in sorted(summary['same_domain']):
            txt_lines.append(f"  {url}")

        txt_lines += ["", "--- JS-DISCOVERED API ENDPOINTS ---"]
        api_types = [t for t in summary['by_type'] if 'js_' in t or 'fetch' in t or 'axios' in t]
        for ep_type in api_types:
            txt_lines.append(f"\n[{ep_type}]")
            for url in sorted(summary['by_type'].get(ep_type, []))[:50]:
                txt_lines.append(f"  {url}")

        txt_lines += ["", "--- FORMS ---"]
        for form in summary['forms']:
            txt_lines.append(f"  {form['method']} {form['action']}")
            for field in form['fields']:
                txt_lines.append(f"    param: {field['name']} (type={field['type']})")

        if summary['dynamic_patterns']:
            txt_lines += ["", "--- DYNAMIC ENDPOINT PATTERNS (review manually) ---"]
            for dp in summary['dynamic_patterns'][:20]:
                txt_lines.append(f"  [{dp['source']}:{dp['line']}] {dp['url'][:120]}")

        txt_path = output_dir / 'endpoints.txt'
        txt_path.write_text('\n'.join(txt_lines), encoding='utf-8')
        print(f"[+] Endpoints TXT:  {txt_path}")

        return summary


# =============================================================================
# STANDALONE CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(description='Endpoint Extractor — standalone mode')
    ap.add_argument('target', help='Target URL or --js-dir flag')
    ap.add_argument('--js-dir', help='Path to directory of downloaded JS files')
    ap.add_argument('--output', default='endpoint_output', help='Output directory')
    args = ap.parse_args()

    collector = EndpointCollector(args.target)

    if args.js_dir:
        collector.collect_from_js_dir(Path(args.js_dir))
    else:
        print(f"[*] Fetching {args.target}...")
        try:
            r = collector.session.get(args.target, timeout=15)
            collector.collect_from_html(r.text, args.target)
            print(f"[+] Fetched page, extracted {sum(len(v) for v in collector.all_endpoints.values())} endpoints from HTML")
        except Exception as e:
            print(f"[!] Failed to fetch: {e}")

    summary = collector.save_report(Path(args.output))
    print(f"\n[✓] Done. Total endpoints: {summary['stats']['total']}")


if __name__ == '__main__':
    main()
