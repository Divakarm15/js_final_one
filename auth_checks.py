#!/usr/bin/env python3
"""
auth_checks.py — Authentication & Session Security Module
==========================================================
Detects:
  1. OAuth 2.0 vulnerabilities
     - Missing state parameter (CSRF on OAuth flow)
     - redirect_uri manipulation (open redirect in OAuth)
     - Token leakage in Referer / logs
     - Implicit flow token in URL fragment
     - PKCE missing (code interception)
  2. Session fixation
     - Session ID unchanged after login
  3. Broken access control
     - Horizontal: access other users' resources without auth change
     - Vertical: low-priv user accessing admin/privileged endpoints
  4. Directory listing
     - Apache/nginx autoindex on directories

FP reduction:
  - OAuth: only flag if we find actual token/code patterns in wrong place
  - Session fixation: requires pre/post login comparison
  - Access control: requires 2 different responses to same resource
  - Directory listing: content must contain specific index signatures
"""

import re
import time
import random
import string
import hashlib
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    raise ImportError("[!] pip install requests")

log = logging.getLogger('jsscout.auth')


def _get(session, url, timeout=10, **kw):
    try:
        return session.get(url, timeout=timeout, verify=False, allow_redirects=False, **kw)
    except Exception:
        return None


def _post(session, url, timeout=10, **kw):
    try:
        return session.post(url, timeout=timeout, verify=False, allow_redirects=False, **kw)
    except Exception:
        return None


# =============================================================================
# 1. OAUTH 2.0 CHECKER
# =============================================================================

class OAuthChecker:
    """
    Detects OAuth 2.0 security issues by:
    1. Finding OAuth authorization endpoints via link/meta scanning
    2. Testing state parameter absence (CSRF)
    3. Testing redirect_uri manipulation
    4. Checking for token leakage in URL / Referer
    5. Detecting implicit flow (token in URL fragment)
    6. Checking for PKCE absence on public clients
    """

    OAUTH_PATHS = [
        '/oauth/authorize', '/oauth/auth', '/oauth2/authorize', '/oauth2/auth',
        '/auth/oauth', '/connect/authorize', '/authorize', '/auth/login',
        '/login/oauth', '/api/oauth/authorize', '/.well-known/openid-configuration',
    ]

    # Patterns indicating OAuth endpoints
    OAUTH_ENDPOINT_RE = re.compile(
        r'(?:href|action|url)\s*[=:]\s*["\']([^"\']*(?:oauth|authorize|auth|login)[^"\']*)["\']',
        re.I
    )
    TOKEN_IN_URL_RE = re.compile(
        r'[?&#](access_token|id_token|token|code)=([A-Za-z0-9._\-]{10,})', re.I
    )
    CLIENT_ID_RE = re.compile(
        r'client_id=([A-Za-z0-9._\-]{4,})', re.I
    )
    STATE_RE = re.compile(r'[?&]state=', re.I)
    REDIRECT_URI_RE = re.compile(r'[?&]redirect_uri=([^&]+)', re.I)

    # Common test redirect URIs for manipulation
    EVIL_REDIRECTS = [
        'https://evil.jsscout.test/callback',
        'https://evil.jsscout.test%2F@legitimate.com/callback',
        'https://legitimate.com.evil.jsscout.test/callback',
        '//evil.jsscout.test/callback',
        'javascript:alert(1)',
    ]

    def __init__(self, session: requests.Session, timeout: int = 8):
        self.session = session
        self.timeout = timeout

    def check(self, base_url: str, page_content: str = '', all_urls: list = None) -> list:
        findings = []
        all_urls = all_urls or []

        # Find OAuth endpoints
        oauth_urls = self._discover_oauth_endpoints(base_url, page_content, all_urls)

        for oauth_url in oauth_urls[:5]:
            findings.extend(self._test_endpoint(base_url, oauth_url))

        # Check all pages for token leakage in URLs
        findings.extend(self._check_token_leakage(all_urls, page_content))

        return findings

    def _discover_oauth_endpoints(self, base_url: str, content: str, urls: list) -> list:
        endpoints = set()

        # Try well-known paths
        for path in self.OAUTH_PATHS:
            endpoints.add(urljoin(base_url, path))

        # Extract from page content
        for m in self.OAUTH_ENDPOINT_RE.finditer(content):
            url = urljoin(base_url, m.group(1))
            if urlparse(url).netloc == urlparse(base_url).netloc:
                endpoints.add(url)

        # From discovered URLs
        for url in urls:
            if any(kw in url.lower() for kw in ['oauth', 'authorize', '/auth/', 'openid']):
                endpoints.add(url)

        return list(endpoints)

    def _test_endpoint(self, base_url: str, oauth_url: str) -> list:
        findings = []

        r = _get(self.session, oauth_url, self.timeout)
        if not r:
            return findings

        # Check if it looks like an OAuth endpoint (has client_id, response_type)
        body = r.text[:5000]
        final_url = r.headers.get('Location', oauth_url)

        has_client_id  = bool(self.CLIENT_ID_RE.search(final_url + body))
        has_state      = bool(self.STATE_RE.search(final_url + body))
        has_redirect   = bool(self.REDIRECT_URI_RE.search(final_url))
        is_oauth_like  = has_client_id or 'response_type' in (final_url + body).lower()

        if not is_oauth_like:
            return findings

        # 1. Missing state parameter
        if not has_state and 'response_type' in final_url.lower():
            findings.append({
                'type':        'OAUTH_MISSING_STATE',
                'severity':    'HIGH',
                'confidence':  'HIGH',
                'url':         oauth_url,
                'description': 'OAuth authorization request missing state parameter — CSRF possible',
                'evidence':    f'Authorization URL lacks state=: {final_url[:200]}',
                'remediation': 'Include a cryptographically random state parameter in all OAuth requests. '
                               'Validate it on callback.',
            })

        # 2. Redirect URI manipulation
        if has_redirect:
            redirect_m = self.REDIRECT_URI_RE.search(final_url)
            if redirect_m:
                legitimate_redir = redirect_m.group(1)
                findings.extend(self._test_redirect_uri_manipulation(oauth_url, legitimate_redir))

        # 3. Implicit flow (token in URL fragment — deprecated, insecure)
        if 'response_type=token' in final_url.lower() or 'token' in parse_qs(urlparse(final_url).query).get('response_type', [''])[0]:
            findings.append({
                'type':        'OAUTH_IMPLICIT_FLOW',
                'severity':    'MEDIUM',
                'confidence':  'HIGH',
                'url':         oauth_url,
                'description': 'OAuth implicit flow detected — access token exposed in URL fragment',
                'evidence':    f'response_type=token found in: {final_url[:200]}',
                'remediation': 'Migrate to Authorization Code flow with PKCE. Implicit flow is deprecated (RFC 9700).',
            })

        # 4. PKCE check (for public clients — if no code_challenge, flag it)
        if 'response_type=code' in final_url.lower():
            if 'code_challenge' not in final_url.lower():
                findings.append({
                    'type':        'OAUTH_MISSING_PKCE',
                    'severity':    'MEDIUM',
                    'confidence':  'MEDIUM',
                    'url':         oauth_url,
                    'description': 'OAuth code flow without PKCE — authorization code interception possible',
                    'evidence':    f'code_challenge absent from: {final_url[:200]}',
                    'remediation': 'Implement PKCE (Proof Key for Code Exchange) for all public clients (RFC 7636).',
                })

        return findings

    def _test_redirect_uri_manipulation(self, oauth_url: str, legitimate_redir: str) -> list:
        findings = []
        parsed   = urlparse(oauth_url)
        base_url_no_redir = oauth_url.replace(f'redirect_uri={legitimate_redir}', 'redirect_uri={}')

        for evil_redir in self.EVIL_REDIRECTS[:3]:
            test_url = base_url_no_redir.format(quote(evil_redir, safe=''))
            r = _get(self.session, test_url, self.timeout)
            if not r:
                continue

            loc = r.headers.get('Location', '')
            # Only flag if server actually redirects to our evil domain
            if 'evil.jsscout.test' in loc or ('javascript:' in loc.lower()):
                findings.append({
                    'type':        'OAUTH_REDIRECT_URI_MANIPULATION',
                    'severity':    'CRITICAL',
                    'confidence':  'HIGH',
                    'url':         test_url,
                    'description': 'OAuth redirect_uri manipulation — server accepts arbitrary redirect URI',
                    'evidence':    f'Redirect to: {loc} after injecting {evil_redir}',
                    'remediation': 'Whitelist exact redirect URIs. Never accept wildcards or partial matches.',
                })
                break

        return findings

    def _check_token_leakage(self, urls: list, page_content: str) -> list:
        findings = []

        # Token in URL (should be in POST body / Authorization header)
        for url in urls:
            m = self.TOKEN_IN_URL_RE.search(url)
            if m:
                param = m.group(1)
                # access_token in URL is always bad; code is OK only on callback
                if param == 'access_token':
                    findings.append({
                        'type':        'OAUTH_TOKEN_IN_URL',
                        'severity':    'HIGH',
                        'confidence':  'HIGH',
                        'url':         url,
                        'description': f'OAuth access_token exposed in URL — leaks via Referer/logs',
                        'evidence':    f'access_token= found in URL: {url[:150]}',
                        'remediation': 'Tokens must be transmitted in Authorization header or POST body, never in URLs.',
                    })

        # Token in page body (might be in HTML response for implicit flow)
        m = self.TOKEN_IN_URL_RE.search(page_content[:10000])
        if m and m.group(1) == 'access_token':
            findings.append({
                'type':        'OAUTH_TOKEN_IN_RESPONSE_BODY',
                'severity':    'MEDIUM',
                'confidence':  'MEDIUM',
                'url':         'page_content',
                'description': 'OAuth access_token appears in HTML response body',
                'evidence':    f'access_token={m.group(2)[:20]}... in page content',
                'remediation': 'Do not embed tokens in HTML. Use secure storage (httpOnly cookie or memory).',
            })

        return findings


# =============================================================================
# 2. SESSION FIXATION CHECKER
# =============================================================================

class SessionFixationChecker:
    """
    Detects session fixation by:
    1. Recording session cookie before login
    2. Performing a login (with test credentials or observing the flow)
    3. Checking if session ID changes post-authentication
    
    Note: Requires login form detection. Will skip if no login found.
    """

    SESSION_COOKIE_RE = re.compile(
        r'^(session|sess|sid|sessionid|phpsessid|jsessionid|asp\.net_sessionid|'
        r'laravel_session|ci_session|flask_session|auth_token|user_token)$', re.I)

    def __init__(self, session: requests.Session, timeout: int = 10):
        self.session = session
        self.timeout = timeout

    def check(self, login_url: str, forms: list = None) -> list:
        if not login_url:
            return []

        findings = []

        # Get pre-login cookies
        pre_cookies = dict(self.session.cookies)
        pre_session_ids = {
            k: v for k, v in pre_cookies.items()
            if self.SESSION_COOKIE_RE.match(k)
        }

        if not pre_session_ids:
            # Try a GET to the login page to get a session
            r = _get(self.session, login_url, self.timeout)
            if r:
                pre_cookies = dict(self.session.cookies)
                pre_session_ids = {
                    k: v for k, v in pre_cookies.items()
                    if self.SESSION_COOKIE_RE.match(k)
                }

        if not pre_session_ids:
            return findings  # No session cookies to test

        # Attempt login with test credentials
        login_form = self._find_login_form(forms or [])
        if not login_form:
            return findings

        test_creds = self._get_test_data(login_form)
        r_login = _post(self.session, login_url, self.timeout, data=test_creds)

        if not r_login:
            return findings

        # Post-login cookies
        post_cookies = dict(self.session.cookies)

        for cookie_name, pre_value in pre_session_ids.items():
            post_value = post_cookies.get(cookie_name)
            if post_value and post_value == pre_value:
                findings.append({
                    'type':        'SESSION_FIXATION',
                    'severity':    'HIGH',
                    'confidence':  'MEDIUM',
                    'url':         login_url,
                    'cookie':      cookie_name,
                    'description': f'Session fixation — "{cookie_name}" unchanged after login attempt',
                    'evidence':    f'Cookie "{cookie_name}" same before and after login: {pre_value[:20]}...',
                    'remediation': 'Regenerate session ID on every successful authentication. '
                                   'Invalidate old session before creating new one.',
                })

        return findings

    def _find_login_form(self, forms: list) -> dict:
        for form in forms:
            inputs = form.get('inputs', [])
            has_password = any(i.get('type') == 'password' for i in inputs)
            has_text     = any(i.get('type') in ('text', 'email') for i in inputs)
            if has_password and has_text:
                return form
        return None

    def _get_test_data(self, form: dict) -> dict:
        data = {}
        for inp in form.get('inputs', []):
            name = inp.get('name', '')
            t    = inp.get('type', 'text')
            if not name:
                continue
            if t == 'password':
                data[name] = 'jsscout_test_pass_12345!'
            elif t in ('text', 'email'):
                data[name] = 'jsscout_test@jsscout.test'
            elif t == 'hidden':
                data[name] = inp.get('value', '')
            elif t == 'submit':
                pass
            else:
                data[name] = inp.get('value', 'test')
        return data


# =============================================================================
# 3. BROKEN ACCESS CONTROL CHECKER
# =============================================================================

class BrokenAccessControlChecker:
    """
    Detects broken access control:
    
    Horizontal privilege escalation:
      - Access user A's resource as user B (via IDOR on profile/orders/documents)
    
    Vertical privilege escalation:
      - Access admin endpoints without admin role
      - Admin functions accessible without authentication
    
    Method: Compare responses for authenticated vs unauthenticated requests
    to sensitive endpoints. Flag when unauthenticated gets same data.
    """

    ADMIN_PATHS = [
        '/admin', '/admin/', '/admin/dashboard', '/admin/users', '/admin/config',
        '/admin/settings', '/admin/logs', '/admin/reports', '/admin/export',
        '/api/admin', '/api/admin/users', '/api/internal', '/api/private',
        '/management', '/manager', '/control', '/panel',
        '/superadmin', '/sysadmin', '/root',
        '/api/v1/admin', '/api/v2/admin',
        '/users', '/users/list', '/api/users', '/api/users/all',
        '/dashboard/admin', '/dashboard/stats',
        '/actuator/env', '/actuator/beans', '/actuator/mappings',
    ]

    def __init__(self, session: requests.Session, timeout: int = 8):
        self.session = session
        self.timeout = timeout

    def check(self, base_url: str, auth_headers: dict = None,
              discovered_admin_urls: list = None) -> list:
        findings = []

        test_urls = list(set(
            [urljoin(base_url, p) for p in self.ADMIN_PATHS] +
            (discovered_admin_urls or [])
        ))

        # Build unauthenticated session
        unauth_session = requests.Session()
        unauth_session.verify = False
        unauth_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; JSScoutPro)'
        })

        for url in test_urls[:30]:
            # Authenticated request
            auth_r = _get(self.session, url, self.timeout)
            if not auth_r or auth_r.status_code == 404:
                continue
            if auth_r.status_code not in (200, 201, 202, 301, 302):
                continue

            # Unauthenticated request (no cookies, no auth header)
            unauth_r = _get(unauth_session, url, self.timeout)
            if not unauth_r:
                continue

            findings.extend(self._compare(url, auth_r, unauth_r))

        return findings

    def _compare(self, url: str, auth_r, unauth_r) -> list:
        findings = []

        # Unauthenticated gets same 200 with substantial content
        if unauth_r.status_code in (200, 201, 202) and len(unauth_r.text) > 200:
            if len(unauth_r.text) > 500:
                findings.append({
                    'type':        'BROKEN_ACCESS_CONTROL',
                    'severity':    'HIGH',
                    'confidence':  'MEDIUM',
                    'url':         url,
                    'description': f'Sensitive endpoint accessible without authentication',
                    'evidence':    (f'Unauthenticated request → {unauth_r.status_code} '
                                    f'({len(unauth_r.text)}B). Auth request → {auth_r.status_code}'),
                    'remediation': 'Enforce authentication on all sensitive endpoints. '
                                   'Use deny-by-default access control.',
                })

        # Unauthenticated gets redirect to same resource (not login page)
        elif unauth_r.status_code in (301, 302):
            loc = unauth_r.headers.get('Location', '')
            if 'login' not in loc.lower() and 'signin' not in loc.lower():
                findings.append({
                    'type':        'BROKEN_ACCESS_CONTROL',
                    'severity':    'MEDIUM',
                    'confidence':  'LOW',
                    'url':         url,
                    'description': f'Sensitive endpoint redirects unauthenticated user (not to login)',
                    'evidence':    f'Unauthenticated → {unauth_r.status_code} Location: {loc}',
                    'remediation': 'Verify redirect destination is the login page.',
                })

        return findings


# =============================================================================
# 4. DIRECTORY LISTING CHECKER
# =============================================================================

class DirectoryListingChecker:
    """
    Checks for enabled directory listing (Apache autoindex, nginx autoindex).
    Uses multiple detection signatures to avoid FPs.
    """

    # These signatures all appearing together = high confidence directory listing
    SIGNATURES = [
        re.compile(r'Index of /', re.I),
        re.compile(r'<title>Index of', re.I),
        re.compile(r'\[To Parent Directory\]', re.I),
        re.compile(r'Directory listing for /', re.I),
        re.compile(r'<a href="\.\./?">\.\.\/?<\/a>', re.I),
    ]

    # Nginx-style
    NGINX_SIG = re.compile(r'<h1>Index of /', re.I)

    # Paths likely to have directories
    TEST_PATHS = [
        '/', '/images/', '/js/', '/css/', '/static/', '/assets/',
        '/uploads/', '/files/', '/backup/', '/temp/', '/tmp/',
        '/logs/', '/log/', '/docs/', '/api/',
        '/media/', '/img/', '/scripts/', '/inc/', '/includes/',
    ]

    def __init__(self, session: requests.Session, timeout: int = 8):
        self.session = session
        self.timeout = timeout

    def check(self, base_url: str, extra_paths: list = None) -> list:
        findings = []
        paths    = self.TEST_PATHS + (extra_paths or [])
        seen     = set()

        for path in paths:
            url = urljoin(base_url, path)
            if url in seen:
                continue
            seen.add(url)

            r = _get(self.session, url, self.timeout)
            if not r or r.status_code != 200:
                continue

            body = r.text[:5000]
            ct   = r.headers.get('Content-Type', '').lower()

            if 'html' not in ct:
                continue

            # Must match at least one strong signature
            matched = [s for s in self.SIGNATURES if s.search(body)]
            if matched or self.NGINX_SIG.search(body):
                findings.append({
                    'type':        'DIRECTORY_LISTING',
                    'severity':    'MEDIUM',
                    'confidence':  'HIGH',
                    'url':         url,
                    'description': f'Directory listing enabled at {path}',
                    'evidence':    f'Signature matched: {matched[0].pattern[:50] if matched else "nginx index"}',
                    'remediation': 'Disable directory listing. Apache: Options -Indexes. Nginx: autoindex off;',
                })

        return findings


# =============================================================================
# 5. PARAMETER DISCOVERY (hidden param fuzzing)
# =============================================================================

class ParameterDiscovery:
    """
    Discovers hidden/undocumented parameters by:
    1. Fuzzing common parameter names and checking for response differences
    2. Extracting params from JS files (variable names, fetch/axios calls)
    3. Checking for param-based debug modes (debug=1, test=1, verbose=1)
    """

    # Common hidden / interesting parameters
    WORDLIST = [
        # Debug / dev
        'debug', 'test', 'verbose', 'dev', 'development', 'preview',
        'trace', 'log', 'logging', 'mode', 'env', 'environment',
        # Auth bypass candidates
        'admin', 'is_admin', 'role', 'privilege', 'access', 'internal',
        'bypass', 'override', 'force',
        # Data access
        'id', 'user_id', 'uid', 'account', 'profile', 'token',
        'key', 'api_key', 'apikey', 'secret',
        # Common form params
        'callback', 'redirect', 'url', 'next', 'return', 'ref',
        'source', 'from', 'format', 'output', 'type',
        # Feature flags
        'feature', 'flag', 'beta', 'experimental',
        # Pagination
        'page', 'limit', 'offset', 'count', 'per_page',
        # Filters
        'filter', 'sort', 'order', 'search', 'q', 'query',
    ]

    DEBUG_PARAMS = {
        'debug': ['1', 'true', 'yes', 'on', '2'],
        'test':  ['1', 'true'],
        'dev':   ['1', 'true'],
        'verbose': ['1', 'true', '2'],
        'trace': ['1', 'true'],
    }

    def __init__(self, session: requests.Session, timeout: int = 8):
        self.session = session
        self.timeout = timeout

    def discover(self, url: str, known_params: list = None,
                 js_content: str = '') -> dict:
        """
        Returns dict with:
          'hidden_params': list of params that change the response
          'debug_params':  list of params that trigger debug output
          'js_params':     params extracted from JS
        """
        results = {
            'hidden_params': [],
            'debug_params':  [],
            'js_params':     [],
        }

        # Baseline
        r_base = _get(self.session, url, self.timeout)
        if not r_base:
            return results

        baseline_hash = hashlib.sha256(r_base.text.encode()).hexdigest()
        baseline_len  = len(r_base.text)

        known = set(known_params or [])
        params_to_test = [p for p in self.WORDLIST if p not in known][:40]

        # Test each param
        for param in params_to_test:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}=jsscout_probe"
            r = _get(self.session, test_url, self.timeout)
            if not r:
                continue

            r_hash = hashlib.sha256(r.text.encode()).hexdigest()
            len_diff = abs(len(r.text) - baseline_len)

            if r_hash != baseline_hash and len_diff > 50:
                results['hidden_params'].append({
                    'param':     param,
                    'url':       test_url,
                    'len_diff':  len_diff,
                    'status':    r.status_code,
                    'evidence':  f'Response changed by {len_diff}B with param={param}',
                })

        # Test debug params
        for param, values in self.DEBUG_PARAMS.items():
            for val in values:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={val}"
                r = _get(self.session, test_url, self.timeout)
                if not r:
                    continue
                body = r.text[:5000]
                # Look for debug indicators in response
                debug_indicators = [
                    'sql query', 'database error', 'stack trace',
                    'debug mode', 'traceback', 'exception', 'warning:',
                    '__debug__', 'var_dump', 'print_r',
                ]
                if any(ind in body.lower() for ind in debug_indicators):
                    results['debug_params'].append({
                        'param':     f'{param}={val}',
                        'url':       test_url,
                        'evidence':  'Debug output detected in response',
                        'severity':  'HIGH',
                    })
                    break

        # Extract params from JS
        results['js_params'] = self._extract_from_js(js_content)

        return results

    def _extract_from_js(self, js_content: str) -> list:
        """Extract parameter names from JS fetch/axios/XMLHttpRequest calls."""
        params = set()

        # fetch('/api/endpoint', {body: JSON.stringify({param: ...})})
        fetch_re  = re.compile(r'fetch\(["\']([^"\']+)["\']', re.I)
        param_re  = re.compile(r'["\']([a-z_][a-z0-9_]{2,30})["\']:\s*(?:params\[|data\.|body\.)', re.I)
        qs_re     = re.compile(r'\?([a-z_][a-z0-9_]{2,30})=', re.I)
        url_re    = re.compile(r'url\s*[+]=\s*["\']&?([a-z_][a-z0-9_]{2,30})=', re.I)

        for pattern in [param_re, qs_re, url_re]:
            for m in pattern.finditer(js_content[:100000]):
                name = m.group(1)
                if name not in {'true', 'false', 'null', 'undefined', 'function'}:
                    params.add(name)

        return sorted(params)[:50]


# =============================================================================
# AUTH CHECKS ORCHESTRATOR
# =============================================================================

class AuthChecker:
    """Runs all authentication and session security checks."""

    def __init__(self, session: requests.Session, timeout: int = 10, log_fn=None):
        self.session  = session
        self.timeout  = timeout
        self.log      = log_fn or print
        self.oauth    = OAuthChecker(session, timeout)
        self.fixation = SessionFixationChecker(session, timeout)
        self.bac      = BrokenAccessControlChecker(session, timeout)
        self.dirlist  = DirectoryListingChecker(session, timeout)
        self.paramd   = ParameterDiscovery(session, timeout)
        self.findings = []

    def run_all(self, base_url: str, page_content: str = '',
                all_urls: list = None, forms: list = None,
                js_content: str = '', login_url: str = None) -> dict:

        results = {
            'oauth':             [],
            'session_fixation':  [],
            'broken_access':     [],
            'directory_listing': [],
            'hidden_params':     [],
        }

        self.log("[*] Auth: OAuth 2.0 checks...")
        r = self.oauth.check(base_url, page_content, all_urls or [])
        results['oauth'].extend(r)
        self._emit(r)

        self.log("[*] Auth: Session Fixation check...")
        if login_url:
            r = self.fixation.check(login_url, forms or [])
            results['session_fixation'].extend(r)
            self._emit(r)

        self.log("[*] Auth: Broken Access Control...")
        r = self.bac.check(base_url)
        results['broken_access'].extend(r)
        self._emit(r)

        self.log("[*] Auth: Directory Listing...")
        r = self.dirlist.check(base_url)
        results['directory_listing'].extend(r)
        self._emit(r)

        self.log("[*] Auth: Parameter Discovery...")
        pd = self.paramd.discover(base_url, js_content=js_content)
        if pd['hidden_params']:
            self.log(f"  [+] {len(pd['hidden_params'])} hidden params found")
        if pd['debug_params']:
            for dp in pd['debug_params']:
                results['hidden_params'].append({
                    'type':        'DEBUG_PARAM',
                    'severity':    'HIGH',
                    'confidence':  'HIGH',
                    'url':         dp['url'],
                    'description': f'Debug parameter {dp["param"]} triggers debug output',
                    'evidence':    dp['evidence'],
                    'remediation': 'Disable debug parameters in production.',
                })
            self._emit(results['hidden_params'])

        total = sum(len(v) for v in results.values())
        self.log(f"[+] Auth checks complete: {total} findings")
        return results

    def _emit(self, findings: list):
        icons = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🔵'}
        for f in findings:
            icon = icons.get(f.get('severity',''), '⚪')
            self.log(f"  {icon} [{f.get('severity','?')}] {f.get('type','?')}: {f.get('description','')[:80]}")
            ev = f.get('evidence', '')
            if ev:
                self.log(f"      → {ev[:120]}")
