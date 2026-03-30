#!/usr/bin/env python3
"""
LinkFinder + SecretFinder — Integrated JS Recon Engine
=======================================================
Combines LinkFinder (API endpoint discovery) and SecretFinder (secret/credential
extraction) pattern engines into your JSScout Pro workflow.

Can be used standalone or as a module imported by jsscout.py / js_secret_analyzer.py

Usage (standalone):
    python3 linkfinder_secretfinder.py <js_file_or_directory>
    python3 linkfinder_secretfinder.py jsscout_output/example.com/js/
    python3 linkfinder_secretfinder.py script.js

Output (in lf_sf_report/):
    report.html         — Rich interactive HTML report
    endpoints.txt       — All discovered API endpoints/links
    secrets.txt         — All discovered secrets/credentials
    combined.json       — Full machine-readable output
"""

import re
import sys
import json
import time
import hashlib
from pathlib import Path
from collections import defaultdict


# =============================================================================
# LINKFINDER PATTERNS  (ported from GerbenJavado/LinkFinder)
# =============================================================================

LINKFINDER_REGEX = re.compile(
    r"""
    (?:"|')                             # Start string quote
    (
        (?:[a-zA-Z]{1,10}://|//)        # URL scheme or protocol-relative
        [^"'/]{1,}                      # Domain
        [a-zA-Z0-9_/:-]{1,}            # Path
        |
        (?:/|\.\./|\./)                 # Relative path start
        [^"'><,;| *()(%%$^/\\\[\]]     # Not special chars
        [^"'><,;|()]{1,}               # Rest of path
        |
        [a-zA-Z0-9_\-/]{1,}/           # Word/path segment
        [a-zA-Z0-9_\-/]{1,}            # More path
        \.(?:[a-zA-Z]{1,4}|action)     # File extension
        (?:[\?|#][^"|']{0,}|)          # Optional query/fragment
        |
        [a-zA-Z0-9_\-/]{1,}/           # Word/path segment
        [a-zA-Z0-9_\-/]{3,}            # More path (min 3)
        (?:[\?|#][^"|']{0,}|)          # Optional query/fragment
        |
        [a-zA-Z0-9_\-]{1,}             # Word
        \.(?:php|asp|aspx|jsp|json|     # PHP/ASP/etc
             action|html|js|txt|xml)   # Common extensions
        (?:[\?|#][^"|']{0,}|)          # Optional query/fragment
    )
    (?:"|')                             # End string quote
    """,
    re.VERBOSE
)

# Additional targeted API endpoint patterns (supplement LinkFinder)
EXTRA_ENDPOINT_PATTERNS = [
    # REST API versioned
    re.compile(r'["\'\`](/api/v?\d+/[a-zA-Z0-9/_\-\.{}:?=&]+)["\'\`]'),
    re.compile(r'["\'\`](/api/[a-zA-Z0-9/_\-\.{}:?=&]{3,})["\'\`]'),
    # GraphQL
    re.compile(r'["\'\`](/graphql[a-zA-Z0-9/_\-?=&]*)["\'\`]'),
    # REST
    re.compile(r'["\'\`](/rest/[a-zA-Z0-9/_\-\.{}:]+)["\'\`]'),
    # Auth/user paths
    re.compile(r'["\'\`](/(?:auth|oauth|login|logout|register|signup|token|refresh|verify|user|users|admin|config|settings|health|status|ping|me|profile|account|password|reset|confirm|invite|search|upload|download|export|import|webhook|callback|redirect)[a-zA-Z0-9/_\-?=&]*)["\'\`]', re.I),
    # axios / fetch / http calls
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch|head)|http\.(?:get|post)|request)\s*\(\s*["\'\`]([^"\'`\s]{4,150})["\'\`]', re.I),
    # URL / endpoint assignments
    re.compile(r'(?:url|endpoint|baseURL|apiUrl|API_URL|base_url|API_BASE|host|baseUrl)\s*[:=]\s*["\'\`]([^"\'`\s]{5,150})["\'\`]', re.I),
    # XMLHttpRequest
    re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH|HEAD)["\'],\s*["\'\`]([^"\'`\s]{4,150})["\'\`]', re.I),
    # Template literals with API paths
    re.compile(r'\`([^`]*?/api/[^`]*?)\`'),
]


# =============================================================================
# SECRETFINDER PATTERNS  (ported from m4ll0k/SecretFinder)
# =============================================================================

SECRETFINDER_PATTERNS = [
    # Google API Key
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google API Key", "HIGH"),
    # Google OAuth
    (re.compile(r'ya29\.[0-9A-Za-z\-_]+'), "Google OAuth Token", "CRITICAL"),
    # Google Cloud Platform OAuth
    (re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'), "Google OAuth Client ID", "HIGH"),
    # Firebase
    (re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'), "Firebase Server Key", "CRITICAL"),
    # Firebase DB URL
    (re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'), "Firebase DB URL", "HIGH"),
    # Firebase API Key in config
    (re.compile(r'(?:firebase|firebaseConfig)[^{]{0,100}apiKey\s*:\s*["\']([^"\']{10,})["\']', re.I), "Firebase API Key", "HIGH"),
    # AWS Access Key ID
    (re.compile(r'(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}'), "AWS Access Key ID", "CRITICAL"),
    # AWS Secret Key
    (re.compile(r'(?:aws_secret_access_key|AWS_SECRET|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.I), "AWS Secret Key", "CRITICAL"),
    # AWS Session Token
    (re.compile(r'(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*["\']([^"\']{20,})["\']', re.I), "AWS Session Token", "CRITICAL"),
    # Stripe Publishable Key
    (re.compile(r'pk_(?:test|live)_[0-9a-zA-Z]{24,}'), "Stripe Publishable Key", "HIGH"),
    # Stripe Secret Key
    (re.compile(r'sk_(?:test|live)_[0-9a-zA-Z]{24,}'), "Stripe Secret Key", "CRITICAL"),
    # Stripe Webhook Secret
    (re.compile(r'whsec_[a-zA-Z0-9]{32,}'), "Stripe Webhook Secret", "HIGH"),
    # GitHub Token (old format)
    (re.compile(r'[0-9a-f]{40}'), "Possible GitHub Token/SHA", "LOW"),
    # GitHub Fine-grained PAT
    (re.compile(r'github_pat_[a-zA-Z0-9_]{82}'), "GitHub Fine-grained PAT", "CRITICAL"),
    # GitHub OAuth/PAT
    (re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'), "GitHub Token", "CRITICAL"),
    # Slack Token
    (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'), "Slack Token", "HIGH"),
    # Slack Webhook
    (re.compile(r'https://hooks\.slack\.com/services/[a-zA-Z0-9/]+'), "Slack Webhook URL", "HIGH"),
    # RSA/EC Private Key
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'), "PEM Private Key", "CRITICAL"),
    # OpenSSH Private Key
    (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), "OpenSSH Private Key", "CRITICAL"),
    # Certificate
    (re.compile(r'-----BEGIN CERTIFICATE-----'), "SSL Certificate", "MEDIUM"),
    # JWT Token
    (re.compile(r'["\']?(eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})["\']?'), "JWT Token", "HIGH"),
    # Password in code
    (re.compile(r'(?:password|passwd|pwd|pass)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "Password", "CRITICAL"),
    # DB Passwords
    (re.compile(r'(?:db_pass|database_pass|db_password|mysql_pass|pg_pass)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "Database Password", "CRITICAL"),
    # MongoDB connection
    (re.compile(r'(?:mongodb|mongodb\+srv)://[^\s"\'<>]{10,}', re.I), "MongoDB Connection String", "CRITICAL"),
    # PostgreSQL connection
    (re.compile(r'(?:postgres|postgresql)://[^\s"\'<>]{10,}', re.I), "PostgreSQL Connection String", "CRITICAL"),
    # MySQL connection
    (re.compile(r'mysql://[^\s"\'<>]{10,}', re.I), "MySQL Connection String", "CRITICAL"),
    # Redis connection
    (re.compile(r'redis://[^\s"\'<>]{10,}', re.I), "Redis Connection String", "HIGH"),
    # AMQP/RabbitMQ
    (re.compile(r'amqp://[^\s"\'<>]{10,}', re.I), "AMQP/RabbitMQ URL", "HIGH"),
    # Twilio Account SID
    (re.compile(r'AC[a-zA-Z0-9]{32}'), "Twilio Account SID", "MEDIUM"),
    # Twilio API Key
    (re.compile(r'SK[a-zA-Z0-9]{32}'), "Twilio API Key", "HIGH"),
    # SendGrid
    (re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'), "SendGrid API Key", "CRITICAL"),
    # Mailchimp
    (re.compile(r'[a-zA-Z0-9]{32}-us\d{1,2}'), "Mailchimp API Key", "HIGH"),
    # Mailgun
    (re.compile(r'key-[a-zA-Z0-9]{32}'), "Mailgun API Key", "HIGH"),
    # Generic API Key/Secret
    (re.compile(r'(?:api[_\-]?key|apikey|api_secret|secret_key)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', re.I), "API Key/Secret", "HIGH"),
    # Access Token
    (re.compile(r'(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.I), "Access/Auth Token", "HIGH"),
    # Secret / Client Secret
    (re.compile(r'(?:secret|client_secret|private_key|app_secret)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "Secret/Client Secret", "HIGH"),
    # OAuth Client ID
    (re.compile(r'(?:client_id|app_id|consumer_key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', re.I), "OAuth Client ID", "MEDIUM"),
    # Encryption Key
    (re.compile(r'(?:encryption_key|encrypt_key|aes_key|cipher_key|SECRET_KEY|DJANGO_SECRET_KEY|FLASK_SECRET)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "Encryption/App Secret Key", "CRITICAL"),
    # SMTP credentials
    (re.compile(r'(?:smtp_pass|smtp_password|mail_password)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "SMTP Password", "CRITICAL"),
    # NPM Token
    (re.compile(r'npm_[a-zA-Z0-9]{36}'), "NPM Access Token", "HIGH"),
    # Shopify
    (re.compile(r'shpat_[a-fA-F0-9]{32}'), "Shopify Access Token", "CRITICAL"),
    (re.compile(r'shpss_[a-fA-F0-9]{32}'), "Shopify Shared Secret", "HIGH"),
    # Cloudinary
    (re.compile(r'cloudinary://[^\s"\'<>]{10,}'), "Cloudinary URL", "HIGH"),
    # Authorization header values
    (re.compile(r'(?:Authorization|x-auth-token|x-api-key)\s*:\s*["\']([^"\']{10,})["\']', re.I), "Auth Header Value", "HIGH"),
    (re.compile(r'(?:Authorization|x-auth-token)\s*:\s*Bearer\s+([a-zA-Z0-9_\-\.]{20,})', re.I), "Bearer Token", "CRITICAL"),
    # GCP Service Account
    (re.compile(r'"type"\s*:\s*"service_account"'), "GCP Service Account JSON", "CRITICAL"),
    # Internal URLs
    (re.compile(r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s"\'<>]{0,100}'), "Localhost URL", "LOW"),
    (re.compile(r'https?://(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+(?::\d+)?[^\s"\'<>]{0,100}'), "Internal IP URL", "MEDIUM"),
    # Hex secrets (32+ char hex strings near secret keywords)
    (re.compile(r'(?:token|secret|key|hash|salt|nonce)\s*[:=]\s*["\']([a-fA-F0-9]{32,})["\']', re.I), "Hex Secret", "MEDIUM"),
    # Base64 secrets
    (re.compile(r'(?:token|secret|key)\s*[:=]\s*["\']([a-zA-Z0-9+/=]{32,})["\']', re.I), "Base64 Secret", "MEDIUM"),
]

# False positive skip values
SKIP_VALUES = {
    'placeholder', 'example', 'changeme', 'your_api_key', 'your_secret',
    'your_token', 'undefined', 'null', 'true', 'false', 'test', 'demo',
    'xxx', 'yyy', 'zzz', 'abc', '123456', 'password', 'secret', 'token',
    'your-api-key', 'your-secret-key', 'insert-key-here', 'api_key_here',
    'replace_me', 'fill_in', 'todo', 'fixme', 'none', 'n/a', 'na',
    'aaaaaa', 'bbbbbb', 'xxxxxx', '000000', '111111', 'sample', 'dummy',
}

SKIP_PATTERNS = [
    re.compile(r'^[a-z_]+$'),          # all lowercase single word
    re.compile(r'^\d+$'),              # all digits only
    re.compile(r'^[A-Z_]+$'),          # all uppercase (env var names)
    re.compile(r'^\$\{.*\}$'),         # template variable ${VAR}
    re.compile(r'^<.*>$'),             # HTML-like placeholder
    re.compile(r'^process\.env\.'),    # process.env reference
    re.compile(r'^[a-f0-9]{40}$'),     # raw 40-char hex — too noisy without context
]

# Paths to skip in LinkFinder results (noisy/irrelevant)
SKIP_LINK_PATTERNS = [
    re.compile(r'\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|otf|pdf|zip|mp4|mp3|webp)$', re.I),
    re.compile(r'^//'),             # protocol-relative (usually CDN)
    re.compile(r'^\s*$'),
    re.compile(r'^["\']'),
]

SKIP_LINK_VALUES = {
    '/', './', '../', '#', '', 'http://', 'https://',
}


def is_secret_fp(value: str, secret_type: str) -> bool:
    v = value.strip().lower()
    if not v or len(v) < 4:
        return True
    if v in SKIP_VALUES:
        return True
    if any(p.match(value.strip()) for p in SKIP_PATTERNS):
        return True
    if value.strip().startswith(('process.env', 'os.environ', 'ENV[', 'config.')):
        return True
    return False


def is_link_valid(link: str) -> bool:
    link = link.strip()
    if link in SKIP_LINK_VALUES or len(link) < 3:
        return False
    if any(p.search(link) for p in SKIP_LINK_PATTERNS):
        return False
    # Must start with /, http, or relative path indicator
    if not (link.startswith('/') or link.startswith('http') or
            link.startswith('./') or link.startswith('../') or
            re.match(r'^[a-zA-Z0-9_\-]+/', link)):
        return False
    return True


# =============================================================================
# CORE ENGINE
# =============================================================================

class LinkFinderSecretFinder:
    """
    Runs LinkFinder + SecretFinder on a directory of JS files (or single file).
    Can also be imported and called programmatically from jsscout.py.
    """

    def __init__(self, target_path: str, output_dir: str = 'lf_sf_report'):
        self.target_path = Path(target_path)
        self.output_dir = Path(output_dir)
        self.endpoints: dict = {}   # endpoint -> [source_files]
        self.secrets: list = []
        self.stats = defaultdict(int)
        self._seen_secrets: set = set()

    # ──────────────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        """Run full analysis. Returns results dict."""
        print(f"\n[*] LinkFinder + SecretFinder — scanning: {self.target_path}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        js_files = self._find_js_files()
        print(f"[*] Found {len(js_files)} JS file(s)\n")
        if not js_files:
            print("[!] No JS files found.")
            return {}

        for js_file in js_files:
            self._analyze_file(js_file)

        results = {
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': str(self.target_path),
            'total_files': len(js_files),
            'endpoints': {ep: files for ep, files in sorted(self.endpoints.items())},
            'secrets': self.secrets,
            'summary': {
                'total_endpoints': len(self.endpoints),
                'total_secrets': len(self.secrets),
                'critical': self.stats['CRITICAL'],
                'high': self.stats['HIGH'],
                'medium': self.stats['MEDIUM'],
                'low': self.stats['LOW'],
            }
        }

        self._write_reports(results)

        print(f"\n[✓] Complete!")
        print(f"    Endpoints : {len(self.endpoints)}")
        print(f"    Secrets   : {len(self.secrets)}  "
              f"(CRITICAL:{self.stats['CRITICAL']}  HIGH:{self.stats['HIGH']}  "
              f"MEDIUM:{self.stats['MEDIUM']}  LOW:{self.stats['LOW']})")
        print(f"    Reports   : {self.output_dir}/")
        return results

    # ──────────────────────────────────────────────────────────────────────────

    def analyze_content(self, content: str, source_name: str = 'inline') -> dict:
        """
        Analyze raw JS content string (for use as jsscout.py module).
        Returns {'endpoints': set, 'secrets': list}
        """
        endpoints = self._linkfinder(content, source_name)
        secrets = self._secretfinder(content, source_name)
        return {'endpoints': endpoints, 'secrets': secrets}

    # ──────────────────────────────────────────────────────────────────────────

    def _find_js_files(self):
        files = []
        if self.target_path.is_file():
            return [self.target_path] if self.target_path.suffix in ('.js', '.mjs', '.ts') else []

        # Check for jsscout-style output (js/ subdirectory)
        js_subdir = self.target_path / 'js'
        if js_subdir.exists():
            files.extend(sorted(js_subdir.glob('*.js')))
            files.extend(sorted(js_subdir.glob('*.mjs')))

        files.extend(sorted(self.target_path.glob('*.js')))
        files.extend(sorted(self.target_path.glob('*.mjs')))

        # Deduplicate
        seen = set()
        unique = []
        for f in files:
            if f not in seen:
                seen.add(f)
                unique.append(f)
        return unique

    def _analyze_file(self, js_file: Path):
        try:
            content = js_file.read_text(encoding='utf-8', errors='replace')
        except Exception as e:
            print(f"  [!] Cannot read {js_file.name}: {e}")
            return

        size_kb = js_file.stat().st_size / 1024
        is_min = self._is_minified(content)
        print(f"  [scan] {js_file.name}  ({size_kb:.1f} KB{'  [minified]' if is_min else ''})")

        # LinkFinder
        ep = self._linkfinder(content, js_file.name)
        for path in ep:
            if path not in self.endpoints:
                self.endpoints[path] = []
            if js_file.name not in self.endpoints[path]:
                self.endpoints[path].append(js_file.name)

        # SecretFinder
        secs = self._secretfinder(content, js_file.name)
        self.secrets.extend(secs)
        for s in secs:
            self.stats[s['severity']] += 1

        n_ep = len(ep)
        n_sec = len(secs)
        if n_ep or n_sec:
            print(f"         → {n_ep} endpoints  |  {n_sec} secrets")

    # ──────────────────────────────────────────────────────────────────────────

    def _linkfinder(self, content: str, source: str) -> set:
        found = set()

        # Primary LinkFinder regex
        for m in LINKFINDER_REGEX.finditer(content):
            link = m.group(1).strip()
            if is_link_valid(link):
                found.add(link)

        # Extra targeted API patterns
        for pat in EXTRA_ENDPOINT_PATTERNS:
            for m in pat.finditer(content):
                link = (m.group(1) if m.lastindex else m.group(0)).strip()
                if link and len(link) > 2 and len(link) < 300:
                    if is_link_valid(link) or link.startswith('http'):
                        found.add(link)

        return found

    def _secretfinder(self, content: str, source: str) -> list:
        found = []
        lines = content.split('\n')

        for pattern, label, severity in SECRETFINDER_PATTERNS:
            for m in pattern.finditer(content):
                value = (m.group(1) if m.lastindex else m.group(0)).strip()

                if is_secret_fp(value, label):
                    continue

                # Dedup globally
                dedup_key = f'{label}:{value[:40]}'
                if dedup_key in self._seen_secrets:
                    continue
                self._seen_secrets.add(dedup_key)

                line_no = content[:m.start()].count('\n') + 1
                line_content = lines[line_no - 1].strip() if line_no <= len(lines) else ''
                context = content[max(0, m.start()-80):m.end()+80].replace('\n', ' ').strip()

                found.append({
                    'file': source,
                    'type': label,
                    'severity': severity,
                    'value': value[:250],
                    'line': line_no,
                    'line_content': line_content[:300],
                    'context': context[:400],
                })

        return found

    def _is_minified(self, content: str) -> bool:
        lines = content.split('\n')
        if not lines:
            return False
        return (sum(len(l) for l in lines) / max(len(lines), 1)) > 200

    # ──────────────────────────────────────────────────────────────────────────

    def _write_reports(self, results: dict):
        out = self.output_dir

        # JSON
        (out / 'combined.json').write_text(json.dumps(results, indent=2), encoding='utf-8')

        # Endpoints TXT
        ep_lines = [f"LINKFINDER — API ENDPOINTS & PATHS ({len(self.endpoints)} found)",
                    "=" * 65, ""]
        for ep in sorted(self.endpoints.keys()):
            sources = ', '.join(self.endpoints[ep][:3])
            ep_lines.append(f"{ep}   [{sources}]")
        (out / 'endpoints.txt').write_text('\n'.join(ep_lines), encoding='utf-8')

        # Secrets TXT
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_secrets = sorted(self.secrets, key=lambda x: sev_order.get(x['severity'], 4))
        sec_lines = [f"SECRETFINDER — SECRETS & CREDENTIALS ({len(self.secrets)} found)",
                     f"Scan time: {results['scan_time']}", "=" * 65, ""]
        for s in sorted_secrets:
            sec_lines += [
                f"[{s['severity']}] {s['type']}",
                f"  File    : {s['file']} (line {s['line']})",
                f"  Value   : {s['value'][:120]}",
                f"  Context : {s['context'][:200]}",
                "",
            ]
        (out / 'secrets.txt').write_text('\n'.join(sec_lines), encoding='utf-8')

        # HTML Report
        self._write_html(results, sorted_secrets)

        print(f"\n[+] Reports written to: {out}/")

    def _write_html(self, results: dict, sorted_secrets: list):
        def h(s):
            return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

        SEV_COLOR = {
            'CRITICAL': '#ff2244', 'HIGH': '#ff6622',
            'MEDIUM': '#ffcc00', 'LOW': '#44aaff', 'INFO': '#888',
        }

        # Endpoint rows (group by category)
        api_rows = ''
        for ep, files in sorted(self.endpoints.items()):
            sources = ', '.join(files[:3])
            category = 'API' if '/api/' in ep else ('Auth' if any(k in ep.lower() for k in ['auth', 'login', 'token', 'oauth']) else ('Admin' if 'admin' in ep.lower() else 'Other'))
            cat_color = {'API': '#00d4ff', 'Auth': '#ff6622', 'Admin': '#ff2244', 'Other': '#888'}.get(category, '#888')
            api_rows += f'<tr><td class="mono" style="color:#00d4ff">{h(ep)}</td><td style="color:{cat_color};font-size:10px">{category}</td><td style="color:#3a5068;font-size:11px">{h(sources)}</td></tr>'

        # Secret rows
        secret_rows = ''
        for s in sorted_secrets:
            color = SEV_COLOR.get(s['severity'], '#888')
            secret_rows += f'''<tr data-sev="{h(s['severity'])}">
              <td><span class="badge" style="background:{color}22;border:1px solid {color};color:{color}">{h(s['severity'])}</span></td>
              <td class="mono">{h(s['type'])}</td>
              <td><span style="color:#00d4ff">{h(s['file'])}</span><span style="color:#3a5068">:{s['line']}</span></td>
              <td class="mono value-cell" title="{h(s['value'])}">{h(s['value'][:80])}{'...' if len(s['value']) > 80 else ''}</td>
              <td class="ctx-cell">{h(s['context'][:120])}</td>
            </tr>'''

        summ = results['summary']
        crit, high, med, low = summ['critical'], summ['high'], summ['medium'], summ['low']

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LinkFinder + SecretFinder Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{background:#07090d;color:#c9d8e8;font-family:"Share Tech Mono",monospace;padding:32px 20px}}
  h1{{font-size:22px;letter-spacing:4px;color:#00ff9f;margin-bottom:4px}}
  h2{{font-size:12px;letter-spacing:3px;color:#00d4ff;margin:28px 0 12px;border-bottom:1px solid #1a2433;padding-bottom:6px;text-transform:uppercase}}
  .meta{{color:#3a5068;font-size:12px;margin-bottom:24px}}
  .stats{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:28px}}
  .stat{{background:#0d1117;border:1px solid #1a2433;padding:12px 20px;min-width:120px;text-align:center}}
  .stat-val{{display:block;font-size:28px;font-weight:bold;margin-bottom:2px}}
  .stat-lbl{{font-size:9px;color:#3a5068;letter-spacing:3px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:20px;font-size:12px}}
  th{{background:#0d1117;color:#3a5068;padding:8px 12px;text-align:left;font-size:10px;letter-spacing:2px;border-bottom:1px solid #1a2433}}
  td{{padding:8px 12px;border-bottom:1px solid #0f1520;vertical-align:top}}
  tr:hover td{{background:#0c1018}}
  .badge{{display:inline-block;padding:2px 8px;font-size:10px;letter-spacing:1px;border-radius:2px;font-weight:bold}}
  .mono{{font-family:"Share Tech Mono",monospace}}
  .value-cell{{color:#ff9944;word-break:break-all;max-width:280px}}
  .ctx-cell{{color:#6a8090;font-size:11px;word-break:break-all;max-width:320px}}
  .empty{{color:#3a5068;padding:20px;text-align:center}}
  input.search{{background:#0d1117;border:1px solid #1a2433;color:#c9d8e8;padding:7px 14px;font-family:inherit;font-size:12px;width:280px;margin-bottom:12px;outline:none}}
  input.search:focus{{border-color:#00d4ff}}
  .filters{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}}
  .fbtn{{background:transparent;border:1px solid #1a2433;color:#3a5068;padding:4px 12px;font-family:inherit;font-size:11px;cursor:pointer;letter-spacing:1px}}
  .fbtn.active,.fbtn:hover{{border-color:#00d4ff;color:#00d4ff}}
  .fbtn[data-sev="CRITICAL"].active{{border-color:#ff2244;color:#ff2244}}
  .fbtn[data-sev="HIGH"].active{{border-color:#ff6622;color:#ff6622}}
  .fbtn[data-sev="MEDIUM"].active{{border-color:#ffcc00;color:#ffcc00}}
  .fbtn[data-sev="LOW"].active{{border-color:#44aaff;color:#44aaff}}
</style>
</head>
<body>

<h1>🔗 LINKFINDER + 🔑 SECRETFINDER</h1>
<div class="meta">
  Target: <b style="color:#c9d8e8">{h(results['target'])}</b> &nbsp;|&nbsp;
  {results['scan_time']} &nbsp;|&nbsp;
  {results['total_files']} JS files scanned
</div>

<div class="stats">
  <div class="stat"><span class="stat-val" style="color:#00d4ff">{summ['total_endpoints']}</span><span class="stat-lbl">ENDPOINTS</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff2244' if summ['total_secrets'] else '#888'}">{summ['total_secrets']}</span><span class="stat-lbl">SECRETS</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff2244' if crit else '#888'}">{crit}</span><span class="stat-lbl">CRITICAL</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ff6622' if high else '#888'}">{high}</span><span class="stat-lbl">HIGH</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#ffcc00' if med else '#888'}">{med}</span><span class="stat-lbl">MEDIUM</span></div>
  <div class="stat"><span class="stat-val" style="color:{'#44aaff' if low else '#888'}">{low}</span><span class="stat-lbl">LOW</span></div>
</div>

<h2>🌐 LinkFinder — API Endpoints & Paths ({summ['total_endpoints']} found)</h2>
<input type="text" class="search" id="epSearch" placeholder="Filter endpoints..." oninput="filterEndpoints()">
{'<table id="epTable"><thead><tr><th>ENDPOINT / PATH</th><th>CATEGORY</th><th>FOUND IN</th></tr></thead><tbody>' + api_rows + '</tbody></table>' if api_rows else "<div class='empty'>No endpoints discovered.</div>"}

<h2>🔑 SecretFinder — Secrets & Credentials ({summ['total_secrets']} found)</h2>
<input type="text" class="search" id="secSearch" placeholder="Search secrets..." oninput="filterSecrets()">
<div class="filters">
  <button class="fbtn active" data-sev="ALL" onclick="setSev('ALL',this)">ALL</button>
  <button class="fbtn" data-sev="CRITICAL" onclick="setSev('CRITICAL',this)">CRITICAL ({crit})</button>
  <button class="fbtn" data-sev="HIGH" onclick="setSev('HIGH',this)">HIGH ({high})</button>
  <button class="fbtn" data-sev="MEDIUM" onclick="setSev('MEDIUM',this)">MEDIUM ({med})</button>
  <button class="fbtn" data-sev="LOW" onclick="setSev('LOW',this)">LOW ({low})</button>
</div>
{'<table id="secTable"><thead><tr><th>SEV</th><th>TYPE</th><th>FILE:LINE</th><th>VALUE</th><th>CONTEXT</th></tr></thead><tbody>' + secret_rows + '</tbody></table>' if secret_rows else "<div class='empty'>No secrets detected.</div>"}

<script>
let curSev = 'ALL';
function filterEndpoints() {{
  const q = document.getElementById('epSearch').value.toLowerCase();
  document.querySelectorAll('#epTable tbody tr').forEach(r => {{
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
function filterSecrets() {{
  const q = document.getElementById('secSearch').value.toLowerCase();
  document.querySelectorAll('#secTable tbody tr').forEach(r => {{
    const sev = r.dataset.sev;
    const match = r.textContent.toLowerCase().includes(q);
    r.style.display = (match && (curSev === 'ALL' || sev === curSev)) ? '' : 'none';
  }});
}}
function setSev(sev, btn) {{
  curSev = sev;
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterSecrets();
}}
</script>

</body>
</html>'''

        (self.output_dir / 'report.html').write_text(html, encoding='utf-8')


# =============================================================================
# CLI ENTRY
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nUsage: python3 linkfinder_secretfinder.py <js_file_or_directory>")
        sys.exit(1)

    target = sys.argv[1]
    if not Path(target).exists():
        print(f"[!] Path not found: {target}")
        sys.exit(1)

    engine = LinkFinderSecretFinder(target)
    engine.run()


if __name__ == '__main__':
    main()
