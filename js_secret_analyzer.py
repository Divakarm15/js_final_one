#!/usr/bin/env python3
"""
JS Secret Analyzer — JS Scout Pro Add-on
==========================================
Deep-scans all downloaded JS files (from jsscout output) or a custom JS directory
to extract: secrets, passwords, API keys, API paths, tokens, credentials, and more.

Usage:
    python3 js_secret_analyzer.py <js_dir_or_jsscout_output_dir>
    python3 js_secret_analyzer.py jsscout_output/example.com/js/
    python3 js_secret_analyzer.py jsscout_output/example.com/

Output:
    secrets_report/
        secrets_report.html   — Rich interactive HTML report
        secrets_report.json   — Machine-readable full findings
        secrets_summary.txt   — Plain text summary
        api_paths.txt         — All API paths/endpoints found
        credentials.txt       — Secrets/credentials only
"""

import re, sys, os, json, hashlib, time
from pathlib import Path
from collections import defaultdict

# =============================================================================
# EXTENDED SECRET PATTERNS
# =============================================================================

SECRET_PATTERNS = [
    # API Keys (generic)
    (re.compile(r'(?:api[_\-]?key|apikey|api_secret|x-api-key)\s*[:=\'"]+\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', re.I), "api_key", "HIGH"),

    # Access / Auth Tokens
    (re.compile(r'(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token|authtoken)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.I), "access_token", "HIGH"),

    # JWT Tokens
    (re.compile(r'["\']?(eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})["\']?'), "jwt_token", "HIGH"),

    # Passwords
    (re.compile(r'(?:password|passwd|pwd|pass)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "password", "CRITICAL"),
    (re.compile(r'(?:db_pass|database_pass|db_password|mysql_pass)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "db_password", "CRITICAL"),

    # Secrets / Private Keys
    (re.compile(r'(?:secret|client_secret|private_key|app_secret|master_key)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "secret", "HIGH"),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'), "private_key_pem", "CRITICAL"),
    (re.compile(r'-----BEGIN CERTIFICATE-----'), "certificate", "MEDIUM"),

    # AWS
    (re.compile(r'(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}'), "aws_access_key_id", "CRITICAL"),
    (re.compile(r'(?:aws_secret|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', re.I), "aws_secret_key", "CRITICAL"),
    (re.compile(r'(?:aws_session_token|AWS_SESSION_TOKEN)\s*[:=]\s*["\']([^"\']{20,})["\']', re.I), "aws_session_token", "CRITICAL"),

    # Google
    (re.compile(r'AIza[a-zA-Z0-9_\-]{35}'), "google_api_key", "HIGH"),
    (re.compile(r'(?:firebase|firebaseConfig)[^{]{0,100}apiKey\s*:\s*["\']([^"\']{10,})["\']', re.I), "firebase_api_key", "HIGH"),
    (re.compile(r'"type"\s*:\s*"service_account"'), "gcp_service_account", "CRITICAL"),
    (re.compile(r'(?:google_client_secret|GOOGLE_CLIENT_SECRET)\s*[:=]\s*["\']([^"\']{10,})["\']', re.I), "google_oauth_secret", "CRITICAL"),

    # Stripe
    (re.compile(r'["\']pk_(?:test|live)_[a-zA-Z0-9]{24,}["\']'), "stripe_publishable_key", "HIGH"),
    (re.compile(r'["\']sk_(?:test|live)_[a-zA-Z0-9]{24,}["\']'), "stripe_secret_key", "CRITICAL"),
    (re.compile(r'["\']rk_(?:test|live)_[a-zA-Z0-9]{24,}["\']'), "stripe_restricted_key", "HIGH"),
    (re.compile(r'whsec_[a-zA-Z0-9]{32,}'), "stripe_webhook_secret", "HIGH"),

    # GitHub
    (re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}'), "github_token", "CRITICAL"),
    (re.compile(r'github_pat_[a-zA-Z0-9_]{82}'), "github_fine_grained_token", "CRITICAL"),

    # Slack
    (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'), "slack_token", "HIGH"),
    (re.compile(r'https://hooks\.slack\.com/services/[a-zA-Z0-9/]+'), "slack_webhook", "HIGH"),

    # Twilio
    (re.compile(r'AC[a-zA-Z0-9]{32}'), "twilio_account_sid", "MEDIUM"),
    (re.compile(r'SK[a-zA-Z0-9]{32}'), "twilio_api_key", "HIGH"),

    # SendGrid
    (re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'), "sendgrid_api_key", "CRITICAL"),

    # Mailchimp
    (re.compile(r'[a-zA-Z0-9]{32}-us\d{1,2}'), "mailchimp_api_key", "HIGH"),

    # Database connection strings
    (re.compile(r'(?:mongodb|mongodb\+srv)://[^\s"\'<>]{10,}', re.I), "mongodb_connection", "CRITICAL"),
    (re.compile(r'(?:postgres|postgresql)://[^\s"\'<>]{10,}', re.I), "postgresql_connection", "CRITICAL"),
    (re.compile(r'mysql://[^\s"\'<>]{10,}', re.I), "mysql_connection", "CRITICAL"),
    (re.compile(r'redis://[^\s"\'<>]{10,}', re.I), "redis_connection", "HIGH"),
    (re.compile(r'amqp://[^\s"\'<>]{10,}', re.I), "rabbitmq_connection", "HIGH"),
    (re.compile(r'(?:mssql|sqlserver)://[^\s"\'<>]{10,}', re.I), "mssql_connection", "CRITICAL"),

    # Authorization headers
    (re.compile(r'(?:Authorization|x-auth-token|x-api-key)\s*:\s*["\']([^"\']{10,})["\']', re.I), "auth_header_value", "HIGH"),
    (re.compile(r'(?:Authorization|x-auth-token)\s*:\s*Bearer\s+([a-zA-Z0-9_\-\.]{20,})', re.I), "bearer_token", "CRITICAL"),

    # OAuth / SSO
    (re.compile(r'(?:client_id|app_id|consumer_key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', re.I), "oauth_client_id", "MEDIUM"),
    (re.compile(r'(?:client_secret|consumer_secret|app_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', re.I), "oauth_client_secret", "HIGH"),

    # Encryption keys
    (re.compile(r'(?:encryption_key|encrypt_key|aes_key|cipher_key)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "encryption_key", "CRITICAL"),
    (re.compile(r'(?:secret_key|SECRET_KEY|DJANGO_SECRET_KEY|FLASK_SECRET)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "app_secret_key", "CRITICAL"),

    # SSH
    (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), "ssh_private_key", "CRITICAL"),
    (re.compile(r'ssh-rsa\s+[a-zA-Z0-9+/=]{20,}'), "ssh_public_key", "LOW"),

    # Hardcoded credentials
    (re.compile(r'(?:username|user|login)\s*[:=]\s*["\']([^"\']{3,50})["\']', re.I), "username", "MEDIUM"),

    # Internal IPs / Local services
    (re.compile(r'(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s"\']{0,100}'), "localhost_url", "LOW"),
    (re.compile(r'https?://(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+(?::\d+)?[^\s"\'<>]{0,100}'), "internal_ip_url", "MEDIUM"),

    # Cloudinary
    (re.compile(r'cloudinary://[^\s"\'<>]{10,}'), "cloudinary_url", "HIGH"),

    # Mailgun
    (re.compile(r'key-[a-zA-Z0-9]{32}'), "mailgun_api_key", "HIGH"),

    # Heroku
    (re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), "uuid_token", "LOW"),

    # NPM tokens
    (re.compile(r'(?:npm_)[a-zA-Z0-9]{36}'), "npm_access_token", "HIGH"),

    # Shopify
    (re.compile(r'shpss_[a-fA-F0-9]{32}'), "shopify_shared_secret", "HIGH"),
    (re.compile(r'shpat_[a-fA-F0-9]{32}'), "shopify_access_token", "CRITICAL"),

    # HubSpot
    (re.compile(r'(?:hubspot[_\-]?api[_\-]?key)\s*[:=]\s*["\']([a-zA-Z0-9\-]{30,})["\']', re.I), "hubspot_api_key", "HIGH"),

    # Okta
    (re.compile(r'(?:okta[_\-]?token|okta[_\-]?secret)\s*[:=]\s*["\']([^"\']{10,})["\']', re.I), "okta_token", "HIGH"),

    # SMTP credentials
    (re.compile(r'(?:smtp_pass|smtp_password|mail_password)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "smtp_password", "CRITICAL"),
    (re.compile(r'(?:smtp_user|smtp_username|mail_user)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I), "smtp_username", "MEDIUM"),

    # Generic secrets that look like real values (long random strings)
    (re.compile(r'(?:token|secret|key|hash|salt|nonce)\s*[:=]\s*["\']([a-fA-F0-9]{32,})["\']', re.I), "hex_secret", "MEDIUM"),
    (re.compile(r'(?:token|secret|key)\s*[:=]\s*["\']([a-zA-Z0-9+/=]{32,})["\']', re.I), "base64_secret", "MEDIUM"),
]

# =============================================================================
# API PATH PATTERNS
# =============================================================================

API_PATH_PATTERNS = [
    re.compile(r'["\'\`](/api/v?\d+/[a-zA-Z0-9/_\-\.{}:?=&]+)["\'\`]'),
    re.compile(r'["\'\`](/api/[a-zA-Z0-9/_\-\.{}:?=&]+)["\'\`]'),
    re.compile(r'["\'\`](/graphql[a-zA-Z0-9/_\-?=&]*)["\'\`]'),
    re.compile(r'["\'\`](/rest/[a-zA-Z0-9/_\-\.{}:]+)["\'\`]'),
    re.compile(r'["\'\`](/v[1-9]\d*/[a-zA-Z0-9/_\-\.{}:]+)["\'\`]'),
    re.compile(r'["\'\`](/[a-zA-Z0-9/_\-]+\.(?:json|xml|yaml|php|asp|aspx|jsp))["\'\`]'),
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'(?:url|endpoint|baseURL|apiUrl|API_URL|base_url|API_BASE)\s*[:=]\s*["\'\`]([^\"\'\`]{5,150})["\'\`]', re.I),
    re.compile(r'(?:https?://[a-zA-Z0-9\-\.]+)(/api/[a-zA-Z0-9/_\-\.{}:?=&]+)'),
    re.compile(r'["\'\`](/(?:auth|oauth|login|logout|register|signup|token|refresh|verify|user|users|admin|config|settings|health|status|ping)[a-zA-Z0-9/_\-?=&]*)["\'\`]'),
    re.compile(r'XMLHttpRequest|\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\.(?:get|post|put|delete|patch)\s*\(\s*["`\']([^"`\']+)["`\']', re.I),
]

# =============================================================================
# FALSE POSITIVE FILTERS
# =============================================================================

SKIP_VALUES = {
    'placeholder', 'example', 'changeme', 'your_api_key', 'your_secret',
    'your_token', 'undefined', 'null', 'true', 'false', 'test', 'demo',
    'xxx', 'yyy', 'zzz', 'abc', '123456', 'password', 'secret', 'token',
    'your-api-key', 'your-secret-key', 'insert-key-here', 'api_key_here',
    'replace_me', 'fill_in', 'todo', 'fixme', 'none', 'n/a', 'na',
    'aaaaaa', 'bbbbbb', 'xxxxxx', '000000', '111111',
}

SKIP_PATTERNS = [
    re.compile(r'^[a-z_]+$'),          # all lowercase single word
    re.compile(r'^\d+$'),              # all digits
    re.compile(r'^[A-Z_]+$'),          # all uppercase (env var names)
    re.compile(r'^\$\{.*\}$'),         # template variable ${VAR}
    re.compile(r'^<.*>$'),             # HTML-like placeholder
    re.compile(r'^process\.env\.'),    # process.env reference
]


def is_false_positive(value: str, secret_type: str) -> bool:
    """Returns True if the value looks like a false positive."""
    v = value.strip().lower()
    if not v or len(v) < 4:
        return True
    if v in SKIP_VALUES:
        return True
    if any(p.match(value.strip()) for p in SKIP_PATTERNS):
        return True
    # Skip if it's obviously a variable reference
    if value.strip().startswith(('process.env', 'os.environ', 'ENV[', 'config.')):
        return True
    # For UUIDs — only flag if near sensitive keywords
    if secret_type == 'uuid_token' and len(value) == 36:
        return True  # too generic without context
    return False


# =============================================================================
# ANALYZER CLASS
# =============================================================================

class JSSecretAnalyzer:
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir)
        self.output_dir = Path('secrets_report')
        self.findings = []
        self.api_paths = set()
        self.stats = defaultdict(int)

    def run(self):
        print(f"\n[*] JS Secret Analyzer — scanning: {self.target_dir}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Find all JS files
        js_files = self._find_js_files()
        print(f"[*] Found {len(js_files)} JS file(s) to analyze\n")

        if not js_files:
            print("[!] No JS files found. Make sure to point to a directory with .js files.")
            sys.exit(1)

        for js_file in js_files:
            self._analyze_file(js_file)

        self._write_reports()
        print(f"\n[✓] Analysis complete!")
        print(f"    Secrets found : {len(self.findings)}")
        print(f"    API paths     : {len(self.api_paths)}")
        print(f"    Reports       : {self.output_dir}/")

    def _find_js_files(self):
        files = []
        # If target is a jsscout output dir, look in js/ subdirectory first
        js_subdir = self.target_dir / 'js'
        if js_subdir.exists():
            files.extend(sorted(js_subdir.glob('*.js')))
            files.extend(sorted(js_subdir.glob('*.mjs')))
        # Also scan root for any .js files
        files.extend(sorted(self.target_dir.glob('*.js')))
        files.extend(sorted(self.target_dir.glob('*.mjs')))
        # Deduplicate preserving order
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

        file_size = js_file.stat().st_size
        is_minified = self._is_minified(content)
        lines = content.split('\n')

        print(f"  [scan] {js_file.name}  ({file_size/1024:.1f} KB{'  [minified]' if is_minified else ''})")

        found_in_file = 0
        seen_in_file = set()

        for pattern, secret_type, severity in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                value = (match.group(1) if match.lastindex else match.group(0)).strip()

                if is_false_positive(value, secret_type):
                    continue

                # Dedup within file
                dedup_key = f"{secret_type}:{value[:40]}"
                if dedup_key in seen_in_file:
                    continue
                seen_in_file.add(dedup_key)

                line_no = content[:match.start()].count('\n') + 1
                line_content = lines[line_no - 1].strip() if line_no <= len(lines) else ''
                context = content[max(0, match.start()-80):match.end()+80].replace('\n', ' ').strip()

                finding = {
                    'file':        js_file.name,
                    'file_path':   str(js_file),
                    'type':        secret_type,
                    'severity':    severity,
                    'value':       value[:200],
                    'line':        line_no,
                    'line_content': line_content[:300],
                    'context':     context[:400],
                    'is_minified': is_minified,
                }
                self.findings.append(finding)
                self.stats[severity] += 1
                found_in_file += 1

        # Extract API paths
        api_found = 0
        for pattern in API_PATH_PATTERNS:
            for match in pattern.finditer(content):
                path = (match.group(1) if match.lastindex else match.group(0)).strip()
                if 3 < len(path) < 300 and not path.startswith(('data:', 'blob:', '//')):
                    self.api_paths.add(path)
                    api_found += 1

        if found_in_file > 0:
            print(f"         → {found_in_file} secret(s) found")
        if api_found > 0:
            print(f"         → {api_found} API path reference(s) found")

    def _is_minified(self, content: str) -> bool:
        lines = content.split('\n')
        if not lines:
            return False
        avg = sum(len(l) for l in lines) / max(len(lines), 1)
        return avg > 200

    def _write_reports(self):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        # Sort findings by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        self.findings.sort(key=lambda x: sev_order.get(x['severity'], 5))

        # ── JSON ──────────────────────────────────────────────────────────────
        report_data = {
            'scan_time': timestamp,
            'target_dir': str(self.target_dir),
            'summary': {
                'total_secrets': len(self.findings),
                'critical': self.stats.get('CRITICAL', 0),
                'high': self.stats.get('HIGH', 0),
                'medium': self.stats.get('MEDIUM', 0),
                'low': self.stats.get('LOW', 0),
                'total_api_paths': len(self.api_paths),
            },
            'findings': self.findings,
            'api_paths': sorted(self.api_paths),
        }
        (self.output_dir / 'secrets_report.json').write_text(
            json.dumps(report_data, indent=2), encoding='utf-8'
        )

        # ── API Paths TXT ─────────────────────────────────────────────────────
        api_lines = [f"API PATHS & ENDPOINTS ({len(self.api_paths)} found)", "=" * 60, ""]
        for path in sorted(self.api_paths):
            api_lines.append(path)
        (self.output_dir / 'api_paths.txt').write_text('\n'.join(api_lines), encoding='utf-8')

        # ── Credentials TXT ───────────────────────────────────────────────────
        cred_lines = [f"SECRETS & CREDENTIALS REPORT", f"Scanned: {timestamp}", "=" * 70, ""]
        if self.findings:
            for f in self.findings:
                cred_lines += [
                    f"[{f['severity']}] {f['type'].upper()}",
                    f"  File    : {f['file']} (line {f['line']})",
                    f"  Value   : {f['value'][:120]}",
                    f"  Context : {f['context'][:200]}",
                    "",
                ]
        else:
            cred_lines.append("No secrets found.")
        (self.output_dir / 'credentials.txt').write_text('\n'.join(cred_lines), encoding='utf-8')

        # ── Plain text summary ────────────────────────────────────────────────
        summary_lines = [
            "JS SECRET ANALYZER — SUMMARY REPORT",
            f"Scanned : {self.target_dir}",
            f"Time    : {timestamp}",
            "",
            f"SECRETS FOUND  : {len(self.findings)}",
            f"  CRITICAL     : {self.stats.get('CRITICAL', 0)}",
            f"  HIGH         : {self.stats.get('HIGH', 0)}",
            f"  MEDIUM       : {self.stats.get('MEDIUM', 0)}",
            f"  LOW          : {self.stats.get('LOW', 0)}",
            f"API PATHS      : {len(self.api_paths)}",
            "",
        ]
        if self.findings:
            summary_lines.append("TOP FINDINGS:")
            for f in self.findings[:30]:
                summary_lines.append(f"  [{f['severity']:8}] {f['type']:30} in {f['file']}:{f['line']}")
                summary_lines.append(f"              Value: {f['value'][:80]}")
            summary_lines.append("")
        (self.output_dir / 'secrets_summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')

        # ── HTML Report ───────────────────────────────────────────────────────
        self._write_html_report(timestamp)
        print(f"\n[+] Reports written to: {self.output_dir}/")

    def _write_html_report(self, timestamp: str):
        def h(s):
            return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

        sev_color = {
            'CRITICAL': '#ff2244',
            'HIGH': '#ff6622',
            'MEDIUM': '#ffcc00',
            'LOW': '#44aaff',
            'INFO': '#888888',
        }

        # Group findings by type
        by_type = defaultdict(list)
        for f in self.findings:
            by_type[f['type']].append(f)

        # Build findings table rows
        rows = ''
        for f in self.findings:
            color = sev_color.get(f['severity'], '#888')
            rows += f'''
            <tr>
                <td><span class="badge" style="background:{color}22;border:1px solid {color};color:{color}">{h(f['severity'])}</span></td>
                <td class="mono">{h(f['type'])}</td>
                <td><span class="filename">{h(f['file'])}</span><span class="lineno">:{f['line']}</span></td>
                <td class="mono value-cell" title="{h(f['value'])}">{h(f['value'][:80])}{'...' if len(f['value']) > 80 else ''}</td>
                <td class="context-cell">{h(f['context'][:150])}</td>
            </tr>'''

        # API paths rows
        api_rows = ''
        for path in sorted(self.api_paths)[:500]:
            api_rows += f'<tr><td class="mono" style="color:#00d4ff">{h(path)}</td></tr>'

        # Stats by type
        type_rows = ''
        for stype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
            top_sev = min(items, key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x['severity'],4))['severity']
            color = sev_color.get(top_sev, '#888')
            type_rows += f'<tr><td class="mono">{h(stype)}</td><td style="color:{color}">{len(items)}</td><td style="color:{color}">{top_sev}</td></tr>'

        crit = self.stats.get('CRITICAL', 0)
        high = self.stats.get('HIGH', 0)
        med = self.stats.get('MEDIUM', 0)
        low = self.stats.get('LOW', 0)

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Secret Analyzer Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
  * {{margin:0;padding:0;box-sizing:border-box}}
  body {{background:#07090d;color:#c9d8e8;font-family:"Share Tech Mono",monospace;padding:32px 20px;min-height:100vh}}
  h1 {{font-size:20px;letter-spacing:5px;color:#00ff9f;margin-bottom:4px}}
  h2 {{font-size:12px;letter-spacing:3px;color:#00d4ff;margin:30px 0 12px;border-bottom:1px solid #1a2433;padding-bottom:6px;text-transform:uppercase}}
  .meta {{color:#3a5068;font-size:12px;margin-bottom:24px}}
  .stats-grid {{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:28px}}
  .stat-box {{background:#0d1117;border:1px solid #1a2433;padding:14px 22px;min-width:130px;text-align:center}}
  .stat-val {{display:block;font-size:30px;font-weight:bold;margin-bottom:2px}}
  .stat-label {{font-size:9px;color:#3a5068;letter-spacing:3px}}
  table {{width:100%;border-collapse:collapse;margin-bottom:20px;font-size:12px}}
  th {{background:#0d1117;color:#3a5068;padding:8px 12px;text-align:left;font-size:10px;letter-spacing:2px;border-bottom:1px solid #1a2433}}
  td {{padding:8px 12px;border-bottom:1px solid #0f1520;vertical-align:top;max-width:400px}}
  tr:hover td {{background:#0c1018}}
  .badge {{display:inline-block;padding:2px 8px;font-size:10px;letter-spacing:1px;border-radius:2px;font-weight:bold}}
  .mono {{font-family:"Share Tech Mono",monospace}}
  .filename {{color:#00d4ff}}
  .lineno {{color:#3a5068}}
  .value-cell {{color:#ff9944;word-break:break-all;max-width:300px}}
  .context-cell {{color:#6a8090;font-size:11px;word-break:break-all;max-width:350px}}
  .empty {{color:#3a5068;font-style:italic;padding:20px;text-align:center}}
  .section-info {{color:#3a5068;font-size:11px;margin-bottom:10px}}
  .search-box {{background:#0d1117;border:1px solid #1a2433;color:#c9d8e8;padding:8px 14px;font-family:inherit;font-size:12px;width:300px;margin-bottom:14px;outline:none}}
  .search-box:focus {{border-color:#00d4ff}}
  .filter-btns {{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}}
  .filter-btn {{background:transparent;border:1px solid #1a2433;color:#3a5068;padding:4px 12px;font-family:inherit;font-size:11px;cursor:pointer;letter-spacing:1px}}
  .filter-btn.active, .filter-btn:hover {{border-color:#00d4ff;color:#00d4ff}}
  .filter-btn[data-sev="CRITICAL"].active {{border-color:#ff2244;color:#ff2244}}
  .filter-btn[data-sev="HIGH"].active {{border-color:#ff6622;color:#ff6622}}
  .filter-btn[data-sev="MEDIUM"].active {{border-color:#ffcc00;color:#ffcc00}}
  .filter-btn[data-sev="LOW"].active {{border-color:#44aaff;color:#44aaff}}
</style>
</head>
<body>

<h1>🔍 JS SECRET ANALYZER</h1>
<div class="meta">
  Scanned: <b style="color:#c9d8e8">{h(str(self.target_dir))}</b> &nbsp;|&nbsp; {timestamp}
</div>

<div class="stats-grid">
  <div class="stat-box">
    <span class="stat-val" style="color:{'#ff2244' if len(self.findings) else '#888'}">{len(self.findings)}</span>
    <span class="stat-label">TOTAL SECRETS</span>
  </div>
  <div class="stat-box">
    <span class="stat-val" style="color:{'#ff2244' if crit else '#888'}">{crit}</span>
    <span class="stat-label">CRITICAL</span>
  </div>
  <div class="stat-box">
    <span class="stat-val" style="color:{'#ff6622' if high else '#888'}">{high}</span>
    <span class="stat-label">HIGH</span>
  </div>
  <div class="stat-box">
    <span class="stat-val" style="color:{'#ffcc00' if med else '#888'}">{med}</span>
    <span class="stat-label">MEDIUM</span>
  </div>
  <div class="stat-box">
    <span class="stat-val" style="color:{'#44aaff' if low else '#888'}">{low}</span>
    <span class="stat-label">LOW</span>
  </div>
  <div class="stat-box">
    <span class="stat-val" style="color:#00d4ff">{len(self.api_paths)}</span>
    <span class="stat-label">API PATHS</span>
  </div>
</div>

<h2>🔑 Secrets & Credentials Found</h2>
<div class="section-info">Sorted by severity. Click column headers to sort.</div>

<input type="text" class="search-box" id="searchBox" placeholder="Search secrets..." oninput="filterTable()">
<div class="filter-btns">
  <button class="filter-btn active" data-sev="ALL" onclick="setSevFilter('ALL',this)">ALL</button>
  <button class="filter-btn" data-sev="CRITICAL" onclick="setSevFilter('CRITICAL',this)">CRITICAL ({crit})</button>
  <button class="filter-btn" data-sev="HIGH" onclick="setSevFilter('HIGH',this)">HIGH ({high})</button>
  <button class="filter-btn" data-sev="MEDIUM" onclick="setSevFilter('MEDIUM',this)">MEDIUM ({med})</button>
  <button class="filter-btn" data-sev="LOW" onclick="setSevFilter('LOW',this)">LOW ({low})</button>
</div>

{'<table id="secretsTable"><thead><tr><th>SEVERITY</th><th>TYPE</th><th>FILE : LINE</th><th>VALUE (hover for full)</th><th>CONTEXT</th></tr></thead><tbody>' + rows + '</tbody></table>' if rows else "<div class='empty'>✓ No secrets detected in scanned JS files.</div>"}

<h2>📊 Findings by Type</h2>
{'<table><thead><tr><th>SECRET TYPE</th><th>COUNT</th><th>HIGHEST SEVERITY</th></tr></thead><tbody>' + type_rows + '</tbody></table>' if type_rows else "<div class='empty'>No findings.</div>"}

<h2>🌐 API Paths & Endpoints ({len(self.api_paths)} found)</h2>
{'<table><thead><tr><th>PATH / ENDPOINT</th></tr></thead><tbody>' + api_rows + '</tbody></table>' if api_rows else "<div class='empty'>No API paths detected.</div>"}

<script>
let currentSev = 'ALL';

function filterTable() {{
  const query = document.getElementById('searchBox').value.toLowerCase();
  const table = document.getElementById('secretsTable');
  if (!table) return;
  const rows = table.querySelectorAll('tbody tr');
  rows.forEach(row => {{
    const text = row.textContent.toLowerCase();
    const sev = row.querySelector('.badge')?.textContent?.trim() || '';
    const sevMatch = currentSev === 'ALL' || sev === currentSev;
    const textMatch = !query || text.includes(query);
    row.style.display = (sevMatch && textMatch) ? '' : 'none';
  }});
}}

function setSevFilter(sev, btn) {{
  currentSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterTable();
}}
</script>

</body>
</html>'''

        (self.output_dir / 'secrets_report.html').write_text(html, encoding='utf-8')


# =============================================================================
# CLI ENTRY
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nUsage: python3 js_secret_analyzer.py <directory_with_js_files>")
        sys.exit(1)

    target = sys.argv[1]
    if not Path(target).exists():
        print(f"[!] Directory not found: {target}")
        sys.exit(1)

    analyzer = JSSecretAnalyzer(target)
    analyzer.run()


if __name__ == '__main__':
    main()
