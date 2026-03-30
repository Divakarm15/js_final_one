#!/usr/bin/env python3
"""
report_generator.py — Structured Vulnerability Report Generator
================================================================
Generates comprehensive, professional security reports including:
  - Executive summary with risk score
  - Detailed vulnerability findings (endpoint, parameter, payload, evidence)
  - Statistics and severity breakdown
  - JSON, plain text, and HTML report formats
  - Per-vulnerability remediation guidance

Usage (as module):
    from report_generator import ReportGenerator
    gen = ReportGenerator(results_dict, output_dir)
    gen.generate_all()
"""

import json
import time
from pathlib import Path
from urllib.parse import urlparse


# =============================================================================
# SEVERITY COLORS AND METADATA
# =============================================================================

SEVERITY_META = {
    'CRITICAL': {'color': '#ff2244', 'bg': '#ff224422', 'icon': '🔴', 'score': 10},
    'HIGH':     {'color': '#ff6622', 'bg': '#ff662222', 'icon': '🟠', 'score': 7},
    'MEDIUM':   {'color': '#ffcc00', 'bg': '#ffcc0022', 'icon': '🟡', 'score': 4},
    'LOW':      {'color': '#44aaff', 'bg': '#44aaff22', 'icon': '🔵', 'score': 2},
    'INFO':     {'color': '#888888', 'bg': '#88888822', 'icon': '⚪', 'score': 1},
}

VULN_TYPE_DESCRIPTIONS = {
    'REFLECTED_XSS':              'Reflected Cross-Site Scripting',
    'STORED_XSS':                 'Stored Cross-Site Scripting',
    'STORED_XSS_CANDIDATE':       'Stored XSS Candidate',
    'DOM_XSS':                    'DOM-Based Cross-Site Scripting',
    'CORS_WILDCARD':              'CORS Wildcard Misconfiguration',
    'CORS_CREDENTIALED_WILDCARD': 'CORS Credentialed Wildcard (Critical)',
    'CORS_ORIGIN_REFLECTION':     'CORS Origin Reflection',
    'CORS_CREDENTIALED_REFLECTION':'CORS Credentialed Origin Reflection',
    'CORS_NULL_ORIGIN':           'CORS Null Origin Allowed',
    'CORS_PREFLIGHT_MISCONFIGURED':'CORS Preflight Misconfigured',
    'OPEN_REDIRECT':              'Open Redirect',
    'HOST_HEADER_INJECTION':      'Host Header Injection',
    'HOST_HEADER_INJECTION_REDIRECT': 'Host Header Injection (Redirect)',
    'SENSITIVE_ENDPOINT':         'Sensitive Endpoint Exposed',
    'PROTECTED_ENDPOINT':         'Protected Endpoint Exists (Auth Required)',
    'api_key':                    'API Key Exposed',
    'access_token':               'Access Token Exposed',
    'jwt_token':                  'JWT Token Exposed',
    'password':                   'Password Hardcoded',
    'secret':                     'Secret/Credential Exposed',
    'aws_access_key':             'AWS Access Key Exposed',
    'google_api_key':             'Google API Key Exposed',
    'stripe_pk':                  'Stripe Publishable Key Exposed',
    'stripe_sk':                  'Stripe Secret Key Exposed',
    'slack_token':                'Slack Token Exposed',
    'github_token':               'GitHub Token Exposed',
    'private_key':                'Private Key Exposed',
    'firebase_key':               'Firebase Key Exposed',
    'db_connection':              'Database Connection String Exposed',
    'gcp_service_account':        'GCP Service Account Exposed',
    'auth_header':                'Auth Header Value Exposed',
}

REMEDIATION_GUIDE = {
    'REFLECTED_XSS': (
        'Encode all user-supplied data before rendering in HTML. '
        'Implement Content-Security-Policy (CSP) headers. '
        'Use framework-native output encoding (e.g., React JSX auto-escaping). '
        'Validate and sanitize input server-side.'
    ),
    'STORED_XSS': (
        'Sanitize all user input before storage and before rendering. '
        'Use a proven sanitizer such as DOMPurify for client-side HTML rendering. '
        'Implement strict CSP headers to block inline scripts. '
        'Apply output encoding appropriate to the context (HTML, JS, URL, CSS).'
    ),
    'DOM_XSS': (
        'Avoid assigning user-controlled data to dangerous sinks (innerHTML, eval, document.write). '
        'Use safe DOM APIs such as textContent, createElement. '
        'If HTML rendering is needed, use DOMPurify.sanitize() before assigning to innerHTML. '
        'Implement CSP with nonces or hashes to restrict script execution.'
    ),
    'CORS_WILDCARD': (
        'Replace the Access-Control-Allow-Origin: * header with a specific allowlist of trusted origins. '
        'Never combine wildcard ACAO with Access-Control-Allow-Credentials: true.'
    ),
    'CORS_ORIGIN_REFLECTION': (
        'Validate the incoming Origin header against a server-side allowlist. '
        'Do not blindly reflect the Origin value back. '
        'Log and alert on unexpected origin values.'
    ),
    'OPEN_REDIRECT': (
        'Validate redirect targets against a server-side allowlist of trusted URLs. '
        'Avoid using user-supplied data in redirect targets. '
        'If redirect parameters are needed, use indirect references (e.g., numeric IDs mapping to safe URLs).'
    ),
    'HOST_HEADER_INJECTION': (
        'Configure your web server to only accept requests with the expected Host header. '
        'Do not use the Host header value in generated links, emails, or redirects without validation. '
        'Use explicit server configuration for the base URL rather than deriving it from the Host header.'
    ),
    'SENSITIVE_ENDPOINT': (
        'Restrict access to sensitive endpoints using authentication and authorization. '
        'Remove or disable debug/development endpoints in production. '
        'Ensure configuration files, backup files, and development tools are not accessible. '
        'Implement network-level controls (firewall rules) for admin interfaces.'
    ),
    'secrets': (
        'Remove all credentials from source code immediately. '
        'Rotate all exposed credentials. '
        'Use environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager) for credentials. '
        'Add pre-commit hooks to detect and prevent credential commits.'
    ),
}


def h(s: str) -> str:
    """HTML-escape a string."""
    return (str(s)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))


def sev_color(severity: str) -> str:
    return SEVERITY_META.get(severity, SEVERITY_META['INFO'])['color']


def sev_icon(severity: str) -> str:
    return SEVERITY_META.get(severity, SEVERITY_META['INFO'])['icon']


# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """
    Generates comprehensive security reports from scan results.
    Supports JSON, plain text, and HTML output formats.
    """

    def __init__(self, results: dict, output_dir: Path):
        self.results    = results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_time  = time.strftime('%Y-%m-%d %H:%M:%S')
        self.target     = results.get('target', 'Unknown')

    def generate_all(self) -> dict:
        """Generate all report formats. Returns dict of output file paths."""
        paths = {}
        paths['json']  = self._write_json()
        paths['text']  = self._write_text()
        paths['html']  = self._write_html()
        return paths

    # =========================================================================
    # JSON REPORT
    # =========================================================================

    def _write_json(self) -> str:
        """Write full machine-readable JSON report."""
        report = {
            'meta': {
                'tool':       'JS Scout Pro v7',
                'target':     self.target,
                'scan_time':  self.scan_time,
                'risk_level': self._calc_risk(),
            },
            'summary':  self._build_summary(),
            'findings': self._collect_all_findings(),
            'raw':      self.results,
        }
        # Convert sets to lists for JSON serialization
        path = self.output_dir / 'full_report.json'
        path.write_text(json.dumps(report, indent=2, default=str), encoding='utf-8')
        return str(path)

    # =========================================================================
    # TEXT REPORT
    # =========================================================================

    def _write_text(self) -> str:
        """Write human-readable plain text report."""
        summary = self._build_summary()
        risk    = self._calc_risk()
        lines   = [
            '=' * 70,
            'JS SCOUT PRO v7 — VULNERABILITY REPORT',
            '=' * 70,
            f'Target    : {self.target}',
            f'Scan Time : {self.scan_time}',
            f'Risk Level: {risk}',
            '',
            '── SUMMARY ──────────────────────────────────────────────────────────',
            f'Total Vulnerabilities : {summary["total_vulns"]}',
            f'  CRITICAL            : {summary["critical"]}',
            f'  HIGH                : {summary["high"]}',
            f'  MEDIUM              : {summary["medium"]}',
            f'  LOW                 : {summary["low"]}',
            '',
            f'JS Files Analyzed     : {summary.get("js_files", 0)}',
            f'Endpoints Discovered  : {summary.get("endpoints", 0)}',
            f'Pages Crawled         : {summary.get("pages_crawled", 0)}',
            '',
            f'XSS Findings:',
            f'  Reflected XSS       : {summary.get("reflected_xss", 0)}',
            f'  Stored XSS          : {summary.get("stored_xss", 0)}',
            f'  DOM XSS Sinks       : {summary.get("dom_xss", 0)}',
            f'  Browser Confirmed   : {summary.get("browser_confirmed", 0)}',
            '',
            f'Other Vulnerabilities:',
            f'  CORS Issues         : {summary.get("cors_issues", 0)}',
            f'  Open Redirects      : {summary.get("open_redirects", 0)}',
            f'  Host Header Inj.    : {summary.get("host_header", 0)}',
            f'  Sensitive Endpoints : {summary.get("sensitive_endpoints", 0)}',
            f'  Secrets Found       : {summary.get("secrets", 0)}',
            '',
        ]

        all_findings = self._collect_all_findings()

        # Group by severity
        for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            sev_findings = [f for f in all_findings if f.get('severity') == severity]
            if sev_findings:
                lines.append(f'── {severity} FINDINGS ──────────────────────────────────────────────')
                for i, f in enumerate(sev_findings, 1):
                    vtype = VULN_TYPE_DESCRIPTIONS.get(f.get('type', ''), f.get('type', 'Unknown'))
                    lines.append(f"\n[{i}] {vtype}")
                    lines.append(f"     URL       : {f.get('url', f.get('base_url', 'N/A'))}")
                    if f.get('param'):
                        lines.append(f"     Parameter : {f['param']}")
                    if f.get('payload'):
                        lines.append(f"     Payload   : {f['payload'][:120]}")
                    if f.get('file'):
                        lines.append(f"     File      : {f['file']}:{f.get('line', '?')}")
                    if f.get('sink'):
                        lines.append(f"     Sink      : {f['sink']}")
                    if f.get('evidence'):
                        lines.append(f"     Evidence  : {str(f['evidence'])[:200]}")
                    if f.get('description'):
                        lines.append(f"     Details   : {f['description']}")
                    # Remediation
                    vuln_type = f.get('type', '')
                    remed = REMEDIATION_GUIDE.get(vuln_type, '')
                    if not remed and 'xss' in vuln_type.lower():
                        remed = REMEDIATION_GUIDE.get('REFLECTED_XSS', '')
                    if not remed and ('secret' in vuln_type.lower() or 'key' in vuln_type.lower()
                                       or 'token' in vuln_type.lower() or 'password' in vuln_type.lower()):
                        remed = REMEDIATION_GUIDE.get('secrets', '')
                    if remed:
                        lines.append(f"     Fix       : {remed[:200]}")
                lines.append('')

        path = self.output_dir / 'vulnerability_report.txt'
        path.write_text('\n'.join(lines), encoding='utf-8')
        return str(path)

    # =========================================================================
    # HTML REPORT
    # =========================================================================

    def _write_html(self) -> str:
        """Write rich interactive HTML vulnerability report."""
        summary  = self._build_summary()
        risk     = self._calc_risk()
        findings = self._collect_all_findings()

        rc = SEVERITY_META.get(risk, SEVERITY_META['INFO'])['color']

        # Build finding cards HTML
        finding_cards = ''
        for i, f in enumerate(findings, 1):
            sev     = f.get('severity', 'INFO')
            sc      = sev_color(sev)
            si      = sev_icon(sev)
            vtype   = VULN_TYPE_DESCRIPTIONS.get(f.get('type', ''), f.get('type', 'Unknown'))
            url_val = f.get('url', f.get('base_url', ''))
            param   = f.get('param', '')
            payload = f.get('payload', '')
            file_   = f.get('file', '')
            line_   = f.get('line', '')
            sink    = f.get('sink', '')
            evidence= str(f.get('evidence', ''))[:300]
            desc    = f.get('description', '')
            browser = '✓ BROWSER CONFIRMED' if f.get('browser_confirmed') else ''
            conf    = '⚡ Source→Sink Flow' if f.get('confirmed_flow') else ''

            # Remediation
            vuln_key = f.get('type', '')
            remed = REMEDIATION_GUIDE.get(vuln_key, '')
            if not remed and 'xss' in vuln_key.lower():
                remed = REMEDIATION_GUIDE.get('REFLECTED_XSS', '')
            if not remed and any(k in vuln_key.lower() for k in ['secret','key','token','password','credential']):
                remed = REMEDIATION_GUIDE.get('secrets', '')

            finding_cards += f'''
            <div class="finding-card" data-sev="{h(sev)}">
              <div class="finding-header" style="border-left: 4px solid {sc}">
                <span class="finding-num">#{i}</span>
                <span class="finding-sev" style="color:{sc}">{si} {h(sev)}</span>
                <span class="finding-type">{h(vtype)}</span>
                {f'<span class="finding-badge browser">{h(browser)}</span>' if browser else ''}
                {f'<span class="finding-badge flow">{h(conf)}</span>' if conf else ''}
              </div>
              <div class="finding-body">
                <table class="finding-table">
                  {f'<tr><th>URL</th><td><a href="{h(url_val)}" target="_blank">{h(url_val[:120])}</a></td></tr>' if url_val else ''}
                  {f'<tr><th>Parameter</th><td><code>{h(param)}</code></td></tr>' if param else ''}
                  {f'<tr><th>Payload</th><td><code>{h(payload[:200])}</code></td></tr>' if payload else ''}
                  {f'<tr><th>File:Line</th><td><code>{h(file_)}:{h(line_)}</code></td></tr>' if file_ else ''}
                  {f'<tr><th>Sink</th><td><code>{h(sink)}</code></td></tr>' if sink else ''}
                  {f'<tr><th>Description</th><td>{h(desc)}</td></tr>' if desc else ''}
                  {f'<tr><th>Evidence</th><td><pre class="evidence">{h(evidence)}</pre></td></tr>' if evidence else ''}
                  {f'<tr><th>Remediation</th><td class="remed">{h(remed[:300])}</td></tr>' if remed else ''}
                </table>
              </div>
            </div>'''

        # Stat cards
        stats_html = ''
        stat_items = [
            ('TOTAL VULNS',    summary['total_vulns'],    '#c9d8e8'),
            ('CRITICAL',       summary['critical'],        '#ff2244'),
            ('HIGH',           summary['high'],            '#ff6622'),
            ('REFLECTED XSS',  summary.get('reflected_xss', 0), '#ff6622'),
            ('DOM XSS SINKS',  summary.get('dom_xss', 0), '#ffcc00'),
            ('SECRETS',        summary.get('secrets', 0), '#ff2244'),
            ('CORS ISSUES',    summary.get('cors_issues', 0), '#ff6622'),
            ('OPEN REDIRECTS', summary.get('open_redirects', 0), '#ffcc00'),
            ('SENSITIVE PATHS',summary.get('sensitive_endpoints', 0), '#44aaff'),
            ('JS FILES',       summary.get('js_files', 0), '#44aaff'),
            ('ENDPOINTS',      summary.get('endpoints', 0), '#00ff9f'),
        ]
        for label, val, color in stat_items:
            stats_html += f'''
            <div class="stat-card">
              <span class="stat-val" style="color:{color}">{val}</span>
              <span class="stat-label">{label}</span>
            </div>'''

        # Filter buttons
        filter_btns = ' '.join(
            f'<button class="filter-btn" onclick="filterBySev(\'{sev}\')">{sev}</button>'
            for sev in ('ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        )

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Scout Pro v7 — Security Report: {h(self.target)}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
  background: #070a0f;
  color: #c9d8e8;
  font-family: "Courier New", "Share Tech Mono", monospace;
  padding: 32px 24px;
  line-height: 1.5;
}}
.header {{ margin-bottom: 28px; }}
.header h1 {{ font-size: 22px; letter-spacing: 5px; color: #00ff9f; margin-bottom: 4px; }}
.header .meta {{ color: #3a5068; font-size: 12px; margin-bottom: 12px; }}
.risk-badge {{
  display: inline-block;
  padding: 6px 20px;
  border: 1px solid {rc};
  background: {rc}22;
  color: {rc};
  font-size: 13px;
  letter-spacing: 4px;
  margin-bottom: 24px;
}}
.stats {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 32px; }}
.stat-card {{
  background: #0d1117;
  border: 1px solid #1e2d3d;
  padding: 14px 20px;
  min-width: 120px;
  text-align: center;
}}
.stat-val {{ display: block; font-size: 28px; font-weight: bold; }}
.stat-label {{ font-size: 9px; color: #3a5068; letter-spacing: 2px; margin-top: 4px; }}
.section-title {{
  font-size: 12px;
  letter-spacing: 3px;
  color: #00d4ff;
  margin: 28px 0 14px;
  padding-bottom: 6px;
  border-bottom: 1px solid #1e2d3d;
}}
.filters {{ margin-bottom: 20px; display: flex; gap: 8px; flex-wrap: wrap; }}
.filter-btn {{
  background: #0d1117;
  border: 1px solid #1e2d3d;
  color: #c9d8e8;
  padding: 6px 14px;
  cursor: pointer;
  font-family: monospace;
  font-size: 11px;
  letter-spacing: 2px;
}}
.filter-btn:hover {{ background: #1e2d3d; }}
.filter-btn.active {{ background: #1e2d3d; border-color: #00d4ff; color: #00d4ff; }}
.finding-card {{
  background: #0d1117;
  border: 1px solid #1e2d3d;
  margin-bottom: 16px;
  border-radius: 3px;
  overflow: hidden;
}}
.finding-header {{
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  background: #0a0f16;
}}
.finding-num  {{ color: #3a5068; font-size: 11px; min-width: 28px; }}
.finding-sev  {{ font-size: 12px; font-weight: bold; min-width: 100px; }}
.finding-type {{ font-size: 12px; color: #c9d8e8; flex: 1; }}
.finding-badge {{
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 2px;
  font-weight: bold;
}}
.finding-badge.browser {{ background: #00ff9f22; color: #00ff9f; border: 1px solid #00ff9f44; }}
.finding-badge.flow    {{ background: #ff224422; color: #ff6666; border: 1px solid #ff224444; }}
.finding-body {{ padding: 14px 16px; }}
.finding-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
.finding-table th {{
  color: #3a5068;
  padding: 4px 12px 4px 0;
  text-align: left;
  font-size: 10px;
  letter-spacing: 1px;
  white-space: nowrap;
  vertical-align: top;
  width: 110px;
}}
.finding-table td {{ padding: 4px 0 4px 0; vertical-align: top; color: #c9d8e8; }}
.finding-table a {{ color: #00d4ff; text-decoration: none; word-break: break-all; }}
.finding-table a:hover {{ text-decoration: underline; }}
.finding-table code {{
  background: #111820;
  padding: 2px 6px;
  font-size: 11px;
  word-break: break-all;
  color: #ffcc88;
}}
pre.evidence {{
  background: #111820;
  padding: 10px;
  font-size: 10px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  color: #88aacc;
  max-height: 120px;
  overflow-y: auto;
}}
.remed {{ color: #aabbcc; font-size: 11px; line-height: 1.6; }}
.no-findings {{ color: #3a5068; font-style: italic; padding: 24px 0; text-align: center; }}
@media (max-width: 600px) {{
  body {{ padding: 16px 12px; }}
  .stat-card {{ min-width: 100px; padding: 10px 14px; }}
}}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ JS SCOUT PRO v7</h1>
  <div class="meta">
    Target: <strong style="color:#c9d8e8">{h(self.target)}</strong>
    &nbsp;|&nbsp; Scan Time: {self.scan_time}
  </div>
  <div class="risk-badge">⚠ RISK LEVEL: {risk}</div>
</div>

<h2 class="section-title">📊 SCAN STATISTICS</h2>
<div class="stats">{stats_html}</div>

<h2 class="section-title">🔍 VULNERABILITY FINDINGS ({len(findings)} total)</h2>
<div class="filters">
  <span style="color:#3a5068;font-size:11px;line-height:28px">FILTER:</span>
  {filter_btns}
</div>

<div id="findings-container">
  {finding_cards if finding_cards else '<div class="no-findings">No vulnerabilities found.</div>'}
</div>

<script>
function filterBySev(sev) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    if (sev === 'ALL' || card.dataset.sev === sev) {{
      card.style.display = '';
    }} else {{
      card.style.display = 'none';
    }}
  }});
}}
// Default: show all, activate ALL button
document.querySelector('.filter-btn').classList.add('active');
</script>
</body>
</html>'''

        path = self.output_dir / 'vulnerability_report.html'
        path.write_text(html, encoding='utf-8')
        return str(path)

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _collect_all_findings(self) -> list:
        """Collect and normalize all findings from all modules."""
        all_findings = []

        # XSS findings
        xss_data = self.results.get('xss_data', {})
        for f in xss_data.get('reflected_xss', []):
            all_findings.append({**f, 'category': 'xss'})
        for f in xss_data.get('stored_xss', []):
            all_findings.append({**f, 'category': 'xss'})
        for f in xss_data.get('dom_xss', []):
            all_findings.append({**f, 'category': 'xss'})

        # Legacy XSS fields (backward compat with original jsscout.py)
        for f in self.results.get('poc_findings', []):
            if not any(e.get('url') == f.get('url') and e.get('param') == f.get('param')
                       for e in all_findings):
                all_findings.append({**f, 'type': 'REFLECTED_XSS', 'severity': 'HIGH', 'category': 'xss'})
        for f in self.results.get('xss_findings', []):
            all_findings.append({**f, 'type': 'DOM_XSS', 'category': 'xss'})

        # Vulnerability checks
        vuln_data = self.results.get('vuln_data', {})
        for f in vuln_data.get('cors', []):
            all_findings.append({**f, 'category': 'vuln'})
        for f in vuln_data.get('open_redirect', []):
            all_findings.append({**f, 'category': 'vuln'})
        for f in vuln_data.get('host_header', []):
            all_findings.append({**f, 'category': 'vuln'})
        for f in vuln_data.get('sensitive_endpoints', []):
            if f.get('severity') in ('CRITICAL', 'HIGH', 'MEDIUM'):
                all_findings.append({**f, 'category': 'vuln'})

        # Secrets
        for f in self.results.get('secrets', []):
            all_findings.append({**f, 'category': 'secret',
                                  'url': f.get('file', ''),
                                  'type': f.get('type', 'secret')})

        # Sort by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        all_findings.sort(key=lambda f: sev_order.get(f.get('severity', 'INFO'), 5))
        return all_findings

    def _build_summary(self) -> dict:
        """Build summary statistics from results."""
        all_findings = self._collect_all_findings()

        xss_data  = self.results.get('xss_data', {})
        vuln_data = self.results.get('vuln_data', {})

        return {
            'total_vulns':   len(all_findings),
            'critical':      sum(1 for f in all_findings if f.get('severity') == 'CRITICAL'),
            'high':          sum(1 for f in all_findings if f.get('severity') == 'HIGH'),
            'medium':        sum(1 for f in all_findings if f.get('severity') == 'MEDIUM'),
            'low':           sum(1 for f in all_findings if f.get('severity') == 'LOW'),
            'reflected_xss': len(xss_data.get('reflected_xss', [])) + len(self.results.get('poc_findings', [])),
            'stored_xss':    len(xss_data.get('stored_xss', [])),
            'dom_xss':       len(xss_data.get('dom_xss', [])) + len(self.results.get('xss_findings', [])),
            'browser_confirmed': sum(1 for f in all_findings if f.get('browser_confirmed')),
            'cors_issues':   len(vuln_data.get('cors', [])),
            'open_redirects': len(vuln_data.get('open_redirect', [])),
            'host_header':   len(vuln_data.get('host_header', [])),
            'sensitive_endpoints': len(vuln_data.get('sensitive_endpoints', [])),
            'secrets':       len(self.results.get('secrets', [])),
            'js_files':      len(self.results.get('js_files', [])),
            'endpoints':     len(self.results.get('endpoints', {})),
            'pages_crawled': len(self.results.get('visited_pages', [])),
        }

    def _calc_risk(self) -> str:
        """Calculate overall risk level."""
        summary = self._build_summary()

        if summary['critical'] > 0:
            return 'CRITICAL'
        if summary['high'] > 0:
            return 'HIGH'
        if summary['medium'] > 0:
            return 'MEDIUM'
        if summary['low'] > 0:
            return 'LOW'
        return 'INFO'
