# JS Scout Pro v9 — Advanced Automated Web Pentesting Framework

```
     ██╗███████╗    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
     ██║██╔════╝    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
     ██║███████╗    ███████╗██║     ██║   ██║██║   ██║   ██║
██   ██║╚════██║    ╚════██║██║     ██║   ██║██║   ██║   ██║
╚█████╔╝███████║    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║
 ╚════╝ ╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝
                                                          PRO v9
```

An automated web application pentesting framework covering 30+ vulnerability
classes with Burp Suite integration, live web UI, and near-zero false positives.

---

## Quick Start

```bash
# 1. Install
pip install -r requirements.txt

# 2. Web UI
python3 server.py        # → http://localhost:7331

# 3. CLI scan
python3 jsscout.py https://target.com

# 4. Through Burp proxy
python3 jsscout.py https://target.com --burp

# 5. With Burp Collaborator (OOB detection)
python3 jsscout.py https://target.com --burp --collab-domain abc.burpcollaborator.net
```

---

## Vulnerability Coverage (30+ classes)

### Authentication & Authorization
| Finding | Module |
|---------|--------|
| IDOR (integer + UUID IDs) | advanced_vulns.py |
| Broken Access Control (horiz + vert) | auth_checks.py |
| OAuth — missing state (CSRF) | auth_checks.py |
| OAuth — redirect_uri manipulation | auth_checks.py |
| OAuth — token leakage in URL | auth_checks.py |
| OAuth — implicit flow (deprecated) | auth_checks.py |
| OAuth — missing PKCE | auth_checks.py |
| JWT — none algorithm bypass | advanced_vulns.py |
| JWT — weak secret brute-force | advanced_vulns.py |
| JWT — expired token accepted | advanced_vulns.py |
| JWT — RS256→HS256 confusion | advanced_vulns.py |
| Session fixation | auth_checks.py |
| Cookie security (HttpOnly/Secure/SameSite) | advanced_vulns.py |
| Account enumeration | advanced_vulns.py |
| Rate limiting absent | advanced_vulns.py |

### Injection
| Finding | Module |
|---------|--------|
| Reflected XSS (15+ contexts, browser confirm) | xss_detector.py |
| Stored XSS (form probing) | xss_detector.py |
| DOM-based XSS (static analysis) | xss_detector.py |
| SSTI — Jinja2/Twig/Freemarker/ERB/Smarty | advanced_vulns.py |
| SQL Injection — error-based (15 DB patterns) | advanced_vulns.py |
| SQL Injection — boolean-blind (3-sample) | advanced_vulns.py |
| SQL Injection — time-blind (MySQL/MSSQL/PgSQL/Oracle) | advanced_vulns.py |
| OS Command Injection — output + time-based | advanced_vulns.py |
| Path Traversal / LFI | advanced_vulns.py |
| XXE — inband + error-based | advanced_vulns.py |
| SSRF — AWS/GCP/Azure IMDS | advanced_vulns.py |
| CRLF Header Injection (raw socket) | advanced_vulns.py |
| HTML Injection | vulnerability_checks.py |
| Mass Assignment | advanced_vulns.py |

### Misconfigurations
| Finding | Module |
|---------|--------|
| CORS wildcard + credentialed abuse | vulnerability_checks.py |
| CORS origin reflection + null origin | vulnerability_checks.py |
| Open Redirect (15+ payloads) | vulnerability_checks.py |
| Host Header Injection | vulnerability_checks.py |
| HTTP Request Smuggling fingerprint | advanced_vulns.py |
| Cache Poisoning (unkeyed headers) | advanced_vulns.py |
| Security Headers — CSP/HSTS/XFO/etc. | advanced_vulns.py |
| CSP — unsafe-inline/unsafe-eval/wildcard | advanced_vulns.py |
| Clickjacking | advanced_vulns.py |
| HTTP Method Tampering (TRACE/PUT/DELETE) | advanced_vulns.py |
| Directory Listing (Apache + nginx) | auth_checks.py |
| GraphQL introspection + batching + depth | advanced_vulns.py |

### Data Exposure
| Finding | Module |
|---------|--------|
| API keys / secrets in JS | js_secret_analyzer.py |
| AWS/Stripe/Google credential patterns | jsscout.py |
| JWT tokens in JS | jsscout.py |
| Stack trace / debug info disclosure | advanced_vulns.py |
| Server version in headers | advanced_vulns.py |
| Internal IP address leakage | advanced_vulns.py |
| Sensitive endpoints (.env/admin/actuator) | vulnerability_checks.py |
| Dependency confusion (package.json) | advanced_vulns.py |
| File upload — PHP/ASP/HTML shells | advanced_vulns.py |

### Recon & Discovery
| Feature | Module |
|---------|--------|
| JS-crawling with Selenium | jsscout.py |
| Deep JS→JS reference chain resolution | jsscout.py |
| JS file secret + API endpoint extraction | js_secret_analyzer.py |
| Subdomain takeover (14 service signatures) | advanced_vulns.py |
| Hidden parameter discovery (40-word fuzz) | auth_checks.py |
| Debug parameter detection | auth_checks.py |
| JS-extracted parameter names | auth_checks.py |

---

## Architecture

```
jsscout_pro/
├── jsscout.py              # Core engine + 12-phase scan pipeline
├── vulnerability_checks.py # CORS, redirect, host injection, HTML injection
├── advanced_vulns.py       # 24 injection/misconfig/data-exposure checkers
├── auth_checks.py          # OAuth, session, access control, dir listing [NEW]
├── burp_integration.py     # Burp proxy + Collaborator + XML export [NEW]
├── xss_detector.py         # DOM/Reflected/Stored XSS + browser confirm
├── endpoint_extractor.py   # Deep endpoint + param discovery
├── js_secret_analyzer.py   # Secret/API key extraction from JS
├── logger.py               # Structured NDJSON + coloured terminal [NEW]
├── report_generator.py     # HTML/JSON/TXT reports
├── server.py               # Flask web UI backend
└── static/index.html       # Web UI frontend
```

### 12-Phase Scan Pipeline

```
Phase 1  → BFS crawler (Selenium + requests)
Phase 2  → Manifest path probing
Phase 3  → JS file download
Phase 4  → Deep JS→JS crawl (recursive)
Phase 4b → Browser scroll/click (lazy chunk trigger)
Phase 5  → JS analysis (secrets, sinks, endpoints)
Phase 6  → Context-aware XSS parameter probing
Phase 7  → Enhanced endpoint extraction
Phase 8  → CORS/Redirect/Host/HTML injection checks
Phase 9  → Enhanced XSS detection (DOM+Reflected+Stored)
Phase 11 → Advanced injection checks (SQLi/SSTI/CMDi/LFI/...)
Phase 12 → Auth/OAuth/Session/Access Control checks [NEW]
Phase 10 → Report generation (HTML + JSON + TXT)
```

---

## Burp Suite Integration

### Route scanner through Burp

```bash
python3 jsscout.py https://target.com --burp
# All requests appear in Proxy > HTTP history
```

### Check Burp connectivity

```bash
# CLI
python3 jsscout.py https://target.com --burp --burp-host 127.0.0.1 --burp-port 8080

# Web UI: Settings → Burp Proxy → Test Connection
# API: GET /api/burp/check?host=127.0.0.1&port=8080
```

### Burp Collaborator (OOB — blind SSRF/XSS/CMDi)

```bash
python3 jsscout.py https://target.com \
  --burp \
  --collab-domain xxxx.burpcollaborator.net
```

Automatically generates unique DNS subdomains per check type:
- `jsscout-ssrf-{id}.xxxx.burpcollaborator.net` for SSRF
- `jsscout-bxss-{id}.xxxx.burpcollaborator.net` for blind XSS
- `jsscout-cmdi-{id}.xxxx.burpcollaborator.net` for blind CMDi

### Export to Burp

```bash
# CLI: generate Burp XML + raw .http files per finding
python3 jsscout.py https://target.com --export-burp

# Web UI: Results → Download → Burp XML
# API:    GET /api/scan/{id}/burp_export
```

Import in Burp: **Proxy → HTTP history → Import**

### Recommended Burp Extensions (printed per finding)

| Finding Type | Extensions |
|-------------|-----------|
| IDOR / BAC | Autorize, Authmatrix |
| SQLi | SQLipy, CO2 |
| XSS | XSS Validator, DOM Invader |
| SSRF | Collaborator Everywhere, SSRF King |
| Hidden Params | Param Miner, GAP |
| JWT | JWT Editor, JSON Web Tokens |
| GraphQL | InQL, GraphQL Raider |
| Cache Poisoning | Param Miner, Web Cache Deception |
| Request Smuggling | HTTP Request Smuggler |
| OAuth | OAuth Scanner, TokenJacking |
| XXE | Content Type Converter |

---

## CLI Options

```
python3 jsscout.py <target> [options]

Scan Control:
  --threads N       Parallel threads (default: 10)
  --timeout N       Request timeout seconds (default: 15)
  --pages N         Max pages to crawl (default: 200)
  --depth N         Crawl depth (default: 3)
  --output DIR      Output directory

Authentication:
  --cookies STR     Cookie string: "session=abc; csrf=xyz"
  --header STR      Extra header (repeatable): "Authorization: Bearer TOKEN"

Module Control:
  --no-selenium     Disable Selenium/browser mode
  --skip-auth       Skip Phase 12 (OAuth/session/access control)
  --skip-advanced   Skip Phase 11 (SQLi/SSTI/CMDi/etc.)
  --skip-vuln-checks  Skip Phase 8 (CORS/redirect/host injection)
  --skip-stored-xss   Skip stored XSS form probing

Burp Suite:
  --burp            Route requests through Burp proxy
  --burp-host H     Burp proxy host (default: 127.0.0.1)
  --burp-port N     Burp proxy port (default: 8080)
  --collab-domain D Burp Collaborator domain for OOB detection
  --export-burp     Export findings as Burp-importable XML

Output:
  --verbose         Verbose debug output
  --json            Output JSON to stdout
```

---

## Web UI API Endpoints

```
GET  /api/health                    Server health check
POST /api/scan/start                Start a scan
GET  /api/scan/{id}/status          Live status + log tail
GET  /api/scan/{id}/results         Full results JSON
GET  /api/scan/{id}/findings        Finding stream (NDJSON)
POST /api/scan/stop/{id}            Stop running scan
GET  /api/scan/{id}/report          Download report.txt
GET  /api/scan/{id}/secrets         Run secret analyzer
GET  /api/scan/{id}/download        Download full ZIP
GET  /api/scan/{id}/burp_export     Burp XML export
GET  /api/burp/check                Test Burp connectivity
GET  /api/scans                     List all scans
GET  /report/{id}                   View HTML report
GET  /report/{id}/secrets           View secrets HTML report
```

---

## Output Files

```
output/<domain>/<scan_id>/
├── report.html              Full HTML vulnerability dashboard
├── report.txt               Plain-text summary
├── summary.json             Machine-readable summary
├── full_results.json        Complete scan data
├── findings.jsonl           NDJSON finding stream (live updates)
├── scan.log.jsonl           Structured scan log
├── vulnerability_findings.json   CORS/redirect/host/HTML checks
├── advanced_findings.json        SQLi/SSTI/CMDi/LFI/JWT/...
├── auth_findings.json            OAuth/session/access-control
├── reflected_xss.txt             Reflected XSS PoC list
├── js/                           Downloaded JS files
├── secrets/secrets_report.html   Secret analyzer report
└── burp_export/
    ├── burp_import.xml           Import into Burp Proxy history
    ├── index.json                Finding export index
    └── *.http                    Raw HTTP requests (Repeater-ready)
```

---

## False Positive Controls

| Technique | Control |
|-----------|---------|
| SQLi boolean-blind | Median of 3 sample-pairs > 500B diff |
| SQLi time-blind | Median(3 payload) > 2.5× median(3 baseline) |
| SSTI | Random A×B math canary — exact product required |
| CMDi output | Unique per-request canary (not static string) |
| CMDi time | 2 consecutive slow responses required |
| LFI | Hard OS file signatures (`root:x:0:0`) |
| SSRF | Cloud IMDS-specific content only — no localhost |
| IDOR | SHA256 hash comparison — not length diff |
| Cache poisoning | Unique random canary per header test |
| CRLF | Raw TCP socket — bypasses requests stripping |
| JWT none-alg | Response must differ from unauthenticated baseline |
| Subdomain takeover | All patterns in set must match simultaneously |
| Directory listing | Requires multiple Apache/nginx specific signatures |
| OAuth redirect | Must redirect to `evil.jsscout.test` specifically |

---

## Legal Notice

**For authorized security testing only.** Always obtain explicit written
permission before scanning systems you do not own. Unauthorized use is
illegal. The authors accept no liability for misuse.
