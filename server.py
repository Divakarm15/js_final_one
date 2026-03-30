#!/usr/bin/env python3
"""
JS Scout Pro — Web Server
Run: python3 server.py
Open: http://localhost:7331
"""

import json, sys, os, threading, time, uuid
from pathlib import Path
from urllib.parse import urlparse

try:
    from flask import Flask, request, jsonify, send_file, make_response
except ImportError:
    print("[!] pip install flask"); sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent))
from jsscout import JSScout, XSS_PAYLOADS
from js_secret_analyzer import JSSecretAnalyzer

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = os.urandom(24)

SCANS = {}
OUTPUT_BASE = Path(__file__).parent / 'output'
OUTPUT_BASE.mkdir(exist_ok=True)

# ── CORS + security headers ───────────────────────────────────────────────────
@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, DELETE'
    response.headers['X-Content-Type-Options']       = 'nosniff'
    return response

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'version': 'v9', 'scans': len(SCANS)})

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return send_file(Path(__file__).parent / 'static' / 'index.html')

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error', 'detail': str(e)}), 500


@app.route('/')
def index():
    return send_file(Path(__file__).parent / 'static' / 'index.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data       = request.get_json() or {}
    target     = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target is required'}), 400

    options    = data.get('options', {})
    cookies    = data.get('cookies', '').strip()
    cookie_json= data.get('cookie_json', '').strip()
    auth_token = data.get('auth_token', '').strip()
    burp_cfg   = data.get('burp', {})
    modules    = data.get('modules', {})

    # If cookie_json supplied (Cookie Editor JSON export), parse it into cookie string
    if cookie_json and not cookies:
        try:
            import json as _json
            parsed_cookies = _json.loads(cookie_json)
            # Support both list of {name, value} objects and plain {name: value} dicts
            if isinstance(parsed_cookies, list):
                cookies = '; '.join(
                    f"{c['name']}={c['value']}" for c in parsed_cookies
                    if 'name' in c and 'value' in c
                )
            elif isinstance(parsed_cookies, dict):
                cookies = '; '.join(f"{k}={v}" for k, v in parsed_cookies.items())
        except Exception:
            pass  # Fall back gracefully; scan will run without auth cookies

    extra_headers = {}
    if auth_token:
        extra_headers['Authorization'] = f'Bearer {auth_token}'

    scan_id    = str(uuid.uuid4())[:8]
    domain     = urlparse(target if '://' in target else 'https://' + target).netloc.replace(':', '_')
    output_dir = OUTPUT_BASE / domain / scan_id

    state = {
        'id': scan_id, 'target': target,
        'status': 'running', 'progress': 0,
        'phase': 'Starting...', 'log': [],
        'results': None, 'report_url': None,
        'output_dir': str(output_dir),
    }
    SCANS[scan_id] = state

    def run():
        def log_fn(msg):
            state['log'].append({'time': time.strftime('%H:%M:%S'), 'msg': msg})
            if   '[*] Phase 1' in msg:
                state['progress'] = 5;  state['phase'] = 'Phase 1: Crawling pages...'
            elif '[+] Crawl'   in msg:
                state['progress'] = 30; state['phase'] = 'Crawl complete'
            elif '[*] Phase 2' in msg:
                state['progress'] = 35; state['phase'] = 'Phase 2: Probing manifests...'
            elif '[*] Phase 3' in msg:
                state['progress'] = 45; state['phase'] = 'Phase 3: Downloading JS files...'
            elif '[+] Downloaded' in msg or '[+] Download' in msg:
                state['progress'] = 55; state['phase'] = 'JS files downloaded'
            elif '[*] Phase 4' in msg:
                state['progress'] = 60; state['phase'] = 'Phase 4: Deep JS crawl...'
            elif '[*] Phase 5' in msg:
                state['progress'] = 70; state['phase'] = 'Phase 5: Analyzing JS files...'
            elif '[analyze]'   in msg:
                state['progress'] = min(state['progress'] + 1, 88)
            elif '[*] Phase 6' in msg:
                state['progress'] = 90; state['phase'] = 'Phase 6: Probing parameters...'
            elif '[probe]'     in msg:
                state['progress'] = 92; state['phase'] = 'Phase 6: Testing XSS params...'
            elif '[⚡ XSS FOUND]' in msg or '[⚡ REFLECTED' in msg:
                state['progress'] = min(state['progress'] + 1, 97)
                state['phase'] = 'Phase 6: Reflected XSS found!'
            elif '[*] Phase 7' in msg:
                state['progress'] = 98; state['phase'] = 'Phase 7: Writing report...'

        try:
            scout = JSScout(
                target=target,
                output_dir=str(output_dir),
                threads=int(options.get('threads', 10)),
                timeout=int(options.get('timeout', 15)),
                max_pages=int(options.get('max_pages', 200)),
                depth=int(options.get('depth', 3)),
                cookies=cookies or None,
                extra_headers=extra_headers or None,
                use_selenium=options.get('use_selenium', True),
                log_fn=log_fn,
            )
            # Apply module toggles
            scout.skip_auth     = not modules.get('auth', True)
            scout.skip_advanced = not modules.get('advanced', True)
            # Apply Burp proxy if requested
            if burp_cfg.get('enabled') and scout.session:
                try:
                    from burp_integration import BurpConfig
                    bc = BurpConfig(
                        proxy_host=burp_cfg.get('host', '127.0.0.1'),
                        proxy_port=int(burp_cfg.get('port', 8080)),
                    )
                    scout.session = bc.patch_existing_session(scout.session)
                    state['log'].append({'time': time.strftime('%H:%M:%S'),
                                         'msg': f'[Burp] Routing through {bc.proxy_url}'})
                except Exception as be:
                    state['log'].append({'time': time.strftime('%H:%M:%S'),
                                         'msg': f'[!] Burp setup failed: {be}'})
            results = scout.run()
            results['external_urls'] = list(results.get('external_urls', []))
            state['results']    = results
            state['status']     = 'complete'
            state['progress']   = 100
            state['phase']      = 'Complete'
            # Report URL that the browser can open directly
            state['report_url'] = f'/report/{scan_id}'
        except Exception as e:
            import traceback
            state['status'] = 'error'
            state['phase']  = f'Error: {e}'
            state['log'].append({'time': time.strftime('%H:%M:%S'), 'msg': f'[ERROR] {e}'})
            state['log'].append({'time': time.strftime('%H:%M:%S'), 'msg': traceback.format_exc()})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'scan_id': scan_id})


@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id):
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    s = SCANS[scan_id]
    return jsonify({
        'id':         s['id'],
        'status':     s['status'],
        'progress':   s['progress'],
        'phase':      s['phase'],
        'log':        s['log'][-60:],
        'report_url': s.get('report_url'),
    })


@app.route('/api/scan/<scan_id>/results')
def scan_results(scan_id):
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    s = SCANS[scan_id]
    if s['status'] != 'complete':
        return jsonify({'error': 'Scan not complete'}), 400
    return jsonify(s['results'])


# Serve the HTML report directly in the browser
@app.route('/report/<scan_id>')
def view_report(scan_id):
    if scan_id not in SCANS:
        return 'Scan not found', 404
    s = SCANS[scan_id]
    html_path = Path(s['output_dir']) / 'report.html'
    if html_path.exists():
        resp = make_response(html_path.read_text(encoding='utf-8'))
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        return resp
    return 'Report not ready yet', 404


# Download raw text report
@app.route('/api/scan/<scan_id>/report')
def download_report(scan_id):
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    s = SCANS[scan_id]
    rp = Path(s['output_dir']) / 'report.txt'
    if rp.exists():
        return send_file(str(rp), as_attachment=True, download_name='jsscout_report.txt')
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/payloads')
def get_payloads():
    return jsonify(XSS_PAYLOADS)


# ── Secret Analyzer endpoint ──────────────────────────────────────────────────
@app.route('/api/scan/<scan_id>/secrets')
def analyze_secrets(scan_id):
    """
    Run the JS Secret Analyzer on an already-completed scan's JS files.
    Returns full secret + API path findings as JSON.
    """
    if scan_id not in SCANS:
        return jsonify({'error': 'Scan not found'}), 404
    s = SCANS[scan_id]
    if s['status'] != 'complete':
        return jsonify({'error': 'Scan not complete yet'}), 400

    output_dir = Path(s['output_dir'])
    js_dir = output_dir / 'js'
    if not js_dir.exists():
        return jsonify({'error': 'No JS directory found'}), 404

    secrets_out = output_dir / 'secrets'
    analyzer = JSSecretAnalyzer(str(js_dir))
    analyzer.output_dir = secrets_out
    analyzer.run()

    return jsonify({
        'scan_id': scan_id,
        'findings': analyzer.findings,
        'api_paths': sorted(analyzer.api_paths),
        'summary': {
            'total_secrets': len(analyzer.findings),
            'critical': analyzer.stats.get('CRITICAL', 0),
            'high': analyzer.stats.get('HIGH', 0),
            'medium': analyzer.stats.get('MEDIUM', 0),
            'low': analyzer.stats.get('LOW', 0),
            'total_api_paths': len(analyzer.api_paths),
        }
    })


@app.route('/report/<scan_id>/secrets')
def view_secrets_report(scan_id):
    """Serve the standalone HTML secrets report."""
    if scan_id not in SCANS:
        return 'Scan not found', 404
    s = SCANS[scan_id]
    html_path = Path(s['output_dir']) / 'secrets' / 'secrets_report.html'
    if html_path.exists():
        resp = make_response(html_path.read_text(encoding='utf-8'))
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        return resp
    return 'Secrets report not generated yet — call /api/scan/<id>/secrets first', 404


@app.route('/api/scans')
def list_scans():
    return jsonify([
        {'id': s['id'], 'target': s['target'],
         'status': s['status'], 'progress': s['progress'],
         'report_url': s.get('report_url')}
        for s in SCANS.values()
    ])


@app.route('/api/scan/stop/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    SCANS[scan_id]['_stop'] = True
    return jsonify({'ok': True})


@app.route('/api/scan/<scan_id>/findings')
def get_findings(scan_id):
    """Stream findings as they arrive (findings.jsonl)"""
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    s = SCANS[scan_id]
    findings_path = Path(s['output_dir']) / 'findings.jsonl'
    if not findings_path.exists():
        return jsonify([])
    findings = []
    for line in findings_path.read_text(encoding='utf-8').strip().splitlines():
        try:
            findings.append(json.loads(line))
        except Exception:
            pass
    return jsonify(findings)


@app.route('/api/scan/<scan_id>/download')
def download_zip(scan_id):
    """Download full scan output as ZIP."""
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    s = SCANS[scan_id]
    import zipfile, io
    output_dir = Path(s['output_dir'])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in output_dir.rglob('*'):
            if f.is_file():
                zf.write(f, f.relative_to(output_dir.parent))
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                     download_name=f'jsscout_{scan_id}.zip',
                     mimetype='application/zip')


@app.route('/api/burp/check')
def burp_check():
    """Check if Burp proxy is reachable."""
    import socket
    host = request.args.get('host', '127.0.0.1')
    port = int(request.args.get('port', 8080))
    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.close()
        return jsonify({'reachable': True, 'host': host, 'port': port})
    except Exception:
        return jsonify({'reachable': False, 'host': host, 'port': port})


@app.route('/api/scan/<scan_id>/burp_export')
def burp_export(scan_id):
    """Return Burp-importable XML of all findings."""
    if scan_id not in SCANS:
        return jsonify({'error': 'Not found'}), 404
    s = SCANS[scan_id]
    burp_path = Path(s['output_dir']) / 'burp_export' / 'burp_import.xml'
    if burp_path.exists():
        resp = make_response(burp_path.read_text(encoding='utf-8'))
        resp.headers['Content-Type'] = 'application/xml'
        resp.headers['Content-Disposition'] = f'attachment; filename="jsscout_{scan_id}_burp.xml"'
        return resp
    return jsonify({'error': 'Not yet exported'}), 404


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7331))
    print(f'\n  JS Scout Pro v9')
    print(f'  Open: http://localhost:{port}\n')
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
