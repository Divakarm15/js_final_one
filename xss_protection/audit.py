#!/usr/bin/env python3
"""
audit.py
========
Scans your Flask/Django project for common XSS vulnerabilities.
Run from your project root:

    python3 audit.py .
    python3 audit.py /path/to/your/project

v2: Improved false-positive filtering — only reports genuine risks.
"""

import sys
import os
import re
from pathlib import Path
from collections import defaultdict


# ── Patterns that indicate potential XSS ─────────────────────────────────────

VULN_PATTERNS = [
    ("CRITICAL", "Unsafe render_template_string with user input",
     re.compile(r'render_template_string\s*\(.*request\.(args|form|GET|POST|json)', re.I)),

    ("CRITICAL", "f-string / format() putting request data directly into HTML",
     re.compile(r'(?:f["\']|\.format\s*\().*request\.(args|form|GET|POST)', re.I)),

    ("CRITICAL", "HttpResponse / make_response with raw user input",
     re.compile(r'(?:HttpResponse|make_response)\s*\(.*request\.(args|form|GET|POST)', re.I)),

    ("CRITICAL", "String concatenation building HTML with user input",
     re.compile(r'(?:<[a-z]+>|<script).*\+.*request\.(args|form|GET|POST)', re.I)),

    ("HIGH", "Direct return of user input as HTML",
     re.compile(r'return\s+.*request\.(args|form|GET|POST)\.get\s*\(', re.I)),

    ("HIGH", "Jinja2 |safe filter used on a variable",
     re.compile(r'\{\{[^}]*\|\s*safe[^}]*\}\}')),

    ("HIGH", "Django {% autoescape off %}",
     re.compile(r'\{%\s*autoescape\s+off\s*%\}')),

    ("HIGH", "Django mark_safe() — only safe after sanitize()",
     re.compile(r'\bmark_safe\s*\(')),

    ("MEDIUM", "redirect() with user-supplied URL — check for open redirect",
     re.compile(r'redirect\s*\(\s*request\.(args|GET)\.get', re.I)),

    ("MEDIUM", "No sanitize() call found before DB save — check for stored XSS",
     re.compile(r'(?:\.save\(\)|\.create\(|objects\.create)(?!.*sanitize)', re.I)),

    # JS sinks — INFO only, confirmed real issues need source tracing
    ("INFO", "innerHTML assignment — verify value is not user-controlled",
     re.compile(r'\.innerHTML\s*=')),

    ("INFO", "document.write — verify value is not user-controlled",
     re.compile(r'document\.write\s*\(')),

    ("INFO", "eval() — verify argument is not user-controlled",
     re.compile(r'(?<!\.)(?<!typeof\s)\beval\s*\(')),
]

# ── Patterns that indicate the code IS protected ─────────────────────────────

SAFE_INDICATORS = [
    re.compile(r'\bsanitize\s*\('),
    re.compile(r'\bescape_output\s*\('),
    re.compile(r'\bhtmlspecialchars\s*\('),
    re.compile(r'\bhtml\.escape\s*\('),
    re.compile(r'\bDOMPurify\.sanitize\s*\('),
    re.compile(r'\bbleach\.clean\s*\('),
    re.compile(r'\bmarkupsafe\.escape\s*\('),
    re.compile(r'\bescapeHtml\s*\('),
    re.compile(r'\bhe\.encode\s*\('),
    re.compile(r'\.innerText\s*='),
    re.compile(r'createTextNode\s*\('),
]

# ── False positive suppression rules ─────────────────────────────────────────
# Each entry: (trigger pattern, list of FP sub-patterns)
# If the line matches a trigger AND any FP sub-pattern, it's suppressed.

FP_RULES = [
    (re.compile(r'\beval\s*\(', re.I), [
        re.compile(r'typeof\s+eval'),
        re.compile(r'eval\s*=\s*'),
        re.compile(r'eval\.(?:call|apply|bind)'),
        re.compile(r'eval\s*\(\s*["\'][^"\']*["\']\s*\)'),   # string literal arg
        re.compile(r'//.*eval\s*\('),                         # in comment
    ]),
    (re.compile(r'\.innerHTML\s*=', re.I), [
        re.compile(r'innerHTML\s*=\s*["\'][^"\'<>]*["\']'),     # plain string literal
        re.compile(r'innerHTML\s*=\s*`[^`$]*`'),                # template, no expressions
        re.compile(r'innerHTML\s*=\s*(?:""|\'\'|``)'),          # empty string
        re.compile(r'innerHTML\s*=\s*(?:DOMPurify|sanitize)\s*\('),
    ]),
    (re.compile(r'document\.write\s*\(', re.I), [
        re.compile(r'document\.write\s*\(\s*["\'][^"\']*["\']'),
        re.compile(r'//.*document\.write'),
    ]),
]

# Lines that are pure test/spec/doc code
TEST_OR_DOC_LINE = re.compile(
    r'(?:describe\s*\(|it\s*\(|test\s*\(|expect\s*\(|assert|mock\.|stub\.|@example|@param\s)',
    re.I
)

SKIP_DIRS = {'.git', '__pycache__', 'node_modules', 'venv', 'env', '.venv', 'migrations', 'static'}
SCAN_EXTS = {'.py', '.html', '.js', '.jinja', '.jinja2', '.htm'}


def _is_fp(line: str) -> bool:
    """Return True if the line is very likely a false positive."""
    stripped = line.strip()
    # Pure comment lines
    if stripped.startswith(('#', '//', '*', '/*')):
        return True
    # Test/spec code
    if TEST_OR_DOC_LINE.search(line):
        return True
    # Apply per-pattern FP rules
    for trigger, fp_pats in FP_RULES:
        if trigger.search(line):
            if any(fp.search(line) for fp in fp_pats):
                return True
    return False


def scan_file(filepath: Path) -> list:
    findings = []
    try:
        content = filepath.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return findings

    lines = content.split('\n')

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        for severity, description, pattern in VULN_PATTERNS:
            if not pattern.search(line):
                continue

            # ── False positive filter ─────────────────────────────────────
            if _is_fp(line):
                break

            context_start = max(0, i - 5)
            context_end   = min(len(lines), i + 3)
            context       = '\n'.join(lines[context_start:context_end])
            is_protected  = any(p.search(context) for p in SAFE_INDICATORS)

            findings.append({
                'file':        str(filepath),
                'line':        i,
                'severity':    severity,
                'description': description,
                'code':        stripped[:120],
                'protected':   is_protected,
            })
            break  # one finding per line

    return findings


def scan_directory(root: str) -> dict:
    root_path = Path(root)
    all_findings = defaultdict(list)
    files_scanned = 0

    for filepath in root_path.rglob('*'):
        if any(skip in filepath.parts for skip in SKIP_DIRS):
            continue
        if filepath.suffix.lower() not in SCAN_EXTS:
            continue
        if not filepath.is_file():
            continue

        findings = scan_file(filepath)
        if findings:
            all_findings[str(filepath)].extend(findings)
        files_scanned += 1

    return dict(all_findings), files_scanned


def print_report(findings: dict, files_scanned: int):
    SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
    SEV_COLOR = {
        'CRITICAL': '\033[91m',
        'HIGH':     '\033[93m',
        'MEDIUM':   '\033[96m',
        'INFO':     '\033[90m',
    }
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    GREEN  = '\033[92m'

    total     = sum(len(v) for v in findings.values())
    protected = sum(1 for flist in findings.values() for f in flist if f['protected'])
    actual    = total - protected

    print(f"\n{BOLD}JS Scout — XSS Audit Report{RESET}")
    print(f"{'─' * 60}")
    print(f"  Files scanned : {files_scanned}")
    print(f"  Issues found  : {total} ({actual} unprotected, {protected} likely OK)")
    print(f"{'─' * 60}\n")

    if not findings:
        print(f"{GREEN}  ✓ No XSS patterns detected.{RESET}\n")
        return

    all_flat = []
    for flist in findings.values():
        all_flat.extend(flist)
    all_flat.sort(key=lambda x: (SEV_ORDER.get(x['severity'], 99), x['file'], x['line']))

    for finding in all_flat:
        sev   = finding['severity']
        color = SEV_COLOR.get(sev, '')
        prot  = finding['protected']

        prefix = f"  {GREEN}[LIKELY OK]{RESET} " if prot else f"  {color}[{sev}]{RESET} "
        print(f"{prefix}{finding['description']}")
        print(f"    {finding['file']}:{finding['line']}")
        print(f"    {BOLD}Code:{RESET} {finding['code']}")
        if prot:
            print(f"    {GREEN}↳ Sanitize/escape detected nearby — verify manually{RESET}")
        print()


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    if not os.path.exists(target):
        print(f"[!] Path not found: {target}")
        sys.exit(1)

    print(f"[*] Scanning: {os.path.abspath(target)}")
    findings, count = scan_directory(target)
    print_report(findings, count)

    has_critical = any(
        f['severity'] in ('CRITICAL', 'HIGH') and not f['protected']
        for flist in findings.values()
        for f in flist
    )
    sys.exit(1 if has_critical else 0)


if __name__ == '__main__':
    main()
