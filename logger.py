#!/usr/bin/env python3
"""
logger.py — JS Scout Pro Structured Logging System
====================================================
Provides:
  - Structured JSON logging for machine-readable output
  - Coloured terminal output with severity levels
  - Per-scan log files with rotation
  - Finding event stream (real-time)
  - Burp Collaborator interaction logging
"""

import os
import sys
import json
import time
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional


# ANSI colours
_C = {
    'reset':  '\033[0m',
    'red':    '\033[91m',
    'orange': '\033[93m',
    'yellow': '\033[93m',
    'green':  '\033[92m',
    'blue':   '\033[94m',
    'cyan':   '\033[96m',
    'dim':    '\033[2m',
    'bold':   '\033[1m',
}

SEV_COLOUR = {
    'CRITICAL': _C['red'],
    'HIGH':     _C['orange'],
    'MEDIUM':   _C['yellow'],
    'LOW':      _C['blue'],
    'INFO':     _C['dim'],
}

SEV_ICON = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🔵',
    'INFO':     '⚪',
}


class ScanLogger:
    """
    Central logging class for a single scan session.
    Writes to:
      - Terminal (coloured)
      - JSON log file (structured, one object per line = NDJSON)
      - findings.jsonl (findings only, for streaming)
    """

    def __init__(self,
                 scan_id: str,
                 target: str,
                 output_dir: Path,
                 log_fn: Optional[Callable] = None,
                 verbose: bool = False,
                 no_color: bool = False):
        self.scan_id    = scan_id
        self.target     = target
        self.output_dir = Path(output_dir)
        self.log_fn     = log_fn       # external callback (e.g. Flask state update)
        self.verbose    = verbose
        self.no_color   = no_color or not sys.stdout.isatty()
        self._lock      = threading.Lock()
        self._start     = time.time()
        self._findings  = []
        self._events    = []

        # Set up log files
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._json_log_path     = self.output_dir / 'scan.log.jsonl'
        self._findings_log_path = self.output_dir / 'findings.jsonl'

        self._json_fh     = open(self._json_log_path,     'a', encoding='utf-8')
        self._findings_fh = open(self._findings_log_path, 'a', encoding='utf-8')

        # Root Python logger
        self._pylog = logging.getLogger(f'jsscout.{scan_id}')
        self._pylog.setLevel(logging.DEBUG if verbose else logging.INFO)

        self._log_event('scan_start', {
            'scan_id': scan_id,
            'target':  target,
        })

    # ── Public interface ──────────────────────────────────────────────────────

    def log(self, msg: str, level: str = 'INFO'):
        """Log a plain text message (mirrors existing log_fn interface)."""
        ts = time.strftime('%H:%M:%S')
        self._write_json({'ts': ts, 'level': level, 'msg': msg})
        self._print_msg(ts, msg, level)
        if self.log_fn:
            self.log_fn(msg)

    def finding(self, finding: dict):
        """Log a vulnerability finding."""
        finding = dict(finding)
        finding.setdefault('scan_id',    self.scan_id)
        finding.setdefault('discovered', datetime.utcnow().isoformat() + 'Z')
        self._findings.append(finding)
        self._write_finding(finding)
        self._print_finding(finding)

    def phase(self, name: str, detail: str = ''):
        """Log a scan phase transition."""
        msg = f"[*] {name}" + (f": {detail}" if detail else '')
        self.log(msg, 'PHASE')

    def ok(self, msg: str):
        """Log a positive result."""
        self.log(f"[+] {msg}", 'OK')

    def warn(self, msg: str):
        """Log a warning."""
        self.log(f"[!] {msg}", 'WARN')

    def debug(self, msg: str):
        if self.verbose:
            self.log(f"[~] {msg}", 'DEBUG')

    def error(self, msg: str, exc: Exception = None):
        """Log an error."""
        detail = f' — {exc}' if exc else ''
        self.log(f"[ERROR] {msg}{detail}", 'ERROR')
        if exc and self.verbose:
            import traceback
            self.log(traceback.format_exc(), 'ERROR')

    def summary(self) -> dict:
        """Return scan summary stats."""
        elapsed = time.time() - self._start
        by_sev  = {}
        by_type = {}
        for f in self._findings:
            sev  = f.get('severity', 'INFO')
            ftyp = f.get('type', 'UNKNOWN')
            by_sev[sev]   = by_sev.get(sev, 0) + 1
            by_type[ftyp] = by_type.get(ftyp, 0) + 1

        s = {
            'scan_id':      self.scan_id,
            'target':       self.target,
            'elapsed_s':    round(elapsed, 1),
            'total_findings': len(self._findings),
            'by_severity':  by_sev,
            'by_type':      by_type,
            'critical':     by_sev.get('CRITICAL', 0),
            'high':         by_sev.get('HIGH', 0),
            'medium':       by_sev.get('MEDIUM', 0),
            'low':          by_sev.get('LOW', 0),
        }
        self._log_event('scan_summary', s)
        return s

    def close(self):
        try:
            self._json_fh.close()
            self._findings_fh.close()
        except Exception:
            pass

    def get_findings(self) -> list:
        return list(self._findings)

    def get_log_paths(self) -> dict:
        return {
            'scan_log':    str(self._json_log_path),
            'findings':    str(self._findings_log_path),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _print_msg(self, ts: str, msg: str, level: str):
        if self.no_color:
            print(f"[{ts}] {msg}", flush=True)
            return

        colour = {
            'PHASE': _C['cyan'],
            'OK':    _C['green'],
            'WARN':  _C['yellow'],
            'ERROR': _C['red'],
            'DEBUG': _C['dim'],
        }.get(level, _C['reset'])

        print(f"{_C['dim']}[{ts}]{_C['reset']} {colour}{msg}{_C['reset']}", flush=True)

    def _print_finding(self, finding: dict):
        sev  = finding.get('severity', 'INFO')
        ftyp = finding.get('type', '?')
        desc = finding.get('description', '')[:80]
        url  = finding.get('url', '')[:80]
        icon = SEV_ICON.get(sev, '⚪')
        col  = SEV_COLOUR.get(sev, '')

        ts = time.strftime('%H:%M:%S')
        if self.no_color:
            print(f"[{ts}] {icon} FINDING [{sev}] {ftyp} — {desc}", flush=True)
            if url:
                print(f"         URL: {url}", flush=True)
        else:
            print(f"{_C['dim']}[{ts}]{_C['reset']} {icon} {col}{_C['bold']}[{sev}] {ftyp}{_C['reset']}{col} — {desc}{_C['reset']}", flush=True)
            if url:
                print(f"         {_C['dim']}URL: {url}{_C['reset']}", flush=True)

        ev = finding.get('evidence', '')
        if ev:
            if self.no_color:
                print(f"         → {ev[:120]}", flush=True)
            else:
                print(f"         {_C['dim']}→ {ev[:120]}{_C['reset']}", flush=True)

        if self.log_fn:
            self.log_fn(f"  {icon} [{sev}] {ftyp} — {desc}")

    def _write_json(self, obj: dict):
        with self._lock:
            try:
                self._json_fh.write(json.dumps(obj, default=str) + '\n')
                self._json_fh.flush()
            except Exception:
                pass

    def _write_finding(self, finding: dict):
        with self._lock:
            try:
                self._findings_fh.write(json.dumps(finding, default=str) + '\n')
                self._findings_fh.flush()
            except Exception:
                pass

    def _log_event(self, event_type: str, data: dict):
        obj = {'event': event_type, 'ts': datetime.utcnow().isoformat() + 'Z', **data}
        self._write_json(obj)


def make_logger(scan_id: str, target: str, output_dir,
                log_fn=None, verbose=False, no_color=False) -> ScanLogger:
    """Factory function for ScanLogger."""
    return ScanLogger(
        scan_id=scan_id,
        target=target,
        output_dir=Path(output_dir),
        log_fn=log_fn,
        verbose=verbose,
        no_color=no_color,
    )
