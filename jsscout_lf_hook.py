"""
jsscout_lf_hook.py — Patch file that adds LinkFinder+SecretFinder to jsscout.py v5
Just place this file alongside jsscout.py. The hook is auto-called at the end of
jsscout.py's run() if you add the following two lines before the return statement:

    from jsscout_lf_hook import run_lf_sf
    self.results['lf_sf'] = run_lf_sf(str(self.output_dir), self.log)

Or use jsscout.py v6 (jsscout_v6.py) which already has the hook built in.
"""
import os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def run_lf_sf(output_dir: str, log_fn=None) -> dict:
    """Run LinkFinder + SecretFinder on the js/ subdirectory of output_dir."""
    log = log_fn or print
    try:
        from linkfinder_secretfinder import LinkFinderSecretFinder
        lf_out = os.path.join(output_dir, 'lf_sf_report')
        engine = LinkFinderSecretFinder(output_dir, output_dir=lf_out)
        results = engine.run()
        log(f"[+] LF+SF: {len(results.get('endpoints', {}))} endpoints | {len(results.get('secrets', []))} secrets")
        log(f"    → Report: {lf_out}/report.html")
        return results
    except ImportError:
        log("[!] linkfinder_secretfinder.py not found — skipping LF+SF")
        return {}
    except Exception as e:
        log(f"[!] LF+SF error: {e}")
        return {}
