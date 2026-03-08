#!/usr/bin/env python3
"""ATILLA v3.0 — Professional XSS Testing Framework"""

import argparse, asyncio, sys, os
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from colorama import Fore, Style, init
    from pyfiglet import Figlet
except ImportError:
    print("pip install httpx colorama pyfiglet"); sys.exit(1)

init(autoreset=True)


def header():
    try:
        print(Fore.CYAN + Figlet(font='slant').renderText("ATILLA"))
    except Exception:
        print(Fore.CYAN + "=" * 60 + "\n   ATILLA v3.0\n" + "=" * 60)
    print(Fore.YELLOW + "  v3.0 — Authorized testing only\n")
    print(Fore.RED + "  WARNING: Unauthorized testing is illegal!" + Style.RESET_ALL + "\n")


def confirm(netloc: str) -> bool:
    safe = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
    if any(s in netloc for s in safe): return True
    print(f"{Fore.RED}[!] Target: {netloc}")
    print(f"{Fore.RED}    Proceed only with written authorisation.")
    return input(f"{Fore.YELLOW}    Type YES to continue: ").strip() == "YES"


def build_parser():
    p = argparse.ArgumentParser(
        description="ATILLA v3.0 — Advanced XSS Detection Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -u "http://localhost/search?q=test"
  python3 main.py -u "http://localhost/page?id=1" --set all -v -o results.json
  python3 main.py -u "http://localhost/" --crawl --set owasp --html-report report.html
  python3 main.py -u "http://localhost/search?q=x" --blind-xss --oob-host your.server.com
  python3 main.py -u "http://localhost/" --auth-cookie "session=abc123" --set owasp
  python3 main.py --gui                           # Launch GUI
  python3 main.py --api --api-port 8080           # Start REST API

Payload Sets:  basic | owasp (default) | advanced | dom | blind | all
        """
    )
    # Mode flags
    p.add_argument("--gui",  action="store_true",  help="Launch the GUI")
    p.add_argument("--api",  action="store_true",  help="Start the REST API server")
    p.add_argument("--api-port", type=int, default=8080, help="API port (default: 8080)")

    # Target
    p.add_argument("-u","--url",         default=None, help="Target URL")
    p.add_argument("--auth-cookie",      help="Cookie header value for authenticated testing")

    # Scan options
    p.add_argument("--set",              choices=["basic","owasp","advanced","dom","blind","all"],
                                         default="owasp", help="Payload set (default: owasp)")
    p.add_argument("--timeout",          type=int,   default=15,  help="Request timeout (s)")
    p.add_argument("--concurrency",      type=int,   default=5,   help="Parallel connections")
    p.add_argument("--delay",            type=float, default=0.2, help="Min delay between requests (s)")
    p.add_argument("--retries",          type=int,   default=3,   help="Retries per request")

    # Discovery
    p.add_argument("--crawl",            action="store_true", help="Crawl domain for URLs")
    p.add_argument("--crawl-depth",      type=int, default=3,  help="Max crawl depth")
    p.add_argument("--playwright",       action="store_true",  help="Use headless browser")

    # Detection
    p.add_argument("--no-smart-context", action="store_true",  help="Disable context detection")
    p.add_argument("--no-mutations",     action="store_true",  help="Disable WAF mutations")
    p.add_argument("--blind-xss",        action="store_true",  help="Inject blind XSS payloads")
    p.add_argument("--oob-host",                               help="OOB callback hostname")

    # Reporting
    p.add_argument("-o","--output",      help="JSON report file path")
    p.add_argument("--html-report",      help="HTML report file path")
    p.add_argument("--cvss",             action="store_true",  help="Include CVSS v3.1 scores")
    p.add_argument("-v","--verbose",     action="store_true",  help="Verbose per-payload output")

    # Tests
    p.add_argument("--test",             action="store_true",  help="Run built-in unit tests")
    return p


async def run_scan(args):
    from core.config      import ScanConfig
    from core.engine      import ScanEngine
    from reporting.report import ReportManager

    cfg = ScanConfig(
        url            = args.url,
        auth_cookie    = args.auth_cookie,
        payload_set    = args.set,
        timeout        = args.timeout,
        concurrency    = args.concurrency,
        delay          = args.delay,
        retries        = args.retries,
        crawl          = args.crawl,
        crawl_depth    = args.crawl_depth,
        use_playwright = args.playwright,
        smart_context  = not args.no_smart_context,
        use_mutations  = not args.no_mutations,
        blind_xss      = args.blind_xss,
        oob_host       = args.oob_host,
        verbose        = args.verbose,
        output_json    = args.output,
        output_html    = args.html_report,
        include_cvss   = args.cvss,
    )
    vulns    = await ScanEngine(cfg).run()
    reporter = ReportManager(cfg, vulns)
    reporter.print_summary()
    if cfg.output_json: reporter.save_json(cfg.output_json)
    if cfg.output_html: reporter.save_html(cfg.output_html)


def run_tests():
    """Run all unit tests."""
    import subprocess
    test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests")
    tests    = ["test_analyzer", "test_context", "test_mutator", "test_payloads"]
    total_passed = total_failed = 0
    for t in tests:
        path   = os.path.join(test_dir, f"{t}.py")
        result = subprocess.run([sys.executable, path], capture_output=True, text=True)
        print(f"\n{'='*50}")
        print(f" {t}")
        print('='*50)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        lines = result.stdout.strip().split("\n")
        if lines:
            summary = lines[-1]
            parts = summary.split(",")
            for part in parts:
                part = part.strip()
                if "passed" in part:
                    try: total_passed += int(part.split()[0])
                    except: pass
                if "failed" in part:
                    try: total_failed += int(part.split()[0])
                    except: pass
    print(f"\n{'='*50}")
    print(f" TOTAL: {total_passed} passed, {total_failed} failed")
    print('='*50)


def main():
    header()
    parser = build_parser()
    args   = parser.parse_args()

    # ── GUI mode ───────────────────────────────────────────────────────────
    if args.gui:
        try:
            from gui.app import launch_gui
            launch_gui()
        except ImportError as e:
            print(f"{Fore.RED}[!] GUI requires tkinter: {e}")
        return

    # ── API mode ───────────────────────────────────────────────────────────
    if args.api:
        from api.server import start_server
        start_server(args.api_port)
        return

    # ── Test mode ──────────────────────────────────────────────────────────
    if args.test:
        run_tests()
        return

    # ── Scan mode ──────────────────────────────────────────────────────────
    if not args.url:
        parser.print_help()
        return

    if not args.url.startswith(("http://", "https://")):
        print(f"{Fore.RED}[!] URL must start with http:// or https://"); sys.exit(1)

    if not confirm(urlparse(args.url).netloc):
        print(f"{Fore.GREEN}Cancelled."); sys.exit(0)

    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted.")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()


if __name__ == "__main__":
    main()
