#!/usr/bin/env python3
"""ATILLA v3.0 — Professional XSS Testing Framework"""

import argparse, asyncio, sys
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init
    from pyfiglet import Figlet
except ImportError:
    print("pip install httpx colorama pyfiglet"); sys.exit(1)

init(autoreset=True)

# Add project root to path so imports work when run from any directory
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine      import ScanEngine
from core.config      import ScanConfig
from reporting.report import ReportManager


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
  python3 main.py -u "http://localhost/search?q=x" --blind-xss --oob-host your.burp.server
  python3 main.py -u "http://localhost/" --auth-cookie "session=abc123" --set owasp

Payload Sets:  basic | owasp (default) | advanced | dom | all
        """
    )
    p.add_argument("-u","--url",         required=True)
    p.add_argument("--auth-cookie",      help="Cookie header value for auth")
    p.add_argument("--set",              choices=["basic","owasp","advanced","dom","blind","all"],
                                         default="owasp")
    p.add_argument("--timeout",          type=int, default=15)
    p.add_argument("--concurrency",      type=int, default=5)
    p.add_argument("--delay",            type=float, default=0.2)
    p.add_argument("--retries",          type=int, default=3)
    p.add_argument("--crawl",            action="store_true")
    p.add_argument("--crawl-depth",      type=int, default=3)
    p.add_argument("--playwright",       action="store_true")
    p.add_argument("--no-smart-context", action="store_true")
    p.add_argument("--no-mutations",     action="store_true")
    p.add_argument("--blind-xss",        action="store_true")
    p.add_argument("--oob-host")
    p.add_argument("-o","--output",      help="JSON report file")
    p.add_argument("--html-report",      help="HTML report file")
    p.add_argument("--cvss",             action="store_true")
    p.add_argument("-v","--verbose",     action="store_true")
    return p


async def run(args):
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


def main():
    header()
    parser = build_parser()
    args   = parser.parse_args()
    if not args.url.startswith(("http://","https://")):
        print(f"{Fore.RED}[!] URL must start with http:// or https://"); sys.exit(1)
    if not confirm(urlparse(args.url).netloc):
        print(f"{Fore.GREEN}Cancelled."); sys.exit(0)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted.")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()


if __name__ == "__main__":
    main()
