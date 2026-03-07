import asyncio, random
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from colorama import Fore
from core.config         import ScanConfig
from core.models         import Vulnerability, Severity
from payloads.library    import PAYLOAD_SETS, get_context_payloads
from payloads.mutator    import mutate_payload
from detection.context   import detect_injection_context, probe_param
from detection.analyzer  import analyze_response
from detection.dom       import find_dom_sinks
from detection.waf       import fingerprint_waf
from detection.csp       import analyze_csp
from detection.blind     import build_blind_payloads
from crawling.crawler    import crawl_urls
from utils.cvss          import compute_cvss


class ScanEngine:
    def __init__(self, cfg: ScanConfig):
        self.cfg   = cfg
        self.vulns: List[Vulnerability] = []

    async def run(self) -> List[Vulnerability]:
        self.cfg.base_domain = urlparse(self.cfg.url).netloc
        limits = httpx.Limits(max_keepalive_connections=self.cfg.concurrency,
                              max_connections=self.cfg.concurrency*2)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.cfg.timeout, connect=5.0),
            headers=self.cfg.base_headers(), verify=False,
            limits=limits, follow_redirects=True,
        ) as client:
            await self._baseline(client)
            urls = await self._discover(client)
            await self._scan_all(client, urls)
        return self.vulns

    async def _baseline(self, client):
        print(f"{Fore.CYAN}[*] Baseline …")
        try:
            resp = await client.get(self.cfg.url)
            waf  = fingerprint_waf(resp)
            if waf:
                self.cfg.detected_waf = waf
                print(f"{Fore.MAGENTA}[!] WAF: {waf}  => mutations on")
            csp = analyze_csp(resp.headers.get("content-security-policy",""))
            if csp["present"]:
                status = "bypassable" if csp["bypassable"] else "strict"
                print(f"{Fore.YELLOW}[*] CSP ({status})")
                for i in csp["issues"]: print(f"{Fore.YELLOW}    . {i}")
            print()
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Baseline failed: {e}\n")

    async def _discover(self, client) -> List[str]:
        urls = [self.cfg.url]
        if self.cfg.crawl:
            print(f"{Fore.CYAN}[*] Crawling {self.cfg.base_domain} …")
            extra = await crawl_urls(client, self.cfg.url, self.cfg.base_domain,
                                     max_depth=self.cfg.crawl_depth, max_urls=60,
                                     use_playwright=self.cfg.use_playwright)
            urls += extra
            print(f"{Fore.CYAN}[*] Found {len(extra)} more URLs\n")
        return list(dict.fromkeys(urls))

    async def _scan_all(self, client, urls):
        sem = asyncio.Semaphore(self.cfg.concurrency)
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params: continue
            print(f"\n{Fore.CYAN}{'='*65}")
            print(f"{Fore.CYAN} {url[:80]}")
            print(f"{Fore.CYAN} Params: {', '.join(params.keys())}")
            print(f"{Fore.CYAN}{'='*65}")
            tasks = [self._scan_param(client, sem, url, parsed, params, p) for p in params]
            await asyncio.gather(*tasks)

    async def _scan_param(self, client, sem, url, parsed_url, params, param):
        async with sem:
            base = list(PAYLOAD_SETS.get(self.cfg.payload_set, PAYLOAD_SETS["owasp"]))
            if self.cfg.smart_context:
                ctx      = await probe_param(client, parsed_url, params, param, self.cfg.verbose)
                payloads = list(dict.fromkeys(base + get_context_payloads(ctx)))
                print(f"{Fore.CYAN}  [{param}] ctx={ctx.value}  {len(payloads)} payloads")
            else:
                payloads = base
            if self.cfg.blind_xss and self.cfg.oob_host:
                payloads += build_blind_payloads(self.cfg.oob_host, param)
            if self.cfg.use_mutations and self.cfg.detected_waf:
                extras = []
                for p in payloads[:25]: extras.extend(mutate_payload(p))
                payloads = list(dict.fromkeys(payloads + extras))
            print(f"{Fore.CYAN}  [{param}] testing {len(payloads)} payloads …")
            for payload in payloads:
                v = await self._test(client, parsed_url, params, param, payload)
                if v: self.vulns.append(v)

    async def _test(self, client, parsed_url, params, param, payload) -> Optional[Vulnerability]:
        tp  = params.copy()
        tp[param] = payload
        url = urlunparse(parsed_url._replace(query=urlencode(tp, doseq=True)))
        resp = None
        for attempt in range(self.cfg.retries):
            try:
                resp = await client.get(url, follow_redirects=True); break
            except (httpx.TimeoutException, httpx.RequestError):
                await asyncio.sleep(2**attempt)
            except Exception:
                break
        if resp is None: return None

        cat, conf, details, evidence = analyze_response(payload, resp.text, dict(resp.headers))
        sinks = find_dom_sinks(resp.text)
        if conf < 40:
            if self.cfg.verbose:
                print(f"{Fore.GREEN}    [-] {cat} ({conf}%)  {payload[:60]}")
            await asyncio.sleep(random.uniform(self.cfg.delay, self.cfg.delay*2))
            return None

        sev = (Severity.CRITICAL if conf>=90 else Severity.HIGH if conf>=70
               else Severity.MEDIUM if conf>=55 else Severity.LOW)
        ctx_enum = detect_injection_context(resp.text, payload[:20])
        cvss     = compute_cvss(sev, ctx_enum) if self.cfg.include_cvss else None
        v = Vulnerability(param=param, payload=payload, url=url,
                          confidence=conf, category=cat, context=ctx_enum.value,
                          severity=sev, details=details, dom_sinks=sinks,
                          response_length=len(resp.text), status_code=resp.status_code,
                          evidence=evidence, cvss=cvss)
        col = v.color()
        print(f"{col}  [!] {sev.value} ({conf}%) — {param} <- {payload[:70]}")
        if self.cfg.verbose:
            for d in details: print(f"{col}      . {d}")
            if sinks: print(f"{Fore.MAGENTA}      DOM: {', '.join(sinks[:3])}")
        await asyncio.sleep(random.uniform(self.cfg.delay, self.cfg.delay*3))
        return v
