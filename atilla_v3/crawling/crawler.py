import asyncio, re
from typing import List, Set
from urllib.parse import urljoin, urlparse
import httpx
from colorama import Fore

_LINK_RE = [
    r'href=["\']([^"\'#][^"\']*)["\']',
    r'action=["\']([^"\']+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
]
_SKIP_EXT = {".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".woff2",
             ".ttf",".css",".pdf",".zip",".mp4",".mp3"}

def _skip(url: str) -> bool:
    return any(urlparse(url).path.lower().endswith(e) for e in _SKIP_EXT)

def _links(base: str, body: str, domain: str) -> List[str]:
    out = []
    for pat in _LINK_RE:
        for m in re.finditer(pat, body, re.I):
            abs_url = urljoin(base, m.group(1)).split("#")[0].split("?")[0]
            if urlparse(abs_url).netloc == domain and not _skip(abs_url):
                out.append(abs_url)
    return out

async def crawl_urls(client, start_url, base_domain,
                     max_depth=3, max_urls=60, use_playwright=False) -> List[str]:
    if use_playwright:
        return await _pw_crawl(start_url, base_domain, max_depth, max_urls)

    visited: Set[str] = set()
    queue = [(start_url, 0)]
    param_urls: List[str] = []

    while queue and len(visited) < max_urls:
        url, depth = queue.pop(0)
        norm = url.split("#")[0]
        if norm in visited or depth > max_depth:
            continue
        visited.add(norm)
        try:
            resp = await client.get(norm, follow_redirects=True)
            body = resp.text
            if urlparse(norm).query:
                param_urls.append(norm)
            for pat in _LINK_RE:
                for m in re.finditer(pat, body, re.I):
                    abs_url = urljoin(norm, m.group(1)).split("#")[0]
                    if urlparse(abs_url).query and base_domain in abs_url:
                        param_urls.append(abs_url)
            for link in _links(norm, body, base_domain):
                abs_link = urljoin(norm, link).split("#")[0]
                if abs_link not in visited:
                    queue.append((abs_link, depth + 1))
            await asyncio.sleep(0.15)
        except Exception:
            continue
    return list(dict.fromkeys(param_urls))

async def _pw_crawl(start_url, base_domain, max_depth, max_urls) -> List[str]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print(f"{Fore.YELLOW}[!] Install playwright: pip install playwright && playwright install chromium")
        return []
    param_urls: List[str] = []
    visited: Set[str] = set()
    queue = [(start_url, 0)]
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--no-sandbox"])
        ctx     = await browser.new_context()
        while queue and len(visited) < max_urls:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth: continue
            visited.add(url)
            try:
                page = await ctx.new_page()
                ajax: List[str] = []
                page.on("request", lambda r: ajax.append(r.url) if r.resource_type in ("xhr","fetch") else None)
                await page.goto(url, wait_until="networkidle", timeout=15000)
                await asyncio.sleep(0.3)
                content = await page.content()
                if urlparse(url).query: param_urls.append(url)
                for ep in ajax:
                    if base_domain in ep and urlparse(ep).query: param_urls.append(ep)
                hrefs = await page.eval_on_selector_all("a[href],form[action]",
                    "els => els.map(e => e.href||e.action||'')")
                for href in hrefs:
                    abs_url = urljoin(url, href).split("#")[0]
                    if base_domain in abs_url and abs_url not in visited:
                        queue.append((abs_url, depth+1))
                for link in _links(url, content, base_domain):
                    if link not in visited: queue.append((link, depth+1))
                await page.close()
            except Exception: continue
        await browser.close()
    return list(dict.fromkeys(param_urls))
