import hashlib
import re
from urllib.parse import urlunparse, urlencode
from core.models import InjectionContext


def detect_injection_context(html_body: str, marker: str) -> InjectionContext:
    if not marker or marker not in html_body:
        return InjectionContext.UNKNOWN
    idx    = html_body.index(marker)
    before = html_body[max(0, idx - 500): idx]

    opens  = len(re.findall(r'<script[^>]*>', before, re.I))
    closes = len(re.findall(r'</script\s*>', before, re.I))
    if opens > closes:
        dq = _unmatched(before, '"')
        sq = _unmatched(before, "'")
        bt = _unmatched(before, "`")
        m  = max(dq, sq, bt)
        if m == bt and bt != -1: return InjectionContext.JS_TEMPLATE
        if m == dq and dq != -1: return InjectionContext.JS_STRING_DQ
        if m == sq and sq != -1: return InjectionContext.JS_STRING_SQ
        return InjectionContext.JS_INLINE

    so = len(re.findall(r'<style[^>]*>', before, re.I))
    sc = len(re.findall(r'</style\s*>', before, re.I))
    if so > sc:
        return InjectionContext.CSS_VALUE

    lo = before.rfind('<')
    lc = before.rfind('>')
    if lo > lc:
        chunk = before[lo:]
        if chunk.count('"') % 2 == 1: return InjectionContext.HTML_ATTRIBUTE_DQ
        if chunk.count("'") % 2 == 1: return InjectionContext.HTML_ATTRIBUTE_SQ
        return InjectionContext.HTML_ATTRIBUTE_DQ

    s = before.strip()
    if s and s[-1] in ('"', ":", ",") and "{" in before[-80:]:
        return InjectionContext.JSON_VALUE

    if re.search(r'(href|src|action)\s*=\s*["\']?[^"\'<>]*$', before, re.I):
        return InjectionContext.URL_PARAM

    return InjectionContext.HTML_TEXT


def _unmatched(text: str, char: str) -> int:
    return text.rfind(char) if text.count(char) % 2 == 1 else -1


async def probe_param(client, parsed_url, params, param, verbose=False):
    import httpx  # lazy import — not needed for static analysis
    marker = "ATILLA" + hashlib.md5(param.encode()).hexdigest()[:8].upper()
    tp = params.copy()
    tp[param] = marker
    url = urlunparse(parsed_url._replace(query=urlencode(tp, doseq=True)))
    try:
        r   = await client.get(url, follow_redirects=True)
        ctx = detect_injection_context(r.text, marker)
        if verbose:
            print(f"          [probe] {param} => {ctx.value}")
        return ctx
    except Exception as e:
        if verbose: print(f"          [probe-err] {e}")
        return InjectionContext.UNKNOWN
