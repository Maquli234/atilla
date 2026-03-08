import html, re, urllib.parse
from typing import Dict, List, Tuple

_EXEC = [
    (r'<script[^>]*>',       "Inside <script> block",   95),
    (r'on\w+\s*=\s*["\']?',  "Inside event handler",    92),
    (r'javascript:',          "Inside javascript: URI",  90),
    (r'src\s*=\s*["\']?',    "Inside src attribute",    85),
    (r'href\s*=\s*["\']?',   "Inside href attribute",   83),
    (r'<svg',                 "Inside SVG tag",          80),
]


def analyze_response(
    payload: str,
    response_text: str,
    response_headers: Dict[str, str],
) -> Tuple[str, int, List[str], str]:
    if not response_text:
        return "NO_RESPONSE", 0, [], ""

    confidence = 0
    details: List[str] = []
    evidence = ""

    # 1. Verbatim reflection
    if payload in response_text:
        idx      = response_text.index(payload)
        evidence = response_text[max(0, idx - 40): idx + len(payload) + 40]
        confidence = 75
        details.append("Payload reflected verbatim")
        snippet = response_text[max(0, idx - 200): idx + len(payload) + 50]
        for pattern, label, score in _EXEC:
            if re.search(pattern, snippet, re.I | re.DOTALL):
                details.append(f"Executable context: {label}")
                confidence = max(confidence, score)
                break
        return ("VULNERABLE" if confidence >= 90 else "REFLECTED"), confidence, details, evidence

    # 2. Encoded variants
    checks = {
        "HTML entity":    payload.replace("<", "&lt;").replace(">", "&gt;"),
        "HTML escaped":   html.escape(payload),
        "URL encoded":    urllib.parse.quote(payload, safe=""),
        "Double URL":     urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),
        "Quote encoded":  payload.replace("'", "&#39;").replace('"', "&quot;"),
        "Unicode angles": payload.replace("<", "\u003c").replace(">", "\u003e"),
    }
    for name, variant in checks.items():
        if variant and variant in response_text:
            idx      = response_text.index(variant)
            evidence = response_text[max(0, idx - 30): idx + len(variant) + 30]
            details.append(f"Encoded as: {name}")
            return "ENCODED", 45, details, evidence

    # 3. Partial fragments
    parts     = [p for p in re.split(r'[<>\'"()\s;=]', payload) if len(p) >= 5]
    reflected = [p for p in parts if p in response_text]
    if reflected:
        ratio      = len(reflected) / max(len(parts), 1)
        confidence = max(20, int(ratio * 55))
        details.append(f"Partial reflection: {len(reflected)}/{len(parts)} fragments")
        for f in reflected[:3]:
            details.append(f"  fragment: '{f[:40]}'")
        return "PARTIAL", confidence, details, evidence

    # 4. WAF/filter keywords
    fw = [w for w in ["blocked", "access denied", "invalid input", "forbidden", "sanitized"]
          if w in response_text.lower()]
    if fw:
        details.append(f"Filter keywords: {', '.join(fw)}")
        return "FILTERED", 20, details, evidence

    # 5. CSP
    csp = response_headers.get("content-security-policy", "")
    if csp:
        details.append(f"CSP header present")
        return "CSP_PROTECTED", 10, details, evidence

    return "STRIPPED", 0, ["Payload not found in response"], evidence
