import re
from typing import List, Tuple

_SINKS: List[Tuple[str, str]] = [
    (r'document\.write\s*\(',        "document.write()"),
    (r'document\.writeln\s*\(',      "document.writeln()"),
    (r'\.innerHTML\s*=',             ".innerHTML"),
    (r'\.outerHTML\s*=',             ".outerHTML"),
    (r'\.insertAdjacentHTML\s*\(',   ".insertAdjacentHTML()"),
    (r'\beval\s*\(',                 "eval()"),
    (r'setTimeout\s*\(\s*[\'"`]',    "setTimeout(string)"),
    (r'setInterval\s*\(\s*[\'"`]',   "setInterval(string)"),
    (r'\bnew\s+Function\s*\(',       "new Function()"),
    (r'location\.href\s*=',          "location.href"),
    (r'location\.replace\s*\(',      "location.replace()"),
    (r'window\.open\s*\(',           "window.open()"),
    (r'\.src\s*=',                   ".src"),
    (r'\.setAttribute\s*\(',         ".setAttribute()"),
    (r'postMessage\s*\(',            "postMessage()"),
    (r'history\.pushState\s*\(',     "history.pushState()"),
    (r'\.srcdoc\s*=',                ".srcdoc"),
    (r'__proto__\[',                 "prototype pollution"),
]

def find_dom_sinks(text: str) -> List[str]:
    return [label for pattern, label in _SINKS if re.search(pattern, text, re.I)]
