from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List, Optional


class InjectionContext(Enum):
    HTML_TEXT         = "html_text"
    HTML_ATTRIBUTE_DQ = "html_attribute_dq"
    HTML_ATTRIBUTE_SQ = "html_attribute_sq"
    JS_STRING_DQ      = "js_string_dq"
    JS_STRING_SQ      = "js_string_sq"
    JS_TEMPLATE       = "js_template"
    JS_INLINE         = "js_inline"
    URL_PARAM         = "url_param"
    CSS_VALUE         = "css_value"
    JSON_VALUE        = "json_value"
    UNKNOWN           = "unknown"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class CvssScore:
    vector:     str   = ""
    base_score: float = 0.0
    rating:     str   = ""


@dataclass
class Vulnerability:
    param:           str
    payload:         str
    url:             str
    confidence:      int
    category:        str
    context:         str
    severity:        Severity
    details:         List[str]           = field(default_factory=list)
    dom_sinks:       List[str]           = field(default_factory=list)
    response_length: int                 = 0
    status_code:     int                 = 0
    evidence:        str                 = ""
    blind:           bool                = False
    cvss:            Optional[CvssScore] = None
    timestamp:       str                 = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        d["cvss"]     = asdict(self.cvss) if self.cvss else None
        return d

    def color(self):
        from colorama import Fore
        return {
            Severity.CRITICAL: Fore.RED,
            Severity.HIGH:     Fore.RED,
            Severity.MEDIUM:   Fore.YELLOW,
            Severity.LOW:      Fore.CYAN,
            Severity.INFO:     Fore.WHITE,
        }.get(self.severity, Fore.WHITE)
