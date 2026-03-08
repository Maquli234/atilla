from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class ScanConfig:
    url:             str             = ""
    auth_cookie:     Optional[str]   = None
    extra_headers:   Dict[str, str]  = field(default_factory=dict)
    payload_set:     str             = "owasp"
    timeout:         int             = 15
    concurrency:     int             = 5
    delay:           float           = 0.2
    retries:         int             = 3
    crawl:           bool            = False
    crawl_depth:     int             = 3
    use_playwright:  bool            = False
    smart_context:   bool            = True
    use_mutations:   bool            = True
    blind_xss:       bool            = False
    oob_host:        Optional[str]   = None
    dom_analysis:    bool            = False
    verbose:         bool            = False
    output_json:     Optional[str]   = None
    output_html:     Optional[str]   = None
    include_cvss:    bool            = False
    detected_waf:    Optional[str]   = None
    base_domain:     str             = ""

    def base_headers(self) -> Dict[str, str]:
        h = {
            "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection":      "keep-alive",
        }
        if self.auth_cookie:
            h["Cookie"] = self.auth_cookie
        h.update(self.extra_headers)
        return h
