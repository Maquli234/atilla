from typing import Dict, List, Optional
import httpx

WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":        ["cf-ray", "cloudflare", "__cfduid"],
    "AWS WAF":           ["x-amzn-requestid", "aws-waf"],
    "Akamai":            ["akamaighost", "akamai"],
    "ModSecurity":       ["mod_security", "modsecurity"],
    "Imperva/Incapsula": ["incap_ses", "_incap_", "visid_incap"],
    "Sucuri":            ["sucuri", "x-sucuri-id"],
    "F5 BIG-IP":         ["ts=", "f5-bigip"],
    "Wordfence":         ["wordfence"],
    "Barracuda":         ["barracuda"],
    "Fortinet":          ["fortigate", "fortiweb"],
}

def fingerprint_waf(response: httpx.Response) -> Optional[str]:
    combined = (str(response.headers).lower()
                + response.text.lower()[:2000]
                + str(response.cookies).lower())
    for name, sigs in WAF_SIGNATURES.items():
        if any(s.lower() in combined for s in sigs):
            return name
    return None
