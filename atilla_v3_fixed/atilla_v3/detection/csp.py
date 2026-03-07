from typing import Any, Dict, List

def analyze_csp(header: str) -> Dict[str, Any]:
    if not header:
        return {"present": False, "bypassable": True, "issues": ["No CSP header"]}
    result: Dict[str, Any] = {"present": True, "raw": header, "issues": [], "bypassable": False}
    directives: Dict[str, List[str]] = {}
    for part in header.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    script_src = directives.get("script-src", directives.get("default-src", []))
    if not script_src:
        result["issues"].append("No script-src => inline scripts permitted")
        result["bypassable"] = True
        return result
    for src in script_src:
        if src in ("'unsafe-inline'", "*"):
            result["issues"].append(f"Dangerous: {src}")
            result["bypassable"] = True
        if src == "'unsafe-eval'":
            result["issues"].append("unsafe-eval present")
            result["bypassable"] = True
        if src.startswith("https://") and src.count("/") == 2:
            result["issues"].append(f"Possible JSONP bypass: {src}")
            result["bypassable"] = True
    return result
