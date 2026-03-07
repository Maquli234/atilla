from typing import Any, Dict, List


def score_finding(vuln: Dict[str, Any]) -> float:
    """Return false-positive probability 0.0 (real) to 1.0 (likely FP)."""
    fp = 0.0
    if vuln.get("category") == "ENCODED":  fp += 0.4
    if vuln.get("category") == "PARTIAL":  fp += 0.35
    if vuln.get("confidence", 0) < 55:     fp += 0.3
    if vuln.get("response_length", 0) > 500_000: fp += 0.15
    if vuln.get("category") == "PARTIAL" and not vuln.get("dom_sinks"): fp += 0.1
    return min(1.0, fp)


def filter_false_positives(vulns: list, threshold: float = 0.6) -> list:
    kept, removed = [], []
    for v in vulns:
        d  = v.to_dict() if hasattr(v, "to_dict") else v
        fp = score_finding(d)
        (removed if fp >= threshold else kept).append(v)
    if removed:
        from colorama import Fore
        print(f"{Fore.YELLOW}[ML] Filtered {len(removed)} likely false positives")
    return kept
