"""tests/test_analyzer.py — Unit tests for the response analyzer."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.analyzer import analyze_response


def test_verbatim_reflection_vulnerable():
    payload = "<script>alert(1)</script>"
    body    = f"<html><body>{payload}</body></html>"
    cat, conf, details, ev = analyze_response(payload, body, {})
    assert cat in ("VULNERABLE", "REFLECTED")
    assert conf >= 75
    assert "verbatim" in details[0].lower()


def test_executable_context_script_tag():
    payload = "<script>alert(1)</script>"
    body    = f"<html><script>{payload}</script></html>"
    cat, conf, details, ev = analyze_response(payload, body, {})
    assert conf >= 90
    assert "script" in " ".join(details).lower()


def test_html_entity_encoded():
    payload  = "<script>alert(1)</script>"
    encoded  = payload.replace("<", "&lt;").replace(">", "&gt;")
    body     = f"<html><body>{encoded}</body></html>"
    cat, conf, details, ev = analyze_response(payload, body, {})
    assert cat == "ENCODED"
    assert conf < 75


def test_no_reflection():
    payload = "<script>alert(1)</script>"
    body    = "<html><body>Nothing here</body></html>"
    cat, conf, details, ev = analyze_response(payload, body, {})
    assert cat == "STRIPPED"
    assert conf == 0


def test_partial_reflection():
    payload = "<script>alert(1)</script>"
    # Only 'alert' is in the body, not the whole payload
    body    = "<html><body>alert found here</body></html>"
    cat, conf, details, ev = analyze_response(payload, body, {})
    assert cat in ("PARTIAL", "STRIPPED")


def test_empty_response():
    cat, conf, details, ev = analyze_response("<script>alert(1)</script>", "", {})
    assert cat == "NO_RESPONSE"
    assert conf == 0


def test_csp_detected():
    payload = "<script>alert(1)</script>"
    body    = "<html><body>hello</body></html>"
    headers = {"content-security-policy": "default-src 'self'"}
    cat, conf, details, ev = analyze_response(payload, body, headers)
    assert cat == "CSP_PROTECTED"


def test_filter_keyword_detected():
    payload = "<script>alert(1)</script>"
    body    = "<html><body>Request blocked by security policy</body></html>"
    cat, conf, details, ev = analyze_response(payload, body, {})
    assert cat == "FILTERED"


def test_evidence_snippet_present():
    payload  = "<img src=x onerror=alert(1)>"
    body     = f"<div>USER INPUT: {payload} END</div>"
    cat, conf, details, ev = analyze_response(payload, body, {})
    assert payload[:10] in ev or len(ev) > 0


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERR   {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
