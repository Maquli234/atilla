"""tests/test_payloads.py — Unit tests for the payload library."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from payloads.library import PAYLOAD_SETS, get_context_payloads
from core.models import InjectionContext


def test_all_sets_defined():
    for key in ["basic", "owasp", "advanced", "dom", "all"]:
        assert key in PAYLOAD_SETS, f"Missing set: {key}"


def test_basic_is_smallest():
    assert len(PAYLOAD_SETS["basic"]) <= len(PAYLOAD_SETS["owasp"])
    assert len(PAYLOAD_SETS["owasp"]) <= len(PAYLOAD_SETS["all"])


def test_all_payloads_are_strings():
    for name, payloads in PAYLOAD_SETS.items():
        for p in payloads:
            assert isinstance(p, str), f"Non-string payload in set '{name}': {p!r}"


def test_no_empty_payloads():
    for name, payloads in PAYLOAD_SETS.items():
        for p in payloads:
            assert len(p.strip()) > 0, f"Empty payload in set '{name}'"


def test_no_duplicates_in_all():
    payloads = PAYLOAD_SETS["all"]
    assert len(payloads) == len(set(payloads)), "Duplicates found in 'all' set"


def test_context_payloads_returns_list():
    for ctx in InjectionContext:
        result = get_context_payloads(ctx)
        assert isinstance(result, list)
        assert len(result) > 0, f"No payloads for context {ctx}"


def test_js_context_has_js_payloads():
    payloads = get_context_payloads(InjectionContext.JS_STRING_DQ)
    assert any('alert' in p and ('"' in p or 'alert' in p) for p in payloads)


def test_html_context_has_script_tags():
    payloads = get_context_payloads(InjectionContext.HTML_TEXT)
    assert any('<script>' in p.lower() or 'onerror' in p.lower() for p in payloads)


def test_basic_contains_alert():
    assert all('alert' in p for p in PAYLOAD_SETS["basic"])


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
