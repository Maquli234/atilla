"""tests/test_context.py — Unit tests for the injection context detector."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.context import detect_injection_context
from core.models import InjectionContext


def test_html_text_context():
    marker = "ATILLA123"
    body   = f"<html><body><p>{marker}</p></body></html>"
    assert detect_injection_context(body, marker) == InjectionContext.HTML_TEXT


def test_html_attribute_dq():
    marker = "ATILLA123"
    body   = f'<html><body><input value="{marker}"></body></html>'
    assert detect_injection_context(body, marker) == InjectionContext.HTML_ATTRIBUTE_DQ


def test_html_attribute_sq():
    marker = "ATILLA123"
    body   = f"<html><body><input value='{marker}'></body></html>"
    assert detect_injection_context(body, marker) == InjectionContext.HTML_ATTRIBUTE_SQ


def test_js_string_dq():
    marker = "ATILLA123"
    body   = f'<script>var x = "{marker}";</script>'
    result = detect_injection_context(body, marker)
    assert result == InjectionContext.JS_STRING_DQ


def test_js_string_sq():
    marker = "ATILLA123"
    body   = f"<script>var x = '{marker}';</script>"
    result = detect_injection_context(body, marker)
    assert result == InjectionContext.JS_STRING_SQ


def test_js_template():
    marker = "ATILLA123"
    body   = f"<script>var x = `{marker}`;</script>"
    result = detect_injection_context(body, marker)
    assert result == InjectionContext.JS_TEMPLATE


def test_js_inline():
    marker = "ATILLA123"
    body   = f"<script>var x = {marker};</script>"
    result = detect_injection_context(body, marker)
    assert result in (InjectionContext.JS_INLINE, InjectionContext.JS_STRING_DQ,
                      InjectionContext.JS_STRING_SQ)


def test_css_context():
    marker = "ATILLA123"
    body   = f"<style>body {{ color: {marker}; }}</style>"
    assert detect_injection_context(body, marker) == InjectionContext.CSS_VALUE


def test_unknown_when_not_present():
    marker = "ATILLA_NOT_HERE"
    body   = "<html><body>nothing</body></html>"
    assert detect_injection_context(body, marker) == InjectionContext.UNKNOWN


def test_url_href_context():
    marker = "ATILLA123"
    body   = f'<a href="https://example.com/{marker}">link</a>'
    result = detect_injection_context(body, marker)
    assert result in (InjectionContext.URL_PARAM, InjectionContext.HTML_TEXT,
                      InjectionContext.HTML_ATTRIBUTE_DQ)


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
