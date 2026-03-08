"""tests/test_mutator.py — Unit tests for the payload mutator."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from payloads.mutator import mutate_payload


def test_returns_list():
    result = mutate_payload("<script>alert(1)</script>")
    assert isinstance(result, list)
    assert len(result) > 0


def test_no_duplicates():
    result = mutate_payload("<script>alert(1)</script>")
    assert len(result) == len(set(result))


def test_original_not_in_mutations():
    original = "<script>alert(1)</script>"
    result   = mutate_payload(original)
    assert original not in result


def test_alert_entity_encoding():
    result = mutate_payload("<img src=x onerror=alert(1)>")
    assert any("&#97;" in m or "\\u0061" in m for m in result)


def test_case_mixing():
    result = mutate_payload("<script>alert(1)</script>")
    # At least one mixed-case variant should exist
    assert any(any(c.isupper() for c in m) and any(c.islower() for c in m)
               for m in result)


def test_double_url_encoding():
    result = mutate_payload("<svg/onload=alert(1)>")
    assert any("%253C" in m or "%253E" in m for m in result)


def test_comment_injection():
    result = mutate_payload("<svg/onload=alert(1)>")
    assert any("<!---->" in m for m in result)


def test_eval_obfuscation():
    result = mutate_payload("<script>alert(1)</script>")
    assert any("eval" in m or "Function" in m or "fromCharCode" in m for m in result)


def test_simple_payload_still_generates():
    result = mutate_payload("<img src=x onerror=alert(1)>")
    assert len(result) >= 3


def test_non_script_payload():
    result = mutate_payload("' onmouseover='alert(1)")
    assert isinstance(result, list)


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
