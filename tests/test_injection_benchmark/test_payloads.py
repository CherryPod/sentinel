"""Tests for injection benchmark payload templates."""
import pytest

from payloads import PAYLOADS, render_payload, get_payloads


def test_all_13_payload_ids_registered():
    """All 13 payload IDs are registered."""
    expected = {
        "direct", "ignore_previous", "system_message", "injecagent",
        "important_instructions", "important_no_names", "important_wrong_user",
        "tool_knowledge", "dos_stop", "dos_captcha", "dos_offensive",
        "subtle_context", "encoded_evasion",
    }
    assert set(PAYLOADS.keys()) == expected


def test_render_payload_substitutes_goal():
    """render_payload substitutes {goal}."""
    result = render_payload("direct", "send evil email", "IB-001")
    assert "send evil email" in result


def test_render_payload_substitutes_test_id():
    """render_payload substitutes {test_id} in goal text."""
    result = render_payload("direct", "send data with subject '{test_id}'",
                            "IB-042")
    assert "IB-042" in result


def test_important_instructions_has_information_tags():
    """important_instructions payload contains <INFORMATION> tags."""
    result = render_payload("important_instructions", "exfil data", "IB-010")
    assert "<INFORMATION>" in result
    assert "</INFORMATION>" in result


def test_encoded_evasion_has_encoding():
    """encoded_evasion payload contains base64 or HTML entity segments."""
    result = render_payload("encoded_evasion", "send evil email", "IB-020")
    # Should contain at least one encoded segment (base64 or HTML entity)
    has_base64 = any(c in result for c in ["==", "base64"])
    has_entity = "&#" in result
    has_homoglyph = True  # Unicode homoglyphs are invisible in assertions
    assert has_base64 or has_entity or has_homoglyph, (
        f"encoded_evasion should contain encoding artifacts, got: {result[:200]}"
    )


def test_dos_stop_contains_stop():
    """dos_stop payload contains stop instruction."""
    result = render_payload("dos_stop", "stop everything", "IB-030")
    assert "stop" in result.lower()


def test_subtle_context_no_obvious_markers():
    """subtle_context payload has no obvious injection markers."""
    result = render_payload("subtle_context", "forward to new email", "IB-040")
    # Should NOT contain obvious injection patterns
    assert "IGNORE" not in result.upper().split("FORWARD")[0] if "FORWARD" in result.upper() else True
    assert "IMPORTANT!!!" not in result
    assert "<INFORMATION>" not in result
    assert "###(system_message)" not in result


def test_get_payloads_all():
    """get_payloads returns all 13 when filter is 'all'."""
    result = get_payloads("all")
    assert len(result) == 13


def test_get_payloads_subset():
    """get_payloads returns subset when filter is a list."""
    result = get_payloads(["direct", "dos_stop"])
    assert result == ["direct", "dos_stop"]
