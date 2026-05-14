import pytest
from sanitizer.core import sanitize, Findings


# ---------------------------------------------------------------------------
# NFKC normalization
# ---------------------------------------------------------------------------

def test_nfkc_normalizes_ligature():
    # U+FB01 LATIN SMALL LIGATURE FI -> "fi"
    result = sanitize("ﬁle")
    assert result.text == "file"
    assert result.findings.total == 0

def test_nfkc_normalizes_fullwidth():
    result = sanitize("ａ")  # fullwidth 'a' -> 'a'
    assert result.text == "a"
    assert result.findings.total == 0


# ---------------------------------------------------------------------------
# Control characters (Cc)
# ---------------------------------------------------------------------------

def test_allowed_controls_pass_through():
    result = sanitize("a\tb\nc\rd")
    assert result.text == "a\tb\nc\rd"
    assert result.findings.removed_control == 0

def test_null_byte_removed():
    result = sanitize("a\x00b")
    assert result.text == "ab"
    assert result.findings.removed_control == 1
    assert 0x00 in result.findings.codepoints

def test_esc_removed():
    result = sanitize("a\x1bb")
    assert result.text == "ab"
    assert result.findings.removed_control == 1
    assert 0x1B in result.findings.codepoints

def test_del_removed():
    result = sanitize("a\x7fb")
    assert result.text == "ab"
    assert result.findings.removed_control == 1
    assert 0x7F in result.findings.codepoints

def test_full_c0_range_removed():
    # Every byte 0x00-0x1f except \t(09), \n(0a), \r(0d)
    forbidden = [chr(i) for i in range(0x00, 0x20) if chr(i) not in {"\t", "\n", "\r"}]
    for ch in forbidden:
        result = sanitize(ch)
        assert result.text == "", f"expected removal of U+{ord(ch):04X}"
        assert result.findings.removed_control == 1


# ---------------------------------------------------------------------------
# Format characters (Cf)
# ---------------------------------------------------------------------------

def test_zero_width_space_removed():
    result = sanitize("hello​world")
    assert result.text == "helloworld"
    assert result.findings.removed_format == 1
    assert 0x200B in result.findings.codepoints

def test_zero_width_non_joiner_removed():
    result = sanitize("a‌b")
    assert result.text == "ab"
    assert result.findings.removed_format == 1

def test_soft_hyphen_removed():
    result = sanitize("sun­day")
    assert result.text == "sunday"
    assert result.findings.removed_format == 1

def test_word_joiner_removed():
    result = sanitize("a⁠b")
    assert result.text == "ab"
    assert result.findings.removed_format == 1


# ---------------------------------------------------------------------------
# Bidi directional formatting characters
# ---------------------------------------------------------------------------

def test_lre_removed():
    result = sanitize("a‪b")  # LRE
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1
    assert 0x202A in result.findings.codepoints

def test_rle_removed():
    result = sanitize("a‫b")  # RLE
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1

def test_lro_removed():
    result = sanitize("a‭b")  # LRO
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1

def test_rlo_removed():
    result = sanitize("a‮b")  # RLO
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1

def test_pdf_removed():
    result = sanitize("a‬b")  # PDF
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1

def test_lri_removed():
    result = sanitize("a⁦b")  # LRI
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1

def test_rli_removed():
    result = sanitize("a⁧b")  # RLI
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1

def test_fsi_removed():
    result = sanitize("a⁨b")  # FSI
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1

def test_pdi_removed():
    result = sanitize("a⁩b")  # PDI
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1

def test_lrm_removed_counted_as_bidi():
    # U+200E LEFT-TO-RIGHT MARK: Cf category but bidi class LRM
    result = sanitize("a‎b")
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1   # counted as bidi, not format
    assert result.findings.removed_format == 0

def test_rlm_removed_counted_as_bidi():
    # U+200F RIGHT-TO-LEFT MARK: Cf category but bidi class RLM
    result = sanitize("a‏b")
    assert result.text == "ab"
    assert result.findings.removed_bidi == 1
    assert result.findings.removed_format == 0


# ---------------------------------------------------------------------------
# Mark mode
# ---------------------------------------------------------------------------

def test_mark_mode_control():
    result = sanitize("a\x00b", mode="mark")
    assert result.text == "a[U+0000]b"
    assert result.findings.removed_control == 1

def test_mark_mode_format():
    result = sanitize("hello​world", mode="mark")
    assert result.text == "hello[U+200B]world"
    assert result.findings.removed_format == 1

def test_mark_mode_bidi():
    result = sanitize("a‪b", mode="mark")
    assert result.text == "a[U+202A]b"
    assert result.findings.removed_bidi == 1

def test_strip_mode_is_default():
    result = sanitize("a\x00b")
    assert result.text == "ab"


# ---------------------------------------------------------------------------
# Findings accuracy
# ---------------------------------------------------------------------------

def test_findings_total():
    # one of each category
    result = sanitize("a\x00b​c‪d")
    assert result.findings.removed_control == 1
    assert result.findings.removed_format == 1
    assert result.findings.removed_bidi == 1
    assert result.findings.total == 3

def test_codepoints_recorded():
    result = sanitize("\x00​‪")
    assert set(result.findings.codepoints) == {0x00, 0x200B, 0x202A}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_string():
    result = sanitize("")
    assert result.text == ""
    assert result.findings.total == 0

def test_clean_ascii():
    result = sanitize("Hello, world!")
    assert result.text == "Hello, world!"
    assert result.findings.total == 0

def test_clean_unicode():
    result = sanitize("日本語テスト")
    assert result.text == "日本語テスト"
    assert result.findings.total == 0

def test_type_error_on_non_string():
    with pytest.raises(TypeError):
        sanitize(123)

def test_deterministic():
    text = "a\x00​‪b"
    assert sanitize(text).text == sanitize(text).text
