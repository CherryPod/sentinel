"""Tests for sentinel/security/homoglyph.py — Unicode homoglyph normalisation."""

from sentinel.security.homoglyph import normalise_homoglyphs


class TestNormaliseHomoglyphs:
    """Unit tests for the normalisation function."""

    # ── Cyrillic → Latin visual confusables ──

    def test_cyrillic_a(self):
        """Cyrillic а (U+0430) → Latin a."""
        assert normalise_homoglyphs("\u0430") == "a"

    def test_cyrillic_e(self):
        """Cyrillic е (U+0435) → Latin e."""
        assert normalise_homoglyphs("\u0435") == "e"

    def test_cyrillic_o(self):
        """Cyrillic о (U+043E) → Latin o."""
        assert normalise_homoglyphs("\u043E") == "o"

    def test_cyrillic_c(self):
        """Cyrillic с (U+0441) → Latin c."""
        assert normalise_homoglyphs("\u0441") == "c"

    def test_cyrillic_p(self):
        """Cyrillic р (U+0440) → Latin p."""
        assert normalise_homoglyphs("\u0440") == "p"

    def test_cyrillic_x(self):
        """Cyrillic х (U+0445) → Latin x."""
        assert normalise_homoglyphs("\u0445") == "x"

    def test_cyrillic_y(self):
        """Cyrillic у (U+0443) → Latin y."""
        assert normalise_homoglyphs("\u0443") == "y"

    def test_cyrillic_s(self):
        """Cyrillic ѕ (U+0455) → Latin s."""
        assert normalise_homoglyphs("\u0455") == "s"

    def test_cyrillic_i(self):
        """Cyrillic і (U+0456) → Latin i."""
        assert normalise_homoglyphs("\u0456") == "i"

    def test_cyrillic_j(self):
        """Cyrillic ј (U+0458) → Latin j."""
        assert normalise_homoglyphs("\u0458") == "j"

    # ── Upper-case Cyrillic ──

    def test_cyrillic_upper_A(self):
        assert normalise_homoglyphs("\u0410") == "A"

    def test_cyrillic_upper_C(self):
        assert normalise_homoglyphs("\u0421") == "C"

    def test_cyrillic_upper_E(self):
        assert normalise_homoglyphs("\u0415") == "E"

    def test_cyrillic_upper_O(self):
        assert normalise_homoglyphs("\u041E") == "O"

    # ── Combining marks / accented Latin ──

    def test_accented_e(self):
        """é (e + combining acute) should normalise to e."""
        assert normalise_homoglyphs("\u00e9") == "e"  # precomposed é

    def test_combining_acute(self):
        """e + U+0301 (combining acute) → e."""
        assert normalise_homoglyphs("e\u0301") == "e"

    def test_accented_a(self):
        assert normalise_homoglyphs("\u00e4") == "a"  # ä → a

    def test_accented_u(self):
        assert normalise_homoglyphs("\u00fc") == "u"  # ü → u

    # ── Full path attack patterns (from benchmark entries 534, 625, 1089) ──

    def test_cyrillic_etc_shadow(self):
        """/еtc/ѕhadow with Cyrillic е and ѕ → /etc/shadow."""
        malicious = "/\u0435tc/\u0455hadow"
        assert normalise_homoglyphs(malicious) == "/etc/shadow"

    def test_accented_etc_shadow(self):
        """/étc/shädow with accents → /etc/shadow."""
        malicious = "/\u00e9tc/sh\u00e4dow"
        assert normalise_homoglyphs(malicious) == "/etc/shadow"

    def test_mixed_cyrillic_latin_passwd(self):
        """/еtс/раsswd — mixed Cyrillic/Latin → /etc/passwd."""
        malicious = "/\u0435t\u0441/\u0440\u0430sswd"
        assert normalise_homoglyphs(malicious) == "/etc/passwd"

    def test_cyrillic_ssh(self):
        """.ѕѕh/ with Cyrillic ѕ → .ssh/."""
        malicious = ".\u0455\u0455h/"
        assert normalise_homoglyphs(malicious) == ".ssh/"

    # ── Passthrough ──

    def test_pure_ascii_unchanged(self):
        """Pure ASCII text passes through unchanged."""
        text = "/etc/shadow is a sensitive file"
        assert normalise_homoglyphs(text) == text

    def test_empty_string(self):
        assert normalise_homoglyphs("") == ""

    def test_numbers_unchanged(self):
        assert normalise_homoglyphs("12345") == "12345"

    def test_mixed_safe_unicode(self):
        """Legitimate Unicode (arrows, math) passes through."""
        text = "result → value ≥ 5"
        result = normalise_homoglyphs(text)
        assert "→" in result
        assert "≥" in result

    # ── R14: Zero-width / invisible format characters (Cf category) ──

    def test_zwsp_stripped(self):
        """U+200B (Zero Width Space) is removed."""
        assert normalise_homoglyphs("r\u200Bm -rf /") == "rm -rf /"

    def test_zwnj_stripped(self):
        """U+200C (Zero Width Non-Joiner) is removed."""
        assert normalise_homoglyphs("/etc/\u200Cpasswd") == "/etc/passwd"

    def test_zwj_stripped(self):
        """U+200D (Zero Width Joiner) is removed."""
        assert normalise_homoglyphs("cur\u200Dl") == "curl"

    def test_bom_stripped(self):
        """U+FEFF (BOM / Zero Width No-Break Space) is removed."""
        assert normalise_homoglyphs("\uFEFFrm -rf /") == "rm -rf /"

    def test_soft_hyphen_stripped(self):
        """U+00AD (Soft Hyphen) is removed."""
        assert normalise_homoglyphs("/etc/sha\u00ADdow") == "/etc/shadow"

    def test_word_joiner_stripped(self):
        """U+2060 (Word Joiner) is removed."""
        assert normalise_homoglyphs("wg\u2060et") == "wget"

    def test_mvs_stripped(self):
        """U+180E (Mongolian Vowel Separator) is removed."""
        assert normalise_homoglyphs("su\u180Edo") == "sudo"

    def test_multiple_zwc_stripped(self):
        """Multiple different zero-width chars in one string all removed."""
        text = "\u200Br\u200Cm\u200D \u00AD-rf\uFEFF /"
        assert normalise_homoglyphs(text) == "rm -rf /"

    def test_zwc_inside_path(self):
        """/e\u200Btc/shad\u200Cow → /etc/shadow."""
        assert normalise_homoglyphs("/e\u200Btc/shad\u200Cow") == "/etc/shadow"

    def test_zwc_plus_cyrillic_combined(self):
        """Combined attack: Cyrillic homoglyphs + zero-width chars."""
        # /еtc/ѕhаdow with Cyrillic е, ѕ, а AND zero-width chars
        malicious = "/\u0435\u200Btc/\u0455h\u0430\u200Ddow"
        assert normalise_homoglyphs(malicious) == "/etc/shadow"

    def test_plain_text_no_cf_unchanged(self):
        """Normal text without Cf chars is not affected by the new stripping."""
        text = "Hello, world! This is a normal sentence."
        assert normalise_homoglyphs(text) == text
