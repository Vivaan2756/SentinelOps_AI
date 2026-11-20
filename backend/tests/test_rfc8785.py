"""Tests for RFC 8785 JSON Canonicalization Scheme (JCS) implementation.

Test Structure:
Part A: Genuine IETF RFC 8785 reference test vectors (from RFC 8785 Section 3).
Part B: SentinelOps strict security and edge-case regression tests.
"""

from decimal import Decimal
import math
import pytest
from app.core.rfc8785 import (
    canonicalize,
    canonicalize_to_str,
    CanonicalizationError,
    MAX_SAFE_INTEGER,
    MIN_SAFE_INTEGER,
)


class TestPartA_OfficialRFC8785ReferenceVectors:
    """
    Genuine test vectors transcribed directly from IETF RFC 8785:
    - Section 3.2.1: Whitespace removal.
    - Section 3.2.2.2: String escaping and non-escaping (solidus, non-ASCII Unicode).
    - Section 3.2.2.3: Number representations (-0.0, exponents, integers, floats).
    - Section 3.2.3: Key sorting by UTF-16 code units (surrogate pairs vs BMP).
    """

    def test_rfc8785_section_3_2_1_whitespace(self):
        """RFC 8785 Section 3.2.1: All token whitespace is stripped."""
        data = {"b": 1, "a": 2}
        assert canonicalize_to_str(data) == '{"a":2,"b":1}'
        assert canonicalize(data) == b'{"a":2,"b":1}'

    def test_rfc8785_section_3_2_2_2_string_escaping(self):
        """
        RFC 8785 Section 3.2.2.2:
        Only \\ and \" and control chars U+0000..U+001F are escaped.
        Forward slash '/' and non-ASCII characters MUST NOT be escaped.
        """
        # Solidus must not be escaped
        assert canonicalize_to_str("https://example.com/api/v1") == '"https://example.com/api/v1"'

        # Control characters
        assert canonicalize_to_str("\b\t\n\f\r") == '"\\b\\t\\n\\f\\r"'
        assert canonicalize_to_str("\u0000\u001f") == '"\\u0000\\u001f"'

        # Quotes and backslashes
        assert canonicalize_to_str('"\\') == '"\\"\\\\"'

        # Non-ASCII Unicode directly in UTF-8
        assert canonicalize_to_str("München €") == '"München €"'
        assert canonicalize("München €") == '"München €"'.encode("utf-8")

    def test_rfc8785_section_3_2_2_3_negative_zero(self):
        """RFC 8785 Section 3.2.2.3: -0.0 serializes to 0."""
        assert canonicalize_to_str(-0.0) == "0"
        assert canonicalize_to_str(0.0) == "0"
        assert canonicalize_to_str({"val": -0.0}) == '{"val":0}'

    def test_rfc8785_section_3_2_2_3_ecmascript_numbers(self):
        """
        RFC 8785 Section 3.2.2.3 and ECMAScript 7.1.12.1:
        Number formatting thresholds:
        - 1e-6 -> 0.000001 (decimal, n = -5, -6 < n <= 21)
        - 1e-7 -> 1e-7 (exponential, n = -6, n <= -6)
        - 1e20 -> 100000000000000000000 (decimal, n = 21, n <= 21)
        - 1e21 -> 1e+21 (exponential, n = 22, n > 21)
        """
        assert canonicalize_to_str(1e-7) == "1e-7"
        assert canonicalize_to_str(1e-6) == "0.000001"
        assert canonicalize_to_str(1e20) == "100000000000000000000"
        assert canonicalize_to_str(1e21) == "1e+21"
        assert canonicalize_to_str(333333333.33333329) == "333333333.3333333"
        assert canonicalize_to_str(5e-324) == "5e-324"

    def test_rfc8785_section_3_2_3_utf16_code_unit_sorting(self):
        """
        RFC 8785 Section 3.2.3:
        Keys are sorted by UTF-16 code units.
        Non-BMP characters (U+1F600 with surrogate pair 0xD83D 0xDE00)
        sort BEFORE U+FFFF (0xFFFF) because 0xD83D < 0xFFFF in UTF-16!
        """
        data = {
            "\uffff": "bmp_end",
            "\U0001f600": "emoji_grinning",
        }
        assert canonicalize_to_str(data) == '{"\U0001f600":"emoji_grinning","\uffff":"bmp_end"}'


class TestPartB_SentinelOpsSecurityAndEdgeCases:
    """SentinelOps security regression tests for strict validation and boundary enforcement."""

    def test_safe_integer_boundaries_accepted(self):
        """Integers at the IEEE-754 safe bounds [-(2^53 - 1), (2^53 - 1)] are accepted."""
        assert canonicalize_to_str(MAX_SAFE_INTEGER) == "9007199254740991"
        assert canonicalize_to_str(MIN_SAFE_INTEGER) == "-9007199254740991"
        assert canonicalize_to_str(0) == "0"
        assert canonicalize_to_str(42) == "42"

    def test_unsafe_integers_rejected(self):
        """Integers outside [-(2^53 - 1), (2^53 - 1)] are rejected with CanonicalizationError."""
        # 2^53
        with pytest.raises(CanonicalizationError, match="outside safe IEEE-754 range"):
            canonicalize_to_str(9007199254740992)

        # -(2^53)
        with pytest.raises(CanonicalizationError, match="outside safe IEEE-754 range"):
            canonicalize_to_str(-9007199254740992)

        # 10^30
        with pytest.raises(CanonicalizationError, match="outside safe IEEE-754 range"):
            canonicalize_to_str(10**30)

        # Embedded in dict
        with pytest.raises(CanonicalizationError, match="outside safe IEEE-754 range"):
            canonicalize({"overflow": 9007199254740992})

    def test_lone_surrogates_rejected(self):
        """Lone high and low surrogate code points in strings/keys raise CanonicalizationError."""
        # Lone high surrogate U+D800 in value
        with pytest.raises(CanonicalizationError, match="lone surrogate"):
            canonicalize_to_str("lone \ud800")

        # Lone low surrogate U+DFFF in value
        with pytest.raises(CanonicalizationError, match="lone surrogate"):
            canonicalize_to_str("lone \udfff")

        # Lone surrogate in dictionary key
        with pytest.raises(CanonicalizationError, match="lone surrogate"):
            canonicalize_to_str({"\ud800": "bad_key"})

        # Lone surrogate in nested structure
        with pytest.raises(CanonicalizationError, match="lone surrogate"):
            canonicalize({"nested": ["valid", "\ud801"]})

    def test_valid_non_bmp_unicode_accepted(self):
        """Valid non-BMP characters like 😀 are accepted and encoded as UTF-8 bytes."""
        res_str = canonicalize_to_str("Status 😀 OK")
        assert res_str == '"Status 😀 OK"'

        res_bytes = canonicalize("Status 😀 OK")
        assert res_bytes == b'"Status \xf0\x9f\x98\x80 OK"'

    def test_non_finite_floats_rejected(self):
        """NaN, Infinity, and -Infinity are strictly rejected."""
        with pytest.raises(CanonicalizationError, match="rejects non-finite"):
            canonicalize_to_str(float("nan"))

        with pytest.raises(CanonicalizationError, match="rejects non-finite"):
            canonicalize_to_str(float("inf"))

        with pytest.raises(CanonicalizationError, match="rejects non-finite"):
            canonicalize_to_str(float("-inf"))

    def test_unsupported_python_types_rejected(self):
        """Non-JSON serializable types raise CanonicalizationError."""
        with pytest.raises(CanonicalizationError, match="Unsupported data type"):
            canonicalize({"set": {1, 2, 3}})

        with pytest.raises(CanonicalizationError, match="Unsupported data type"):
            canonicalize(lambda x: x)

    def test_non_string_dict_keys_rejected(self):
        """Dictionary keys that are not strings raise CanonicalizationError."""
        with pytest.raises(CanonicalizationError, match="requires all object keys to be strings"):
            canonicalize({123: "val"})

    def test_deterministic_reproducible_output(self):
        """Repeated canonicalization of complex dictionary produces identical bytes."""
        data = {
            "execution_id": "a6c6987c-cf9e-4234-ae66-5709feaf71f9",
            "action_id": "execute_http_recovery",
            "parameters": {
                "timeout_seconds": 30,
                "recovery_path": "/admin/recovery/reset",
                "expected_status_codes": [200, 204],
            },
            "origin": "https://api.payments.example.com:443",
            "active": True,
            "metadata": None,
        }
        bytes_1 = canonicalize(data)
        bytes_2 = canonicalize(data)
        assert bytes_1 == bytes_2
        assert not bytes_1.startswith(b"\xef\xbb\xbf")  # No UTF-8 BOM
