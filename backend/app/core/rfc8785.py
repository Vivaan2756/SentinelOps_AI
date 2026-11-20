"""RFC 8785 JSON Canonicalization Scheme (JCS) Implementation.

Conforms strictly to IETF RFC 8785:
- UTF-8 encoding without BOM.
- Whitespace elimination.
- Lexicographical sorting of object keys by UTF-16 code units (Section 3.2.3).
- Minimal string escaping (Section 3.2.2.2): only quotation mark ("), reverse solidus (\\),
  and control characters U+0000 through U+001F are escaped; all other characters
  (including solidus '/' and non-ASCII Unicode) are emitted directly as unescaped UTF-8.
- Explicit rejection of lone surrogates (U+D800..U+DFFF) with CanonicalizationError.
- Canonical number representation (Section 3.2.2.3 / ECMAScript 7.1.12.1):
  - Strictly implements ECMAScript Number.prototype.toString() format.
  - Exponent format used ONLY when exponent k < -6 or k >= 21.
  - -0.0 serialized as 0.
  - Rejection of NaN, Infinity, -Infinity.
- Safe integer enforcement: integers outside -(2^53 - 1) <= n <= (2^53 - 1) are rejected
  with CanonicalizationError to guarantee cross-language IEEE-754 precision safety.
- Strict rejection of duplicate object keys and unsupported types.

Integration Note for Broker IPC:
When raw JSON bytes are parsed before canonicalization, a strict JSON parser
with an object_pairs_hook must be employed to reject duplicate object keys,
as standard Python dicts do not preserve duplicate keys present in raw JSON.
"""

from decimal import Decimal
import math
from typing import Any, Dict, List, Union

# IEEE-754 Safe Integer Bounds (RFC 8785 / ECMAScript Number.MAX_SAFE_INTEGER)
MAX_SAFE_INTEGER = (2**53) - 1
MIN_SAFE_INTEGER = -((2**53) - 1)


class CanonicalizationError(ValueError):
    """Raised when data cannot be canonicalized according to RFC 8785."""
    pass


def _utf16_sort_key(s: str) -> bytes:
    """
    Return UTF-16BE bytes for lexicographical sorting by UTF-16 code units
    as mandated by RFC 8785 Section 3.2.3.
    """
    return s.encode("utf-16-be")


def _check_no_lone_surrogates(s: str) -> None:
    """
    Check if string contains any lone surrogate code points (U+D800..U+DFFF).
    Raises CanonicalizationError if found.
    """
    for char in s:
        cp = ord(char)
        if 0xD800 <= cp <= 0xDFFF:
            raise CanonicalizationError(
                f"RFC 8785 rejects lone surrogate code point U+{cp:04X} in string."
            )


def _serialize_string(s: str) -> str:
    """
    Serialize string according to RFC 8785 Section 3.2.2.2.
    Only quotation mark ("), reverse solidus (\\), and control characters
    (U+0000 through U+001F) are escaped.
    Lone surrogates are rejected with CanonicalizationError.
    """
    _check_no_lone_surrogates(s)

    out = ['"']
    for char in s:
        cp = ord(char)
        if cp == 0x22:  # quotation mark "
            out.append('\\"')
        elif cp == 0x5C:  # reverse solidus \
            out.append('\\\\')
        elif cp == 0x08:  # backspace
            out.append('\\b')
        elif cp == 0x09:  # character tabulation
            out.append('\\t')
        elif cp == 0x0A:  # line feed
            out.append('\\n')
        elif cp == 0x0C:  # form feed
            out.append('\\f')
        elif cp == 0x0D:  # carriage return
            out.append('\\r')
        elif cp < 0x20:  # other control characters U+0000 to U+001F
            out.append(f"\\u{cp:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _serialize_float_ecmascript(f: float) -> str:
    """
    Serialize IEEE 754 float according to ECMAScript 7.1.12.1 (ToString Applied to the Number Type)
    and RFC 8785 Section 3.2.2.3.

    ECMAScript Rules:
    1. If f is NaN, return 'NaN' (rejected by caller).
    2. If f is +0 or -0, return '0'.
    3. If f < 0, return '-' + ToString(-f).
    4. If f is Infinity, return 'Infinity' (rejected by caller).
    5. Let n, k, and s be integers such that k >= 1, 10^(k-1) <= s < 10^k,
       the Number value for s * 10^(n-k) is f, and k is as small as possible.
    6. If k <= n <= 21: return digits + '0' * (n - k)
    7. If 0 < n <= 21: return digits[:n] + '.' + digits[n:]
    8. If -6 < n <= 0: return '0.' + '0' * (-n) + digits
    9. If k == 1: return digits + 'e' + ('+' if n-1 >= 0 else '') + str(n-1)
    10. Otherwise: return digits[0] + '.' + digits[1:] + 'e' + ('+' if n-1 >= 0 else '') + str(n-1)
    """
    if f == 0.0:
        return "0"
    if f < 0:
        return "-" + _serialize_float_ecmascript(-f)

    # Python's repr(f) uses David Gay / Ryū dtoa algorithm, producing the exact shortest
    # unique round-tripping decimal representation for 64-bit IEEE-754.
    s = repr(f)

    # Decompose into significant digits and integer exponent
    if "e" in s or "E" in s:
        mantissa_str, exp_str = s.lower().split("e")
        exp = int(exp_str)
        if "." in mantissa_str:
            dot_pos = mantissa_str.index(".")
            digits = mantissa_str.replace(".", "")
            exponent_of_integer = exp - (len(mantissa_str) - 1 - dot_pos)
        else:
            digits = mantissa_str
            exponent_of_integer = exp
    else:
        if "." in s:
            int_part, frac_part = s.split(".")
            if frac_part == "0":
                digits = int_part
                exponent_of_integer = 0
            elif int_part == "0":
                frac_lstripped = frac_part.lstrip("0")
                leading_zeros = len(frac_part) - len(frac_lstripped)
                digits = frac_lstripped
                exponent_of_integer = -(leading_zeros + len(digits))
            else:
                digits = int_part + frac_part
                exponent_of_integer = -len(frac_part)
        else:
            digits = s
            exponent_of_integer = 0

    # k is the number of significant digits
    k = len(digits)
    # n is the base-10 exponent of the first significant digit plus 1
    # s * 10^(n - k) == integer(digits) * 10^exponent_of_integer
    n = exponent_of_integer + k

    # Format according to ECMAScript 7.1.12.1 step 5-10
    if k <= n <= 21:
        return digits + "0" * (n - k)
    elif 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    elif k == 1:
        sign = "+" if (n - 1) >= 0 else ""
        return digits + "e" + sign + str(n - 1)
    else:
        sign = "+" if (n - 1) >= 0 else ""
        return digits[0] + "." + digits[1:] + "e" + sign + str(n - 1)


def _serialize_number(n: Union[int, float, Decimal]) -> str:
    """
    Serialize number according to RFC 8785 Section 3.2.2.3 and ECMAScript 7.1.12.1.
    Rejects NaN, Infinity, -Infinity.
    Rejects integers outside safe IEEE-754 range: -(2^53 - 1) <= n <= (2^53 - 1).
    -0.0 is serialized as 0.
    """
    if isinstance(n, bool):
        return "true" if n else "false"

    if isinstance(n, int):
        if n < MIN_SAFE_INTEGER or n > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"Integer {n} is outside safe IEEE-754 range [{MIN_SAFE_INTEGER}, {MAX_SAFE_INTEGER}]. "
                "RFC 8785 rejects unsafe integers to prevent cross-language precision loss."
            )
        return str(n)

    if isinstance(n, Decimal):
        if n.is_nan() or n.is_infinite():
            raise CanonicalizationError(f"RFC 8785 rejects non-finite Decimal: {n}")
        if n.is_zero():
            return "0"
        return _serialize_float_ecmascript(float(n))

    if isinstance(n, float):
        if math.isnan(n) or math.isinf(n):
            raise CanonicalizationError(f"RFC 8785 rejects non-finite float: {n}")
        return _serialize_float_ecmascript(n)

    raise CanonicalizationError(f"Unsupported number type: {type(n)}")


def canonicalize_to_str(data: Any) -> str:
    """
    Serialize Python data structure to an RFC 8785 canonical JSON string.
    """
    if data is None:
        return "null"

    if isinstance(data, bool):
        return "true" if data else "false"

    if isinstance(data, (int, float, Decimal)):
        return _serialize_number(data)

    if isinstance(data, str):
        return _serialize_string(data)

    if isinstance(data, (list, tuple)):
        items = [canonicalize_to_str(item) for item in data]
        return "[" + ",".join(items) + "]"

    if isinstance(data, dict):
        for k in data.keys():
            if not isinstance(k, str):
                raise CanonicalizationError(
                    f"RFC 8785 requires all object keys to be strings, got {type(k)}: {k}"
                )
            _check_no_lone_surrogates(k)

        # Lexicographical sort by UTF-16 code units (Section 3.2.3)
        sorted_keys = sorted(data.keys(), key=_utf16_sort_key)

        members = []
        for k in sorted_keys:
            key_str = _serialize_string(k)
            val_str = canonicalize_to_str(data[k])
            members.append(f"{key_str}:{val_str}")
        return "{" + ",".join(members) + "}"

    raise CanonicalizationError(f"Unsupported data type for RFC 8785 canonicalization: {type(data)}")


def canonicalize(data: Any) -> bytes:
    """
    Serialize Python data structure to RFC 8785 canonical JSON UTF-8 bytes.
    This is the exact byte sequence used for cryptographic hashing and Ed25519 signing.
    """
    canonical_str = canonicalize_to_str(data)
    try:
        return canonical_str.encode("utf-8")
    except UnicodeEncodeError as e:
        raise CanonicalizationError(f"Unicode encoding failure during RFC 8785 canonicalization: {e}")
