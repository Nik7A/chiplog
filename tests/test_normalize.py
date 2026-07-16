"""Part B: normalize_for_canonical replaces JCS-hostile scalars with faithful,
self-describing markers and ANNOUNCES every substitution.

A marker records TYPE + HASH only, never a reconstructed value: the original
magnitude of an un-representable int (or the bytes behind a `bytes`) is not
recoverable in a JCS-signable form, and the marker does not pretend otherwise.
It proves existence and distinguishes two different values by hash.

The four JCS-hostile scalar kinds this must detect pre-model:
  - integer_out_of_jcs_domain  (abs(int) >= 2**53)
  - float_not_finite           (nan AND inf)
  - unsupported_type           (bytes / set / other non-JSON scalars)
and the non-string dict-key hole (JCS keys must be strings), including the
silent-collision case (None-key vs "None"-key must not merge).
"""

from __future__ import annotations

import hashlib
import math

import rfc8785

from chiplog.normalize import (
    MARKER_KEY,
    MARKER_TAG,
    UnrepresentableReason,
    normalize_for_canonical,
)


def _sha(value: object) -> str:
    return hashlib.sha256(repr(value).encode("utf-8")).hexdigest()


def _canonicalizes(value: object) -> bool:
    try:
        rfc8785.dumps(value)
        return True
    except Exception:
        return False


# --- clean values pass through unchanged --------------------------------------


def test_json_native_values_pass_through() -> None:
    value = {"a": 1, "b": [True, None, "x", 3.14], "c": {"d": -5}}
    out, entries = normalize_for_canonical(value)
    assert out == value
    assert entries == []


def test_safe_boundary_int_passes_through() -> None:
    ok = 2**53 - 1
    out, entries = normalize_for_canonical({"n": ok})
    assert out == {"n": ok}
    assert entries == []


def test_bool_is_not_treated_as_out_of_domain_int() -> None:
    out, entries = normalize_for_canonical({"flag": True})
    assert out == {"flag": True}
    assert entries == []


# --- integer out of JCS domain ------------------------------------------------


def test_big_positive_int_becomes_marker() -> None:
    big = 2**53
    out, entries = normalize_for_canonical({"n": big}, "$.input")
    marker = out["n"]
    assert marker[MARKER_KEY] == MARKER_TAG
    assert marker["reason"] == UnrepresentableReason.INTEGER_OUT_OF_JCS_DOMAIN.value
    assert marker["py_type"] == "int"
    assert marker["sha256"] == _sha(big)
    assert len(entries) == 1
    assert entries[0].path == "$.input.n"
    assert entries[0].reason == UnrepresentableReason.INTEGER_OUT_OF_JCS_DOMAIN
    assert _canonicalizes(out)


def test_big_negative_int_becomes_marker() -> None:
    out, entries = normalize_for_canonical({"n": -(2**53)})
    assert out["n"][MARKER_KEY] == MARKER_TAG
    assert len(entries) == 1


def test_two_different_big_ints_distinguishable_by_hash() -> None:
    out_a, _ = normalize_for_canonical(2**53)
    out_b, _ = normalize_for_canonical(2**53 + 1)
    assert out_a["sha256"] != out_b["sha256"]


# --- float not finite: BOTH nan AND inf ---------------------------------------


def test_nan_becomes_marker_not_null() -> None:
    out, entries = normalize_for_canonical({"f": math.nan})
    assert out["f"][MARKER_KEY] == MARKER_TAG
    assert out["f"]["reason"] == UnrepresentableReason.FLOAT_NOT_FINITE.value
    assert len(entries) == 1
    assert _canonicalizes(out)


def test_positive_inf_becomes_marker() -> None:
    out, entries = normalize_for_canonical({"f": math.inf})
    assert out["f"]["reason"] == UnrepresentableReason.FLOAT_NOT_FINITE.value
    assert len(entries) == 1


def test_negative_inf_becomes_marker() -> None:
    out, entries = normalize_for_canonical({"f": -math.inf})
    assert out["f"]["reason"] == UnrepresentableReason.FLOAT_NOT_FINITE.value
    assert len(entries) == 1


def test_finite_float_passes_through() -> None:
    out, entries = normalize_for_canonical({"f": 1.5})
    assert out == {"f": 1.5}
    assert entries == []


# --- unsupported types --------------------------------------------------------


def test_bytes_becomes_marker_not_decoded_string() -> None:
    """model_dump silently decodes bytes to a str — a secret would then look
    like an ordinary string value. The marker records type+hash instead."""
    secret = b"super-secret"
    out, entries = normalize_for_canonical({"b": secret})
    assert out["b"][MARKER_KEY] == MARKER_TAG
    assert out["b"]["reason"] == UnrepresentableReason.UNSUPPORTED_TYPE.value
    assert out["b"]["py_type"] == "bytes"
    assert out["b"]["sha256"] == _sha(secret)
    # The decoded text must NOT appear anywhere in the marker.
    assert "super-secret" not in rfc8785.dumps(out).decode()
    assert len(entries) == 1


def test_set_becomes_marker() -> None:
    out, entries = normalize_for_canonical({"s": {1, 2, 3}})
    assert out["s"]["reason"] == UnrepresentableReason.UNSUPPORTED_TYPE.value
    assert out["s"]["py_type"] == "set"
    assert len(entries) == 1


def test_tuple_is_walked_and_hostile_scalar_inside_is_caught() -> None:
    """Tuples must be walked (they slip past redact today). A hostile scalar
    nested inside a tuple must still be replaced."""
    out, entries = normalize_for_canonical({"t": (1, 2**53, 3)})
    assert isinstance(out["t"], list)
    assert out["t"][0] == 1
    assert out["t"][1][MARKER_KEY] == MARKER_TAG
    assert out["t"][2] == 3
    assert len(entries) == 1
    assert entries[0].path == "$.t[1]"
    assert _canonicalizes(out)


# --- non-string dict keys -----------------------------------------------------


def test_non_string_key_is_stringified_and_announced() -> None:
    out, entries = normalize_for_canonical({1: "a"}, "$.input")
    assert out == {"1": "a"}
    assert any(
        e.reason == UnrepresentableReason.NON_STRING_DICT_KEY for e in entries
    )
    assert _canonicalizes(out)


def test_none_key_and_string_none_key_do_not_merge() -> None:
    """The silent-collision hole: {None: 'a', 'None': 'b'} loses 'a' under
    model_dump. normalize must keep BOTH values and announce the substitution."""
    out, entries = normalize_for_canonical({None: "a", "None": "b"})
    # Both values survive.
    values = set(out.values())
    assert "a" in values and "b" in values
    # The legitimate string key keeps its natural slot.
    assert out["None"] == "b"
    # Two distinct keys, no merge.
    assert len(out) == 2
    # The None-key substitution is announced.
    assert any(
        e.reason == UnrepresentableReason.NON_STRING_DICT_KEY for e in entries
    )
    assert _canonicalizes(out)


def test_colliding_stringified_keys_do_not_merge() -> None:
    out, entries = normalize_for_canonical({1: "a", "1": "b"})
    assert set(out.values()) == {"a", "b"}
    assert out["1"] == "b"
    assert len(out) == 2
    assert _canonicalizes(out)


def test_nested_hostile_values_under_non_string_key() -> None:
    out, entries = normalize_for_canonical({None: {"deep": 2**53}})
    assert _canonicalizes(out)
    # one entry for the key, one for the nested int
    reasons = sorted(e.reason.value for e in entries)
    assert "integer_out_of_jcs_domain" in reasons
    assert "non_string_dict_key" in reasons


# --- marker faithfulness ------------------------------------------------------


def test_marker_records_type_and_hash_never_a_value() -> None:
    """The marker must never carry a reconstructed value field."""
    out, _ = normalize_for_canonical(2**60)
    assert set(out.keys()) == {MARKER_KEY, "reason", "py_type", "sha256"}
