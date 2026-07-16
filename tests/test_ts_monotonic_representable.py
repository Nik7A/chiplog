"""Part A: ts_monotonic_ns must be JCS-representable forever.

The raw monotonic-ns int in the signed TimeBlock crosses 2**53 after ~104 days
of host uptime, at which point rfc8785 (JCS) refuses to canonicalize it and the
record is silently dropped. Storing the value as a
decimal STRING escapes JCS's float-safe-integer domain at full ns precision and
forever.

These tests pin: new records store the decimal string; the model still ACCEPTS
old int-valued records (so verification-time model use of pre-v1.2 records does
not break); and a value beyond 2**53 canonicalizes cleanly.
"""

from __future__ import annotations

import rfc8785

from chiplog.schema.v1 import (
    SCHEMA_VERSION,
    NoGateReason,
    Output,
    Payload,
    TimeBlock,
    ToolCall,
    success,
    ungated,
)


def test_schema_version_bumped_to_v1_2() -> None:
    assert SCHEMA_VERSION == "v1.2"


def test_int_input_is_stored_as_decimal_string() -> None:
    tb = TimeBlock(ts_utc="2026-07-14T10:00:00.000000000Z", ts_monotonic_ns=1000)
    assert tb.ts_monotonic_ns == "1000"
    assert isinstance(tb.ts_monotonic_ns, str)


def test_string_input_is_accepted_unchanged() -> None:
    tb = TimeBlock(ts_utc="2026-07-14T10:00:00.000000000Z", ts_monotonic_ns="1000")
    assert tb.ts_monotonic_ns == "1000"


def test_value_beyond_2_53_canonicalizes() -> None:
    """The exact time-bomb: a monotonic ns count past 2**53. As an int this
    raises IntegerDomainError; as a decimal string it is representable."""
    big = 2**53 + 12345
    tb = TimeBlock(ts_utc="2026-07-14T10:00:00.000000000Z", ts_monotonic_ns=big)
    assert tb.ts_monotonic_ns == str(big)
    # Would raise IntegerDomainError if this were still an int.
    rfc8785.dumps(tb.model_dump(mode="json"))


def test_model_validate_accepts_old_int_valued_record() -> None:
    """A pre-v1.2 record carried ts_monotonic_ns as an int. Record.model_validate
    must still accept it (stringifying), never reject it."""
    payload = Payload.model_validate(
        {
            "time": {
                "ts_utc": "2026-06-22T09:15:00.000000000Z",
                "ts_monotonic_ns": 123456789,
                "ts_source": "system",
            },
            "tool": {"name": "read_file", "mcp": None},
            "input": {"path": "/etc/hosts"},
            "output": {"body": "x", "truncated": False},
            "policy": {"kind": "none", "reason": "auto_allowed_low_risk"},
            "outcome": {"kind": "success"},
        }
    )
    assert payload.time.ts_monotonic_ns == "123456789"


def test_negative_int_is_rejected() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        TimeBlock(ts_utc="2026-07-14T10:00:00.000000000Z", ts_monotonic_ns=-1)


def test_new_record_via_payload_stores_string() -> None:
    p = Payload(
        time=TimeBlock(ts_utc="2026-07-14T10:00:00.000000000Z", ts_monotonic_ns=42),
        tool=ToolCall(name="t"),
        input={},
        output=Output(),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    d = p.model_dump(mode="json")
    assert d["time"]["ts_monotonic_ns"] == "42"
