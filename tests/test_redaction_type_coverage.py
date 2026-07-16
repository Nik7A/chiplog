"""Class-level redaction fix — the type-bypass leak matrix, proven end-to-end.

The CLASS: redaction only inspected `str`, but `normalize_for_canonical` produces
the value that actually reaches the signed bytes — it STRINGIFIES non-string dict
keys and PASSES non-string scalars through. So any value or KEY that is not a
`str` was signed WITHOUT ever being shown to the redactor. Three instances:

  1. integer-valued PII (a PAN as an `int`) → signed cleartext;
  2. a non-string dict KEY that is a secret (bytes / int) → signed cleartext;
  3. `tool.name` / `mcp.server_id` never redacted → a secret there is signed
     cleartext.

The invariant that closes the class: every value and every dict key, in the
EXACT form it will take in the signed canonical bytes, must pass through
redaction before it is signed. These tests assert the secret is absent from the
signed bytes AND that the redaction is announced — for each instance — plus a
non-over-redaction matrix proving benign non-string scalars/keys survive, and the
authenticity-in-verify + URL-userinfo over-redaction fixes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_audit.emit import AuditRecorder
from agent_audit.integrity import verify_record
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.redact import (
    RedactionConfig,
    redact_value,
    redaction_authenticity,
)
from agent_audit.schema.v1 import (
    MCPContext,
    MCPTransport,
    NoGateReason,
    Output,
    ToolCall,
    success,
    ungated,
)
from agent_audit.sinks.local_file import LocalFileSink


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


@pytest.fixture
def recorder(tmp_path: Path, signing_key: SigningKey) -> AuditRecorder:
    return AuditRecorder(sink=LocalFileSink(dir=tmp_path), signing_key=signing_key)


async def _record(recorder: AuditRecorder, **over: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = dict(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    kwargs.update(over)
    return await recorder.record(**kwargs)


def _signed_bytes(signed: dict[str, Any]) -> str:
    return json.dumps(signed)


# A Luhn-valid Visa test PAN that fits under 2**53 (16 digits) — so before the
# fix normalize passes the INT straight through into the signed bytes.
PAN_INT = 4111111111111111
PAN_STR = "4111111111111111"
SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"  # canonical AWS example key


# ---------------------------------------------------------------------------
# Instance 1 — integer-valued PII (pure type bypass)
# ---------------------------------------------------------------------------


async def test_int_pan_value_is_redacted(recorder: AuditRecorder) -> None:
    signed = await _record(recorder, input={"card_number": PAN_INT})
    blob = _signed_bytes(signed)
    assert PAN_STR not in blob, "integer-valued PAN leaked cleartext into signed bytes"
    policies = [e["policy"] for e in signed["payload"]["redaction"]]
    assert "pii.deny.credit_card" in policies


def test_unit_int_pan_matches_card_rule() -> None:
    cfg = RedactionConfig()
    redacted, entries = redact_value(PAN_INT, cfg, path="$.card")
    assert isinstance(redacted, dict) and redacted["redacted"] is True
    assert entries[0].policy == "pii.deny.credit_card"


async def test_int_pan_nested_in_list_is_redacted(recorder: AuditRecorder) -> None:
    signed = await _record(recorder, output=Output(body={"cards": [PAN_INT, 7]}))
    assert PAN_STR not in _signed_bytes(signed)


# ---------------------------------------------------------------------------
# Instance 2 — non-string dict KEY (bytes AND int), nested
# ---------------------------------------------------------------------------


async def test_bytes_secret_key_is_redacted(recorder: AuditRecorder) -> None:
    signed = await _record(recorder, input={SECRET_KEY.encode(): "v"})
    assert SECRET_KEY not in _signed_bytes(signed)
    policies = [e["policy"] for e in signed["payload"]["redaction"]]
    assert "pii.deny.aws_access_key" in policies


async def test_int_pan_key_is_redacted_nested(recorder: AuditRecorder) -> None:
    signed = await _record(recorder, input={"outer": {PAN_INT: "v"}})
    assert PAN_STR not in _signed_bytes(signed)


async def test_bytes_secret_key_nested_in_list(recorder: AuditRecorder) -> None:
    signed = await _record(
        recorder, output=Output(body=[{SECRET_KEY.encode(): "x"}])
    )
    assert SECRET_KEY not in _signed_bytes(signed)


# ---------------------------------------------------------------------------
# Instance 3 — tool identity (tool.name, mcp.server_id)
# ---------------------------------------------------------------------------


async def test_tool_name_secret_is_redacted(recorder: AuditRecorder) -> None:
    signed = await _record(recorder, tool=ToolCall(name=SECRET_KEY))
    assert SECRET_KEY not in _signed_bytes(signed)
    policies = [e["policy"] for e in signed["payload"]["redaction"]]
    assert "pii.deny.aws_access_key" in policies


async def test_mcp_server_id_secret_is_redacted(recorder: AuditRecorder) -> None:
    tool = ToolCall(
        name="query",
        mcp=MCPContext(
            server_id=f"mcp+stdio://{SECRET_KEY}@1.0", transport=MCPTransport.STDIO
        ),
    )
    signed = await _record(recorder, tool=tool)
    assert SECRET_KEY not in _signed_bytes(signed)


async def test_normal_tool_name_untouched(recorder: AuditRecorder) -> None:
    signed = await _record(recorder, tool=ToolCall(name="Read"))
    assert signed["payload"]["tool"]["name"] == "Read"


# ---------------------------------------------------------------------------
# NON-over-redaction — benign non-string scalars / keys survive verbatim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "benign_int",
    [
        123456789012345678,  # 18-digit Snowflake-like, non-Luhn
        1234567890123456789,  # 19-digit, non-Luhn
        42,
        0,
        -7,
        1000,  # a count
        1752566400,  # a unix timestamp
    ],
)
def test_benign_int_survives(benign_int: int) -> None:
    cfg = RedactionConfig()
    redacted, entries = redact_value(benign_int, cfg, path="$.x")
    assert redacted == benign_int, f"benign int over-redacted: {benign_int!r}"
    assert entries == []


async def test_benign_int_key_survives_and_is_announced_as_nonstring(
    recorder: AuditRecorder,
) -> None:
    """A benign non-string key must NOT be redacted, but must still be announced
    by normalize as a non-string-dict-key substitution (not silently dropped)."""
    snowflake = 123456789012345678
    signed = await _record(recorder, input={snowflake: "v"})
    # The key survives into the signed bytes as its stringified form...
    assert str(snowflake) in _signed_bytes(signed)
    # ...announced by normalize, and NOT redacted.
    reasons = [u["reason"] for u in signed["payload"]["unrepresentable"]]
    assert "non_string_dict_key" in reasons
    assert signed["payload"]["redaction"] == []


@pytest.mark.parametrize(
    "benign",
    [
        "550e8400-e29b-41d4-a716-446655440000",  # UUID
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",  # git SHA-like
        "2026-07-14T12:00:00.000000000Z",  # ISO timestamp
        "https://example.com/docs/page?ref=home",  # plain https URL
        "https://user@example.com/page",  # URL userinfo, NO password
    ],
)
def test_benign_string_survives(benign: str) -> None:
    cfg = RedactionConfig()
    redacted, entries = redact_value(benign, cfg, path="$.x")
    assert redacted == benign, f"benign value over-redacted: {benign!r}"
    assert entries == []


def test_url_with_password_still_redacted() -> None:
    """A real password/token in a URL is still a leak — must be redacted even
    though bare userinfo is not."""
    cfg = RedactionConfig()
    redacted, entries = redact_value(
        "https://user:s3cr3t@example.com/page", cfg, path="$.x"
    )
    assert isinstance(redacted, dict) and redacted["redacted"] is True
    assert "sha256" not in redacted  # strip_hash — the password is not hashed in


# ---------------------------------------------------------------------------
# Records still verify after redacting the new domains
# ---------------------------------------------------------------------------


async def test_type_covered_record_still_verifies(
    recorder: AuditRecorder, signing_key: SigningKey
) -> None:
    signed = await _record(
        recorder,
        tool=ToolCall(name=SECRET_KEY),
        input={PAN_INT: PAN_INT, SECRET_KEY.encode(): "v"},
    )
    result = verify_record(signed, {signing_key.key_id: signing_key.public_key})
    assert result.is_valid
    audit = redaction_authenticity(signed)
    assert audit.authentic
    blob = _signed_bytes(signed)
    assert PAN_STR not in blob
    assert SECRET_KEY not in blob
