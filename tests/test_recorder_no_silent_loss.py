"""End-to-end: the recorder must not silently lose or launder evidence.

Before this fix, a tool arg carrying an int >= 2**53 (or nan/inf/bytes/set)
either RAISED inside canonicalization — the record vanished with NO chain break —
or was silently laundered (bytes -> str, nan -> null) and signed as if genuine.

Part B (normalization) turns the representable-but-hostile kinds into announced
markers, recorded faithfully. Part C (defense in depth) guarantees that anything
still un-canonicalizable fails LOUDLY, leaving a detectable trace instead of
vanishing.
"""

from __future__ import annotations

import math

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_audit.emit import AuditRecorder, RecordSigningError
from agent_audit.integrity import verify_record
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.normalize import MARKER_KEY
from agent_audit.schema.v1 import (
    NoGateReason,
    Output,
    ToolCall,
    error,
    success,
    ungated,
)
from agent_audit.sinks.base import InMemorySink


def _signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


def _recorder(sink: InMemorySink) -> AuditRecorder:
    return AuditRecorder(sink=sink, signing_key=_signing_key())


# --- Part B: representable-but-hostile inputs are recorded faithfully ---------


async def test_big_int_input_is_recorded_not_dropped() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record(
        session_id="s",
        step_id="1",
        tool=ToolCall(name="t"),
        input={"count": 2**53 + 7},
        output=Output(),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    # It was written, it verifies, and the substitution is announced.
    assert len(sink.records) == 1
    marker = signed["payload"]["input"]["count"]
    assert marker[MARKER_KEY] == "unrepresentable"
    assert len(signed["payload"]["unrepresentable"]) == 1
    result = verify_record(signed, {rec._signing_key.key_id: rec._signing_key.public_key})
    assert result.is_valid


async def test_bytes_output_is_not_laundered_into_a_string() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record(
        session_id="s",
        step_id="1",
        tool=ToolCall(name="t"),
        input={},
        output=Output(body={"blob": b"super-secret"}),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    import rfc8785

    assert "super-secret" not in rfc8785.dumps(signed).decode()
    assert signed["payload"]["output"]["body"]["blob"][MARKER_KEY] == "unrepresentable"


async def test_nan_in_error_message_is_marked_and_announced() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record(
        session_id="s",
        step_id="1",
        tool=ToolCall(name="t"),
        input={},
        output=Output(),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=error("ValueError", {"nan_field": math.nan}),
    )
    assert signed["payload"]["outcome"]["message"]["nan_field"][MARKER_KEY] == (
        "unrepresentable"
    )
    assert any(
        e["path"].startswith("$.outcome.message")
        for e in signed["payload"]["unrepresentable"]
    )


async def test_clean_record_has_empty_unrepresentable_list() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record(
        session_id="s",
        step_id="1",
        tool=ToolCall(name="t"),
        input={"a": 1},
        output=Output(body="ok"),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    assert signed["payload"]["unrepresentable"] == []


# --- Part C: an input Part B does NOT catch must fail LOUDLY, never silently --


def _surrogate_input() -> dict[str, str]:
    # A lone UTF-16 surrogate cannot be encoded to UTF-8, so rfc8785 refuses it.
    # normalize passes strings through, so this reaches signing intact — a real
    # defense-in-depth trigger, not a mock.
    return {"s": "\ud800"}


async def test_uncanonicalizable_input_raises_typed_error() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    with pytest.raises(RecordSigningError):
        await rec.record(
            session_id="s",
            step_id="1",
            tool=ToolCall(name="t"),
            input=_surrogate_input(),
            output=Output(),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            outcome=success(),
        )
    # The record was NOT written...
    assert sink.records == []


async def test_silent_loss_now_leaves_a_chain_break_trace() -> None:
    """The core guarantee: a record that used to vanish silently now leaves a
    trace a verifier can see. Even if the caller swallows RecordSigningError, the
    NEXT successfully-recorded record breaks the chain, because the failed record
    poisoned the chain head."""
    sink = InMemorySink()
    rec = _recorder(sink)

    a = await rec.record(
        session_id="s",
        step_id="a",
        tool=ToolCall(name="t"),
        input={"ok": 1},
        output=Output(),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )

    # A caller (like every adapter) that swallows the recorder failure.
    try:
        await rec.record(
            session_id="s",
            step_id="b",
            tool=ToolCall(name="t"),
            input=_surrogate_input(),
            output=Output(),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            outcome=success(),
        )
    except RecordSigningError:
        pass

    c = await rec.record(
        session_id="s",
        step_id="c",
        tool=ToolCall(name="t"),
        input={"ok": 2},
        output=Output(),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )

    from agent_audit.integrity import compute_chain_link

    # c does NOT chain onto a — the dropped record poisoned the head, so the gap
    # is visible as a chain break rather than an invisible hole.
    assert c["envelope"]["prev_hash"] != compute_chain_link(a)
    assert sink.records == [a, c]
