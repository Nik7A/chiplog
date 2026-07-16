"""Step 3: AuditRecorder facade — sign + redact + chain + write.

Covers BUILD_PLAN Step 3 verification gate:
- record() emits chain-valid, signed records
- email in input is redacted; the resulting record still verifies
- chain head advances correctly across multiple records
- record_sync wraps async correctly OUTSIDE a loop; refuses INSIDE one
- closed sink rejects further writes
- gate / ungated policies both flow through correctly
- chain_id defaults to first session_id, can be overridden
- parent_session_id captures Claude Code subagent dispatch
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_audit.emit import AuditRecorder
from agent_audit.integrity import compute_chain_link, verify_record
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.redact import RedactionConfig
from agent_audit.schema.v1 import (
    GateDecision,
    NoGateReason,
    Output,
    ToolCall,
    error,
    gate,
    success,
    timeout,
    ungated,
)
from agent_audit.sinks.base import InMemorySink, SinkError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


@pytest.fixture
def sink() -> InMemorySink:
    return InMemorySink()


@pytest.fixture
def recorder(sink: InMemorySink, signing_key: SigningKey) -> AuditRecorder:
    return AuditRecorder(sink=sink, signing_key=signing_key)


def _read_args(input_field: object) -> dict[str, object]:
    """Cast input_field to dict for assertions. Pytest narrowing helper."""
    assert isinstance(input_field, dict)
    return input_field


# ---------------------------------------------------------------------------
# Round-trip: emit + write + verify
# ---------------------------------------------------------------------------


async def test_record_writes_signed_record_to_sink(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    signed = await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={"file_path": "/etc/hosts"},
        output=Output(body="127.0.0.1 localhost"),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )

    assert sink.records == [signed]
    result = verify_record(signed, {signing_key.key_id: signing_key.public_key})
    assert result.is_valid


async def test_genesis_record_has_null_prev_hash(recorder: AuditRecorder) -> None:
    signed = await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    assert signed["envelope"]["prev_hash"] is None


async def test_chain_advances_to_previous_chain_link(
    recorder: AuditRecorder,
) -> None:
    """Second record's prev_hash == compute_chain_link of first record."""
    r1 = await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    r2 = await recorder.record(
        session_id="sess-1",
        step_id="step-2",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )

    assert r2["envelope"]["prev_hash"] == compute_chain_link(r1)


# ---------------------------------------------------------------------------
# Redaction integration
# ---------------------------------------------------------------------------


async def test_email_in_input_is_redacted_and_record_still_verifies(
    recorder: AuditRecorder, signing_key: SigningKey
) -> None:
    signed = await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={"message": "ping foo@bar.com"},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )

    args = _read_args(signed["payload"]["input"])
    assert isinstance(args["message"], dict)
    assert args["message"]["redacted"] is True
    assert args["message"]["policy"] == "pii.deny.email"

    redaction = signed["payload"]["redaction"]
    assert len(redaction) == 1
    assert redaction[0]["path"] == "$.input.message"

    result = verify_record(signed, {signing_key.key_id: signing_key.public_key})
    assert result.is_valid


async def test_aws_key_in_output_redacted_without_sha256(
    recorder: AuditRecorder,
) -> None:
    signed = await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Bash"),
        input={"command": "env"},
        output=Output(body={"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    output_body = signed["payload"]["output"]["body"]
    assert isinstance(output_body, dict)
    marker = output_body["AWS_ACCESS_KEY_ID"]
    assert marker["redacted"] is True
    assert "sha256" not in marker


async def test_redaction_disabled_records_intact_email(
    sink: InMemorySink, signing_key: SigningKey
) -> None:
    config = RedactionConfig(disable=True)
    recorder = AuditRecorder(
        sink=sink, signing_key=signing_key, redaction_config=config
    )
    signed = await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={"email": "foo@bar.com"},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    args = _read_args(signed["payload"]["input"])
    assert args["email"] == "foo@bar.com"
    assert signed["payload"]["redaction"] == []


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


async def test_record_with_gate_policy(recorder: AuditRecorder) -> None:
    signed = await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Bash"),
        input={"command": "rm -rf /tmp/foo"},
        output=Output(body="done"),
        policy=gate("safety.bash_rm", GateDecision.ALLOW, approver="nik@cli"),
        outcome=success(),
    )
    policy = signed["payload"]["policy"]
    assert policy["kind"] == "gate"
    assert policy["policy_id"] == "safety.bash_rm"
    assert policy["decision"] == "allow"
    assert policy["approver"] == "nik@cli"


async def test_ungated_record_carries_reason(recorder: AuditRecorder) -> None:
    signed = await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    policy = signed["payload"]["policy"]
    assert policy["kind"] == "none"
    assert policy["reason"] == "auto_allowed_low_risk"


# ---------------------------------------------------------------------------
# chain_id
# ---------------------------------------------------------------------------


async def test_chain_id_defaults_to_first_session_id(
    recorder: AuditRecorder,
) -> None:
    r = await recorder.record(
        session_id="sess-XYZ",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    assert r["envelope"]["chain_id"] == "sess-XYZ"


async def test_explicit_chain_id_overrides_session(
    sink: InMemorySink, signing_key: SigningKey
) -> None:
    recorder = AuditRecorder(
        sink=sink, signing_key=signing_key, chain_id="custom-chain"
    )
    r = await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    assert r["envelope"]["chain_id"] == "custom-chain"


# ---------------------------------------------------------------------------
# Subagent parent_session_id
# ---------------------------------------------------------------------------


async def test_parent_session_id_captured_in_header(
    recorder: AuditRecorder,
) -> None:
    signed = await recorder.record(
        session_id="sub-sess-1",
        step_id="step-1",
        tool=ToolCall(name="Write"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
        parent_session_id="parent-sess-A",
    )
    assert signed["header"]["parent_session_id"] == "parent-sess-A"


# ---------------------------------------------------------------------------
# Sync wrapper
# ---------------------------------------------------------------------------


def test_record_sync_works_outside_event_loop(
    sink: InMemorySink, signing_key: SigningKey
) -> None:
    """The Claude Code hook handler runs as a one-shot subprocess with no loop —
    record_sync must work in that scenario."""
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)
    signed = recorder.record_sync(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    assert signed["envelope"]["hash"] is not None
    assert signed["envelope"]["signature"] is not None


async def test_record_sync_inside_event_loop_raises(
    recorder: AuditRecorder,
) -> None:
    """If someone accidentally calls record_sync from async code, raise loud
    rather than silently nesting event loops."""
    with pytest.raises(RuntimeError, match="running event loop"):
        recorder.record_sync(
            session_id="sess-1",
            step_id="step-1",
            tool=ToolCall(name="Read"),
            input={},
            output=Output(body=""),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            outcome=success(),
        )


# ---------------------------------------------------------------------------
# Sink lifecycle
# ---------------------------------------------------------------------------


async def test_closed_recorder_rejects_writes(
    sink: InMemorySink, signing_key: SigningKey
) -> None:
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)
    await recorder.close()

    with pytest.raises(SinkError):
        await recorder.record(
            session_id="sess-1",
            step_id="step-1",
            tool=ToolCall(name="Read"),
            input={},
            output=Output(body=""),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            outcome=success(),
        )


async def test_flush_propagates_to_sink(recorder: AuditRecorder) -> None:
    """Smoke test that flush() doesn't crash. InMemorySink.flush is a no-op;
    real LocalFileSink (Step 4) will exercise the durability contract."""
    await recorder.record(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    await recorder.flush()


# ---------------------------------------------------------------------------
# Outcome
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_emits_success_outcome(recorder, sink) -> None:  # type: ignore[no-untyped-def]
    await recorder.record(
        session_id="s1",
        step_id="step-1",
        tool=ToolCall(name="read_file"),
        input={"path": "/tmp/x"},
        output=Output(body="ok"),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    rec = sink.records[-1]
    assert rec["payload"]["outcome"] == {"kind": "success"}


@pytest.mark.asyncio
async def test_record_emits_error_outcome(recorder, sink) -> None:  # type: ignore[no-untyped-def]
    await recorder.record(
        session_id="s1",
        step_id="step-1",
        tool=ToolCall(name="fetch"),
        input={},
        output=Output(body=None),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=error("ConnectionError", "connection refused"),
    )
    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "ConnectionError"
    assert outcome["message"] == "connection refused"


@pytest.mark.asyncio
async def test_error_message_is_redacted(recorder, sink) -> None:  # type: ignore[no-untyped-def]
    """An exception string routinely carries the very material redaction exists for."""
    await recorder.record(
        session_id="s1",
        step_id="step-1",
        tool=ToolCall(name="fetch"),
        input={},
        output=Output(body=None),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=error("AuthError", "401 for user alice@example.com"),
    )
    rec = sink.records[-1]
    message = rec["payload"]["outcome"]["message"]
    assert isinstance(message, dict)
    assert message["redacted"] is True
    assert message["policy"] == "pii.deny.email"
    assert "alice@example.com" not in json.dumps(rec)

    paths = [e["path"] for e in rec["payload"]["redaction"]]
    assert "$.outcome.message" in paths


@pytest.mark.asyncio
async def test_success_outcome_has_no_message_to_redact(recorder, sink) -> None:  # type: ignore[no-untyped-def]
    """Non-Error variants pass through untouched — no spurious redaction entries."""
    await recorder.record(
        session_id="s1",
        step_id="step-1",
        tool=ToolCall(name="sleep"),
        input={},
        output=Output(body=None),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=timeout(30_000),
    )
    rec = sink.records[-1]
    assert rec["payload"]["outcome"] == {"kind": "timeout", "elapsed_ms": 30000}
    assert rec["payload"]["redaction"] == []
