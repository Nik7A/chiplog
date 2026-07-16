"""Outcome union: construction, discrimination, and cross-field consistency."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_audit.schema.v1 import (
    SCHEMA_VERSION,
    Denied,
    Error,
    GateDecision,
    NoGateReason,
    Output,
    Payload,
    Success,
    TimeBlock,
    Timeout,
    ToolCall,
    Unobserved,
    UnobservedReason,
    denied,
    error,
    gate,
    success,
    timeout,
    ungated,
    unobserved,
)


def _time() -> TimeBlock:
    return TimeBlock(ts_utc="2026-07-14T10:00:00.000000000Z", ts_monotonic_ns=1)


def _payload(outcome, policy):  # type: ignore[no-untyped-def]
    return Payload(
        time=_time(),
        tool=ToolCall(name="read_file"),
        input={"path": "/tmp/x"},
        output=Output(body="ok"),
        policy=policy,
        outcome=outcome,
    )


def test_schema_version_is_v1_2() -> None:
    assert SCHEMA_VERSION == "v1.2"


def test_success_variant() -> None:
    p = _payload(success(), ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK))
    assert isinstance(p.outcome, Success)
    assert p.outcome.kind == "success"


def test_error_variant_carries_type_and_message() -> None:
    p = _payload(
        error("ConnectionError", "connection refused"),
        ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
    )
    assert isinstance(p.outcome, Error)
    assert p.outcome.error_type == "ConnectionError"
    assert p.outcome.message == "connection refused"


def test_timeout_variant_carries_elapsed_ms() -> None:
    p = _payload(timeout(30_000), ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK))
    assert isinstance(p.outcome, Timeout)
    assert p.outcome.elapsed_ms == 30_000


def test_timeout_rejects_negative_elapsed() -> None:
    with pytest.raises(ValidationError):
        Timeout(elapsed_ms=-1)


def test_outcome_is_required() -> None:
    with pytest.raises(ValidationError):
        Payload(
            time=_time(),
            tool=ToolCall(name="read_file"),
            input={},
            output=Output(),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        )  # type: ignore[call-arg]


def test_outcome_variants_forbid_extra_keys() -> None:
    with pytest.raises(ValidationError):
        Success(kind="success", surprise=1)  # type: ignore[call-arg]


def test_unobserved_variant_carries_reason() -> None:
    p = _payload(
        unobserved(UnobservedReason.RUNTIME_LAUNDERS_EXCEPTIONS),
        ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
    )
    assert isinstance(p.outcome, Unobserved)
    assert p.outcome.reason == UnobservedReason.RUNTIME_LAUNDERS_EXCEPTIONS


def test_unobserved_requires_a_reason() -> None:
    """An unobservable outcome is an assertion, not a shrug — it must say why."""
    with pytest.raises(ValidationError):
        Unobserved()  # type: ignore[call-arg]


def test_unobserved_rejects_unknown_reason() -> None:
    """The reason enum is closed: blind spots stay few and reviewable."""
    with pytest.raises(ValidationError):
        Unobserved(reason="whatever")  # type: ignore[arg-type]


# --- cross-field consistency: denied <=> Gate(decision=deny) ---


def test_denied_with_matching_gate_deny_passes() -> None:
    p = _payload(denied("policy.fs.write"), gate("policy.fs.write", GateDecision.DENY))
    assert isinstance(p.outcome, Denied)
    assert p.outcome.policy_id == "policy.fs.write"


def test_denied_outcome_without_deny_gate_raises() -> None:
    with pytest.raises(ValidationError, match="denied"):
        _payload(denied("policy.fs.write"), ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK))


def test_denied_outcome_with_allow_gate_raises() -> None:
    with pytest.raises(ValidationError, match="denied"):
        _payload(denied("policy.fs.write"), gate("policy.fs.write", GateDecision.ALLOW))


def test_deny_gate_without_denied_outcome_raises() -> None:
    with pytest.raises(ValidationError, match="denied"):
        _payload(success(), gate("policy.fs.write", GateDecision.DENY))


def test_denied_policy_id_must_match_gate_policy_id() -> None:
    with pytest.raises(ValidationError, match="policy_id"):
        _payload(denied("policy.other"), gate("policy.fs.write", GateDecision.DENY))
