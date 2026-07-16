"""Lifecycle-event records — a node/router event is NOT a tool call.

81% of bosun's real trail (node.enter / node.exit / route) was shoehorned into
the tool-call schema, carrying a fabricated tool AND a fabricated policy. This
record type expresses a lifecycle event honestly: no tool, no policy, no
synthesized outcome. Runtime-reported status/risk live in an `attributes` bag
documented as UNATTESTED.
"""

from __future__ import annotations

import math

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from chiplog.emit import AuditRecorder, RecordBuildError
from chiplog.integrity import compute_chain_link, verify_record
from chiplog.keys import SigningKey, compute_key_id
from chiplog.normalize import MARKER_KEY
from chiplog.schema.v1 import (
    LifecycleEventPayload,
    LifecyclePhase,
    NodeTransition,
    Output,
    PolicyUnobservedReason,
    RouteTransition,
    ToolCall,
    node_transition,
    policy_unobserved,
    route_transition,
    success,
)
from chiplog.sinks.base import InMemorySink


def _signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


def _recorder(sink: InMemorySink) -> AuditRecorder:
    return AuditRecorder(sink=sink, signing_key=_signing_key())


# --- phase set is exactly the three real bosun events ------------------------


def test_phase_set_matches_real_bosun_events() -> None:
    assert {p.value for p in LifecyclePhase} == {"node_enter", "node_exit", "route"}


# --- a lifecycle record carries NO tool / policy / outcome -------------------


async def test_node_enter_record_has_no_tool_policy_or_outcome() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record_event(
        session_id="s",
        step_id="1",
        phase=LifecyclePhase.NODE_ENTER,
        transition=node_transition("start"),
    )
    payload = signed["payload"]
    assert "tool" not in payload
    assert "policy" not in payload
    assert "outcome" not in payload
    assert payload["phase"] == "node_enter"
    assert payload["transition"] == {"kind": "node", "node": "start"}


async def test_route_transition_has_no_from_to_node_only_chosen() -> None:
    """A route decision names a router-CLAIMED chosen edge/skill. It must NOT
    carry a node id — the recorder observed a choice, not a node traversal."""
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record_event(
        session_id="s",
        step_id="1",
        phase=LifecyclePhase.ROUTE,
        transition=route_transition("spec_critic"),
    )
    tr = signed["payload"]["transition"]
    assert tr == {"kind": "route", "chosen": "spec_critic"}
    assert "node" not in tr


# --- phase and transition must agree (honest structural constraint) ----------


def test_route_phase_rejects_a_node_transition() -> None:
    with pytest.raises(ValidationError):
        LifecycleEventPayload(
            time={"ts_utc": "2026-07-15T00:00:00.000000000Z", "ts_monotonic_ns": "1"},  # type: ignore[arg-type]
            phase=LifecyclePhase.ROUTE,
            transition=NodeTransition(node="start"),
        )


def test_node_phase_rejects_a_route_transition() -> None:
    with pytest.raises(ValidationError):
        LifecycleEventPayload(
            time={"ts_utc": "2026-07-15T00:00:00.000000000Z", "ts_monotonic_ns": "1"},  # type: ignore[arg-type]
            phase=LifecyclePhase.NODE_EXIT,
            transition=RouteTransition(chosen="x"),
        )


# --- attributes are runtime-reported and UNATTESTED --------------------------


async def test_attributes_carry_runtime_status_and_verify() -> None:
    sink = InMemorySink()
    key = _signing_key()
    rec = AuditRecorder(sink=sink, signing_key=key)
    signed = await rec.record_event(
        session_id="s",
        step_id="1",
        phase=LifecyclePhase.NODE_EXIT,
        transition=node_transition("execute"),
        attributes={"status": "ok", "duration_ms": 42},
    )
    assert signed["payload"]["attributes"] == {"status": "ok", "duration_ms": 42}
    result = verify_record(signed, {key.key_id: key.public_key})
    assert result.is_valid


async def test_lifecycle_record_chains_with_tool_calls() -> None:
    """A lifecycle event and a tool call share one chain: record() and
    record_event() advance the same head."""
    sink = InMemorySink()
    rec = _recorder(sink)
    a = await rec.record_event(
        session_id="s",
        step_id="a",
        phase=LifecyclePhase.NODE_ENTER,
        transition=node_transition("start"),
    )
    b = await rec.record(
        session_id="s",
        step_id="b",
        tool=ToolCall(name="claude_cli"),
        input={"task": "x"},
        output=Output(body={"ok": True}),
        policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
        outcome=success(),
    )
    assert b["envelope"]["prev_hash"] == compute_chain_link(a)
    assert a["envelope"]["prev_hash"] is None


# --- construction guard: a hostile attribute never vanishes silently ---------


async def test_hostile_attribute_is_marked_not_dropped() -> None:
    """A big int / nan in the attributes bag is normalized to an announced
    marker rather than crashing signing invisibly — record_event inherits the
    area-1 construction guard."""
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record_event(
        session_id="s",
        step_id="1",
        phase=LifecyclePhase.NODE_EXIT,
        transition=node_transition("execute"),
        attributes={"weird": 2**53 + 9, "worse": math.nan},
    )
    attrs = signed["payload"]["attributes"]
    assert attrs["weird"][MARKER_KEY] == "unrepresentable"
    assert attrs["worse"][MARKER_KEY] == "unrepresentable"
    assert len(signed["payload"]["unrepresentable"]) == 2


async def test_uncanonicalizable_attribute_poisons_chain_not_silent() -> None:
    """The area-1 guarantee, now for record_event: a value signing cannot encode
    (a lone surrogate) raises a typed error AND poisons the head, so the next
    record breaks the chain instead of the loss vanishing."""
    from chiplog.emit import RecordSigningError

    sink = InMemorySink()
    rec = _recorder(sink)
    a = await rec.record_event(
        session_id="s",
        step_id="a",
        phase=LifecyclePhase.NODE_ENTER,
        transition=node_transition("start"),
    )
    with pytest.raises(RecordBuildError):
        await rec.record_event(
            session_id="s",
            step_id="b",
            phase=LifecyclePhase.NODE_EXIT,
            transition=node_transition("start"),
            attributes={"s": "\ud800"},
        )
    c = await rec.record_event(
        session_id="s",
        step_id="c",
        phase=LifecyclePhase.NODE_ENTER,
        transition=node_transition("route"),
    )
    assert c["envelope"]["prev_hash"] != compute_chain_link(a)
    assert isinstance(RecordSigningError("x"), RecordBuildError)


def test_record_event_sync_twin_exists_and_records() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = rec.record_event_sync(
        session_id="s",
        step_id="1",
        phase=LifecyclePhase.NODE_ENTER,
        transition=node_transition("start"),
    )
    assert signed["payload"]["phase"] == "node_enter"
    assert len(sink.records) == 1


def test_lifecycle_payload_rejects_unknown_field_extra_forbid() -> None:
    """A policy/risk/outcome must never be smuggled into a lifecycle record via an extra field."""
    from pydantic import ValidationError
    from chiplog.schema.v1 import LifecycleEventPayload, LifecyclePhase

    ok = LifecycleEventPayload(
        time={"ts_utc": "2026-07-15T00:00:00.000000000Z", "ts_monotonic_ns": "1"},  # type: ignore[arg-type]
        phase=LifecyclePhase.NODE_ENTER,
        transition=node_transition("start"),
    )
    for smuggled in ("policy", "outcome", "tool", "risk"):
        with pytest.raises(ValidationError):
            LifecycleEventPayload.model_validate(
                {**ok.model_dump(mode="json"), smuggled: {"kind": "none"}}
            )
