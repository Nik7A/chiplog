"""Model-side lifecycle records — what the model was told, and what it said.

A chain used to hold every tool call a model made and never a word the model
produced. `llm_prompt` and `llm_turn` are the two records that close that
gap. Both carry host content, so they go through the recorder's redaction
and normalization like tool input/output; a node or route transition still
does not, because it carries only an identity.
"""

from __future__ import annotations

import math
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from chiplog.emit import AuditRecorder, RecordBuildError
from chiplog.integrity import compute_chain_link, verify_record
from chiplog.keys import SigningKey, compute_key_id
from chiplog.normalize import MARKER_KEY
from chiplog.redact import RedactionConfig, RedactionRule
from chiplog.schema.v1 import (
    LifecycleEventPayload,
    LifecyclePhase,
    LLMToolUse,
    LLMTurnTransition,
    NodeTransition,
    Output,
    PolicyUnobservedReason,
    ToolCall,
    llm_prompt_transition,
    llm_turn_transition,
    node_transition,
    policy_unobserved,
    success,
)
from chiplog.sinks.base import InMemorySink


def _signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


def _recorder(sink: InMemorySink, **kwargs: object) -> AuditRecorder:
    return AuditRecorder(sink=sink, signing_key=_signing_key(), **kwargs)  # type: ignore[arg-type]


# --- the phase set grew by exactly the two model-side events -----------------


def test_phase_set_is_the_three_graph_events_plus_two_model_events() -> None:
    assert {p.value for p in LifecyclePhase} == {
        "node_enter",
        "node_exit",
        "route",
        "llm_prompt",
        "llm_turn",
    }


# --- shape ---------------------------------------------------------------------


async def test_llm_turn_record_carries_text_and_tool_uses_and_nothing_else() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record_event(
        session_id="s",
        step_id="turn-3",
        phase=LifecyclePhase.LLM_TURN,
        transition=llm_turn_transition(
            3,
            text=["Reading the module first."],
            tool_uses=[LLMToolUse(id="toolu_01A", name="Read", input={"path": "x.py"})],
        ),
    )
    payload = signed["payload"]
    assert "tool" not in payload
    assert "policy" not in payload
    assert "outcome" not in payload
    assert payload["phase"] == "llm_turn"
    assert payload["transition"] == {
        "kind": "llm_turn",
        "turn": 3,
        "text": ["Reading the module first."],
        "tool_uses": [{"id": "toolu_01A", "name": "Read", "input": {"path": "x.py"}}],
    }


async def test_llm_prompt_record_carries_the_instructions_verbatim() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record_event(
        session_id="s",
        step_id="prompt",
        phase=LifecyclePhase.LLM_PROMPT,
        transition=llm_prompt_transition("You are the implement stage.\n\nRules: …"),
    )
    assert signed["payload"]["transition"] == {
        "kind": "llm_prompt",
        "instructions": "You are the implement stage.\n\nRules: …",
    }


def test_turn_numbers_start_at_one() -> None:
    with pytest.raises(ValidationError):
        LLMTurnTransition(turn=0)


# --- phase and transition must agree ------------------------------------------


def test_llm_turn_phase_rejects_a_node_transition() -> None:
    with pytest.raises(ValidationError):
        LifecycleEventPayload(
            time={"ts_utc": "2026-07-15T00:00:00.000000000Z", "ts_monotonic_ns": "1"},  # type: ignore[arg-type]
            phase=LifecyclePhase.LLM_TURN,
            transition=NodeTransition(node="start"),
        )


def test_node_phase_rejects_an_llm_prompt_transition() -> None:
    with pytest.raises(ValidationError):
        LifecycleEventPayload(
            time={"ts_utc": "2026-07-15T00:00:00.000000000Z", "ts_monotonic_ns": "1"},  # type: ignore[arg-type]
            phase=LifecyclePhase.NODE_ENTER,
            transition=llm_prompt_transition("x"),
        )


# --- content is redacted and normalized like tool output ----------------------


async def test_a_secret_in_the_turn_text_is_redacted_and_announced() -> None:
    sink = InMemorySink()
    key = _signing_key()
    rule = RedactionRule(
        policy_id="secret.deny.token",
        pattern=re.compile(r"sk-[A-Za-z0-9]{8,}"),
    )
    rec = AuditRecorder(
        sink=sink,
        signing_key=key,
        redaction_config=RedactionConfig(rules=(rule,)),
    )
    signed = await rec.record_event(
        session_id="s",
        step_id="turn-1",
        phase=LifecyclePhase.LLM_TURN,
        transition=llm_turn_transition(
            1,
            text=["Use the key sk-abcdefghijkl for the call."],
            tool_uses=[
                LLMToolUse(
                    id="toolu_1", name="Bash", input={"command": "echo sk-zzzzzzzzzzzz"}
                )
            ],
        ),
    )
    tr = signed["payload"]["transition"]
    # A matched string is replaced whole by a marker dict, never edited in place.
    assert isinstance(tr["text"][0], dict) and tr["text"][0]["redacted"] is True
    assert "sk-abcdefghijkl" not in str(tr["text"][0])
    assert isinstance(tr["tool_uses"][0]["input"]["command"], dict)
    assert "sk-zzzzzzzzzzzz" not in str(tr["tool_uses"][0]["input"]["command"])
    paths = {e["path"] for e in signed["payload"]["redaction"]}
    assert "$.transition.text[0]" in paths
    assert "$.transition.tool_uses[0].input.command" in paths
    assert verify_record(signed, {key.key_id: key.public_key}).is_valid


async def test_a_hostile_value_in_tool_use_input_becomes_a_marker() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    signed = await rec.record_event(
        session_id="s",
        step_id="turn-1",
        phase=LifecyclePhase.LLM_TURN,
        transition=llm_turn_transition(
            1, tool_uses=[LLMToolUse(id="toolu_1", name="Calc", input={"x": math.nan})]
        ),
    )
    # A not-finite float is not representable in JCS; normalization substitutes
    # an announced marker for it, exactly as it does for a tool output. (A JSON
    # mode dump on the way in would have laundered the nan into null with no
    # entry at all — this is the test that catches that.)
    marker = signed["payload"]["transition"]["tool_uses"][0]["input"]["x"]
    assert isinstance(marker, dict) and MARKER_KEY in marker
    entry = signed["payload"]["unrepresentable"][0]
    assert entry["path"] == "$.transition.tool_uses[0].input.x"
    assert entry["reason"] == "float_not_finite"


async def test_node_transitions_are_not_touched_by_the_content_pass() -> None:
    """A node id is an identity the instrumentation observed, not content; the
    content pass must not rewrite it even when a rule would match it."""
    sink = InMemorySink()
    rule = RedactionRule(policy_id="x", pattern=re.compile(r"start"))
    rec = AuditRecorder(
        sink=sink,
        signing_key=_signing_key(),
        redaction_config=RedactionConfig(rules=(rule,)),
    )
    signed = await rec.record_event(
        session_id="s",
        step_id="1",
        phase=LifecyclePhase.NODE_ENTER,
        transition=node_transition("start"),
    )
    assert signed["payload"]["transition"] == {"kind": "node", "node": "start"}
    assert signed["payload"]["redaction"] == []


# --- a turn joins its tool calls by the provider's tool-use id ----------------


async def test_turn_and_tool_call_share_one_chain_and_one_step_id() -> None:
    sink = InMemorySink()
    rec = _recorder(sink)
    turn = await rec.record_event(
        session_id="s",
        step_id="turn-1",
        phase=LifecyclePhase.LLM_TURN,
        transition=llm_turn_transition(
            1, tool_uses=[LLMToolUse(id="toolu_01A", name="Read", input={"path": "x"})]
        ),
    )
    call = await rec.record(
        session_id="s",
        step_id="toolu_01A",
        tool=ToolCall(name="Read"),
        input={"path": "x"},
        output=Output(body="…"),
        policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
        outcome=success(),
    )
    assert call["envelope"]["prev_hash"] == compute_chain_link(turn)
    assert (
        call["header"]["step_id"] == turn["payload"]["transition"]["tool_uses"][0]["id"]
    )


# --- the construction guard still holds ---------------------------------------


async def test_a_marker_on_the_join_key_poisons_the_head_rather_than_forging_it() -> (
    None
):
    """`LLMToolUse.id` is the join to the tool-call record and is typed `str`.
    A redaction rule that matches it would put a marker dict where the schema
    admits only a string; re-validation fails inside the construction guard,
    so the record is refused loudly and the chain head is poisoned — never a
    signed record whose join key is a sentinel that joins to nothing."""
    sink = InMemorySink()
    rule = RedactionRule(policy_id="x", pattern=re.compile(r"^toolu_"))
    rec = AuditRecorder(
        sink=sink,
        signing_key=_signing_key(),
        redaction_config=RedactionConfig(rules=(rule,)),
    )
    with pytest.raises(RecordBuildError):
        await rec.record_event(
            session_id="s",
            step_id="turn-1",
            phase=LifecyclePhase.LLM_TURN,
            transition=llm_turn_transition(
                1, tool_uses=[LLMToolUse(id="toolu_1", name="X", input={})]
            ),
        )
    assert sink.records == []
