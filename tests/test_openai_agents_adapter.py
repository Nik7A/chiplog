"""OpenAI Agents SDK adapter tests.

Covers:
- _extract_tool_name: tool.name preferred, falls back to context.tool_name, then "unknown_tool"
- _extract_tool_args: parses JSON string from ToolContext.tool_arguments, passes through dicts, handles malformed
- _extract_output_body: string passthrough, .output attribute, str() fallback
- raw extracted args/output are handed to the recorder; its normalize pass marks hostile values
- AuditHooks.on_tool_end emits a signed record via the recorder
- The emitted record carries the expected tool name, parsed args, output body, and agent name
- The record verifies under the same signing key
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_audit.adapters.openai_agents import (
    AuditHooks,
    _extract_output_body,
    _extract_tool_args,
    _extract_tool_name,
)
from agent_audit.emit import AuditRecorder
from agent_audit.integrity import verify_record
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.sinks.base import InMemorySink


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
def recorder(signing_key: SigningKey, sink: InMemorySink) -> AuditRecorder:
    return AuditRecorder(sink=sink, signing_key=signing_key)


# ---------------------------------------------------------------------------
# Minimal stand-ins for SDK objects (no openai-agents Runner / Agent needed)
# ---------------------------------------------------------------------------


@dataclass
class FakeTool:
    name: str


@dataclass
class FakeAgent:
    name: str


@dataclass
class FakeToolContext:
    tool_name: str
    tool_arguments: str
    tool_call_id: str = "call-abc-123"


@dataclass
class StructuredResult:
    output: Any


# ---------------------------------------------------------------------------
# Helper extractors
# ---------------------------------------------------------------------------


def test_extract_tool_name_prefers_tool_attr() -> None:
    tool = FakeTool(name="search_documents")
    ctx = FakeToolContext(tool_name="ctx_name", tool_arguments="{}")
    assert _extract_tool_name(tool, ctx) == "search_documents"


def test_extract_tool_name_falls_back_to_context() -> None:
    tool = object()  # no .name
    ctx = FakeToolContext(tool_name="search_documents", tool_arguments="{}")
    assert _extract_tool_name(tool, ctx) == "search_documents"


def test_extract_tool_name_returns_unknown_when_nothing_present() -> None:
    tool = object()
    ctx = object()
    assert _extract_tool_name(tool, ctx) == "unknown_tool"


def test_extract_tool_args_parses_json_string() -> None:
    ctx = FakeToolContext(
        tool_name="t",
        tool_arguments='{"query": "vat invoices", "limit": 50}',
    )
    assert _extract_tool_args(ctx) == {"query": "vat invoices", "limit": 50}


def test_extract_tool_args_returns_empty_when_missing() -> None:
    ctx = object()
    assert _extract_tool_args(ctx) == {}


def test_extract_tool_args_passes_malformed_string_through() -> None:
    ctx = FakeToolContext(tool_name="t", tool_arguments="not-json {[")
    assert _extract_tool_args(ctx) == "not-json {["


def test_extract_output_body_string_passthrough() -> None:
    assert _extract_output_body("matched 12 invoices") == "matched 12 invoices"


def test_extract_output_body_structured_result() -> None:
    result = StructuredResult(output={"matched": 12})
    assert _extract_output_body(result) == {"matched": 12}


def test_extract_output_body_falls_back_to_str() -> None:
    class Thing:
        def __repr__(self) -> str:
            return "<Thing custom>"

    assert _extract_output_body(Thing()) == "<Thing custom>"


# ---------------------------------------------------------------------------
# AuditHooks integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_tool_end_emits_signed_record(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    hooks = AuditHooks(recorder=recorder, session_id="test-session")
    ctx = FakeToolContext(
        tool_name="search_documents",
        tool_arguments='{"query": "Q4 2025 invoices"}',
    )
    tool = FakeTool(name="search_documents")
    agent = FakeAgent(name="finance_assistant")
    result = "matched 12 invoices"

    await hooks.on_tool_end(context=ctx, agent=agent, tool=tool, result=result)

    assert len(sink.records) == 1
    record = sink.records[0]

    assert record["header"]["session_id"] == "test-session"
    assert record["header"]["agent_name"] == "finance_assistant"
    assert record["payload"]["tool"]["name"] == "search_documents"
    assert record["payload"]["input"] == {"query": "Q4 2025 invoices"}
    assert record["payload"]["output"]["body"] == "matched 12 invoices"

    pubkey_by_id = {signing_key.key_id: signing_key.public_key}
    verification = verify_record(record, pubkey_by_id)
    assert verification.is_valid, verification.detail


@pytest.mark.asyncio
async def test_on_tool_end_handles_unknown_tool_and_missing_args(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hooks = AuditHooks(recorder=recorder)
    await hooks.on_tool_end(
        context=object(),
        agent=object(),
        tool=object(),
        result="ok",
    )

    assert len(sink.records) == 1
    record = sink.records[0]
    assert record["payload"]["tool"]["name"] == "unknown_tool"
    assert record["payload"]["input"] == {}
    assert record["payload"]["output"]["body"] == "ok"


@pytest.mark.asyncio
async def test_default_session_id_when_not_provided(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hooks = AuditHooks(recorder=recorder)
    ctx = FakeToolContext(tool_name="t", tool_arguments="{}")
    await hooks.on_tool_end(
        context=ctx, agent=FakeAgent(name="a"), tool=FakeTool(name="t"), result="ok"
    )
    assert sink.records[0]["header"]["session_id"] == "openai-agents-default"


@pytest.mark.asyncio
async def test_chain_of_two_records(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    """Two sequential tool calls produce a valid signed chain."""
    hooks = AuditHooks(recorder=recorder, session_id="chain-session")
    tool = FakeTool(name="t")
    agent = FakeAgent(name="a")

    for i in range(2):
        ctx = FakeToolContext(
            tool_name="t",
            tool_arguments=json.dumps({"i": i}),
        )
        await hooks.on_tool_end(context=ctx, agent=agent, tool=tool, result=f"r{i}")

    assert len(sink.records) == 2
    first, second = sink.records
    # Second record's prev_hash points at first record's chain link
    assert second["envelope"]["prev_hash"] is not None
    assert first["envelope"]["prev_hash"] is None

    pubkey_by_id = {signing_key.key_id: signing_key.public_key}
    for rec in (first, second):
        assert verify_record(rec, pubkey_by_id).is_valid


# ---------------------------------------------------------------------------
# Unobserved outcome — AuditHooks must never sign Success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audited_tool_on_openai_callable_records_error(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """The decorator sits inside the SDK's failure handling and sees the real exception."""
    from agent_audit.adapters.langgraph import audited_tool

    @audited_tool(recorder, session_id="oai")
    async def flaky_search(query: str) -> str:
        raise RuntimeError("upstream 503")

    with pytest.raises(RuntimeError):
        await flaky_search("cats")

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "RuntimeError"
    assert outcome["message"] == "upstream 503"


@pytest.mark.asyncio
async def test_audit_hooks_never_asserts_success(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """on_tool_end cannot tell success from failure, so it must not claim either.

    Even on a genuinely successful call the hook records Unobserved: from where
    it sits, a success and an SDK-laundered failure are byte-identical.
    """
    hooks = AuditHooks(recorder=recorder, session_id="oai")
    await hooks.on_tool_end(
        context=FakeToolContext(tool_name="search", tool_arguments='{"q": "cats"}'),
        agent=FakeAgent(name="researcher"),
        tool=FakeTool(name="search"),
        result="found 3 results",
    )
    assert sink.records[-1]["payload"]["outcome"] == {
        "kind": "unobserved",
        "reason": "runtime_launders_exceptions",
    }


@pytest.mark.asyncio
async def test_audit_hooks_records_laundered_failure_as_unobserved(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """The SDK's error text arrives as an ordinary result — still Unobserved, not Success."""
    hooks = AuditHooks(recorder=recorder, session_id="oai")
    await hooks.on_tool_end(
        context=FakeToolContext(tool_name="search", tool_arguments='{"q": "cats"}'),
        agent=FakeAgent(name="researcher"),
        tool=FakeTool(name="search"),
        result="An error occurred while running the tool. Please try again. Error: boom",
    )
    assert sink.records[-1]["payload"]["outcome"]["kind"] == "unobserved"
