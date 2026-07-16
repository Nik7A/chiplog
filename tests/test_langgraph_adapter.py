"""Step 6.5: LangGraph adapter tests.

Covers:
- @audited_tool on a sync function: records input, records output, verifier accepts
- @audited_tool on an async function (verified via plain pytest-asyncio test)
- @audited_tool preserves return value and metadata (__name__, __doc__)
- AuditMiddleware.wrap_tool_call records the tool call from a fake ToolCallRequest
- AuditMiddleware.awrap_tool_call records the tool call from async path
- AuditMiddleware extracts tool name and args from dict-shaped tool_call
- AuditMiddleware handles ToolMessage-shaped results (content attr) and raw returns
- Real create_agent integration: build a tiny agent, invoke a single tool, audit log
  contains the expected record, verifier returns exit 0
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import PublicFormat

# Module scope, not function scope, unlike the other LangChain imports in this
# file: `from __future__ import annotations` makes every annotation a string,
# and LangChain resolves an `@tool`'s annotations against its MODULE globals.
# `Annotated[str, InjectedToolCallId]` and `-> Command` on the e2e tools below
# therefore have to be resolvable from here.
from langchain_core.tools import InjectedToolCallId
from langgraph.types import Command

from agent_audit.adapters.langgraph import (
    AuditMiddleware,
    _extract_output_body,
    _extract_tool_info,
    audited_tool,
)
from agent_audit.emit import AuditRecorder
from agent_audit.integrity import verify_record
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.sinks.base import InMemorySink


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


# ---------------------------------------------------------------------------
# @audited_tool
# ---------------------------------------------------------------------------


def test_audited_tool_sync_records_and_returns(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    @audited_tool(recorder, session_id="demo")
    def add(x: int, y: int) -> int:
        return x + y

    result = add(2, 3)
    assert result == 5

    assert len(sink.records) == 1
    rec = sink.records[0]
    assert rec["payload"]["tool"]["name"] == "add"
    assert rec["payload"]["output"]["body"] == 5
    assert rec["payload"]["input"]["kwargs"] == {}

    # Audit record verifies
    assert verify_record(rec, {signing_key.key_id: signing_key.public_key}).is_valid


def test_audited_tool_captures_kwargs(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="demo")
    def search(query: str, limit: int = 10) -> list[str]:
        return [f"{query}-{i}" for i in range(min(limit, 2))]

    search(query="foo", limit=2)
    rec = sink.records[0]
    assert rec["payload"]["input"]["kwargs"] == {"query": "foo", "limit": 2}
    assert rec["payload"]["output"]["body"] == ["foo-0", "foo-1"]


def test_audited_tool_preserves_metadata(recorder: AuditRecorder) -> None:
    @audited_tool(recorder)
    def my_func(x: int) -> int:
        """Original docstring."""
        return x

    assert my_func.__name__ == "my_func"
    assert my_func.__doc__ == "Original docstring."


def test_audited_tool_custom_name(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, tool_name="custom_label")
    def some_fn() -> str:
        return "ok"

    some_fn()
    assert sink.records[0]["payload"]["tool"]["name"] == "custom_label"


async def test_audited_tool_async_records_and_returns(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="demo")
    async def fetch(url: str) -> str:
        return f"<body of {url}>"

    result = await fetch(url="https://example.com")
    assert result == "<body of https://example.com>"

    rec = sink.records[0]
    assert rec["payload"]["tool"]["name"] == "fetch"
    assert rec["payload"]["input"]["kwargs"] == {"url": "https://example.com"}


def test_audited_tool_chain_advances_across_calls(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    from agent_audit.integrity import compute_chain_link

    @audited_tool(recorder)
    def noop() -> int:
        return 0

    noop()
    noop()
    noop()

    r0, r1, r2 = sink.records
    assert r0["envelope"]["prev_hash"] is None
    assert r1["envelope"]["prev_hash"] == compute_chain_link(r0)
    assert r2["envelope"]["prev_hash"] == compute_chain_link(r1)


@pytest.mark.asyncio
async def test_audited_tool_records_error_and_reraises(recorder, sink) -> None:  # type: ignore[no-untyped-def]
    @audited_tool(recorder, session_id="s1")
    async def failing_tool(x: int) -> int:
        raise ConnectionError("connection refused")

    with pytest.raises(ConnectionError):
        await failing_tool(1)

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "ConnectionError"
    assert outcome["message"] == "connection refused"


@pytest.mark.asyncio
async def test_audited_tool_records_timeout(recorder, sink) -> None:  # type: ignore[no-untyped-def]
    @audited_tool(recorder, session_id="s1")
    async def slow_tool() -> None:
        raise asyncio.TimeoutError()

    with pytest.raises(asyncio.TimeoutError):
        await slow_tool()

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "timeout"
    assert outcome["elapsed_ms"] >= 0


@pytest.mark.asyncio
async def test_audited_tool_records_success(recorder, sink) -> None:  # type: ignore[no-untyped-def]
    @audited_tool(recorder, session_id="s1")
    async def ok_tool(x: int) -> int:
        return x + 1

    assert await ok_tool(1) == 2
    assert sink.records[-1]["payload"]["outcome"] == {"kind": "success"}


@pytest.mark.asyncio
async def test_failed_tool_output_body_is_none(recorder, sink) -> None:  # type: ignore[no-untyped-def]
    @audited_tool(recorder, session_id="s1")
    async def failing_tool() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        await failing_tool()

    assert sink.records[-1]["payload"]["output"]["body"] is None


def test_audited_tool_sync_records_error_and_reraises(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="s1")
    def failing_tool(x: int) -> int:
        raise ConnectionError("connection refused")

    with pytest.raises(ConnectionError):
        failing_tool(1)

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "ConnectionError"
    assert outcome["message"] == "connection refused"
    assert sink.records[-1]["payload"]["output"]["body"] is None


def test_audited_tool_sync_records_timeout(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """Sync decorator path: asyncio.TimeoutError must be caught BEFORE the
    generic Exception handler (it aliases builtin TimeoutError, a subclass
    of OSError, since Python 3.11). A reversed except order still catches
    it via the generic handler and mislabels it as 'error'."""

    @audited_tool(recorder, session_id="s1")
    def slow_tool() -> None:
        raise asyncio.TimeoutError()

    with pytest.raises(asyncio.TimeoutError):
        slow_tool()

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "timeout"
    assert outcome["elapsed_ms"] >= 0


# ---------------------------------------------------------------------------
# Recorder failures must never mask the tool's original exception
# ---------------------------------------------------------------------------


class _RaisingSink:
    """A sink whose write() always fails — simulates a degraded sink (e.g.
    a full disk) so we can assert the audit layer never lets that failure
    replace the tool's original exception."""

    async def write(self, record: dict[str, Any]) -> None:
        raise RuntimeError("disk full")

    async def flush(self) -> None:
        return

    async def close(self) -> None:
        return


@pytest.fixture
def raising_recorder(signing_key: SigningKey) -> AuditRecorder:
    return AuditRecorder(sink=_RaisingSink(), signing_key=signing_key)


@pytest.mark.asyncio
async def test_audited_tool_async_recorder_failure_does_not_mask_original_exception(
    raising_recorder: AuditRecorder,
) -> None:
    """If recorder.record() raises while recording a tool failure, the
    tool's ORIGINAL exception must still reach the caller — never the
    recorder's (sink) exception."""

    @audited_tool(raising_recorder, session_id="s1")
    async def failing_tool() -> None:
        raise ConnectionError("original failure")

    with pytest.raises(ConnectionError, match="original failure"):
        await failing_tool()


def test_audited_tool_sync_recorder_failure_does_not_mask_original_exception(
    raising_recorder: AuditRecorder,
) -> None:
    @audited_tool(raising_recorder, session_id="s1")
    def failing_tool() -> None:
        raise ConnectionError("original failure")

    with pytest.raises(ConnectionError, match="original failure"):
        failing_tool()


def test_middleware_wrap_tool_call_recorder_failure_does_not_mask_original_exception(
    raising_recorder: AuditRecorder,
) -> None:
    mw = AuditMiddleware(raising_recorder, session_id="sync-session")

    def handler(request: Any) -> Any:
        raise ConnectionError("original failure")

    request = _FakeRequest("add", {"x": 1, "y": 2})
    with pytest.raises(ConnectionError, match="original failure"):
        mw.wrap_tool_call(request, handler)


async def test_middleware_awrap_tool_call_recorder_failure_does_not_mask_original_exception(
    raising_recorder: AuditRecorder,
) -> None:
    mw = AuditMiddleware(raising_recorder, session_id="async-session")

    async def handler(request: Any) -> Any:
        raise ConnectionError("original failure")

    request = _FakeRequest("add", {"x": 1, "y": 2})
    with pytest.raises(ConnectionError, match="original failure"):
        await mw.awrap_tool_call(request, handler)


# ---------------------------------------------------------------------------
# AuditMiddleware internals (via fake request shapes)
# ---------------------------------------------------------------------------


class _FakeRequest:
    """Mimics enough of LangChain's ToolCallRequest for the middleware to read."""

    def __init__(self, name: str, args: dict[str, Any]) -> None:
        self.tool_call = {"name": name, "args": args, "id": "fake-call-1"}


class _FakeToolMessage:
    """Mimics ToolMessage: has a .content attribute."""

    def __init__(self, content: Any) -> None:
        self.content = content


def test_middleware_wrap_tool_call_records_sync(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeToolMessage:
        return _FakeToolMessage(content="42")

    request = _FakeRequest("add", {"x": 1, "y": 2})
    result = mw.wrap_tool_call(request, handler)

    assert result.content == "42"
    assert len(sink.records) == 1
    rec = sink.records[0]
    assert rec["payload"]["tool"]["name"] == "add"
    assert rec["payload"]["input"] == {"x": 1, "y": 2}
    assert rec["payload"]["output"]["body"] == "42"


async def test_middleware_awrap_tool_call_records_async(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="async-session")

    async def handler(request: Any) -> _FakeToolMessage:
        return _FakeToolMessage(content={"k": "v"})

    request = _FakeRequest("dict_tool", {"q": "x"})
    result = await mw.awrap_tool_call(request, handler)

    assert result.content == {"k": "v"}
    rec = sink.records[0]
    assert rec["payload"]["tool"]["name"] == "dict_tool"
    assert rec["payload"]["output"]["body"] == {"k": "v"}


def test_middleware_wrap_tool_call_records_timeout(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """Sync middleware path: asyncio.TimeoutError must be caught BEFORE the
    generic Exception handler (it aliases builtin TimeoutError, a subclass
    of OSError, since Python 3.11). A reversed except order still catches
    it via the generic handler and mislabels it as 'error'."""
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeToolMessage:
        raise asyncio.TimeoutError()

    request = _FakeRequest("slow", {})
    with pytest.raises(asyncio.TimeoutError):
        mw.wrap_tool_call(request, handler)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "timeout"
    assert rec["payload"]["outcome"]["elapsed_ms"] >= 0
    assert rec["payload"]["output"]["body"] is None


def test_middleware_wrap_tool_call_records_error_and_reraises(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeToolMessage:
        raise ConnectionError("connection refused")

    request = _FakeRequest("add", {"x": 1, "y": 2})
    with pytest.raises(ConnectionError):
        mw.wrap_tool_call(request, handler)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error"
    assert rec["payload"]["outcome"]["error_type"] == "ConnectionError"
    assert rec["payload"]["outcome"]["message"] == "connection refused"
    assert rec["payload"]["output"]["body"] is None


async def test_middleware_awrap_tool_call_records_timeout(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="async-session")

    async def handler(request: Any) -> _FakeToolMessage:
        raise asyncio.TimeoutError()

    request = _FakeRequest("slow", {})
    with pytest.raises(asyncio.TimeoutError):
        await mw.awrap_tool_call(request, handler)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "timeout"
    assert rec["payload"]["outcome"]["elapsed_ms"] >= 0
    assert rec["payload"]["output"]["body"] is None


def test_middleware_handles_missing_tool_call_gracefully(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A malformed request with no tool_call attribute should not crash —
    just record 'unknown_tool' so the audit trail isn't silently dropped."""
    mw = AuditMiddleware(recorder, session_id="x")

    class Bare:
        pass

    mw.wrap_tool_call(Bare(), lambda req: _FakeToolMessage(content="x"))
    assert sink.records[0]["payload"]["tool"]["name"] == "unknown_tool"


def test_extract_helpers() -> None:
    assert _extract_tool_info(_FakeRequest("foo", {"a": 1})) == ("foo", {"a": 1})
    assert _extract_output_body(_FakeToolMessage(content="hello")) == "hello"


def test_non_json_value_becomes_announced_marker(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A non-serialisable object in a returned body is handed to the recorder
    raw and becomes a faithful, announced `unsupported_type` marker — not a
    str()-laundered value, and never a dropped record. The adapter no longer
    pre-launders; `normalize_for_canonical` in the recorder does the honest work.
    """
    from agent_audit.normalize import MARKER_KEY

    class Weird:
        def __str__(self) -> str:
            return "weird-thing"

    @audited_tool(recorder, session_id="s")
    def tool() -> dict[str, Any]:
        return {"obj": Weird(), "n": 42}

    tool()
    rec = sink.records[0]
    assert rec["payload"]["output"]["body"]["obj"][MARKER_KEY] == "unrepresentable"
    assert rec["payload"]["output"]["body"]["n"] == 42
    assert any(
        e["reason"] == "unsupported_type"
        for e in rec["payload"]["unrepresentable"]
    )


# ---------------------------------------------------------------------------
# End-to-end via real create_agent + FakeListChatModel
# ---------------------------------------------------------------------------


class _FakeToolCallingChatModel:
    """Minimal stand-in for a tool-calling chat model in create_agent.

    Yields a pre-configured sequence of AIMessages — first one with a
    tool_calls entry (so create_agent dispatches to the tool), second
    with plain text (so the agent terminates). bind_tools is a no-op.
    """

    def __init__(self, messages: list[Any]) -> None:
        self._messages = list(messages)
        self._idx = 0

    def bind_tools(self, tools: list[Any], **kwargs: Any) -> _FakeToolCallingChatModel:
        return self

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        msg = self._messages[self._idx]
        self._idx += 1
        return msg

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        return self.invoke(input, config, **kwargs)


def test_real_create_agent_with_audit_middleware_records_tool_call(
    tmp_path: Path,
) -> None:
    """Build a tiny LangChain agent with a fake tool-calling model, invoke
    a single tool, and verify the audit log captured exactly that call."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _E,
        NoEncryption,
        PrivateFormat,
    )
    from langchain.agents import create_agent
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from click.testing import CliRunner

    from agent_audit.cli import EXIT_OK, cli
    from agent_audit.keys import load_signing_key
    from agent_audit.sinks.local_file import LocalFileSink

    pk = Ed25519PrivateKey.generate()
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    priv.write_bytes(
        pk.private_bytes(_E.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    priv.chmod(0o600)
    pub.write_bytes(
        pk.public_key().public_bytes(_E.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    sk = load_signing_key(priv)
    sink = LocalFileSink(dir=tmp_path / "audit", pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(sink=sink, signing_key=sk, chain_id="e2e")

    @tool
    def echo(text: str) -> str:
        """Echo the input."""
        return f"echoed: {text}"

    tool_call_msg = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "echo",
                "args": {"text": "hello"},
                "id": "call-1",
                "type": "tool_call",
            }
        ],
    )
    final_msg = AIMessage(content="done")
    model = _FakeToolCallingChatModel([tool_call_msg, final_msg])

    agent = create_agent(
        model=model,  # type: ignore[arg-type]
        tools=[echo],
        middleware=[AuditMiddleware(recorder, session_id="e2e-session")],
    )

    agent.invoke({"messages": [{"role": "user", "content": "say hi"}]})

    jsonl = next((tmp_path / "audit").glob("audit-*.jsonl"))
    lines = jsonl.read_text().splitlines()
    assert len(lines) == 1, f"expected 1 tool-call record, got {len(lines)}"
    record = json.loads(lines[0])
    assert record["payload"]["tool"]["name"] == "echo"
    assert record["payload"]["input"] == {"text": "hello"}
    assert "echoed" in str(record["payload"]["output"]["body"])
    assert record["envelope"]["chain_id"] == "e2e"

    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(jsonl), "--pubkey", str(pub)])
    assert result.exit_code == EXIT_OK, result.output


def test_real_create_agent_records_error_for_runtime_handled_tool_failure(
    tmp_path: Path,
) -> None:
    """A tool call that FAILS under a real `create_agent` must record `error`.

    This is the failure path the runtime actually takes, and no unit test in
    this file exercised it: LangGraph's ToolNode does not re-raise on its
    default `handle_tool_errors`. It CATCHES the tool's exception and RETURNS
    `ToolMessage(status="error")` from the very handler passed to
    `wrap_tool_call`. The handler returns normally, so an adapter that infers
    failure from a raised exception falls into its success branch and signs
    `outcome: success` over the error text — cryptographically attested false
    evidence, the worst defect this library can have.

    The trigger here is the commonest real agent failure there is: the model
    calls a tool with arguments that don't validate. That raises
    ToolInvocationError, which the default handler converts to an error
    ToolMessage rather than propagating.
    """
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _E,
        NoEncryption,
        PrivateFormat,
    )
    from langchain.agents import create_agent
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from click.testing import CliRunner

    from agent_audit.cli import EXIT_OK, cli
    from agent_audit.keys import load_signing_key
    from agent_audit.sinks.local_file import LocalFileSink

    pk = Ed25519PrivateKey.generate()
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    priv.write_bytes(pk.private_bytes(_E.PEM, PrivateFormat.PKCS8, NoEncryption()))
    priv.chmod(0o600)
    pub.write_bytes(
        pk.public_key().public_bytes(_E.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    sk = load_signing_key(priv)
    sink = LocalFileSink(dir=tmp_path / "audit", pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(sink=sink, signing_key=sk, chain_id="e2e-fail")

    @tool
    def charge_card(amount_cents: int) -> str:
        """Charge the customer's card."""
        return f"charged {amount_cents}"

    tool_call_msg = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "charge_card",
                # Not an int, and not coercible — the model got the schema wrong.
                "args": {"amount_cents": "twenty dollars"},
                "id": "call-1",
                "type": "tool_call",
            }
        ],
    )
    final_msg = AIMessage(content="done")
    model = _FakeToolCallingChatModel([tool_call_msg, final_msg])

    agent = create_agent(
        model=model,  # type: ignore[arg-type]
        tools=[charge_card],
        middleware=[AuditMiddleware(recorder, session_id="e2e-fail-session")],
    )

    result_state = agent.invoke({"messages": [{"role": "user", "content": "charge"}]})

    # Precondition: the runtime really did report this as a failed tool call,
    # and it did so by RETURNING, not raising. If LangGraph ever changes this,
    # the assertion below tells us before the audit assertions do.
    tool_messages = [
        m for m in result_state["messages"] if getattr(m, "type", None) == "tool"
    ]
    assert len(tool_messages) == 1
    assert tool_messages[0].status == "error"

    jsonl = next((tmp_path / "audit").glob("audit-*.jsonl"))
    lines = jsonl.read_text().splitlines()
    assert len(lines) == 1, f"expected 1 tool-call record, got {len(lines)}"
    record = json.loads(lines[0])

    assert record["payload"]["tool"]["name"] == "charge_card"
    outcome = record["payload"]["outcome"]
    assert outcome["kind"] == "error", (
        "signed a success for a tool call the runtime reported as failed; "
        f"record outcome was {outcome!r}"
    )
    assert outcome["error_type"] == "ToolFailure"
    assert outcome["message"]

    runner = CliRunner()
    verified = runner.invoke(cli, ["verify", str(jsonl), "--pubkey", str(pub)])
    assert verified.exit_code == EXIT_OK, verified.output


# ---------------------------------------------------------------------------
# Runtime-handled tool failure: the handler RETURNS an error ToolMessage
#
# LangGraph's ToolNode catches the tool's exception and returns
# ToolMessage(content=<error text>, status="error") — the handler passed to
# wrap_tool_call / awrap_tool_call does not raise. `status` is a runtime-set
# Literal["success", "error"] field, the same class of structural evidence as
# `is_interrupt` and `backgroundTaskId`. Reading it is not error-string
# sniffing, and the adapter must never fall back to sniffing `content`.
# ---------------------------------------------------------------------------


class _FakeErrorToolMessage:
    """Mimics ToolMessage(status="error"): .content, .status, and .type.

    `type == "tool"` is not decoration. The real `ToolMessage` carries it, and
    the adapter requires it precisely so that an arbitrary object with a
    `.status` — an HTTP response, a job record — is not read as a failed tool
    call by `@audited_tool`, which wraps arbitrary callables. A fake that
    omitted it would be testing a shape the runtime never produces.
    """

    def __init__(self, content: Any, status: str = "error") -> None:
        self.content = content
        self.status = status
        self.type = "tool"


class _FakeCommand:
    """Mimics Command: a state update, and no `status` field at all."""

    def __init__(self, update: Any) -> None:
        self.update = update


def test_middleware_wrap_tool_call_records_error_when_handler_returns_error_message(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeErrorToolMessage:
        return _FakeErrorToolMessage(
            content="Error invoking tool 'charge_card' with kwargs {...}"
        )

    result = mw.wrap_tool_call(_FakeRequest("charge_card", {"amount": "x"}), handler)

    # The audit layer observes control flow; it never alters it. The error
    # ToolMessage still reaches the agent unchanged.
    assert isinstance(result, _FakeErrorToolMessage)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error"
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert "charge_card" in rec["payload"]["outcome"]["message"]


async def test_middleware_awrap_tool_call_records_error_when_handler_returns_error_message(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="async-session")

    async def handler(request: Any) -> _FakeErrorToolMessage:
        return _FakeErrorToolMessage(content="tool blew up")

    result = await mw.awrap_tool_call(_FakeRequest("charge_card", {}), handler)
    assert isinstance(result, _FakeErrorToolMessage)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error"
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "tool blew up"


def test_middleware_wrap_tool_call_records_success_for_status_success_message(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """`status="success"` is the runtime saying the call succeeded. Trust it."""
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeErrorToolMessage:
        return _FakeErrorToolMessage(content="42", status="success")

    mw.wrap_tool_call(_FakeRequest("add", {"x": 1}), handler)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "success"
    assert rec["payload"]["output"]["body"] == "42"


async def test_middleware_awrap_tool_call_records_success_for_command_return(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A Command carries no `status`. Absence of a failure signal on a type
    that has no failure signal is not evidence of failure — it stays success."""
    mw = AuditMiddleware(recorder, session_id="async-session")

    async def handler(request: Any) -> _FakeCommand:
        return _FakeCommand(update={"messages": []})

    await mw.awrap_tool_call(_FakeRequest("handoff", {}), handler)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "success"


# ---------------------------------------------------------------------------
# Cancellation
#
# asyncio.CancelledError inherits from BaseException, not Exception (3.8+).
# Neither `except asyncio.TimeoutError` nor `except Exception` sees it, so a
# cancelled tool call used to produce NO record at all — a call that happened
# and vanished, which is this library's worst possible failure. It is exactly
# how an outer asyncio.wait_for / asyncio.timeout / TaskGroup abort behaves,
# and how the OpenAI Agents SDK enforces its own tool timeouts.
#
# The outcome is Error(error_type="CancelledError"), never Timeout: from
# inside the callable we cannot know WHY we were cancelled (outer deadline,
# user interrupt, sibling task failing). Error states what was observed.
# ---------------------------------------------------------------------------


class _SlowSink:
    """A sink whose write() suspends — like any sink doing real I/O.

    The Sink protocol is async precisely so backends can await, and that is
    what makes the cancellation bug reachable: a recorder call issued from
    inside `except CancelledError` has its own await points, and those are
    cancellable too. InMemorySink never suspends, so it hides the problem.
    """

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    async def write(self, record: dict[str, Any]) -> None:
        await asyncio.sleep(0.02)
        self.records.append(record)

    async def flush(self) -> None:
        return

    async def close(self) -> None:
        return


@pytest.fixture
def slow_sink() -> _SlowSink:
    return _SlowSink()


@pytest.fixture
def slow_recorder(slow_sink: _SlowSink, signing_key: SigningKey) -> AuditRecorder:
    return AuditRecorder(sink=slow_sink, signing_key=signing_key)


async def test_audited_tool_async_records_cancellation_under_wait_for(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """The original reproducer: an outer deadline cancels the coroutine.

    The caller must still observe TimeoutError from its own wait_for — the
    audit layer observes control flow, it never alters it — and the call must
    leave exactly one record behind.
    """

    @audited_tool(recorder, session_id="probe")
    async def slow_tool() -> str:
        await asyncio.sleep(10)
        return "never"

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(slow_tool(), timeout=0.05)

    assert len(sink.records) == 1
    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "CancelledError"
    assert outcome["message"]
    assert sink.records[-1]["payload"]["output"]["body"] is None


async def test_audited_tool_async_cancellation_is_reraised(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """Swallowing a cancellation breaks task cancellation and can hang the
    loop. It must propagate, and the task must still end up cancelled()."""
    started = asyncio.Event()

    @audited_tool(recorder, session_id="s1")
    async def slow_tool() -> str:
        started.set()
        await asyncio.sleep(10)
        return "never"

    task = asyncio.create_task(slow_tool())
    await started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert task.cancelled()

    assert len(sink.records) == 1
    assert sink.records[-1]["payload"]["outcome"]["error_type"] == "CancelledError"


async def test_audited_tool_records_cancellation_when_cancelled_repeatedly(
    slow_recorder: AuditRecorder, slow_sink: _SlowSink
) -> None:
    """The crux of the fix.

    Inside `except asyncio.CancelledError` the task is ALREADY being cancelled.
    A bare `await recorder.record(...)` there has its own suspension points, and
    a canceller that cancels until the task is done (loop shutdown, cancel-retry
    loops) cancels those too — so nothing is written and the fix is a no-op that
    only looks correct. asyncio.shield is what makes the write survive.

    This test fails (0 records) against a bare await; it passes against shield.
    """
    started = asyncio.Event()

    @audited_tool(slow_recorder, session_id="s1")
    async def slow_tool() -> str:
        started.set()
        await asyncio.sleep(10)
        return "never"

    task = asyncio.create_task(slow_tool())
    await started.wait()

    for _ in range(20):
        task.cancel()
        await asyncio.sleep(0)

    with pytest.raises(asyncio.CancelledError):
        await task

    # The write may have been detached by the re-cancellation; give the loop
    # the turns it needs to finish it.
    await asyncio.sleep(0.2)

    assert len(slow_sink.records) == 1
    outcome = slow_sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "CancelledError"


async def test_audited_tool_cancellation_recorder_failure_does_not_mask(
    raising_recorder: AuditRecorder,
) -> None:
    """A degraded sink must not replace the cancellation the caller expects."""

    @audited_tool(raising_recorder, session_id="s1")
    async def slow_tool() -> str:
        await asyncio.sleep(10)
        return "never"

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(slow_tool(), timeout=0.05)


def test_audited_tool_sync_records_cancelled_error(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """asyncio cannot cancel synchronous code, but a sync callable can still
    RAISE asyncio.CancelledError — e.g. a sync bridge re-raising the one it got
    from a loop it drove itself. It is a BaseException, so `except Exception`
    misses it and the record vanishes: same bug, same fix, no shield needed
    (there is no loop cancelling us here)."""

    @audited_tool(recorder, session_id="s1")
    def bridged_tool() -> None:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        bridged_tool()

    assert len(sink.records) == 1
    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "CancelledError"
    assert outcome["message"]
    assert sink.records[-1]["payload"]["output"]["body"] is None


def test_audited_tool_sync_cancellation_recorder_failure_does_not_mask(
    raising_recorder: AuditRecorder,
) -> None:
    @audited_tool(raising_recorder, session_id="s1")
    def bridged_tool() -> None:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        bridged_tool()


async def test_middleware_awrap_tool_call_records_cancellation(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="async-session")

    async def handler(request: Any) -> Any:
        await asyncio.sleep(10)
        return "never"

    request = _FakeRequest("add", {"x": 1, "y": 2})
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(mw.awrap_tool_call(request, handler), timeout=0.05)

    assert len(sink.records) == 1
    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "CancelledError"
    assert sink.records[-1]["payload"]["tool"]["name"] == "add"


async def test_middleware_awrap_records_cancellation_when_cancelled_repeatedly(
    slow_recorder: AuditRecorder, slow_sink: _SlowSink
) -> None:
    mw = AuditMiddleware(slow_recorder, session_id="async-session")
    started = asyncio.Event()

    async def handler(request: Any) -> Any:
        started.set()
        await asyncio.sleep(10)
        return "never"

    request = _FakeRequest("add", {"x": 1, "y": 2})
    task = asyncio.create_task(mw.awrap_tool_call(request, handler))
    await started.wait()

    for _ in range(20):
        task.cancel()
        await asyncio.sleep(0)

    with pytest.raises(asyncio.CancelledError):
        await task

    await asyncio.sleep(0.2)

    assert len(slow_sink.records) == 1
    assert slow_sink.records[-1]["payload"]["outcome"]["error_type"] == "CancelledError"


def test_middleware_wrap_tool_call_records_cancelled_error(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> Any:
        raise asyncio.CancelledError

    request = _FakeRequest("add", {"x": 1, "y": 2})
    with pytest.raises(asyncio.CancelledError):
        mw.wrap_tool_call(request, handler)

    assert len(sink.records) == 1
    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "CancelledError"


def test_middleware_wrap_cancellation_recorder_failure_does_not_mask(
    raising_recorder: AuditRecorder,
) -> None:
    mw = AuditMiddleware(raising_recorder, session_id="sync-session")

    def handler(request: Any) -> Any:
        raise asyncio.CancelledError

    request = _FakeRequest("add", {"x": 1, "y": 2})
    with pytest.raises(asyncio.CancelledError):
        mw.wrap_tool_call(request, handler)


# ---------------------------------------------------------------------------
# Public re-export
#
# `audited_tool` is runtime-agnostic — it wraps any Python callable, and the
# README advertises it for OpenAI Agents, custom agents, and direct SDK loops.
# It lives in the langgraph module for historical reasons, so the package root
# must re-export it: a user on any other runtime should never have to import
# from `adapters.langgraph` to audit a plain callable.
# ---------------------------------------------------------------------------


def test_audited_tool_is_exported_from_package_root() -> None:
    import agent_audit
    from agent_audit import audited_tool as root_audited_tool
    from agent_audit.adapters.langgraph import audited_tool as adapter_audited_tool

    assert root_audited_tool is adapter_audited_tool
    assert "audited_tool" in agent_audit.__all__


# ---------------------------------------------------------------------------
# The optional-LangChain-import guarantee
#
# `_find_runtime_failure` duck-types (`getattr(result, "status", ...)`,
# `getattr(result, "update", ...)`) instead of `isinstance(result, ToolMessage)`
# / `isinstance(result, Command)`, and `_control_flow_signal_type` imports
# `GraphBubbleUp` lazily inside the function rather than at module scope. Both
# choices are justified ENTIRELY by one promise: `@audited_tool` — re-exported
# from the package root — must keep working with langchain and langgraph absent.
# `agent_audit/__init__.py` imports `adapters.langgraph`, so a single unguarded
# module-scope `from langchain_core.messages import ToolMessage` would break
# `import agent_audit` for every user who never installed LangChain.
#
# Without this test nothing in CI defends that promise, and the next person to
# reach for `isinstance` ships green. The subprocess below installs a meta-path
# finder that makes langchain*/langgraph* genuinely unimportable — the same
# ModuleNotFoundError a user without them installed would get — and then does
# real audited work.
# ---------------------------------------------------------------------------


_NO_LANGCHAIN_SCRIPT = '''
import sys

_BLOCKED = {"langchain", "langchain_core", "langgraph"}


class _NotInstalled:
    """Make langchain/langgraph look like they were never pip-installed."""

    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in _BLOCKED:
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return None


sys.meta_path.insert(0, _NotInstalled())
for _mod in [m for m in sys.modules if m.split(".")[0] in _BLOCKED]:
    del sys.modules[_mod]

try:
    import langchain_core.messages  # noqa: F401
except ModuleNotFoundError:
    pass
else:
    raise AssertionError("the blocker did not block; this test proves nothing")

# The load-bearing line: a module-scope LangChain import anywhere reachable
# from the package root raises HERE.
import agent_audit
from agent_audit import AuditRecorder, audited_tool
from agent_audit.adapters.langgraph import AuditMiddleware
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.sinks.base import InMemorySink
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

assert "audited_tool" in agent_audit.__all__

_pk = Ed25519PrivateKey.generate()
_pub = _pk.public_key()
_sink = InMemorySink()
_recorder = AuditRecorder(
    sink=_sink,
    signing_key=SigningKey(
        private_key=_pk, public_key=_pub, key_id=compute_key_id(_pub)
    ),
)


@audited_tool(_recorder, session_id="no-langchain")
def add(a, b):
    return a + b


assert add(2, 3) == 5
assert len(_sink.records) == 1
assert _sink.records[0]["payload"]["outcome"]["kind"] == "success"
assert _sink.records[0]["payload"]["tool"]["name"] == "add"


@audited_tool(_recorder, session_id="no-langchain")
def boom():
    raise RuntimeError("kaboom")


try:
    boom()
except RuntimeError:
    pass
else:
    raise AssertionError("audited_tool swallowed the exception")

assert _sink.records[-1]["payload"]["outcome"]["kind"] == "error"
assert _sink.records[-1]["payload"]["outcome"]["error_type"] == "RuntimeError"

# AuditMiddleware is the one thing that legitimately needs LangChain, and it
# must say so loudly rather than fail somewhere obscure later.
try:
    AuditMiddleware(_recorder)
except ImportError:
    pass
else:
    raise AssertionError("AuditMiddleware must raise ImportError without langchain")

print("NO_LANGCHAIN_OK")
'''


def test_package_works_with_langchain_and_langgraph_absent() -> None:
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-c", _NO_LANGCHAIN_SCRIPT],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, (
        "agent_audit must import and audit with langchain/langgraph absent — a "
        "module-scope LangChain import in an adapter breaks every user who never "
        f"installed it.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert "NO_LANGCHAIN_OK" in proc.stdout


# ---------------------------------------------------------------------------
# Runtime-reported failure carried in a NESTED shape
#
# A failed tool call does not always arrive as a top-level
# ToolMessage(status="error"). LangGraph tools may return:
#
#   Command(update={"messages": [ToolMessage(..., status="error")]})
#   [Command(...), ToolMessage(..., status="error")]
#
# Neither carries a top-level `status`, so an adapter that reads only
# `result.status` falls into its success branch and signs `outcome: success`
# over a call the runtime reported as failed. Both shapes are produced by a
# real `create_agent` (see the e2e tests below): a Command-returning tool is
# the mainstream handoff/state-update pattern, and ToolNode's `execute` closure
# is annotated `-> ToolMessage | Command` but actually returns the wider
# `ToolMessage | Command | list[Command | ToolMessage]` of `_execute_tool_sync`.
#
# Detection stays STRUCTURAL: `status` on a message, `update` on a Command.
# Nothing sniffs `content` or error text.
# ---------------------------------------------------------------------------


def test_middleware_wrap_tool_call_records_error_for_failure_nested_in_command(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeCommand:
        return _FakeCommand(
            update={
                "messages": [_FakeErrorToolMessage(content="transfer to billing failed")]
            }
        )

    result = mw.wrap_tool_call(_FakeRequest("transfer", {"to": "billing"}), handler)

    # The audit layer observes control flow; it never alters it.
    assert isinstance(result, _FakeCommand)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error", (
        "signed a success for a failure the runtime nested inside Command.update"
    )
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "transfer to billing failed"
    assert rec["payload"]["output"]["body"] is None


async def test_middleware_awrap_tool_call_records_error_for_failure_nested_in_command(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="async-session")

    async def handler(request: Any) -> _FakeCommand:
        return _FakeCommand(
            update={"messages": [_FakeErrorToolMessage(content="handoff failed")]}
        )

    await mw.awrap_tool_call(_FakeRequest("transfer", {}), handler)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error"
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "handoff failed"


def test_middleware_wrap_tool_call_records_error_for_error_message_in_list(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """`[Command(...), ToolMessage(status="error")]` — ANY failing element fails."""
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> list[Any]:
        return [
            _FakeCommand(update={"messages": []}),
            _FakeErrorToolMessage(content="charge_card blew up"),
        ]

    result = mw.wrap_tool_call(_FakeRequest("charge_card", {}), handler)
    assert isinstance(result, list)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error", (
        "signed a success for a failure the runtime returned inside a list"
    )
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "charge_card blew up"


async def test_middleware_awrap_tool_call_records_error_for_command_nested_in_list(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """Both nestings at once: a list whose Command carries the error message."""
    mw = AuditMiddleware(recorder, session_id="async-session")

    async def handler(request: Any) -> list[Any]:
        return [
            _FakeCommand(
                update={"messages": [_FakeErrorToolMessage(content="nested failure")]}
            )
        ]

    await mw.awrap_tool_call(_FakeRequest("transfer", {}), handler)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error"
    assert rec["payload"]["outcome"]["message"] == "nested failure"


def test_middleware_records_success_for_list_of_non_failing_returns(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """No element reports failure — the call succeeded. No false positives."""
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> list[Any]:
        return [
            _FakeCommand(update={"messages": []}),
            _FakeErrorToolMessage(content="42", status="success"),
        ]

    mw.wrap_tool_call(_FakeRequest("add", {"x": 1}), handler)

    assert sink.records[-1]["payload"]["outcome"]["kind"] == "success"


def test_middleware_records_success_for_command_with_successful_message(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeCommand:
        return _FakeCommand(
            update={"messages": [_FakeErrorToolMessage(content="ok", status="success")]}
        )

    mw.wrap_tool_call(_FakeRequest("transfer", {}), handler)

    assert sink.records[-1]["payload"]["outcome"]["kind"] == "success"


@pytest.mark.parametrize(
    "update",
    [
        None,
        {},
        {"messages": None},
        {"messages": "not-a-list"},
        "not-a-dict",
        ["not-a-message"],
        {"other_state_field": 7},
    ],
)
def test_middleware_command_with_odd_update_records_success_without_raising(
    recorder: AuditRecorder, sink: InMemorySink, update: Any
) -> None:
    """An `update` we cannot read messages out of is not evidence of failure —
    and must never make the audit layer raise into the tool's return path."""
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeCommand:
        return _FakeCommand(update=update)

    mw.wrap_tool_call(_FakeRequest("transfer", {}), handler)

    assert sink.records[-1]["payload"]["outcome"]["kind"] == "success"


def test_middleware_command_without_update_attribute_records_success(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    class _NoUpdate:
        pass

    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _NoUpdate:
        return _NoUpdate()

    mw.wrap_tool_call(_FakeRequest("weird", {}), handler)

    assert sink.records[-1]["payload"]["outcome"]["kind"] == "success"


def test_runtime_failure_detection_never_sniffs_content(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A tool that legitimately returns the word "error" still succeeded.

    Only the structural `status` field decides. This is the heuristic the
    library refuses: guessing failure from the shape of the output text.
    """
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeCommand:
        return _FakeCommand(
            update={
                "messages": [
                    _FakeErrorToolMessage(
                        content="Error: 0 rows matched (this is a normal result)",
                        status="success",
                    )
                ]
            }
        )

    mw.wrap_tool_call(_FakeRequest("grep_logs", {"q": "error"}), handler)

    assert sink.records[-1]["payload"]["outcome"]["kind"] == "success"


# ---------------------------------------------------------------------------
# The nested shapes, end to end, through a real create_agent
#
# The previous fix passed its unit tests and still shipped this bug, because
# the fakes it asserted against were not the shape the runtime actually
# produces. These two tests drive the real LangGraph runtime.
# ---------------------------------------------------------------------------


def _e2e_keys(tmp_path: Path) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _E,
        NoEncryption,
        PrivateFormat,
    )

    pk = Ed25519PrivateKey.generate()
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    priv.write_bytes(pk.private_bytes(_E.PEM, PrivateFormat.PKCS8, NoEncryption()))
    priv.chmod(0o600)
    pub.write_bytes(
        pk.public_key().public_bytes(_E.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return priv, pub


def test_real_create_agent_records_error_for_failure_nested_in_command(
    tmp_path: Path,
) -> None:
    """A Command-returning tool that failed: the error rides inside
    `Command.update["messages"]`, with NO top-level `status` anywhere."""
    from click.testing import CliRunner
    from langchain.agents import create_agent
    from langchain_core.messages import AIMessage, ToolMessage
    from langchain_core.tools import tool

    from agent_audit.cli import EXIT_OK, cli
    from agent_audit.keys import load_signing_key
    from agent_audit.sinks.local_file import LocalFileSink

    priv, pub = _e2e_keys(tmp_path)
    sink = LocalFileSink(dir=tmp_path / "audit", pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(
        sink=sink, signing_key=load_signing_key(priv), chain_id="e2e-cmd"
    )

    @tool
    def transfer_funds(
        to_account: str, tool_call_id: Annotated[str, InjectedToolCallId]
    ) -> Command:
        """Transfer funds and update graph state."""
        return Command(
            update={
                "messages": [
                    ToolMessage(
                        content=f"transfer to {to_account} rejected: account frozen",
                        tool_call_id=tool_call_id,
                        status="error",
                    )
                ]
            }
        )

    model = _FakeToolCallingChatModel(
        [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "transfer_funds",
                        "args": {"to_account": "ACC-9"},
                        "id": "call-1",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="done"),
        ]
    )
    agent = create_agent(
        model=model,  # type: ignore[arg-type]
        tools=[transfer_funds],
        middleware=[AuditMiddleware(recorder, session_id="e2e-cmd-session")],
    )

    state = agent.invoke({"messages": [{"role": "user", "content": "transfer"}]})

    # Precondition: the runtime really did report failure, via a nested message.
    tool_messages = [m for m in state["messages"] if getattr(m, "type", None) == "tool"]
    assert len(tool_messages) == 1
    assert tool_messages[0].status == "error"

    jsonl = next((tmp_path / "audit").glob("audit-*.jsonl"))
    lines = jsonl.read_text().splitlines()
    assert len(lines) == 1
    outcome = json.loads(lines[0])["payload"]["outcome"]
    assert outcome["kind"] == "error", (
        "signed a success for a tool call the runtime reported as failed inside "
        f"Command.update; record outcome was {outcome!r}"
    )
    assert outcome["error_type"] == "ToolFailure"
    assert "frozen" in str(outcome["message"])

    verified = CliRunner().invoke(cli, ["verify", str(jsonl), "--pubkey", str(pub)])
    assert verified.exit_code == EXIT_OK, verified.output


async def test_real_create_agent_records_error_for_list_return_async(
    tmp_path: Path,
) -> None:
    """The list shape, through the real ASYNC runtime (`awrap_tool_call`).

    `ToolNode._run_one`'s `execute` closure is annotated `-> ToolMessage |
    Command`, but returns `_execute_tool_sync`/`_execute_tool_async`, whose
    real return type includes `list[Command | ToolMessage]`. The annotation is
    narrower than the runtime value, so the list shape reaches the middleware.
    """
    from click.testing import CliRunner
    from langchain.agents import create_agent
    from langchain_core.messages import AIMessage, ToolMessage
    from langchain_core.tools import tool

    from agent_audit.cli import EXIT_OK, cli
    from agent_audit.keys import load_signing_key
    from agent_audit.sinks.local_file import LocalFileSink

    priv, pub = _e2e_keys(tmp_path)
    sink = LocalFileSink(dir=tmp_path / "audit", pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(
        sink=sink, signing_key=load_signing_key(priv), chain_id="e2e-list"
    )

    @tool
    async def deploy(
        service: str, tool_call_id: Annotated[str, InjectedToolCallId]
    ) -> list[Any]:
        """Deploy a service, updating state and reporting the result."""
        return [
            Command(update={"messages": []}),
            ToolMessage(
                content=f"deploy of {service} failed: image pull backoff",
                tool_call_id=tool_call_id,
                status="error",
            ),
        ]

    model = _FakeToolCallingChatModel(
        [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "deploy",
                        "args": {"service": "api"},
                        "id": "call-1",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="done"),
        ]
    )
    agent = create_agent(
        model=model,  # type: ignore[arg-type]
        tools=[deploy],
        middleware=[AuditMiddleware(recorder, session_id="e2e-list-session")],
    )

    state = await agent.ainvoke({"messages": [{"role": "user", "content": "deploy"}]})

    tool_messages = [m for m in state["messages"] if getattr(m, "type", None) == "tool"]
    assert len(tool_messages) == 1
    assert tool_messages[0].status == "error"

    jsonl = next((tmp_path / "audit").glob("audit-*.jsonl"))
    lines = jsonl.read_text().splitlines()
    assert len(lines) == 1
    outcome = json.loads(lines[0])["payload"]["outcome"]
    assert outcome["kind"] == "error", (
        "signed a success for a tool call the runtime reported as failed in a "
        f"list return; record outcome was {outcome!r}"
    )
    assert outcome["error_type"] == "ToolFailure"
    assert "backoff" in str(outcome["message"])

    verified = CliRunner().invoke(cli, ["verify", str(jsonl), "--pubkey", str(pub)])
    assert verified.exit_code == EXIT_OK, verified.output


# ---------------------------------------------------------------------------
# The leaf predicate must require the ToolMessage SHAPE, not just `.status`
#
# Inside AuditMiddleware, `status == "error"` is a safe test: ToolNode returns
# only ToolMessage | Command | list, so nothing else can carry that field.
# `@audited_tool` wraps ARBITRARY user callables, where the same read is unsafe:
# an HTTP-response object, a job record, a CI build result — all routinely carry
# `.status`, and "error" is an ordinary value for them to hold. Recording those
# as failed calls would be a false FAILURE: the mirror image of the bug this
# branch keeps closing, and just as dishonest.
#
# ToolMessage also carries `type == "tool"` (langchain-core 1.4.9). Requiring
# both fields keeps every real runtime failure detected and excludes the
# look-alikes. Still duck-typed: importing ToolMessage at module scope would
# break `@audited_tool` for users without LangChain installed.
# ---------------------------------------------------------------------------


class _FakeHttpResponse:
    """NOT a ToolMessage. An ordinary object that happens to carry `.status`.

    A tool returning one of these — an HTTP client response, a job record, a
    build result — returned normally and succeeded. `status="error"` is its
    payload, not a runtime failure signal.
    """

    def __init__(self, status: str = "error") -> None:
        self.status = status
        self.body = {"detail": "upstream returned 500"}


def test_find_runtime_failure_ignores_status_on_a_non_toolmessage() -> None:
    """The predicate must not fire on any object that merely has `.status`."""
    from agent_audit.adapters.langgraph import _find_runtime_failure

    assert _find_runtime_failure(_FakeHttpResponse(status="error")) is None, (
        "an arbitrary object with .status == 'error' was read as a runtime "
        "failure; @audited_tool wraps arbitrary callables, so this records a "
        "false FAILURE for a call that succeeded"
    )


def test_audited_tool_records_success_for_returned_http_error_response(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A tool that returns an HTTP-shaped object with `.status == "error"` still
    SUCCEEDED. The call returned; the runtime reported nothing."""

    @audited_tool(recorder, session_id="s1")
    def call_upstream(url: str) -> _FakeHttpResponse:
        return _FakeHttpResponse(status="error")

    call_upstream("https://example.com")

    assert sink.records[-1]["payload"]["outcome"]["kind"] == "success", (
        "recorded a failure for a tool that returned an ordinary object "
        "carrying .status == 'error'"
    )


async def test_audited_tool_async_records_success_for_returned_http_error_response(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="s1")
    async def call_upstream(url: str) -> _FakeHttpResponse:
        return _FakeHttpResponse(status="error")

    await call_upstream("https://example.com")

    assert sink.records[-1]["payload"]["outcome"]["kind"] == "success"


# ---------------------------------------------------------------------------
# @audited_tool signs `success` over a returned failure
#
# The fifth instance of one pattern: the runtime encodes failure in the RETURN
# VALUE, and the adapter takes "returned normally" as evidence of success.
# AuditMiddleware catches both shapes. Its sibling entry point in the same file
# — the one the module docstring and README route raw `StateGraph` users to —
# never called `_find_runtime_failure` at all.
#
# A `Command`-returning tool is LangGraph's idiomatic state-update / handoff
# pattern, so the nested shape is not exotic.
# ---------------------------------------------------------------------------


def test_audited_tool_records_error_when_tool_returns_failed_tool_message(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="s1")
    def charge_card(amount: int) -> _FakeErrorToolMessage:
        return _FakeErrorToolMessage(content="charge_card blew up")

    result = charge_card(100)

    # The audit layer observes control flow; it never alters it.
    assert isinstance(result, _FakeErrorToolMessage)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error", (
        "signed a success for a tool call the runtime reported as failed"
    )
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "charge_card blew up"
    assert rec["payload"]["output"]["body"] is None


async def test_audited_tool_async_records_error_when_tool_returns_failed_tool_message(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="s1")
    async def charge_card(amount: int) -> _FakeErrorToolMessage:
        return _FakeErrorToolMessage(content="charge_card blew up")

    result = await charge_card(100)
    assert isinstance(result, _FakeErrorToolMessage)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error", (
        "signed a success for a tool call the runtime reported as failed"
    )
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "charge_card blew up"
    assert rec["payload"]["output"]["body"] is None


def test_audited_tool_records_error_for_failure_nested_in_command(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """`Command(update={"messages": [ToolMessage(status="error")]})` — the
    idiomatic LangGraph state-update return, carrying a failure."""

    @audited_tool(recorder, session_id="s1")
    def transfer(to: str) -> _FakeCommand:
        return _FakeCommand(
            update={
                "messages": [_FakeErrorToolMessage(content="transfer to billing failed")]
            }
        )

    result = transfer("billing")
    assert isinstance(result, _FakeCommand)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error", (
        "signed a success for a failure the runtime nested inside Command.update"
    )
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "transfer to billing failed"
    assert rec["payload"]["output"]["body"] is None


async def test_audited_tool_async_records_error_for_failure_nested_in_command(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="s1")
    async def transfer(to: str) -> _FakeCommand:
        return _FakeCommand(
            update={"messages": [_FakeErrorToolMessage(content="handoff failed")]}
        )

    await transfer("billing")

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error", (
        "signed a success for a failure the runtime nested inside Command.update"
    )
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "handoff failed"


def test_audited_tool_records_error_for_failure_in_list_return(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="s1")
    def deploy(service: str) -> list[Any]:
        return [
            _FakeCommand(update={"messages": []}),
            _FakeErrorToolMessage(content="image pull backoff"),
        ]

    deploy("api")

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error"
    assert rec["payload"]["outcome"]["message"] == "image pull backoff"


def test_audited_tool_records_success_for_successful_tool_message(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """No false positives: `status="success"` is the runtime saying it worked."""

    @audited_tool(recorder, session_id="s1")
    def add(x: int) -> _FakeErrorToolMessage:
        return _FakeErrorToolMessage(content="42", status="success")

    add(1)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "success"
    # The successful return is still recorded as output, as it always was.
    assert rec["payload"]["output"]["body"] is not None


async def test_real_tool_message_failure_through_audited_tool(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """The real `ToolMessage`, not a fake — the shape a raw `StateGraph` node
    actually returns. The previous fix's fakes were the reason a bug shipped."""
    from langchain_core.messages import ToolMessage

    @audited_tool(recorder, session_id="s1")
    async def charge_card(amount: int) -> ToolMessage:
        return ToolMessage(
            content="card declined", tool_call_id="call-1", status="error"
        )

    await charge_card(100)

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error"
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "card declined"
    assert rec["payload"]["output"]["body"] is None


async def test_real_command_nested_failure_through_audited_tool(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """The real `Command` + real `ToolMessage` — LangGraph's handoff pattern."""
    from langchain_core.messages import ToolMessage

    @audited_tool(recorder, session_id="s1")
    async def transfer(to: str) -> Command[Any]:
        return Command(
            update={
                "messages": [
                    ToolMessage(
                        content="handoff to billing failed",
                        tool_call_id="call-1",
                        status="error",
                    )
                ]
            }
        )

    await transfer("billing")

    rec = sink.records[-1]
    assert rec["payload"]["outcome"]["kind"] == "error"
    assert rec["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert rec["payload"]["outcome"]["message"] == "handoff to billing failed"
    assert rec["payload"]["output"]["body"] is None


# ---------------------------------------------------------------------------
# Runtime CONTROL-FLOW SIGNAL: the runtime raises, but nothing failed
#
# The mirror image of the returned-failure bug, and just as dishonest.
#
# LangGraph signals control flow by RAISING `GraphBubbleUp` — an `Exception`
# subclass. `interrupt()` inside a tool (human-in-the-loop) raises
# `GraphInterrupt`; a tool that bubbles a navigation Command to the parent graph
# raises `ParentCommand`. Neither is a failure. The graph suspends, a human
# answers, and the tool is RE-EXECUTED from the top and succeeds.
#
# An adapter whose `except Exception` treats "an exception crossed this
# boundary" as evidence of failure signs `error(error_type="GraphInterrupt")`
# over a tool call that did not fail — cryptographically attested false
# evidence, exactly as bad as signing `success` over a returned failure.
#
# The honest outcome is `unobserved`: the call was entered, the runtime took
# control away before any outcome existed, and nobody observed one.
# ---------------------------------------------------------------------------


class _FakeGraphInterrupt(Exception):
    """Stand-in used only where the real langgraph types are not imported."""


def test_middleware_records_unobserved_for_graph_interrupt_not_error(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A HITL interrupt is not a tool failure. It must never record `error`."""
    from langgraph.errors import GraphInterrupt

    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> Any:
        raise GraphInterrupt(("approve this?",))

    with pytest.raises(GraphInterrupt):
        mw.wrap_tool_call(_FakeRequest("book_flight", {"to": "LCA"}), handler)

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] != "error", (
        "signed an `error` for a tool call that did NOT fail — it was suspended "
        f"for human input and will be re-executed on resume. outcome={outcome!r}"
    )
    assert outcome["kind"] == "unobserved"


async def test_amiddleware_records_unobserved_for_graph_interrupt_not_error(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    from langgraph.errors import GraphInterrupt

    mw = AuditMiddleware(recorder, session_id="async-session")

    async def handler(request: Any) -> Any:
        raise GraphInterrupt(("approve this?",))

    with pytest.raises(GraphInterrupt):
        await mw.awrap_tool_call(_FakeRequest("book_flight", {}), handler)

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "unobserved", (
        f"signed `{outcome['kind']}` for a suspended call; outcome={outcome!r}"
    )


def test_audited_tool_records_unobserved_for_graph_interrupt_not_error(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    from langgraph.errors import GraphInterrupt

    @audited_tool(recorder, session_id="s")
    def book_flight(to: str) -> str:
        raise GraphInterrupt(("approve?",))

    with pytest.raises(GraphInterrupt):
        book_flight("LCA")

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "unobserved", (
        f"signed `{outcome['kind']}` for a suspended call; outcome={outcome!r}"
    )


async def test_audited_tool_async_records_unobserved_for_parent_command(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """`ParentCommand` bubbles a navigation Command up. The tool SUCCEEDED."""
    from langgraph.errors import ParentCommand
    from langgraph.types import Command

    @audited_tool(recorder, session_id="s")
    async def handoff(to: str) -> str:
        raise ParentCommand(Command(goto="billing"))

    with pytest.raises(ParentCommand):
        await handoff("billing")

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] != "error", (
        f"signed an `error` over a control-flow signal; outcome={outcome!r}"
    )


def test_middleware_still_records_error_for_a_real_langgraph_failure(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """Control-flow signals are NOT failures — but real failures still are.

    The fix must not widen into "any langgraph exception is unobserved". Only
    `GraphBubbleUp` is the control-flow channel; `InvalidUpdateError` and friends
    are genuine failures and must keep recording `error`.
    """
    from langgraph.errors import InvalidUpdateError

    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> Any:
        raise InvalidUpdateError("bad state update")

    with pytest.raises(InvalidUpdateError):
        mw.wrap_tool_call(_FakeRequest("t", {}), handler)

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "InvalidUpdateError"
