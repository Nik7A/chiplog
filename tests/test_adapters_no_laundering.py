"""Adapter boundary: an adapter must not pre-launder a value before the
recorder sees it.

The recorder's `normalize_for_canonical` pass turns every JCS-hostile value into
a faithful, ANNOUNCED marker and never raises (see
`test_recorder_no_silent_loss.py`). But an adapter that pre-processes a value
with `json.loads(json.dumps(value, default=str))` BEFORE calling
`recorder.record(...)` defeats that guarantee two ways, both silent:

  - a dict with a non-string key (tuple / frozenset / bytes / custom object key)
    makes `json.dumps` RAISE `TypeError: keys must be str...`, which the adapter's
    own `except Exception: log-and-swallow` catches. The tool RAN, NOTHING was
    recorded, and the chain did NOT break — a silently dropped tool call, the one
    failure this product claims it cannot have.
  - a hostile VALUE (bytes -> "b'...'", set -> "{1, 2}", nan -> null) is
    stringified by `default=str` with `payload.unrepresentable` left EMPTY — a
    secret laundered into an ordinary-looking value, signed as genuine.

Every adapter path is covered: the sync and async `@audited_tool`,
`AuditMiddleware` (sync + async), the Claude Agent SDK `AuditHook`, and the
OpenAI Agents `AuditHooks`. Each must yield EITHER a faithful record with an
announced marker OR a detectable loud failure — never zero records with no
chain break, and never a laundered value with an empty `unrepresentable` list.
"""

from __future__ import annotations

from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chiplog.adapters.claude_agent_sdk import AuditHook
from chiplog.adapters.langgraph import AuditMiddleware, audited_tool
from chiplog.adapters.openai_agents import AuditHooks
from chiplog.emit import AuditRecorder
from chiplog.integrity import verify_record
from chiplog.keys import SigningKey, compute_key_id
from chiplog.schema.v1 import UnrepresentableReason
from chiplog.sinks.base import InMemorySink

# A secret that, if laundered by `default=str`, would appear verbatim in the
# signed canonical bytes. The not-laundered assertion greps for it.
_SECRET = b"top-secret-blob-value"

# A dict return with BOTH a non-string key (drops the record via a raised
# TypeError today) and a bytes value (laundered silently today).
def _hostile_dict() -> dict[Any, Any]:
    return {"blob": _SECRET, ("tuple", "key"): 1}


# A dict whose ONLY hostility is a bytes value — this DOES get recorded today,
# but laundered: bytes -> "b'...'" with an empty unrepresentable list.
def _bytes_only_dict() -> dict[str, Any]:
    return {"blob": _SECRET}


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


def _assert_faithful_marked_record(
    sink: InMemorySink, signing_key: SigningKey, *, expect_non_string_key: bool
) -> dict[str, Any]:
    """Exactly one record, it verifies, it announces its substitutions, and the
    secret bytes never made it into the signed canonical form."""
    assert len(sink.records) == 1, "the tool call must not be silently dropped"
    rec = sink.records[0]

    # It is a real, verifiable, signed record.
    assert verify_record(
        rec, {signing_key.key_id: signing_key.public_key}
    ).is_valid

    # The hostile value was ANNOUNCED, not laundered.
    entries = rec["payload"]["unrepresentable"]
    reasons = {e["reason"] for e in entries}
    assert UnrepresentableReason.UNSUPPORTED_TYPE.value in reasons
    if expect_non_string_key:
        assert UnrepresentableReason.NON_STRING_DICT_KEY.value in reasons

    # The secret bytes are NOT in the signed bytes.
    assert _SECRET.decode() not in rfc8785.dumps(rec).decode()
    return rec


# ---------------------------------------------------------------------------
# @audited_tool — sync
# ---------------------------------------------------------------------------


def test_sync_audited_tool_tuple_key_return_is_not_dropped(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    @audited_tool(recorder, session_id="s")
    def tool() -> dict[Any, Any]:
        return _hostile_dict()

    tool()
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=True)


def test_sync_audited_tool_bytes_value_is_not_laundered(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    @audited_tool(recorder, session_id="s")
    def tool() -> dict[str, Any]:
        return _bytes_only_dict()

    tool()
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=False)


# ---------------------------------------------------------------------------
# @audited_tool — async
# ---------------------------------------------------------------------------


async def test_async_audited_tool_tuple_key_return_is_not_dropped(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    @audited_tool(recorder, session_id="s")
    async def tool() -> dict[Any, Any]:
        return _hostile_dict()

    await tool()
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=True)


async def test_async_audited_tool_bytes_value_is_not_laundered(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    @audited_tool(recorder, session_id="s")
    async def tool() -> dict[str, Any]:
        return _bytes_only_dict()

    await tool()
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=False)


# ---------------------------------------------------------------------------
# AuditMiddleware — sync + async
# ---------------------------------------------------------------------------


class _FakeRequest:
    def __init__(self, name: str, args: dict[str, Any]) -> None:
        self.tool_call = {"name": name, "args": args, "id": "fake-call-1"}


class _FakeToolMessage:
    def __init__(self, content: Any) -> None:
        self.content = content


def test_middleware_sync_tuple_key_return_is_not_dropped(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    mw = AuditMiddleware(recorder, session_id="s")

    def handler(request: Any) -> _FakeToolMessage:
        return _FakeToolMessage(content=_hostile_dict())

    mw.wrap_tool_call(_FakeRequest("t", {"q": "x"}), handler)
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=True)


def test_middleware_sync_bytes_value_is_not_laundered(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    mw = AuditMiddleware(recorder, session_id="s")

    def handler(request: Any) -> _FakeToolMessage:
        return _FakeToolMessage(content=_bytes_only_dict())

    mw.wrap_tool_call(_FakeRequest("t", {"q": "x"}), handler)
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=False)


async def test_middleware_async_tuple_key_return_is_not_dropped(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    mw = AuditMiddleware(recorder, session_id="s")

    async def handler(request: Any) -> _FakeToolMessage:
        return _FakeToolMessage(content=_hostile_dict())

    await mw.awrap_tool_call(_FakeRequest("t", {"q": "x"}), handler)
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=True)


# ---------------------------------------------------------------------------
# Claude Agent SDK — AuditHook (PostToolUse)
# ---------------------------------------------------------------------------


async def test_claude_sdk_hook_tuple_key_response_is_not_dropped(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    hook = AuditHook(recorder=recorder)
    hook_input: dict[str, Any] = {
        "hook_event_name": "PostToolUse",
        "session_id": "sdk-s",
        "tool_use_id": "toolu_1",
        "tool_name": "Read",
        "tool_input": {"path": "/x"},
        "tool_response": _hostile_dict(),
    }
    await hook(hook_input, "toolu_1", {})
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=True)


async def test_claude_sdk_hook_bytes_response_is_not_laundered(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    hook = AuditHook(recorder=recorder)
    hook_input: dict[str, Any] = {
        "hook_event_name": "PostToolUse",
        "session_id": "sdk-s",
        "tool_use_id": "toolu_1",
        "tool_name": "Read",
        "tool_input": {"path": "/x"},
        "tool_response": _bytes_only_dict(),
    }
    await hook(hook_input, "toolu_1", {})
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=False)


# ---------------------------------------------------------------------------
# OpenAI Agents — AuditHooks.on_tool_end
# ---------------------------------------------------------------------------


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeAgent:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeToolContext:
    def __init__(self, tool_name: str, tool_arguments: str) -> None:
        self.tool_name = tool_name
        self.tool_arguments = tool_arguments


class _StructuredResult:
    def __init__(self, output: Any) -> None:
        self.output = output


async def test_openai_hook_tuple_key_output_is_not_dropped(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    hooks = AuditHooks(recorder=recorder, session_id="oa-s")
    await hooks.on_tool_end(
        _FakeToolContext("t", "{}"),
        _FakeAgent("a"),
        _FakeTool("t"),
        _StructuredResult(output=_hostile_dict()),
    )
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=True)


async def test_openai_hook_bytes_output_is_not_laundered(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    hooks = AuditHooks(recorder=recorder, session_id="oa-s")
    await hooks.on_tool_end(
        _FakeToolContext("t", "{}"),
        _FakeAgent("a"),
        _FakeTool("t"),
        _StructuredResult(output=_bytes_only_dict()),
    )
    _assert_faithful_marked_record(sink, signing_key, expect_non_string_key=False)
