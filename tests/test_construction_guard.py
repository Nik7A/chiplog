"""Structural: NO construction step may drop a tool call silently.

The recorder's one promise is that a tool call that happened is never silently
lost. Two earlier patches guarded only `sign_record`. But a record is built in
several steps BEFORE signing — redaction and normalization both call `str()` /
`repr()` on caller-supplied values — and a value whose `repr()` raises, or a dict
KEY whose `str()` raises, dies in one of THOSE steps, before the chain head is
ever poisoned. The recorder then raises with the head untouched, every adapter
swallows it, and the next record chains cleanly: the hostile call vanishes with
NO chain break. Silent evidence loss.

This file pins the structural guarantee: for EVERY construction step and EVERY
adapter path × side, a hostile value yields EITHER a faithful, announced,
verifiable record OR a LOUD, detectable failure (a chain break the verifier sees,
plus a typed `RecordBuildError` if it propagates). Never a clean chain with the
call gone.

Shapes, and which outcome each must produce:

  - repr-raising object   -> LOUD  (its digest needs repr(); it cannot be faithful)
  - str-raising dict key  -> LOUD  (its path needs str(); it cannot be faithful)
  - tuple-keyed dict      -> FAITHFUL (announced non_string_dict_key marker)
  - bytes value           -> FAITHFUL (announced unsupported_type marker)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from agent_audit.adapters.claude_agent_sdk import AuditHook
from agent_audit.adapters.langgraph import AuditMiddleware, audited_tool
from agent_audit.adapters.openai_agents import AuditHooks
from agent_audit.emit import AuditRecorder, RecordBuildError
from agent_audit.integrity import compute_chain_link
from agent_audit.keys import SigningKey, compute_key_id, load_public_key
from agent_audit.schema.v1 import (
    NoGateReason,
    Output,
    ToolCall,
    UnrepresentableReason,
    success,
    ungated,
)
from agent_audit.sinks.base import InMemorySink
from agent_audit.sinks.local_file import LocalFileSink
from agent_audit.verify import ChainCheckOutcome, verify_log

# A secret that, if laundered by `str()`/`default=str`, would show up verbatim in
# the signed canonical bytes.
_SECRET = b"top-secret-blob-value"


# ---------------------------------------------------------------------------
# Hostile value shapes
# ---------------------------------------------------------------------------


class _ReprRaises:
    """A value whose repr() raises — dies in normalize's `_digest`."""

    def __repr__(self) -> str:
        raise RuntimeError("hostile __repr__")


class _StrRaisesKey:
    """A hashable dict KEY whose str()/repr() raise — dies in redact's
    `f"{path}.{k}"` (and in normalize's key stringify)."""

    def __repr__(self) -> str:
        raise RuntimeError("hostile key __repr__")

    def __str__(self) -> str:
        raise RuntimeError("hostile key __str__")

    def __hash__(self) -> int:
        return 7

    def __eq__(self, other: object) -> bool:
        return other is self


# (factory, expectation, faithful_reason_or_None)
_SHAPES: dict[str, tuple[Callable[[], Any], str, UnrepresentableReason | None]] = {
    "repr_raising": (lambda: _ReprRaises(), "loud", None),
    "str_raising_key": (lambda: {_StrRaisesKey(): 1}, "loud", None),
    "tuple_key": (
        lambda: {("t", "k"): 1, "blob": _SECRET},
        "faithful",
        UnrepresentableReason.NON_STRING_DICT_KEY,
    ),
    "bytes_value": (lambda: {"blob": _SECRET}, "faithful", UnrepresentableReason.UNSUPPORTED_TYPE),
}

_SHAPE_IDS = sorted(_SHAPES)
_SIDES = ["input", "output"]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _keypair(tmp_path: Path) -> tuple[SigningKey, Path]:
    pk = Ed25519PrivateKey.generate()
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    priv.write_bytes(pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    priv.chmod(0o600)
    pub.write_bytes(
        pk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    public = pk.public_key()
    key = SigningKey(private_key=pk, public_key=public, key_id=compute_key_id(public))
    return key, pub


def _the_jsonl(audit_dir: Path) -> Path:
    files = sorted(audit_dir.glob("audit-*.jsonl"))
    assert len(files) == 1, f"expected one daily file, got {files}"
    return files[0]


def _assert_faithful_or_loud(
    audit_dir: Path,
    pub: Path,
    *,
    shape_id: str,
    raised: BaseException | None,
) -> None:
    """The universal check: hostile call B (between normal A and normal C) must be
    faithful-or-loud, never a silent hole in a clean chain."""
    factory, expectation, reason = _SHAPES[shape_id]
    pubkey, key_id = load_public_key(pub)
    result = verify_log(_the_jsonl(audit_dir), {key_id: pubkey})

    # No adapter path may let a RAW, untyped exception escape. Either nothing
    # propagated (the LangGraph adapters swallow), or it is a typed member of the
    # construction-failure family.
    assert raised is None or isinstance(raised, RecordBuildError), (
        f"a raw {type(raised).__name__} escaped instead of a typed RecordBuildError"
    )

    if expectation == "faithful":
        assert result.outcome is ChainCheckOutcome.OK, (
            f"faithful shape {shape_id} must keep a verifiable chain, got "
            f"{result.outcome.value} at offset {result.failed_at_offset}"
        )
        assert result.record_count == 3, "all three records must be recorded"
        # The middle record announces the substitution — nothing laundered.
        rec = json.loads(_the_jsonl(audit_dir).read_text().splitlines()[1])
        reasons = {e["reason"] for e in rec["payload"]["unrepresentable"]}
        assert reason is not None and reason.value in reasons, (
            f"{shape_id} must announce {reason}; got {reasons}"
        )
        assert _SECRET.decode() not in _the_jsonl(audit_dir).read_text(), (
            "the secret must never appear laundered in the signed log"
        )
    else:  # loud
        # The hostile record died during construction, before the sink write, so
        # it is not on disk. The poisoned head makes C break the chain — a trace
        # the verifier sees even though every LangGraph adapter swallowed the
        # error. That is the whole point: under-recording is LOUD.
        assert result.outcome is ChainCheckOutcome.CHAIN_BREAK, (
            f"loud shape {shape_id} must leave a detectable chain break, got "
            f"{result.outcome.value} (record_count={result.record_count}). "
            "A clean chain here means the hostile call vanished silently."
        )


# Each driver performs ONE adapter-level call producing ONE record. `value=None`
# means a benign call; otherwise the hostile value is placed on `side`.


def _drive_audited_tool_sync(
    recorder: AuditRecorder, side: str, value: Any
) -> None:
    if side == "input":

        @audited_tool(recorder, session_id="s")
        def t(x: Any) -> str:
            return "ok"

        t(value if value is not None else "benign")
    else:

        @audited_tool(recorder, session_id="s")
        def t() -> Any:
            return value if value is not None else "ok"

        t()


async def _drive_audited_tool_async(
    recorder: AuditRecorder, side: str, value: Any
) -> None:
    if side == "input":

        @audited_tool(recorder, session_id="s")
        async def t(x: Any) -> str:
            return "ok"

        await t(value if value is not None else "benign")
    else:

        @audited_tool(recorder, session_id="s")
        async def t() -> Any:
            return value if value is not None else "ok"

        await t()


class _Request:
    def __init__(self, args: Any) -> None:
        self.tool_call = {"name": "t", "args": args, "id": "c1"}


class _Msg:
    def __init__(self, content: Any) -> None:
        self.content = content


def _drive_middleware_sync(recorder: AuditRecorder, side: str, value: Any) -> None:
    mw = AuditMiddleware(recorder, session_id="s")
    if side == "input":
        args = value if value is not None else {"q": "x"}
        mw.wrap_tool_call(_Request(args), lambda _r: _Msg("ok"))
    else:
        body = value if value is not None else "ok"
        mw.wrap_tool_call(_Request({"q": "x"}), lambda _r: _Msg(body))


async def _drive_middleware_async(
    recorder: AuditRecorder, side: str, value: Any
) -> None:
    mw = AuditMiddleware(recorder, session_id="s")
    if side == "input":
        args = value if value is not None else {"q": "x"}

        async def h(_r: Any) -> _Msg:
            return _Msg("ok")

        await mw.awrap_tool_call(_Request(args), h)
    else:
        body = value if value is not None else "ok"

        async def h2(_r: Any) -> _Msg:
            return _Msg(body)

        await mw.awrap_tool_call(_Request({"q": "x"}), h2)


async def _drive_claude_sdk_hook(
    recorder: AuditRecorder, side: str, value: Any
) -> None:
    hook = AuditHook(recorder=recorder)
    hook_input: dict[str, Any] = {
        "hook_event_name": "PostToolUse",
        "session_id": "sdk-s",
        "tool_use_id": "toolu_1",
        "tool_name": "Read",
        "tool_input": value if (side == "input" and value is not None) else {"path": "/x"},
        "tool_response": value if (side == "output" and value is not None) else {"ok": True},
    }
    await hook(hook_input, "toolu_1", {})


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeAgent:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeToolContext:
    def __init__(self, tool_name: str, tool_arguments: Any) -> None:
        self.tool_name = tool_name
        self.tool_arguments = tool_arguments


class _StructuredResult:
    def __init__(self, output: Any) -> None:
        self.output = output


async def _drive_openai_hooks(
    recorder: AuditRecorder, side: str, value: Any
) -> None:
    hooks = AuditHooks(recorder=recorder, session_id="oa-s")
    args: Any = value if (side == "input" and value is not None) else "{}"
    body: Any = value if (side == "output" and value is not None) else "ok"
    await hooks.on_tool_end(
        _FakeToolContext("t", args),
        _FakeAgent("a"),
        _FakeTool("t"),
        _StructuredResult(output=body),
    )


def _run_sync(
    tmp_path: Path, driver: Callable[[AuditRecorder, str, Any], None], side: str, shape_id: str
) -> None:
    factory, _exp, _reason = _SHAPES[shape_id]
    key, pub = _keypair(tmp_path)
    audit_dir = tmp_path / "audit"
    sink = LocalFileSink(dir=audit_dir, pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(sink=sink, signing_key=key, chain_id="m")
    driver(recorder, side, None)
    raised: BaseException | None = None
    try:
        driver(recorder, side, factory())
    except BaseException as exc:  # noqa: BLE001 — captured, then asserted
        raised = exc
    driver(recorder, side, None)
    _assert_faithful_or_loud(audit_dir, pub, shape_id=shape_id, raised=raised)


async def _run_async(
    tmp_path: Path,
    driver: Callable[[AuditRecorder, str, Any], Any],
    side: str,
    shape_id: str,
) -> None:
    factory, _exp, _reason = _SHAPES[shape_id]
    key, pub = _keypair(tmp_path)
    audit_dir = tmp_path / "audit"
    sink = LocalFileSink(dir=audit_dir, pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(sink=sink, signing_key=key, chain_id="m")
    await driver(recorder, side, None)
    raised: BaseException | None = None
    try:
        await driver(recorder, side, factory())
    except BaseException as exc:  # noqa: BLE001 — captured, then asserted
        raised = exc
    await driver(recorder, side, None)
    _assert_faithful_or_loud(audit_dir, pub, shape_id=shape_id, raised=raised)


# ---------------------------------------------------------------------------
# Recorder-level: the two vanish reproductions, direct and minimal.
# ---------------------------------------------------------------------------


def _mem_recorder() -> tuple[InMemorySink, AuditRecorder]:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    key = SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))
    sink = InMemorySink()
    return sink, AuditRecorder(sink=sink, signing_key=key)


async def _rec(rec: AuditRecorder, step: str, value: Any) -> dict[str, Any]:
    return await rec.record(
        session_id="s",
        step_id=step,
        tool=ToolCall(name="t"),
        input=value,
        output=Output(),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )


async def test_repr_raising_input_is_loud_not_silent() -> None:
    """A value whose repr() raises dies in normalize. It must poison the chain and
    raise a typed error — never leave the head clean so the next record hides it."""
    sink, rec = _mem_recorder()
    a = await _rec(rec, "a", {"ok": 1})

    with pytest.raises(RecordBuildError):
        await _rec(rec, "b", {"hostile": _ReprRaises()})

    c = await _rec(rec, "c", {"ok": 2})

    # The dropped record poisoned the head, so c does NOT chain onto a.
    assert c["envelope"]["prev_hash"] != compute_chain_link(a)
    assert sink.records == [a, c]


async def test_str_raising_key_input_is_loud_not_silent() -> None:
    """A dict key whose str() raises dies in redact's `f"{path}.{k}"`. Same rule:
    poison + typed error, not a silent hole."""
    sink, rec = _mem_recorder()
    a = await _rec(rec, "a", {"ok": 1})

    with pytest.raises(RecordBuildError):
        await _rec(rec, "b", {"m": {_StrRaisesKey(): 1}})

    c = await _rec(rec, "c", {"ok": 2})

    assert c["envelope"]["prev_hash"] != compute_chain_link(a)
    assert sink.records == [a, c]


# ---------------------------------------------------------------------------
# Adapter matrix — every path × side × shape.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("side", _SIDES)
@pytest.mark.parametrize("shape_id", _SHAPE_IDS)
def test_audited_tool_sync_matrix(tmp_path: Path, shape_id: str, side: str) -> None:
    _run_sync(tmp_path, _drive_audited_tool_sync, side, shape_id)


@pytest.mark.parametrize("side", _SIDES)
@pytest.mark.parametrize("shape_id", _SHAPE_IDS)
async def test_audited_tool_async_matrix(
    tmp_path: Path, shape_id: str, side: str
) -> None:
    await _run_async(tmp_path, _drive_audited_tool_async, side, shape_id)


@pytest.mark.parametrize("side", _SIDES)
@pytest.mark.parametrize("shape_id", _SHAPE_IDS)
def test_middleware_sync_matrix(tmp_path: Path, shape_id: str, side: str) -> None:
    _run_sync(tmp_path, _drive_middleware_sync, side, shape_id)


@pytest.mark.parametrize("side", _SIDES)
@pytest.mark.parametrize("shape_id", _SHAPE_IDS)
async def test_middleware_async_matrix(
    tmp_path: Path, shape_id: str, side: str
) -> None:
    await _run_async(tmp_path, _drive_middleware_async, side, shape_id)


@pytest.mark.parametrize("side", _SIDES)
@pytest.mark.parametrize("shape_id", _SHAPE_IDS)
async def test_claude_sdk_hook_matrix(
    tmp_path: Path, shape_id: str, side: str
) -> None:
    await _run_async(tmp_path, _drive_claude_sdk_hook, side, shape_id)


@pytest.mark.parametrize("side", _SIDES)
@pytest.mark.parametrize("shape_id", _SHAPE_IDS)
async def test_openai_hooks_matrix(
    tmp_path: Path, shape_id: str, side: str
) -> None:
    await _run_async(tmp_path, _drive_openai_hooks, side, shape_id)
