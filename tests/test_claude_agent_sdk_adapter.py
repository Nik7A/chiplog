"""Claude Agent SDK adapter tests.

Covers:
- _extract_session_id: caller override beats SDK-supplied; SDK value used otherwise; default fallback when both missing
- _extract_step_id: uses tool_use_id from input; falls back to UUIDv7 when missing
- raw tool_input/tool_response are handed to the recorder; its normalize pass marks hostile values
- AuditHook.__call__ on a PostToolUse input emits a signed record
- The emitted record carries the SDK session_id, tool_use_id as step_id, tool_name, tool_input, tool_response
- Non-PostToolUse events are silently no-op'd (defensive)
- AuditHook records two sequential calls into a verifiable chain
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chiplog.adapters.claude_agent_sdk import (
    AuditHook,
    _extract_session_id,
    _extract_step_id,
)
from chiplog.emit import AuditRecorder
from chiplog.integrity import compute_chain_link, verify_record
from chiplog.keys import SigningKey, compute_key_id
from chiplog.sinks.base import InMemorySink


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


def _post_tool_use_input(
    *,
    session_id: str = "sdk-session-001",
    tool_use_id: str = "toolu_01ABCdef",
    tool_name: str = "Bash",
    tool_input: dict[str, Any] | None = None,
    tool_response: Any = "command exited 0",
) -> dict[str, Any]:
    """Shape mirrors claude_agent_sdk.PostToolUseHookInput."""
    return {
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/workspace",
        "tool_use_id": tool_use_id,
        "tool_name": tool_name,
        "tool_input": tool_input if tool_input is not None else {"command": "ls -la"},
        "tool_response": tool_response,
    }


# ---------------------------------------------------------------------------
# Extractor unit tests
# ---------------------------------------------------------------------------


def test_extract_session_id_caller_override_wins() -> None:
    hook_input = _post_tool_use_input(session_id="sdk-session")
    assert _extract_session_id(hook_input, "user-override") == "user-override"


def test_extract_session_id_uses_sdk_value_when_no_override() -> None:
    hook_input = _post_tool_use_input(session_id="sdk-session-abc")
    assert _extract_session_id(hook_input, None) == "sdk-session-abc"


def test_extract_session_id_falls_back_when_missing() -> None:
    hook_input: dict[str, Any] = {"hook_event_name": "PostToolUse"}
    assert (
        _extract_session_id(hook_input, None) == "claude-agent-sdk-default"
    )


def test_extract_step_id_uses_tool_use_id() -> None:
    hook_input = _post_tool_use_input(tool_use_id="toolu_99XYZ")
    assert _extract_step_id(hook_input) == "toolu_99XYZ"


def test_extract_step_id_falls_back_to_uuid7() -> None:
    hook_input: dict[str, Any] = {"hook_event_name": "PostToolUse"}
    result = _extract_step_id(hook_input)
    # UUIDv7 string is 36 chars with the canonical hyphen layout
    assert len(result) == 36 and result.count("-") == 4


# ---------------------------------------------------------------------------
# AuditHook integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_emits_signed_record(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    hook = AuditHook(recorder=recorder)
    hook_input = _post_tool_use_input(
        session_id="my-session",
        tool_use_id="toolu_xy_001",
        tool_name="Read",
        tool_input={"file_path": "/etc/hosts"},
        tool_response={"content": "127.0.0.1 localhost"},
    )

    result = await hook(hook_input=hook_input, tool_use_id="toolu_xy_001", context={})
    assert result == {}  # hook does not modify SDK behavior

    assert len(sink.records) == 1
    record = sink.records[0]

    assert record["header"]["session_id"] == "my-session"
    assert record["header"]["step_id"] == "toolu_xy_001"
    assert record["payload"]["tool"]["name"] == "Read"
    assert record["payload"]["input"] == {"file_path": "/etc/hosts"}
    assert record["payload"]["output"]["body"] == {"content": "127.0.0.1 localhost"}

    pubkey_by_id = {signing_key.key_id: signing_key.public_key}
    verification = verify_record(record, pubkey_by_id)
    assert verification.is_valid, verification.detail


@pytest.mark.asyncio
async def test_call_with_session_override(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hook = AuditHook(recorder=recorder, session_id="audit-override")
    hook_input = _post_tool_use_input(session_id="sdk-supplied")
    await hook(hook_input=hook_input, tool_use_id="t1", context={})

    assert sink.records[0]["header"]["session_id"] == "audit-override"


@pytest.mark.asyncio
async def test_call_with_unknown_tool_name_is_recorded(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hook = AuditHook(recorder=recorder)
    hook_input = _post_tool_use_input(tool_name="")
    await hook(hook_input=hook_input, tool_use_id="t1", context={})

    assert sink.records[0]["payload"]["tool"]["name"] == "unknown_tool"


@pytest.mark.asyncio
async def test_non_post_tool_use_event_is_silently_skipped(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A misregistered hook receiving e.g. PreToolUse must not crash; just no-op."""
    hook = AuditHook(recorder=recorder)
    pre_tool_input = {
        "hook_event_name": "PreToolUse",
        "session_id": "s",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "tool_use_id": "t1",
    }
    result = await hook(hook_input=pre_tool_input, tool_use_id="t1", context={})

    assert result == {}
    assert len(sink.records) == 0


@pytest.mark.asyncio
async def test_chain_of_two_records(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    hook = AuditHook(recorder=recorder)
    for i in range(2):
        hook_input = _post_tool_use_input(
            tool_use_id=f"toolu_{i:03d}",
            tool_input={"i": i},
            tool_response=f"result-{i}",
        )
        await hook(hook_input=hook_input, tool_use_id=f"toolu_{i:03d}", context={})

    assert len(sink.records) == 2
    first, second = sink.records
    assert first["envelope"]["prev_hash"] is None
    assert second["envelope"]["prev_hash"] is not None

    pubkey_by_id = {signing_key.key_id: signing_key.public_key}
    for rec in (first, second):
        assert verify_record(rec, pubkey_by_id).is_valid


# ---------------------------------------------------------------------------
# PostToolUseFailure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_tool_use_failure_records_error(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": "false"},
            "tool_use_id": "tu-1",
            "error": "command exited with status 1",
        },
        tool_use_id="tu-1",
        context={},
    )
    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["error_type"] == "ToolFailure"
    assert outcome["message"] == "command exited with status 1"
    assert sink.records[-1]["payload"]["output"]["body"] is None


@pytest.mark.asyncio
async def test_interrupt_is_labelled_distinctly(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": "sleep 999"},
            "tool_use_id": "tu-2",
            "error": "interrupted by user",
            "is_interrupt": True,
        },
        tool_use_id="tu-2",
        context={},
    )
    assert sink.records[-1]["payload"]["outcome"]["error_type"] == "Interrupt"


@pytest.mark.asyncio
async def test_post_tool_use_still_records_success(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/x"},
            "tool_response": "contents",
            "tool_use_id": "tu-3",
        },
        tool_use_id="tu-3",
        context={},
    )
    assert sink.records[-1]["payload"]["outcome"] == {"kind": "success"}


# ---------------------------------------------------------------------------
# User DENIAL at the permission prompt → outcome=denied + a truthful Gate(DENY)
#
# The SDK drives the same binary as the CLI, so a user rejection arrives as a
# PostToolUseFailure whose `error` begins with the same rejection lead-sentence
# (probed verbatim from CLI 2.1.207). The denial mapping routes through the SAME
# shared predicate the CLI adapter uses (adapters/_claude_hooks) so the two
# cannot drift.
# ---------------------------------------------------------------------------


_SDK_DENIAL_ERROR = (
    "The user doesn't want to proceed with this tool use. The tool use was "
    "rejected (eg. if it was a file edit, the new_string was NOT written to the "
    "file). To tell you how to proceed, the user said: no thanks"
)


@pytest.mark.asyncio
async def test_user_denial_records_denied_with_gate(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    """A user denial → outcome=denied + Gate(DENY) with matching policy_id and
    output.body=None. Not error(Interrupt). Signs and verifies."""
    from chiplog.adapters._claude_hooks import PERMISSION_DENIED_POLICY_ID

    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf ./build"},
            "tool_use_id": "tu-deny",
            "error": _SDK_DENIAL_ERROR,
            "is_interrupt": True,
        },
        tool_use_id="tu-deny",
        context={},
    )
    record = sink.records[-1]
    outcome = record["payload"]["outcome"]
    policy = record["payload"]["policy"]

    assert outcome["kind"] == "denied"
    assert outcome["policy_id"] == PERMISSION_DENIED_POLICY_ID
    assert policy["kind"] == "gate"
    assert policy["decision"] == "deny"
    assert policy["policy_id"] == PERMISSION_DENIED_POLICY_ID
    assert policy["approver"] is None
    assert policy["evaluation_ms"] is None
    assert record["payload"]["output"]["body"] is None

    pubkey_by_id = {signing_key.key_id: signing_key.public_key}
    assert verify_record(record, pubkey_by_id).is_valid


@pytest.mark.asyncio
async def test_genuine_failure_is_not_denied(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """The predicate does not over-match: a genuine `Exit code 1` stays error."""
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": "false"},
            "tool_use_id": "tu-f",
            "error": "Exit code 1",
        },
        tool_use_id="tu-f",
        context={},
    )
    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error"
    assert outcome["kind"] != "denied"
    assert sink.records[-1]["payload"]["policy"]["kind"] == "policy_unobserved"


# ---------------------------------------------------------------------------
# Backgrounded Bash calls — the SDK drives the same binary as the CLI, and it
# has no timeout failure signal either.
#
# The payload below is a verbatim capture from claude-agent-sdk 0.2.118. A Bash
# call that exceeds its `timeout` does NOT fire PostToolUseFailure. The runtime
# moves the command to the background and fires an ordinary PostToolUse — the
# SUCCESS slot — with no `error` key, `interrupted: false`, empty stdout, and a
# `backgroundTaskId`. Same shape the Claude Code CLI produces, because it is the
# same runtime underneath.
#
# Signing that as `success` attests that a call succeeded when nobody observed
# whether it did. The discriminator (a `backgroundTaskId` the caller never asked
# for) lives in adapters/_claude_hooks.py and is shared with the CLI adapter, so
# the two cannot drift.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runtime_backgrounded_timeout_is_unobserved_not_success(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """THE BUG. Verbatim payload from claude-agent-sdk 0.2.118: a Bash command
    that blew its timeout arrives on PostToolUse and was signed as `success`.
    The command may still be running, may fail later, may never finish — the
    hook cannot tell. `unobserved` is the only honest record."""
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "python3 -c 'import time; time.sleep(60)'",
                "timeout": 3000,
            },
            "tool_response": {
                "stdout": "",
                "stderr": "",
                "interrupted": False,
                "backgroundTaskId": "bnopr5ak5",
            },
            "tool_use_id": "tu-bg",
            "duration_ms": 3750,
        },
        tool_use_id="tu-bg",
        context={},
    )
    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "unobserved"
    assert outcome["reason"] == "no_failure_signal"
    # Not success, and not a synthesized timeout — the runtime never reported one.
    assert outcome["kind"] != "success"
    assert outcome["kind"] != "timeout"

    # The thin tool_response is still evidence: backgroundTaskId names the task
    # that inherited the work and is the only thread an investigator can pull.
    body = sink.records[-1]["payload"]["output"]["body"]
    assert body["backgroundTaskId"] == "bnopr5ak5"


@pytest.mark.asyncio
async def test_intentional_background_stays_success(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """The caller asked for `run_in_background: true`. That call genuinely
    succeeded — the tool was asked to launch a process and it launched one.
    Relabelling it `unobserved` would destroy good evidence, which is why
    `backgroundTaskId` alone cannot be the discriminator."""
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "python3 -c 'import time; time.sleep(60)'",
                "run_in_background": True,
            },
            "tool_response": {
                "stdout": "",
                "stderr": "",
                "interrupted": False,
                "backgroundTaskId": "b2twld3af",
            },
            "tool_use_id": "tu-bg2",
        },
        tool_use_id="tu-bg2",
        context={},
    )
    assert sink.records[-1]["payload"]["outcome"] == {"kind": "success"}
    body = sink.records[-1]["payload"]["output"]["body"]
    assert body["backgroundTaskId"] == "b2twld3af"


@pytest.mark.asyncio
async def test_ordinary_bash_call_has_no_background_task_and_stays_success(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """Control: a fast command carries no `backgroundTaskId` at all."""
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo control-probe"},
            "tool_response": {
                "stdout": "control-probe",
                "stderr": "",
                "interrupted": False,
            },
            "tool_use_id": "tu-bg3",
        },
        tool_use_id="tu-bg3",
        context={},
    )
    assert sink.records[-1]["payload"]["outcome"] == {"kind": "success"}


@pytest.mark.asyncio
async def test_background_detection_does_not_touch_non_bash_tools(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A non-Bash tool whose output merely mentions `backgroundTaskId` is not a
    backgrounded Bash call. The discriminator reads the runtime's structural
    field on the Bash tool, not any dict key anywhere."""
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/notes.md"},
            "tool_response": "the runtime sets backgroundTaskId when it backgrounds a task",
            "tool_use_id": "tu-bg4",
        },
        tool_use_id="tu-bg4",
        context={},
    )
    assert sink.records[-1]["payload"]["outcome"] == {"kind": "success"}


@pytest.mark.asyncio
async def test_unobserved_record_is_signed_and_chained(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    """An unobserved record is a first-class link: signed, verifiable, chained.
    An outcome nobody could observe is still evidence that the call happened."""
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input=_post_tool_use_input(tool_use_id="tu-a", tool_name="Read"),
        tool_use_id="tu-a",
        context={},
    )
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "sleep 60", "timeout": 3000},
            "tool_response": {"stdout": "", "backgroundTaskId": "bnopr5ak5"},
            "tool_use_id": "tu-b",
        },
        tool_use_id="tu-b",
        context={},
    )

    backgrounded = sink.records[-1]
    assert backgrounded["payload"]["outcome"]["kind"] == "unobserved"
    assert backgrounded["envelope"]["prev_hash"] == compute_chain_link(sink.records[-2])

    keyring = {signing_key.key_id: signing_key.public_key}
    assert verify_record(backgrounded, keyring).is_valid


# ---------------------------------------------------------------------------
# An INTERRUPTED tool call must never be signed as `success` — SDK side.
#
# The rule lives in adapters/_claude_hooks.py and is shared with the Claude Code
# CLI adapter, for the same reason the background discriminator is: same runtime,
# byte-identical payloads, and two adapters that have already drifted once.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_interrupted_tool_response_is_unobserved_not_success(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf ./build"},
            "tool_response": {"stdout": "", "stderr": "", "interrupted": True},
            "tool_use_id": "tu-int",
        },
        tool_use_id="tu-int",
        context={},
    )
    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "unobserved", (
        "signed a success for a tool call that was interrupted mid-flight"
    )
    assert outcome["reason"] == "no_failure_signal"
    assert outcome["kind"] != "success"


@pytest.mark.asyncio
async def test_interrupted_false_stays_success(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """Control: an ordinary completed call carries `interrupted: false`."""
    hook = AuditHook(recorder=recorder, session_id="cas")
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo ok"},
            "tool_response": {"stdout": "ok", "stderr": "", "interrupted": False},
            "tool_use_id": "tu-int2",
        },
        tool_use_id="tu-int2",
        context={},
    )
    assert sink.records[-1]["payload"]["outcome"] == {"kind": "success"}
