"""THE OUTCOME-HONESTY MATRIX — the guard against instance N+1.

Read this before you touch any adapter's outcome logic.

-------------------------------------------------------------------------------
THE INVARIANT
-------------------------------------------------------------------------------

    CONTROL FLOW IS NOT AN OUTCOME.

    That a call RETURNED is not evidence that it succeeded.
    That a call RAISED is not evidence that it failed.

    An outcome may only be recorded from a signal the runtime DESIGNATES as an
    outcome signal — a status field, an error flag, a dedicated failure event.
    Never from the mere shape of the control flow that delivered it, and never
    from sniffing an error string out of a payload.

    When the runtime designates no such signal, the honest record is
    `unobserved(reason)`. Never a guessed `success`, and never a guessed `error`.

-------------------------------------------------------------------------------
WHY THIS FILE EXISTS
-------------------------------------------------------------------------------

Six times now, an adapter has signed a false outcome because it read control
flow as an outcome. Five in one direction (a returned failure recorded as
`success`), one in the other (a raised control-flow signal recorded as `error`):

  1. OpenAI Agents `RunHooks`   — SDK converts tool exceptions to string results
  2. Claude Code / Agent SDK    — a timed-out Bash call is backgrounded, reported
                                  on the SUCCESS hook
  3. LangGraph `AuditMiddleware`— `ToolNode` RETURNS `ToolMessage(status="error")`
  4. ...the same, nested in a `Command(update=...)` or a list
  5. ...the same, through `@audited_tool` (the sibling entry point)
  6. LangGraph `GraphInterrupt` — a human-in-the-loop `interrupt()` RAISES, and
                                  the adapter recorded `error` for a call that
                                  was merely paused and then SUCCEEDED

Every one of those was found by reading the RUNTIME, and missed by reading the
adapter. Each fix closed a known site; none closed the class. Hence this matrix.

-------------------------------------------------------------------------------
WHAT YOU MUST DO
-------------------------------------------------------------------------------

This file enumerates, per runtime, EVERY mechanism by which that runtime can
report something other than a plain success, and pins the outcome the adapter
must record for it.

  * Adding an adapter?      Add its runtime's table here.
  * Upgrading a runtime?    Re-derive its table from the runtime's OWN source and
                            extend it. A new mechanism with no row is instance N+1
                            waiting to happen.
  * A row here fails?       The runtime changed how it reports outcomes. Do not
                            "fix" the test to match the new behaviour without
                            first deciding what the HONEST record is.

`test_langgraph_control_flow_boundary_is_exactly_graph_bubble_up` is the tripwire
that would have caught instance six BEFORE it shipped: it pins the adapter's
notion of "this exception is not a failure" against the runtime's own class
hierarchy. If LangGraph adds a control-flow signal outside `GraphBubbleUp`, or
moves a genuine failure under it, that test fails loudly instead of the audit
chain silently acquiring a false outcome.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chiplog.adapters._claude_hooks import (
    is_failure_event,
    is_interrupted,
    is_recordable_event,
    is_unrequested_background,
)
from chiplog.adapters.langgraph import (
    AuditMiddleware,
    _find_runtime_failure,
    _is_control_flow_signal,
    audited_tool,
)
from chiplog.emit import AuditRecorder
from chiplog.keys import SigningKey, compute_key_id
from chiplog.sinks.base import InMemorySink


@pytest.fixture
def sink() -> InMemorySink:
    return InMemorySink()


@pytest.fixture
def recorder(sink: InMemorySink) -> AuditRecorder:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    key = SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))
    return AuditRecorder(sink=sink, signing_key=key)


class _Request:
    def __init__(self, name: str, args: Any) -> None:
        self.tool_call = {"name": name, "args": args, "id": "call-1"}


# =============================================================================
# RUNTIME: LangGraph / LangChain  (langchain 1.3.x, langgraph 1.2.x)
# =============================================================================
#
# How this runtime reports a tool call that is not a plain success:
#
#   MECHANISM                                   SHAPE              -> OUTCOME
#   -------------------------------------------------------------------------
#   ToolNode handled the tool's exception       RETURNS            -> error
#     ToolMessage(status="error")                 top-level
#     Command(update={"messages":[...]})          nested in Command
#     [Command(...), ToolMessage(...)]            nested in a list
#   Model called an unregistered tool           RETURNS            -> error
#     (_validate_tool_call -> status="error")
#   BaseTool.handle_tool_error /                RETURNS            -> error
#     handle_validation_error                     ToolMessage(status="error")
#   Tool raised, ToolNode declined to handle    RAISES             -> error
#   Control-flow signal (GraphBubbleUp)         RAISES             -> unobserved
#     GraphInterrupt / NodeInterrupt               (HITL pause; tool re-runs)
#     ParentCommand                                (tool SUCCEEDED)
#     GraphDrained                                 (internal)
#   Deadline                                    RAISES TimeoutError-> timeout
#   Cancelled from outside                      RAISES Cancelled   -> error
#   Plain success                               RETURNS            -> success
#
# The two RETURNS-but-failed rows are instances 3/4/5. The GraphBubbleUp row is
# instance 6. Both directions are covered below.


def test_langgraph_control_flow_boundary_is_exactly_graph_bubble_up() -> None:
    """THE TRIPWIRE. Pins the adapter's control-flow notion to the runtime's own
    class hierarchy.

    The adapter treats an exception as "not a failure" iff it is a
    `GraphBubbleUp`. That is a claim ABOUT THE RUNTIME, and the runtime is free
    to change it. This asserts the claim against every exception LangGraph
    actually defines — so a new control-flow signal introduced outside
    `GraphBubbleUp`, or a genuine failure moved under it, fails here rather than
    quietly producing a signed false outcome.
    """
    from langgraph import errors as lg_errors
    from langgraph.errors import GraphBubbleUp

    exception_classes = [
        cls
        for cls in vars(lg_errors).values()
        if inspect.isclass(cls)
        and issubclass(cls, BaseException)
        and cls.__module__.startswith("langgraph")
    ]
    assert exception_classes, "found no langgraph exception classes — import moved?"

    for cls in exception_classes:
        # Build without invoking __init__ — several take required args.
        exc = cls.__new__(cls)
        expected_control_flow = issubclass(cls, GraphBubbleUp)
        assert _is_control_flow_signal(exc) is expected_control_flow, (
            f"{cls.__name__}: adapter says control_flow="
            f"{_is_control_flow_signal(exc)}, runtime hierarchy says "
            f"{expected_control_flow}. The control-flow boundary moved. Decide "
            f"what the HONEST outcome is before changing this assertion."
        )

    # And the channel is non-empty in both directions, or the test proves nothing.
    assert any(issubclass(c, GraphBubbleUp) for c in exception_classes)
    assert any(not issubclass(c, GraphBubbleUp) for c in exception_classes)


@pytest.mark.parametrize(
    "signal_name",
    ["GraphInterrupt", "NodeInterrupt", "ParentCommand", "GraphDrained"],
)
def test_langgraph_control_flow_signal_records_unobserved_never_error(
    signal_name: str, recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """RAISED, but nothing failed -> unobserved. Never `error`.

    A `GraphInterrupt` means the graph SUSPENDED for human input and will
    RE-EXECUTE this tool on resume. A `ParentCommand` means the tool SUCCEEDED
    and its result is a navigation Command. Signing `error` over either attests
    a failure that never happened.
    """
    from langgraph import errors as lg_errors

    signal_cls = getattr(lg_errors, signal_name)
    exc = signal_cls.__new__(signal_cls)

    mw = AuditMiddleware(recorder, session_id="matrix")

    def handler(request: Any) -> Any:
        raise exc

    with pytest.raises(BaseException):  # noqa: B017 - re-raise is the contract
        mw.wrap_tool_call(_Request("book_flight", {"to": "LCA"}), handler)

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "unobserved", (
        f"{signal_name} is a CONTROL-FLOW signal, not a failure, but the adapter "
        f"recorded {outcome!r}"
    )
    assert outcome["reason"] == "control_flow_signal"


@pytest.mark.parametrize(
    "failure_name", ["InvalidUpdateError", "GraphRecursionError", "NodeTimeoutError"]
)
def test_langgraph_genuine_failure_still_records_error(
    failure_name: str, recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """The control-flow carve-out must not widen into "any langgraph exception".

    These are real failures. They must keep recording `error` — a false
    `unobserved` would erase evidence just as surely as a false `success`.
    """
    from langgraph import errors as lg_errors

    failure_cls = getattr(lg_errors, failure_name)
    exc = failure_cls.__new__(failure_cls)

    mw = AuditMiddleware(recorder, session_id="matrix")

    def handler(request: Any) -> Any:
        raise exc

    with pytest.raises(BaseException):  # noqa: B017
        mw.wrap_tool_call(_Request("t", {}), handler)

    outcome = sink.records[-1]["payload"]["outcome"]
    assert outcome["kind"] == "error", (
        f"{failure_name} is a genuine failure but was recorded as {outcome!r}"
    )
    assert outcome["error_type"] == failure_name


def test_langgraph_returned_failure_shapes_all_detected() -> None:
    """RETURNED, but failed -> must be found. Instances 3, 4 and 5.

    Every shape LangGraph delivers a handled tool failure in. A shape that
    escapes `_find_runtime_failure` lands in the adapter's success branch and is
    signed `success` over the runtime's own error text.
    """
    from langchain_core.messages import ToolMessage
    from langgraph.types import Command

    failed = ToolMessage(content="boom", tool_call_id="c1", status="error")
    ok = ToolMessage(content="fine", tool_call_id="c1", status="success")

    shapes: list[tuple[str, Any]] = [
        ("top-level ToolMessage", failed),
        ("nested in Command(update=dict)", Command(update={"messages": [failed]})),
        ("nested in Command(update=list)", Command(update=[failed])),
        ("in a list", [ok, failed]),
        ("in a list, inside a Command", [Command(update={"messages": [failed]})]),
    ]
    for label, shape in shapes:
        assert _find_runtime_failure(shape) is not None, (
            f"UNDETECTED returned failure: {label}. The adapter will sign "
            f"`success` over this."
        )

    # And the mirror: a real success must NOT be read as a failure.
    for label, shape in [
        ("successful ToolMessage", ok),
        ("plain string return", "just a string"),
        ("Command with no failure", Command(update={"messages": [ok]})),
        ("dict with an unrelated status field", {"status": "error"}),
    ]:
        assert _find_runtime_failure(shape) is None, (
            f"FALSE FAILURE: {label} was read as a runtime-reported failure."
        )


async def test_langgraph_audited_tool_matches_middleware_on_every_row(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """The two entry points must not drift. Instance 5 was exactly that drift.

    `@audited_tool` and `AuditMiddleware` face the same runtime from opposite
    sides. Any rule one applies, the other must apply.
    """
    from langchain_core.messages import ToolMessage
    from langgraph.errors import GraphInterrupt

    @audited_tool(recorder, session_id="matrix")
    async def returns_failure() -> Any:
        return ToolMessage(content="boom", tool_call_id="c1", status="error")

    await returns_failure()
    assert sink.records[-1]["payload"]["outcome"]["kind"] == "error"

    @audited_tool(recorder, session_id="matrix")
    async def raises_control_flow() -> Any:
        raise GraphInterrupt(("approve?",))

    with pytest.raises(GraphInterrupt):
        await raises_control_flow()
    assert sink.records[-1]["payload"]["outcome"]["kind"] == "unobserved"

    @audited_tool(recorder, session_id="matrix")
    async def really_succeeds() -> str:
        return "ok"

    await really_succeeds()
    assert sink.records[-1]["payload"]["outcome"]["kind"] == "success"


# =============================================================================
# RUNTIME: Claude Code CLI + Claude Agent SDK  (CLI 2.1.207, SDK 0.2.118)
# =============================================================================
#
# Same runtime behind both adapters — the SDK drives the same binary — so the
# rules live once in `adapters/_claude_hooks.py`.
#
# Probed live against CLI 2.1.207 by registering a hook under both events and
# forcing each failure mode. The CLI routes EVERY failure to
# `PostToolUseFailure`; `PostToolUse` is the success slot:
#
#   MECHANISM                          EVENT                  -> OUTCOME
#   -------------------------------------------------------------------------
#   Bash non-zero exit code            PostToolUseFailure     -> error
#   Built-in tool error (missing file) PostToolUseFailure     -> error
#   MCP tool returns isError: true     PostToolUseFailure     -> error
#   MCP JSON-RPC protocol error        PostToolUseFailure     -> error
#   Bash exceeded timeout              PostToolUse (!!)       -> unobserved
#     -> backgrounded, `backgroundTaskId` set, no error key   (instance 2)
#   Caller asked for run_in_background PostToolUse            -> success
#   Runtime marked `interrupted: true` PostToolUse            -> unobserved
#   Plain success                      PostToolUse            -> success
#   Any other event (PreToolUse, Stop) —                      -> no record
#
# The `isError`/protocol-error rows are the shapes MCP uses to report a tool
# failure WITHOUT a protocol failure — the canonical "failure in the return
# value". They were probed specifically because that is this bug class's calling
# card. The CLI handles them correctly; the adapter inherits that.

_CLAUDE_HOOK_MATRIX: list[tuple[str, dict[str, Any], str]] = [
    # (label, payload, expected outcome kind)
    (
        "bash non-zero exit",
        {
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": "exit 7"},
            "error": "Exit code 7\nto-stdout\nto-stderr",
        },
        "error",
    ),
    (
        "mcp tool returned isError: true",
        {
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "mcp__probe__failing_tool",
            "tool_input": {},
            "error": "PROBE_FAIL: the database is on fire",
        },
        "error",
    ),
    (
        "mcp json-rpc protocol error",
        {
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "mcp__probe__raising_tool",
            "tool_input": {},
            "error": "MCP error -32603: PROBE_RAISE: internal error",
        },
        "error",
    ),
    (
        "bash timed out -> runtime backgrounded it (instance 2)",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "sleep 600", "timeout": 5000},
            "tool_response": {
                "stdout": "",
                "stderr": "",
                "interrupted": False,
                "backgroundTaskId": "task-abc",
            },
        },
        "unobserved",
    ),
    (
        "caller ASKED to background -> genuinely succeeded",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "npm run dev", "run_in_background": True},
            "tool_response": {
                "stdout": "",
                "stderr": "",
                "interrupted": False,
                "backgroundTaskId": "task-xyz",
            },
        },
        "success",
    ),
    (
        "runtime marked the call interrupted",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "sleep 60"},
            "tool_response": {"stdout": "", "stderr": "", "interrupted": True},
        },
        "unobserved",
    ),
    (
        "plain success",
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
            "tool_response": {"stdout": "hi", "stderr": "", "interrupted": False},
        },
        "success",
    ),
]


@pytest.mark.parametrize(
    ("label", "payload", "expected"),
    _CLAUDE_HOOK_MATRIX,
    ids=[row[0] for row in _CLAUDE_HOOK_MATRIX],
)
def test_claude_hook_payload_maps_to_honest_outcome(
    label: str, payload: dict[str, Any], expected: str
) -> None:
    """Pins the shared `_claude_hooks` predicates against real probed payloads.

    Expressed against the shared predicates rather than either adapter, because
    both adapters read these payloads through them — which is the whole point of
    the shared module. `claude_code` and `claude_agent_sdk` drifted once already.
    """
    event = payload["hook_event_name"]
    assert is_recordable_event(event)

    if is_failure_event(event):
        kind = "error"
    elif is_unrequested_background(
        payload["tool_name"], payload["tool_input"], payload.get("tool_response")
    ) or is_interrupted(payload.get("tool_response")):
        kind = "unobserved"
    else:
        kind = "success"

    assert kind == expected, f"{label}: adapter would record {kind}, expected {expected}"


@pytest.mark.parametrize(
    "event", ["PreToolUse", "Stop", "SubagentStop", "UserPromptSubmit", "Notification"]
)
def test_claude_non_completion_events_are_never_recorded(event: str) -> None:
    """A positive allowlist. "Not the failure event" is not the success slot —
    a `PreToolUse` payload would otherwise be signed `success` for a tool call
    that has not run."""
    assert not is_recordable_event(event)


# =============================================================================
# RUNTIME: OpenAI Agents SDK  (openai-agents 0.18.x)
# =============================================================================
#
#   MECHANISM                                  -> OUTCOME
#   -------------------------------------------------------------------------
#   Tool raises; SDK's failure_error_function     `on_tool_end` fires with an
#     converts it to an ordinary STRING result    ordinary string  -> unobserved
#   Tool times out; timeout_behavior defaults     same             -> unobserved
#     to "error_as_result"
#
# `RunHooks` structurally cannot tell a laundered failure from a real success,
# so `AuditHooks` records `unobserved(runtime_launders_exceptions)` for EVERY
# call and never `success`. That is instance 1, and the fix was to stop claiming
# an outcome this instrumentation point cannot see. Real coverage comes from
# `@audited_tool`, which runs INSIDE the SDK's failure handling.
#
# This test pins that: the day someone "improves" AuditHooks by recording
# `success` on `on_tool_end`, instance 1 is back.


async def test_openai_agents_hooks_never_record_success() -> None:
    from chiplog.adapters.openai_agents import AuditHooks

    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    key = SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))
    sink = InMemorySink()
    hooks = AuditHooks(AuditRecorder(sink=sink, signing_key=key), session_id="matrix")

    class _Tool:
        name = "search"

    class _Ctx:
        tool_name = "search"
        tool_arguments = '{"q": "x"}'

    # Byte-identical from the hook's side: a real success, and a failure the SDK
    # laundered into an ordinary string. It cannot tell them apart, and must not
    # pretend otherwise.
    await hooks.on_tool_end(_Ctx(), None, _Tool(), "genuine result")
    await hooks.on_tool_end(
        _Ctx(),
        None,
        _Tool(),
        "An error occurred while running the tool. Please try again. Error: boom",
    )

    kinds = [r["payload"]["outcome"]["kind"] for r in sink.records]
    assert kinds == ["unobserved", "unobserved"], (
        f"AuditHooks cannot observe outcomes and must never claim one; got {kinds}"
    )
    assert all(
        r["payload"]["outcome"]["reason"] == "runtime_launders_exceptions"
        for r in sink.records
    )
