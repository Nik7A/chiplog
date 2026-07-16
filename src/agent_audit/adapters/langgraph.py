"""LangGraph adapter — secondary instrumentation path (for non-Claude-CLI users).

Two entry points:

  1. `AuditMiddleware` — subclass of LangChain 1.x's `AgentMiddleware`. Plug
     into `create_agent(model, tools, middleware=[AuditMiddleware(rec)])`
     and every tool call goes through `wrap_tool_call` / `awrap_tool_call`
     → one audit record per tool call.

  2. `@audited_tool` — decorator for any callable (sync or async). Useful
     for raw `StateGraph` users who don't go through `create_agent`, or for
     plain Python code that wants the same audit semantics.

Both routes use the same `AuditRecorder` underneath, and both read the outcome
through the same two module-level rules. Differences between the two are just
how they attach to the runtime.

THE RULE THIS MODULE EXISTS TO ENFORCE — control flow is not an outcome:

  A RETURN is not evidence of success. LangGraph's `ToolNode` catches the tool's
  exception and RETURNS the failure (`ToolMessage(status="error")`, possibly
  nested in a `Command` or a list). An entry point that took a normal return for
  a success would sign `outcome: success` over the runtime's own error text.
  `_find_runtime_failure` is the guard.

  A RAISE is not evidence of failure. LangGraph redirects control flow by
  raising `GraphBubbleUp` — a human-in-the-loop `interrupt()` raises
  `GraphInterrupt` and the tool is RE-EXECUTED on resume; a `ParentCommand`
  carries the result of a tool that SUCCEEDED. An entry point that took any
  exception for a failure would sign `outcome: error` over a call that did not
  fail. `_is_control_flow_signal` is the guard.

Both directions are dishonest, and both have shipped here. See
`tests/test_outcome_honesty_matrix.py` before changing either.

Designed against LangChain 1.3.x / LangGraph 1.2.x. Older versions without
`langchain.agents.middleware` will get a clear ImportError when constructing
`AuditMiddleware`; the `@audited_tool` decorator has no LangChain dependency.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import time
from collections.abc import Coroutine
from typing import Any, Callable, TypeVar

from uuid import uuid7

from agent_audit.emit import AuditRecorder
from agent_audit.schema.v1 import (
    PolicyUnobservedReason,
    Output,
    ToolCall,
    UnobservedReason,
    error,
    success,
    timeout,
    policy_unobserved,
    unobserved,
)

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# str(CancelledError()) is almost always "" — asyncio raises it bare. A record
# whose message is empty asserts nothing, so fall back to a stable description.
#
# Note what this does NOT say: "timeout". From inside the callable we cannot
# know WHY we were cancelled — an outer deadline, a user interrupt, a sibling
# task in a TaskGroup failing. Recording Timeout would be a guess. Error with
# error_type="CancelledError" states exactly what was observed and nothing more.
CANCELLED_MESSAGE = (
    "tool call cancelled from outside; the cause of the cancellation "
    "(deadline, interrupt, sibling failure) is not observable here"
)

# Audit writes that outlived the task that requested them (see
# _record_under_cancellation). The event loop only holds weak references to
# tasks, so without a strong reference here a detached write can be garbage
# collected mid-flight — losing the very record we are trying to save.
_DETACHED_WRITES: set[asyncio.Task[Any]] = set()


def _on_detached_write_done(task: asyncio.Task[Any]) -> None:
    _DETACHED_WRITES.discard(task)
    if task.cancelled():
        logger.error(
            "audit record for a cancelled tool call was itself cancelled "
            "before it could be written; the chain will show a break at "
            "verification time"
        )
        return
    exc = task.exception()
    if exc is not None:
        logger.error(
            "audit recorder failed while recording a cancellation",
            exc_info=exc,
        )


async def _record_under_cancellation(coro: Coroutine[Any, Any, Any]) -> None:
    """Await a recorder call from inside an `except asyncio.CancelledError` block.

    A bare `await recorder.record(...)` is NOT enough here. The task is already
    being cancelled, and the recorder call has await points of its own (the Sink
    protocol is async precisely so backends can do real I/O). A canceller that
    cancels until the task is done — loop shutdown, a cancel-retry loop, an
    aggressive supervisor — cancels those await points too, so nothing is
    written and the handler becomes a no-op that merely looks correct.

    `asyncio.shield` moves the write onto its own task, so a second cancellation
    hits the shield wrapper instead of the write. If that happens we detach the
    write: it keeps running to completion on the loop while we return at once,
    because blocking a task the runtime is trying to kill is not our call to
    make. Detachment is best-effort by nature — if the loop itself is torn down
    the write may not land, and that surfaces later as a chain break, which is
    the correct and visible failure mode.

    This function never raises. Neither a recorder failure nor a second
    cancellation may replace the original CancelledError that the caller is
    about to re-raise — the guarantee the error/timeout paths already give.
    Note the plain `except Exception` those paths use is not sufficient here:
    the shielded await can raise CancelledError, which is a BaseException.
    """
    task = asyncio.ensure_future(coro)
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        _DETACHED_WRITES.add(task)
        task.add_done_callback(_on_detached_write_done)
    except Exception:
        logger.exception(
            "audit recorder failed while recording a cancellation; "
            "the original CancelledError will be re-raised"
        )


# ---------------------------------------------------------------------------
# Handing raw values to the recorder
#
# The values an adapter captures — tool args, a returned body, a runtime
# failure's text — are passed to `recorder.record(...)` AS-IS. The recorder
# redacts them and then runs `normalize_for_canonical`, which replaces every
# JCS-hostile value (bytes, set, an out-of-domain int, a non-string dict key)
# with a faithful, ANNOUNCED marker. When it CANNOT (a value whose repr() raises,
# a dict key whose str() raises, a surrogate str), the recorder does not drop the
# call silently: its construction guard poisons the chain head and raises a typed
# RecordBuildError, so the loss is visible as a chain break at verification time.
# Either way — faithful marker or loud chain break — the tool call leaves a trace.
#
# An earlier `_coerce_to_json = json.loads(json.dumps(v, default=str))` step
# did that normalization here, badly, and BEFORE the recorder saw the value:
#   - a dict with a non-string key made `json.dumps` raise `TypeError`, which
#     the surrounding `except Exception` swallowed — the tool ran, no record was
#     written, and the chain did NOT break. A silently dropped tool call.
#   - a hostile value (bytes -> "b'...'", set -> "{...}") was stringified with
#     `payload.unrepresentable` left EMPTY — a laundered value signed as genuine.
# Handing the raw value to the recorder is what lets its normalize pass do the
# honest thing. LangGraph state / config / runtime objects that used to be
# str()-ed for readability now become an announced `unsupported_type` marker,
# which states what they were without pretending to a value they never had.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Runtime-reported failure detection — shared by BOTH entry points
#
# `@audited_tool` and `AuditMiddleware` face the same hazard from opposite
# sides, so the rule that decides "did this return value report a failure?"
# lives once, above both of them, and is not owned by either.
# ---------------------------------------------------------------------------


def _extract_output_body(result: Any) -> Any:
    """Extract body from ToolMessage / Command / raw return."""
    content = getattr(result, "content", None)
    if content is not None:
        return content
    update = getattr(result, "update", None)
    if update is not None:
        return update
    return str(result)


# `ToolMessage.status` is typed `Literal["success", "error"]` and is set by the
# runtime, not by the tool. "error" is the only value that means failure.
_TOOL_MESSAGE_ERROR_STATUS = "error"

# `ToolMessage.type` is the literal `"tool"` (langchain-core 1.4.9) — the
# discriminator LangChain itself uses to tell message classes apart. Requiring
# it alongside `status` is what makes the predicate safe for `@audited_tool`;
# see `_is_failed_message`.
_TOOL_MESSAGE_TYPE = "tool"

# error_type for a failure the runtime handed over as a message rather than an
# exception. The original exception class is gone by the time ToolNode has
# converted it to text, so naming one would be fabricating evidence. Same label,
# same reasoning, as the Claude adapters use for their message-shaped failures.
_RUNTIME_FAILURE_TYPE = "ToolFailure"


def _is_failed_message(obj: Any) -> bool:
    """True for a ToolMessage-shaped object the runtime marked as failed.

    `status` is a runtime-supplied structural field with a closed set of literal
    values (`Literal["success", "error"]`) — the same class of evidence as
    `is_interrupt` and `backgroundTaskId` in the Claude adapters. Reading it is
    not error-string sniffing, and nothing here falls back to inspecting
    `content`: guessing failure from the shape of a message would derive a
    conclusion the runtime never reported, and it would misfire the first time a
    tool legitimately returns the word "error".

    BOTH fields are required, not just `status`. Inside `AuditMiddleware`,
    `status` alone would be enough — LangGraph's `ToolNode` constrains what can
    reach it to `ToolMessage | Command | list`, and nothing else in that set
    carries a `status`. But this predicate also serves `@audited_tool`, which
    wraps ARBITRARY user callables. An HTTP-response object, a job record, a CI
    build result: all routinely carry a `.status`, and "error" is an ordinary
    value for them to hold. Reading one of those as a failed tool call would
    record a false FAILURE — the mirror image of signing `success` over a
    returned failure, and no more honest. `type == "tool"` is the discriminator
    LangChain itself uses to tell message classes apart, and it excludes the
    look-alikes without missing a single real `ToolMessage`.

    Still duck-typed, deliberately: an `isinstance(obj, ToolMessage)` check
    would need a module-scope import of a LangChain type, and `@audited_tool`
    must keep working with langchain and langgraph absent (see
    `test_package_works_with_langchain_and_langgraph_absent`).
    """
    return (
        getattr(obj, "status", None) == _TOOL_MESSAGE_ERROR_STATUS
        and getattr(obj, "type", None) == _TOOL_MESSAGE_TYPE
    )


def _command_messages(result: Any) -> list[Any]:
    """Messages carried in a `Command`'s state update; `[]` for anything else.

    `Command.update` is either a dict of state fields (the ToolNode `dict` /
    `tool_calls` input types — what `create_agent` uses) or a bare list of
    messages (the `list` input type). The messages live under ToolNode's
    `messages_key`, which is configurable and which an adapter cannot see from
    here, so every list-valued field is scanned rather than guessing the key.
    That cannot produce a false positive: only an object carrying a literal
    `status == "error"` counts, and no ordinary state value has one.

    Never raises. An `update` that is absent, None, or shaped in a way we cannot
    read messages out of yields no messages — which is not evidence of failure,
    and must not become an exception thrown into the tool's return path.
    """
    update = getattr(result, "update", None)
    if isinstance(update, dict):
        candidates: list[Any] = list(update.values())
    elif isinstance(update, (list, tuple)):
        candidates = [update]
    else:
        return []

    messages: list[Any] = []
    for candidate in candidates:
        if isinstance(candidate, (list, tuple)):
            messages.extend(candidate)
    return messages


def _find_runtime_failure(result: Any) -> Any | None:
    """The first message the runtime marked as failed, or None if there is none.

    A failed tool call does NOT arrive here as a raised exception. LangGraph's
    `ToolNode` catches the tool's exception and RETURNS a failure — and that
    ToolNode method is precisely the `handler` passed to `wrap_tool_call` /
    `awrap_tool_call`. The handler returns normally. An adapter that infers
    failure only from a raised exception therefore falls into its success branch
    and signs `outcome: success` over the error text: an Ed25519 signature
    attesting that a call succeeded when the runtime said it failed.

    This is not an edge case. Under `create_agent` — which does not expose
    `handle_tool_errors`, so ToolNode's default governs — a model calling a tool
    with arguments that fail validation raises `ToolInvocationError`, which the
    default handler converts into an error ToolMessage rather than propagating.
    Bad tool arguments are among the commonest real agent failures. And a caller
    who sets `ToolNode(..., handle_tool_errors=True)` routes EVERY tool exception
    down this return-don't-raise path, so nothing would ever be recorded honestly.

    The failure reaches us in any of THREE shapes, and only the first carries a
    top-level `status`. All three are produced by a real `create_agent`:

      ToolMessage(status="error")
      Command(update={"messages": [ToolMessage(status="error")]})
      [Command(...), ToolMessage(status="error")]

    A `Command`-returning tool — the mainstream handoff / state-update pattern —
    puts the failure inside its state update, where a top-level `status` read
    finds nothing. The list shape reaches us because `ToolNode._run_one`'s
    `execute` closure is annotated `-> ToolMessage | Command` while returning
    `_execute_tool_sync`, whose real return type is
    `ToolMessage | Command | list[Command | ToolMessage]`: the annotation is
    narrower than the runtime value. Reading only the top level signed `success`
    over both.

    Recursion is bounded — a list holds Commands and messages, a Command holds
    messages, and messages hold nothing further.

    Duck-typed rather than `isinstance(result, (ToolMessage, Command))` on
    purpose: this module's LangChain imports are optional (`@audited_tool` must
    keep working with langchain and langgraph absent — see
    `test_package_works_with_langchain_and_langgraph_absent`), and importing
    either type at module scope to answer this question would break that
    guarantee for every user who never installed LangChain.
    """
    if isinstance(result, (list, tuple)):
        for item in result:
            failure = _find_runtime_failure(item)
            if failure is not None:
                return failure
        return None

    if _is_failed_message(result):
        return result

    for message in _command_messages(result):
        if _is_failed_message(message):
            return message

    return None


# ---------------------------------------------------------------------------
# Runtime CONTROL-FLOW signals — the mirror image of the hazard above
#
# `_find_runtime_failure` exists because a RETURN is not evidence of success.
# This exists because a RAISE is not evidence of failure.
#
# LangGraph signals control flow by raising `GraphBubbleUp`, an ordinary
# `Exception` subclass. Its subclasses are the whole channel:
#
#   GraphInterrupt / NodeInterrupt — `interrupt()` inside a tool. The graph
#       SUSPENDS for human input; on resume the tool is RE-EXECUTED from the top
#       and typically succeeds.
#   ParentCommand — the tool bubbled a navigation `Command` to the parent graph.
#       The tool SUCCEEDED; the exception is how its result travels.
#   GraphDrained — internal scheduling signal.
#
# None of them is a failure. An `except Exception` that records
# `error(type(exc).__name__, ...)` therefore signs an Ed25519 signature
# attesting that `book_flight` FAILED with a `GraphInterrupt` — over a call that
# was merely paused for approval and then completed. A false failure is exactly
# as dishonest as a false success, and it is the same root confusion: reading
# CONTROL FLOW as if it were an OUTCOME. The runtime never said "failed".
#
# The boundary is `GraphBubbleUp` itself, not a list of its subclasses. Every
# other exception langgraph defines (`InvalidUpdateError`, `GraphRecursionError`,
# `NodeTimeoutError`, ...) is a genuine failure and must keep recording `error`,
# and a future subclass of `GraphBubbleUp` is covered without a code change.
# ---------------------------------------------------------------------------


@functools.cache
def _control_flow_signal_type() -> type[BaseException] | None:
    """`langgraph.errors.GraphBubbleUp`, or None when langgraph is absent.

    Imported lazily, on first exception, and never at module scope: this module
    must keep importing with langchain and langgraph uninstalled — `@audited_tool`
    is runtime-agnostic and is the decorator the OpenAI Agents adapter points its
    users at (see `test_package_works_with_langchain_and_langgraph_absent`).

    A real `issubclass` check against the real class, not a name-match on the
    exception: the identity of the control-flow channel is a structural fact the
    runtime supplies, and matching on `type(exc).__name__` would fire on any
    unrelated class that happened to be called `GraphInterrupt`.
    """
    try:
        from langgraph.errors import GraphBubbleUp
    except ImportError:
        return None
    return GraphBubbleUp


def _is_control_flow_signal(exc: BaseException) -> bool:
    """True when the runtime raised to redirect control flow, not to report a failure."""
    signal_type = _control_flow_signal_type()
    return signal_type is not None and isinstance(exc, signal_type)


def audited_tool(
    recorder: AuditRecorder,
    *,
    session_id: str | None = None,
    tool_name: str | None = None,
) -> Callable[[F], F]:
    """Decorator: wrap a tool callable with audit recording.

    Records ONE audit entry per call. Works on both sync and async
    callables. Detects the real outcome: `Timeout` on `asyncio.TimeoutError`,
    `Error(error_type="CancelledError")` on `asyncio.CancelledError`,
    `Unobserved(control_flow_signal)` on a LangGraph control-flow signal
    (`GraphBubbleUp` — a HITL `interrupt()`, a `ParentCommand` handoff), `Error`
    on any other exception, `Error(error_type="ToolFailure")` on a failure the
    runtime RETURNED, and `Success` only when none of those hold. The exception
    is always re-raised after recording — an audit layer observes control flow,
    it never alters it.

    Returning normally is NOT the same as succeeding, which is why the success
    branch is the last one and not the default. A tool run under LangGraph's
    `ToolNode` — the runtime a raw `StateGraph` user reaches this decorator
    through — has its exception caught by the runtime and handed back as a
    RETURN VALUE: `ToolMessage(status="error")`, or one nested inside the
    `Command` a state-update / handoff tool returns. `_find_runtime_failure`
    looks for it in every shape it arrives in, exactly as `AuditMiddleware`
    does. Taking "returned" for "succeeded" would sign an Ed25519 signature
    attesting that a call succeeded when the runtime said it failed.

    The returned failure is passed through to the caller unaltered.

    A raise is NOT evidence of failure either, which is why the generic
    exception branch asks `_is_control_flow_signal` first. LangGraph signals
    control flow by raising: `interrupt()` inside a tool raises `GraphInterrupt`,
    the graph suspends for human input, and on resume the tool is RE-EXECUTED
    from the top and typically succeeds. Recording `error(GraphInterrupt)` would
    attest a failure that never happened — a false failure, exactly as dishonest
    as a false success.

    Cancellation gets its own branch because `asyncio.CancelledError` derives
    from BaseException, so `except Exception` never sees it: an outer
    `asyncio.wait_for` / `asyncio.timeout` / TaskGroup abort — including the
    OpenAI Agents SDK's own tool-timeout enforcement, which cancels the
    coroutine from outside — would otherwise leave NO record of a call that
    really happened. It is recorded as Error, never Timeout: from in here the
    cause of the cancellation is not observable, and this library does not
    guess.

    If the recorder itself raises (e.g. a degraded sink), that secondary failure
    is logged and swallowed on EVERY path — the tool's own result reaches the
    caller either way: its ORIGINAL exception where it raised, its return value
    where it returned. An audit layer that can crash the call it is observing is
    not observing it.

    A dropped record is not lost evidence: AuditRecorder advances its chain head
    before writing, so a failed write surfaces later as a chain break at
    verification time. Under-recording visibly beats crashing the run.
    """

    def decorator(fn: F) -> F:
        actual_name: str = tool_name or str(getattr(fn, "__name__", "anonymous_tool"))
        sid = session_id or "langgraph-default"

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                started_ns = time.monotonic_ns()
                tool_input = {"args": args, "kwargs": kwargs}
                try:
                    result = await fn(*args, **kwargs)
                except asyncio.CancelledError as exc:
                    # BaseException, not Exception — invisible to both handlers
                    # below. Without this branch the call would leave no record.
                    await _record_under_cancellation(
                        recorder.record(
                            session_id=sid,
                            step_id=str(uuid7()),
                            tool=ToolCall(name=actual_name),
                            input=tool_input,
                            output=Output(body=None),
                            policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                            outcome=error(
                                "CancelledError", str(exc) or CANCELLED_MESSAGE
                            ),
                        )
                    )
                    raise
                except asyncio.TimeoutError:
                    elapsed_ms = (time.monotonic_ns() - started_ns) // 1_000_000
                    try:
                        await recorder.record(
                            session_id=sid,
                            step_id=str(uuid7()),
                            tool=ToolCall(name=actual_name),
                            input=tool_input,
                            output=Output(body=None),
                            policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                            outcome=timeout(elapsed_ms),
                        )
                    except Exception:
                        logger.exception(
                            "audit recorder failed while recording a timeout "
                            "for tool %r; original exception will be re-raised",
                            actual_name,
                        )
                    raise
                except Exception as exc:
                    # A raise is not evidence of failure. LangGraph redirects
                    # control flow by raising `GraphBubbleUp` — a HITL
                    # `interrupt()`, a `ParentCommand` handoff — and the call
                    # neither succeeded nor failed: it did not finish.
                    outcome = (
                        unobserved(UnobservedReason.CONTROL_FLOW_SIGNAL)
                        if _is_control_flow_signal(exc)
                        else error(type(exc).__name__, str(exc))
                    )
                    try:
                        await recorder.record(
                            session_id=sid,
                            step_id=str(uuid7()),
                            tool=ToolCall(name=actual_name),
                            input=tool_input,
                            output=Output(body=None),
                            policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                            outcome=outcome,
                        )
                    except Exception:
                        logger.exception(
                            "audit recorder failed while recording an error "
                            "for tool %r; original exception will be re-raised",
                            actual_name,
                        )
                    raise
                else:
                    # Returning normally is NOT evidence of success. The runtime
                    # encodes a failure it handled itself in the RETURN VALUE —
                    # top-level, or nested in a Command's state update, or in a
                    # list. `AuditMiddleware` has looked for it since the
                    # ToolMessage fix; this entry point must too, and it is the
                    # one the module docstring routes raw StateGraph users to.
                    failure = _find_runtime_failure(result)
                    try:
                        if failure is not None:
                            await recorder.record(
                                session_id=sid,
                                step_id=str(uuid7()),
                                tool=ToolCall(name=actual_name),
                                input=tool_input,
                                # The error text is the record's evidence and it
                                # lives in outcome.message. For a nested failure
                                # it is the FAILING message's content, not the
                                # top-level object's. No successful output exists.
                                output=Output(body=None),
                                policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                                outcome=error(
                                    _RUNTIME_FAILURE_TYPE,
                                    _extract_output_body(failure),
                                ),
                            )
                        else:
                            await recorder.record(
                                session_id=sid,
                                step_id=str(uuid7()),
                                tool=ToolCall(name=actual_name),
                                input=tool_input,
                                output=Output(body=result),
                                policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                                outcome=success(),
                            )
                    except Exception:
                        # The tool RETURNED. A degraded sink does not get to turn
                        # that into an exception the tool never raised.
                        logger.exception(
                            "audit recorder failed while recording a returned "
                            "outcome for tool %r; the tool's result is returned "
                            "unaltered",
                            actual_name,
                        )
                    return result

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            started_ns = time.monotonic_ns()
            tool_input = {"args": args, "kwargs": kwargs}
            try:
                result = fn(*args, **kwargs)
            except asyncio.CancelledError as exc:
                # asyncio cannot cancel synchronous code — no shield is needed
                # or possible here, and record_sync drives its own loop. But a
                # sync callable can still RAISE CancelledError (a sync bridge
                # re-raising the one it got from a loop it drove itself), and
                # because it is a BaseException the handlers below would miss
                # it and drop the record. Same bug, same outcome, no shield.
                try:
                    recorder.record_sync(
                        session_id=sid,
                        step_id=str(uuid7()),
                        tool=ToolCall(name=actual_name),
                        input=tool_input,
                        output=Output(body=None),
                        policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                        outcome=error("CancelledError", str(exc) or CANCELLED_MESSAGE),
                    )
                except Exception:
                    logger.exception(
                        "audit recorder failed while recording a cancellation "
                        "for tool %r; original exception will be re-raised",
                        actual_name,
                    )
                raise
            except asyncio.TimeoutError:
                elapsed_ms = (time.monotonic_ns() - started_ns) // 1_000_000
                try:
                    recorder.record_sync(
                        session_id=sid,
                        step_id=str(uuid7()),
                        tool=ToolCall(name=actual_name),
                        input=tool_input,
                        output=Output(body=None),
                        policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                        outcome=timeout(elapsed_ms),
                    )
                except Exception:
                    logger.exception(
                        "audit recorder failed while recording a timeout "
                        "for tool %r; original exception will be re-raised",
                        actual_name,
                    )
                raise
            except Exception as exc:
                # See the async wrapper: `GraphBubbleUp` is a control-flow
                # signal, not a failure. Same rule, same reason.
                outcome = (
                    unobserved(UnobservedReason.CONTROL_FLOW_SIGNAL)
                    if _is_control_flow_signal(exc)
                    else error(type(exc).__name__, str(exc))
                )
                try:
                    recorder.record_sync(
                        session_id=sid,
                        step_id=str(uuid7()),
                        tool=ToolCall(name=actual_name),
                        input=tool_input,
                        output=Output(body=None),
                        policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                        outcome=outcome,
                    )
                except Exception:
                    logger.exception(
                        "audit recorder failed while recording an error "
                        "for tool %r; original exception will be re-raised",
                        actual_name,
                    )
                raise
            else:
                # See the async wrapper: a failure the runtime handled itself
                # arrives as a RETURN VALUE, not an exception. Same shapes, same
                # detection, same reason.
                failure = _find_runtime_failure(result)
                try:
                    if failure is not None:
                        recorder.record_sync(
                            session_id=sid,
                            step_id=str(uuid7()),
                            tool=ToolCall(name=actual_name),
                            input=tool_input,
                            output=Output(body=None),
                            policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                            outcome=error(
                                _RUNTIME_FAILURE_TYPE,
                                _extract_output_body(failure),
                            ),
                        )
                    else:
                        recorder.record_sync(
                            session_id=sid,
                            step_id=str(uuid7()),
                            tool=ToolCall(name=actual_name),
                            input=tool_input,
                            output=Output(body=result),
                            policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                            outcome=success(),
                        )
                except Exception:
                    # See the async wrapper: the tool RETURNED, and a recorder
                    # failure must not replace its result.
                    logger.exception(
                        "audit recorder failed while recording a returned "
                        "outcome for tool %r; the tool's result is returned "
                        "unaltered",
                        actual_name,
                    )
                return result

        return sync_wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# AgentMiddleware integration
# ---------------------------------------------------------------------------

try:
    from langchain.agents.middleware import AgentMiddleware as _AgentMiddleware

    _AGENT_MIDDLEWARE_AVAILABLE = True
except ImportError:
    _AgentMiddleware = object  # type: ignore[assignment, misc]
    _AGENT_MIDDLEWARE_AVAILABLE = False


def _extract_tool_info(request: Any) -> tuple[str, Any]:
    """Best-effort extraction of (tool_name, tool_args) from a ToolCallRequest."""
    tool_call = getattr(request, "tool_call", None)
    if isinstance(tool_call, dict):
        return tool_call.get("name", "unknown_tool"), tool_call.get("args", {})
    if tool_call is not None:
        return (
            getattr(tool_call, "name", "unknown_tool"),
            getattr(tool_call, "args", {}),
        )
    return "unknown_tool", {}


class AuditMiddleware(_AgentMiddleware):
    """LangChain 1.x AgentMiddleware that records every tool call.

    Usage:
        from langchain.agents import create_agent
        from agent_audit import AuditRecorder, LocalFileSink, load_signing_key
        from agent_audit.adapters.langgraph import AuditMiddleware

        recorder = AuditRecorder(
            sink=LocalFileSink(dir="./audit"),
            signing_key=load_signing_key("./signing.key"),
        )
        agent = create_agent(
            model="claude-opus-4-7",
            tools=[my_tool],
            middleware=[AuditMiddleware(recorder, session_id="demo")],
        )
    """

    def __init__(
        self,
        recorder: AuditRecorder,
        *,
        session_id: str | None = None,
    ) -> None:
        if not _AGENT_MIDDLEWARE_AVAILABLE:
            raise ImportError(
                "AuditMiddleware requires langchain >= 1.0 with "
                "langchain.agents.middleware. Install via `pip install langchain`."
            )
        super().__init__()
        self._recorder = recorder
        self._session_id = session_id or "langgraph-default"

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        """Sync interceptor: run the tool, record the real outcome, return.

        A tool failure reaches this method by TWO different routes, and both
        must record `error`:

          - the handler raises (ToolNode with `handle_tool_errors=False`, or an
            exception type its handler declines) — the `except` branches below;
          - the handler RETURNS the failure (ToolNode's default and the
            `handle_tool_errors=True` path, where it catches the tool's exception
            itself) — `_find_runtime_failure` in the `else` branch. The returned
            failure may be a top-level `ToolMessage(status="error")`, or nested
            inside a `Command`'s state update, or inside a list; see
            `_find_runtime_failure`.

        The second route is the one the runtime takes by default. Treating a
        normal return as a success without looking for `status` signs a `success`
        over the runtime's own error text.

        The exception (if any) is always re-raised after recording, and a
        returned failure is passed onward unaltered — an audit layer observes
        control flow, it never alters it.

        A RECORDER failure never alters control flow either, on ANY route. Every
        recorder call in this method is guarded: the failure is logged, and the
        tool's own result — its return value or its original exception — is what
        reaches the caller. The success and returned-failure routes used to be
        unguarded, and that is how a degraded sink came to crash the tool calls
        it was only supposed to be observing: the concurrency defect produced the
        SinkErrors, and the unguarded success path is what let them out into the
        agent. An audit layer that can break the run it is auditing is not an
        audit layer.

        A dropped record is not lost evidence: AuditRecorder advances its chain
        head before writing, so a failed write surfaces as a chain break at
        verification time — visible to the verifier, and without destroying the
        run that produced it. Under-recording loudly beats crashing.
        """
        started_ns = time.monotonic_ns()
        try:
            result = handler(request)
        except asyncio.CancelledError as exc:
            # See the sync decorator path: asyncio cannot cancel sync code, but
            # a handler can still raise CancelledError, and it is a
            # BaseException that both handlers below would miss.
            try:
                self._record_sync_outcome(
                    request,
                    error("CancelledError", str(exc) or CANCELLED_MESSAGE),
                    None,
                )
            except Exception:
                logger.exception(
                    "audit recorder failed while recording a cancellation; "
                    "original exception will be re-raised"
                )
            raise
        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic_ns() - started_ns) // 1_000_000
            try:
                self._record_sync_outcome(request, timeout(elapsed_ms), None)
            except Exception:
                logger.exception(
                    "audit recorder failed while recording a timeout; "
                    "original exception will be re-raised"
                )
            raise
        except Exception as exc:
            # A raise is not evidence of failure. `GraphBubbleUp` is how
            # LangGraph redirects control flow — a HITL `interrupt()` suspends
            # the graph and RE-EXECUTES this tool on resume; a `ParentCommand`
            # carries the result of a tool that SUCCEEDED. Recording `error` for
            # either signs a failure that never happened.
            outcome = (
                unobserved(UnobservedReason.CONTROL_FLOW_SIGNAL)
                if _is_control_flow_signal(exc)
                else error(type(exc).__name__, str(exc))
            )
            try:
                self._record_sync_outcome(request, outcome, None)
            except Exception:
                logger.exception(
                    "audit recorder failed while recording a tool error; "
                    "original exception will be re-raised"
                )
            raise
        else:
            # Returning normally is NOT the same as succeeding. ToolNode catches
            # the tool's exception and returns the failure from this very handler
            # — as an error ToolMessage, or nested inside a Command's state
            # update, or inside a list. Only `status`, wherever it sits, tells us
            # which happened.
            failure = _find_runtime_failure(result)
            try:
                if failure is not None:
                    self._record_sync_outcome(
                        request,
                        error(
                            _RUNTIME_FAILURE_TYPE,
                            # The evidence is the FAILING message's content,
                            # which for a nested failure is not the top-level
                            # object's.
                            _extract_output_body(failure),
                        ),
                        # The error text is the record's evidence and it lives in
                        # outcome.message. No successful output exists to report.
                        None,
                    )
                else:
                    self._record_sync_outcome(
                        request, success(), _extract_output_body(result)
                    )
            except Exception:
                # The tool RETURNED. Whatever it returned is the truth about what
                # happened, and a failing sink does not get to overwrite it with
                # an exception the tool never raised.
                logger.exception(
                    "audit recorder failed while recording a returned outcome; "
                    "the tool's result is returned unaltered"
                )
            return result

    async def awrap_tool_call(
        self, request: Any, handler: Callable[[Any], Any]
    ) -> Any:
        """Async interceptor: await the tool, record the real outcome, return.

        Like the sync path, a failure arrives either as a raised exception or as
        a returned failure — top-level, nested in a `Command`'s state update, or
        inside a list. ToolNode's async executor catches and converts exactly as
        the sync one does. See `wrap_tool_call`, including its note on which
        recorder failures are swallowed and which are not: the returned-failure
        branch below is unguarded, exactly as on the sync path.

        `asyncio.TimeoutError` is caught before the generic `Exception`
        handler: since Python 3.11 it aliases the builtin `TimeoutError`,
        which subclasses `OSError`, so a generic handler placed first would
        swallow it and mislabel every timeout as a plain error.

        If the recorder fails while recording a RAISED tool failure, that
        secondary failure is logged and swallowed so the tool's ORIGINAL
        exception is never replaced.
        """
        started_ns = time.monotonic_ns()
        try:
            result = await handler(request)
        except asyncio.CancelledError as exc:
            # BaseException, not Exception — invisible to both handlers below.
            # This is the path an SDK-enforced tool timeout takes (the runtime
            # wraps the call from outside and cancels the coroutine), so
            # without this branch those calls leave no record at all.
            name, args = _extract_tool_info(request)
            await _record_under_cancellation(
                self._recorder.record(
                    session_id=self._session_id,
                    step_id=str(uuid7()),
                    tool=ToolCall(name=name),
                    input=args,
                    output=Output(body=None),
                    policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                    outcome=error("CancelledError", str(exc) or CANCELLED_MESSAGE),
                )
            )
            raise
        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic_ns() - started_ns) // 1_000_000
            try:
                await self._record_async_outcome(request, timeout(elapsed_ms), None)
            except Exception:
                logger.exception(
                    "audit recorder failed while recording a timeout; "
                    "original exception will be re-raised"
                )
            raise
        except Exception as exc:
            # See wrap_tool_call: `GraphBubbleUp` is a control-flow signal, not
            # a failure. The async ToolNode path re-raises it identically.
            outcome = (
                unobserved(UnobservedReason.CONTROL_FLOW_SIGNAL)
                if _is_control_flow_signal(exc)
                else error(type(exc).__name__, str(exc))
            )
            try:
                await self._record_async_outcome(request, outcome, None)
            except Exception:
                logger.exception(
                    "audit recorder failed while recording a tool error; "
                    "original exception will be re-raised"
                )
            raise
        else:
            # See wrap_tool_call: the async ToolNode path (`_execute_tool_async`)
            # catches and returns the failure — top-level, nested in a Command,
            # or in a list — in exactly the same shapes as the sync one.
            failure = _find_runtime_failure(result)
            try:
                if failure is not None:
                    await self._record_async_outcome(
                        request,
                        error(
                            _RUNTIME_FAILURE_TYPE,
                            _extract_output_body(failure),
                        ),
                        None,
                    )
                else:
                    await self._record_async_outcome(
                        request, success(), _extract_output_body(result)
                    )
            except Exception:
                # See wrap_tool_call: the tool RETURNED, so a recorder failure
                # must not replace its result with an exception.
                logger.exception(
                    "audit recorder failed while recording a returned outcome; "
                    "the tool's result is returned unaltered"
                )
            return result

    def _record_sync_outcome(
        self, request: Any, outcome: Any, output_body: Any
    ) -> None:
        name, args = _extract_tool_info(request)
        self._recorder.record_sync(
            session_id=self._session_id,
            step_id=str(uuid7()),
            tool=ToolCall(name=name),
            input=args,
            output=Output(body=output_body),
            policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
            outcome=outcome,
        )

    async def _record_async_outcome(
        self, request: Any, outcome: Any, output_body: Any
    ) -> None:
        name, args = _extract_tool_info(request)
        await self._recorder.record(
            session_id=self._session_id,
            step_id=str(uuid7()),
            tool=ToolCall(name=name),
            input=args,
            output=Output(body=output_body),
            policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
            outcome=outcome,
        )


__all__ = ["AuditMiddleware", "audited_tool"]
