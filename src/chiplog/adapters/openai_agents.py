"""OpenAI Agents SDK adapter for chiplog.

**Use `@audited_tool` for audit-grade coverage. `AuditHooks` cannot detect failures.**

`RunHooks` structurally cannot observe a failed tool call. When a function tool
raises, the SDK catches the exception itself and calls `failure_error_function`
(default: `default_tool_error_function`), which converts it into a plain string —
"An error occurred while running the tool. Please try again. Error: ...". That
string is returned as an ordinary tool result, so `on_tool_end` fires with it and
cannot distinguish it from a legitimate string return. Timeouts behave the same
way: `timeout_behavior` defaults to "error_as_result".

In the alternative configuration (`failure_error_function=None`,
`timeout_behavior="raise_exception"`) the exception — `ToolTimeoutError` —
propagates instead, `on_tool_end` never fires, and the failed call produces no
record at all.

Both branches are unusable for audit: one launders failures into successes, the
other drops them. Therefore:

    from chiplog import audited_tool  # runtime-agnostic

    @audited_tool(recorder, session_id="my-run")
    async def search(query: str) -> str:
        ...

The decorator wraps your callable and therefore runs *inside* the SDK's failure
handling, seeing the live exception before conversion.

`AuditHooks` remains for users who want a runtime-level hook. Because it cannot
tell a success from an SDK-laundered failure, every record it writes carries
``outcome=Unobserved(reason="runtime_launders_exceptions")`` — never ``Success``.
It asserts what it actually knows and nothing more. If you need the outcome
itself, use ``@audited_tool``.

Designed against openai-agents 0.18.2.
"""

from __future__ import annotations

import json
from typing import Any

from uuid import uuid7

from chiplog.emit import AuditRecorder
from chiplog.schema.v1 import (
    PolicyUnobservedReason,
    Output,
    ToolCall,
    UnobservedReason,
    policy_unobserved,
    unobserved,
)


def _extract_tool_name(tool: Any, fallback_context: Any) -> str:
    """Best-effort tool-name extraction from the SDK objects.

    Function tools expose ``name``; other local-tool families may not.
    ``ToolContext`` carries ``tool_name`` for function-tool invocations
    as the canonical fallback.
    """
    name = getattr(tool, "name", None)
    if isinstance(name, str) and name:
        return name
    name = getattr(fallback_context, "tool_name", None)
    if isinstance(name, str) and name:
        return name
    return "unknown_tool"


def _extract_tool_args(context: Any) -> Any:
    """Decode the JSON-string arguments from ``ToolContext`` when present.

    ``ToolContext.tool_arguments`` is the raw JSON string the SDK passes
    to the tool. When parsing fails (malformed, or non-ToolContext context),
    return the value as-is so the audit record still captures what the SDK
    actually saw rather than silently dropping the field.
    """
    args = getattr(context, "tool_arguments", None)
    if args is None:
        return {}
    if isinstance(args, str):
        try:
            return json.loads(args)
        except (ValueError, TypeError):
            return args
    return args


def _extract_output_body(result: Any) -> Any:
    """Normalise a tool result to a JSON-friendly body.

    Function-tool results are typically str. Structured tool-output objects
    expose ``output`` directly. Anything else falls back to ``str(result)``
    so the record always has *something* to canonicalise.
    """
    if isinstance(result, str):
        return result
    body = getattr(result, "output", None)
    if body is not None:
        return body
    return str(result)


# ---------------------------------------------------------------------------
# AuditHooks
# ---------------------------------------------------------------------------

try:
    from agents import RunHooks as _RunHooks

    _RUN_HOOKS_AVAILABLE = True
except ImportError:
    _RunHooks = object  # type: ignore[assignment, misc]
    _RUN_HOOKS_AVAILABLE = False


class AuditHooks(_RunHooks):
    """OpenAI Agents SDK ``RunHooks`` that records every local tool call.

    Usage:
        from agents import Agent, Runner
        from chiplog import AuditRecorder, LocalFileSink, load_signing_key
        from chiplog.adapters.openai_agents import AuditHooks

        recorder = AuditRecorder(
            sink=LocalFileSink(dir="./audit"),
            signing_key=load_signing_key("./signing.key"),
        )
        agent = Agent(name="researcher", tools=[my_tool])
        result = await Runner.run(
            starting_agent=agent,
            input="...",
            hooks=AuditHooks(recorder=recorder, session_id="demo"),
        )

    Records are emitted on ``on_tool_end`` with
    ``outcome=Unobserved(reason="runtime_launders_exceptions")``.

    This hook cannot detect failures: the SDK converts tool exceptions into
    ordinary string results before ``on_tool_end`` sees them, so a failed call and
    a successful one are byte-identical from here. Rather than sign a ``success``
    it cannot vouch for, it records that the outcome was unobservable and why.
    Use ``@audited_tool`` on the tool callable for real outcome coverage.
    """

    def __init__(
        self,
        recorder: AuditRecorder,
        *,
        session_id: str | None = None,
    ) -> None:
        if not _RUN_HOOKS_AVAILABLE:
            raise ImportError(
                "AuditHooks requires openai-agents >= 0.18 (tested against 0.18.2). "
                "Install via `pip install openai-agents`."
            )
        super().__init__()
        self._recorder = recorder
        self._session_id = session_id or "openai-agents-default"

    async def on_tool_end(
        self, context: Any, agent: Any, tool: Any, result: Any
    ) -> None:
        """Emit one audit record for the completed tool invocation."""
        # Hand the RAW extracted values to the recorder. It redacts, then runs
        # `normalize_for_canonical`, which turns every JCS-hostile value (bytes,
        # set, a non-string dict key, an out-of-domain int) into a faithful,
        # ANNOUNCED marker. For a value that defeats even that (its repr() raises,
        # a dict key's str() raises), the recorder's construction guard poisons
        # the chain head and raises a typed RecordBuildError instead of dropping
        # the call — so the loss is a chain break at verification time and a typed
        # error out of this hook, never silent. Pre-laundering here with
        # `json.dumps(default=str)` would defeat that guarantee: a non-string key
        # would raise a raw `TypeError` (crashing this hook untyped, no chain
        # break), and a hostile value would be stringified with nothing recorded
        # in `payload.unrepresentable`.
        await self._recorder.record(
            session_id=self._session_id,
            step_id=str(uuid7()),
            tool=ToolCall(name=_extract_tool_name(tool, context)),
            input=_extract_tool_args(context),
            output=Output(body=_extract_output_body(result)),
            policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
            outcome=unobserved(UnobservedReason.RUNTIME_LAUNDERS_EXCEPTIONS),
            agent_name=getattr(agent, "name", None),
        )


__all__ = ["AuditHooks"]
