"""OpenAI Agents SDK adapter — `RunHooks` for ai-agent-audit.

Plug `AuditHooks(recorder)` into `Runner.run(..., hooks=...)` and every
local tool call performed during the run produces one signed audit record.

Designed against openai-agents 0.17.x. Older versions without
`agents.RunHooks` will get a clear ImportError when constructing
`AuditHooks`; the `@audited_tool` decorator from the LangGraph adapter
also works on raw function-tool callables for users who prefer
per-callable instrumentation over a runtime-level hook.
"""

from __future__ import annotations

import json
from typing import Any

from uuid import uuid7

from agent_audit.emit import AuditRecorder
from agent_audit.schema.v1 import NoGateReason, Output, ToolCall, ungated


def _coerce_to_json(value: Any) -> Any:
    """Round-trip through JSON to drop non-serialisable Python objects.

    OpenAI Agents SDK tool outputs are typically str or JSON-shaped, but
    custom tools may return arbitrary Python objects. The fallback to
    str() via json.dumps(default=str) keeps the audit record canonicalisable
    without losing a human-readable hint of what the value was.
    """
    return json.loads(json.dumps(value, default=str))


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
        from agent_audit import AuditRecorder, LocalFileSink, load_signing_key
        from agent_audit.adapters.openai_agents import AuditHooks

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

    Records are emitted on ``on_tool_end``; failed tool calls are not
    recorded in v0.1 (the ``Stop`` / ``SubagentStop`` coverage shipping
    in v0.2 closes that gap).
    """

    def __init__(
        self,
        recorder: AuditRecorder,
        *,
        session_id: str | None = None,
    ) -> None:
        if not _RUN_HOOKS_AVAILABLE:
            raise ImportError(
                "AuditHooks requires openai-agents >= 0.17. "
                "Install via `pip install openai-agents`."
            )
        super().__init__()
        self._recorder = recorder
        self._session_id = session_id or "openai-agents-default"

    async def on_tool_end(
        self, context: Any, agent: Any, tool: Any, result: Any
    ) -> None:
        """Emit one audit record for the completed tool invocation."""
        await self._recorder.record(
            session_id=self._session_id,
            step_id=str(uuid7()),
            tool=ToolCall(name=_extract_tool_name(tool, context)),
            input=_coerce_to_json(_extract_tool_args(context)),
            output=Output(body=_coerce_to_json(_extract_output_body(result))),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            agent_name=getattr(agent, "name", None),
        )


__all__ = ["AuditHooks"]
