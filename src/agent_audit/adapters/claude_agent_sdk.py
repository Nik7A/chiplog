"""Claude Agent SDK (Python) adapter — `HookCallback` for ai-agent-audit.

The Claude Agent SDK exposes a native hooks system (see
``claude_agent_sdk.HookMatcher`` / ``HookCallback``). ``AuditHook`` is a
``HookCallback``-shaped class that records every successful tool call from
a ``ClaudeSDKClient`` session into the audit chain.

Plug it into ``ClaudeAgentOptions.hooks`` under BOTH the ``PostToolUse`` and
``PostToolUseFailure`` events — registering only the former means failed
tool calls silently go unaudited:

    from claude_agent_sdk import (
        ClaudeAgentOptions, ClaudeSDKClient, HookMatcher,
    )
    from agent_audit import AuditRecorder, LocalFileSink, load_signing_key
    from agent_audit.adapters.claude_agent_sdk import AuditHook

    recorder = AuditRecorder(
        sink=LocalFileSink(dir="./audit"),
        signing_key=load_signing_key("./signing.key"),
    )
    audit_hook = AuditHook(recorder=recorder)
    options = ClaudeAgentOptions(
        hooks={
            "PostToolUse": [HookMatcher(matcher="*", hooks=[audit_hook])],
            "PostToolUseFailure": [HookMatcher(matcher="*", hooks=[audit_hook])],
        },
    )
    client = ClaudeSDKClient(options=options)

The hook payload supplies ``session_id`` and ``tool_use_id`` directly from
the SDK, so callers don't need to thread them through manually.

``PostToolUseFailure`` events map to an ``Error`` outcome with
``error_type`` set to ``"Interrupt"`` (when the SDK's ``is_interrupt`` flag
is truthy) or ``"ToolFailure"`` otherwise. The SDK only hands adapters a
message string, not an exception class, so inventing a plausible-looking
Python exception type name would be fabricating evidence — these two labels
say exactly what the runtime reported and nothing more.

There is no native timeout signal in this SDK, and one case makes that bite:
a ``Bash`` call that exceeds its ``timeout``. The runtime does not fail it. It
moves the command to the background and fires an ordinary ``PostToolUse`` — the
success slot — with no ``error``, ``interrupted: false``, empty stdout, and a
``backgroundTaskId`` naming the task that inherited the work.
``PostToolUseFailure`` never fires. Signing that as ``success`` would attest a
call succeeded when nobody observed whether it did, so those records get
``unobserved(no_failure_signal)`` instead. The discriminator is shared with the
Claude Code CLI adapter (``adapters._claude_hooks``) — the SDK drives the same
binary and hands over the same payload shape, so the two must not be able to
drift. A call the caller *intentionally* backgrounded with
``run_in_background: true`` genuinely succeeded and stays ``success``.

Designed against claude-agent-sdk 0.2.x; background behaviour probed on 0.2.118.
"""

from __future__ import annotations

from typing import Any

from uuid import uuid7

from agent_audit.adapters._claude_hooks import (
    PERMISSION_DENIED_POLICY_ID,
    is_failure_event,
    is_interrupted,
    is_recordable_event,
    is_unrequested_background,
    is_user_denial,
)
from agent_audit.emit import AuditRecorder
from agent_audit.schema.v1 import (
    GateDecision,
    PolicyUnobservedReason,
    OutcomeContext,
    Output,
    ToolCall,
    UnobservedReason,
    denied,
    error,
    gate,
    success,
    policy_unobserved,
    unobserved,
)


def _extract_session_id(
    hook_input: dict[str, Any], override: str | None
) -> str:
    """Caller override beats the SDK-supplied session_id."""
    if override:
        return override
    sid = hook_input.get("session_id")
    if isinstance(sid, str) and sid:
        return sid
    return "claude-agent-sdk-default"


def _extract_step_id(hook_input: dict[str, Any]) -> str:
    """tool_use_id is the SDK's per-invocation identifier; fall back to a fresh
    UUIDv7 only if it's missing (should not happen with a real PostToolUse)."""
    tool_use_id = hook_input.get("tool_use_id")
    if isinstance(tool_use_id, str) and tool_use_id:
        return tool_use_id
    return str(uuid7())


# ---------------------------------------------------------------------------
# AuditHook
# ---------------------------------------------------------------------------

try:
    import claude_agent_sdk  # noqa: F401

    _CLAUDE_AGENT_SDK_AVAILABLE = True
except ImportError:
    _CLAUDE_AGENT_SDK_AVAILABLE = False


class AuditHook:
    """Claude Agent SDK ``HookCallback`` that records every PostToolUse event.

    Construct once per recorder; pass it to ``ClaudeAgentOptions.hooks`` for
    every tool you want audited (use ``matcher="*"`` to cover all).

    The instance is itself an awaitable callable — the SDK invokes
    ``await audit_hook(input, tool_use_id, context)`` and that triggers one
    signed audit-record write.
    """

    def __init__(
        self,
        recorder: AuditRecorder,
        *,
        session_id: str | None = None,
    ) -> None:
        if not _CLAUDE_AGENT_SDK_AVAILABLE:
            raise ImportError(
                "AuditHook requires claude-agent-sdk >= 0.2. "
                "Install via `pip install claude-agent-sdk`."
            )
        self._recorder = recorder
        self._session_override = session_id

    async def __call__(
        self,
        hook_input: dict[str, Any],
        tool_use_id: str | None,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Record one audit entry for the completed (or failed) tool call.

        Returns an empty dict — the audit hook does not modify SDK behavior
        or block the tool result. Future ``Gate``-shaped policy records will
        live behind a separate adapter type, not this one.
        """
        event = hook_input.get("hook_event_name")

        # Only PostToolUse / PostToolUseFailure report a completed tool call. A
        # mis-registration onto some other event (PreToolUse fires before the
        # tool has even run) must never be attested as a success — and must not
        # crash the agent loop either. No-op. The allowlist is shared with the
        # Claude Code CLI adapter, which reads the same payloads from the same
        # runtime and must not be able to drift from this.
        if not is_recordable_event(event):
            return {}

        tool_name = hook_input.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            tool_name = "unknown_tool"

        tool_input = hook_input.get("tool_input", {})

        if is_failure_event(event):
            raw_error = hook_input.get("error")
            if is_user_denial(raw_error):
                # A user denied this call at the permission prompt: the tool NEVER
                # RAN. That prompt is a real verification gate that fired and
                # denied, so record a synthetic Gate(DENY) + outcome=denied with
                # the SAME policy_id (Payload._outcome_agrees_with_policy checks
                # they match) — NOT error(Interrupt), which would assert the tool
                # ran and faulted. approver/evaluation_ms are None: the payload
                # carries neither a human identity nor gate timing. The denial is
                # matched by the anchored sentinel in `_claude_hooks.is_user_denial`,
                # shared with the Claude Code CLI adapter so the two cannot drift.
                await self._recorder.record(
                    session_id=_extract_session_id(hook_input, self._session_override),
                    step_id=_extract_step_id(hook_input),
                    tool=ToolCall(name=tool_name),
                    input=tool_input,
                    output=Output(body=None),
                    policy=gate(PERMISSION_DENIED_POLICY_ID, GateDecision.DENY),
                    outcome=denied(PERMISSION_DENIED_POLICY_ID),
                )
                return {}
            # A genuine tool fault (or a genuine interrupt): the tool ran and
            # failed, or was cut short. is_interrupt only labels a cut-short call
            # vs a faulting one HERE, where the error is NOT a denial.
            error_type = "Interrupt" if hook_input.get("is_interrupt") else "ToolFailure"
            await self._recorder.record(
                session_id=_extract_session_id(hook_input, self._session_override),
                step_id=_extract_step_id(hook_input),
                tool=ToolCall(name=tool_name),
                input=tool_input,
                output=Output(body=None),
                policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
                outcome=error(error_type, str(raw_error if raw_error is not None else "")),
            )
            return {}

        tool_response = hook_input.get("tool_response")

        # PostToolUse is the success slot, but two payloads can arrive here whose
        # outcome nobody observed.
        #
        # A Bash call the runtime backgrounded because it blew its timeout: it
        # carries a `backgroundTaskId` the caller never asked for, and nothing in
        # it establishes that the command succeeded — it may still be running,
        # may fail later, may never finish. An intentional `run_in_background:
        # true` call DID succeed (it was asked to launch a process and it
        # launched one) and is not caught by this.
        #
        # A call the runtime marked `interrupted`: cut short rather than
        # finished. The runtime fires no hook at all for one of those today (see
        # the blind spot in the README), so this is a guard, not a live path.
        #
        # Both rules live in `_claude_hooks`, shared with the Claude Code CLI
        # adapter, which sees identical payloads from the identical runtime.
        outcome: OutcomeContext
        if is_unrequested_background(
            tool_name, tool_input, tool_response
        ) or is_interrupted(tool_response):
            outcome = unobserved(UnobservedReason.NO_FAILURE_SIGNAL)
        else:
            outcome = success()

        # The thin tool_response is kept either way: `backgroundTaskId` names the
        # task that inherited the work and is the only thread an investigator can
        # pull.
        #
        # Hand `tool_input` / `tool_response` to the recorder RAW. The SDK can
        # deliver arbitrary Python here (content blocks, dataclasses, bytes,
        # dicts with non-string keys), and the recorder's redact +
        # `normalize_for_canonical` pass turns every JCS-hostile value into a
        # faithful, ANNOUNCED marker. When a value defeats even that (its repr()
        # raises, a dict key's str() raises), the recorder's construction guard
        # poisons the chain head and raises a typed RecordBuildError rather than
        # dropping the call — so a failure here surfaces as a chain break at
        # verification time (and a typed error out of this hook), never silently.
        # Pre-laundering with `json.dumps(default=str)` did the recorder's job
        # badly: a non-string key raised a raw `TypeError` out of this hook, and a
        # bytes/set value was stringified with nothing in `payload.unrepresentable`.
        await self._recorder.record(
            session_id=_extract_session_id(hook_input, self._session_override),
            step_id=_extract_step_id(hook_input),
            tool=ToolCall(name=tool_name),
            input=tool_input,
            output=Output(body=tool_response),
            policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
            outcome=outcome,
        )
        return {}


__all__ = ["AuditHook"]
