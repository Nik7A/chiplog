"""Claude Code hooks adapter — agent-audit's primary v0.1 instrumentation path.

Register BOTH events in `~/.claude/settings.json` with matcher `*`:

    {
      "hooks": {
        "PostToolUse": [
          { "matcher": "*", "hooks": [
            { "type": "command", "command": "agent-audit hook-record" }
          ]}
        ],
        "PostToolUseFailure": [
          { "matcher": "*", "hooks": [
            { "type": "command", "command": "agent-audit hook-record" }
          ]}
        ]
      }
    }

Registering only `PostToolUse` yields ZERO failure coverage — the CLI routes
failed calls exclusively to `PostToolUseFailure`, so a `PostToolUse`-only
install silently records successes and drops every failure on the floor.

Observed payload shapes (verified against Claude Code CLI 2.1.207 by
registering a probe hook under both events and forcing real tool failures):

    PostToolUse         — success. Carries `tool_response`; no `error` key.
    PostToolUseFailure  — failure. Carries `error` (str) and `is_interrupt`
                          (bool); carries NO `tool_response`.

The two events are disjoint: a failed call fires only `PostToolUseFailure`,
a successful call fires only `PostToolUse`. That disjointness is what makes
`PostToolUse -> Success` an honest claim rather than a guess — the CLI does
have a failure signal, and it arrives on the other channel.

Those two are also the ONLY events this adapter will record. Every other hook
event is a no-op: `PreToolUse` fires before the tool has run, and `Stop` /
`SubagentStop` / `UserPromptSubmit` describe no tool call at all. The allowlist
is positive rather than "anything that is not the failure event", because the
negative form signs `outcome: success` for whatever it is handed — including a
`PreToolUse` payload for a call that has not happened. It is shared with the
Claude Agent SDK adapter (`_claude_hooks.is_recordable_event`) for the same
reason the background discriminator is: same runtime, same payloads, must not
drift.

With ONE exception, also probed: a `Bash` call that exceeds its `timeout`.
The CLI does not fail it. It moves the command to the background and fires an
ordinary `PostToolUse` — the success slot — with no `error`, `interrupted:
false`, empty stdout, and a `backgroundTaskId` naming the task that inherited
the work. `PostToolUseFailure` never fires. Signing that as `success` would
attest that a call succeeded when nobody observed whether it did, so those
records get `unobserved(NO_FAILURE_SIGNAL)` instead. The discriminator — and
why it needs two fields, not one — lives in `_claude_hooks`, shared with the
Claude Agent SDK adapter, which sees the identical payload from the identical
runtime and must not be able to drift from this one.

Each invocation runs as a one-shot subprocess: stdin holds the JSON hook
payload (`session_id`, `tool_name`, `tool_input`, `tool_response`, etc),
the adapter signs + chains a record, appends to JSONL, and exits.

Concurrent invocations (parallel `Task` spawns in Claude Code) are
serialised via flock on `<dir>/state.lock` so the chain head stays
consistent across processes. See `cli.py::cmd_hook_record`.

Defaults to one chain per session_id. Set `AGENT_AUDIT_CHAIN_ID` in the
daemon's environment if you want a single global chain across many
sessions (Nikolai's daemon-driven Claude flow).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_audit.adapters._claude_hooks import (
    PERMISSION_DENIED_POLICY_ID,
    is_failure_event,
    is_interrupted,
    is_recordable_event,
    is_unrequested_background,
    is_user_denial,
)
from agent_audit.emit import AuditRecorder
from agent_audit.keys import load_signing_key
from agent_audit.schema.v1 import (
    GateDecision,
    MCPCapabilityNamespace,
    MCPContext,
    MCPTransport,
    PolicyContext,
    PolicyUnobservedReason,
    Output,
    OutcomeContext,
    ToolCall,
    UnobservedReason,
    denied,
    gate,
    success,
    policy_unobserved,
    unobserved,
)
from agent_audit.schema.v1 import error as error_outcome
from agent_audit.sinks.local_file import LocalFileSink

# Claude Code MCP tools follow the convention `mcp__<server>__<tool>`.
_MCP_PREFIX = "mcp__"

# Truncate tool output at 64KB; the hash of the full body is preserved.
_OUTPUT_SIZE_CAP = 64 * 1024

# Default config search paths.
_DEFAULT_AUDIT_DIR = Path("~/.config/agent-audit")
_DEFAULT_SIGNING_KEY = "signing.key"
_DEFAULT_PUBKEY = "signing.pub"


def _is_unrequested_background(hook_input: HookInput) -> bool:
    """True when the CLI backgrounded a Bash call the caller did not ask to background.

    Thin projection of this adapter's payload type onto the shared
    discriminator in `_claude_hooks`. The rule itself is deliberately NOT
    duplicated here: the Claude Agent SDK adapter sees byte-identical payloads
    from the same runtime and had the identical bug, so the two adapters must
    read those fields through one implementation and cannot be allowed to
    diverge. See `_claude_hooks.is_unrequested_background` for the reasoning.
    """
    return is_unrequested_background(
        hook_input.tool_name, hook_input.tool_input, hook_input.tool_response
    )


@dataclass(frozen=True)
class HookInput:
    """Parsed Claude Code hook payload (PostToolUse or PostToolUseFailure).

    `error` and `is_interrupt` are populated only on PostToolUseFailure;
    `tool_response` only on PostToolUse. They are optional with defaults so
    existing construction sites keep working.
    """

    hook_event_name: str
    session_id: str
    tool_name: str
    tool_input: Any
    tool_response: Any = None
    transcript_path: str | None = None
    cwd: str | None = None
    error: str | None = None
    is_interrupt: bool = False


@dataclass(frozen=True)
class HookConfig:
    """Where the hook handler reads + writes state."""

    audit_dir: Path
    signing_key_path: Path
    pubkey_path: Path | None = None
    chain_id_override: str | None = None

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> HookConfig:
        env = os.environ if environ is None else environ
        audit_dir = Path(env.get("AGENT_AUDIT_DIR", str(_DEFAULT_AUDIT_DIR))).expanduser()
        signing_key_path = Path(
            env.get("AGENT_AUDIT_SIGNING_KEY", str(audit_dir / _DEFAULT_SIGNING_KEY))
        ).expanduser()
        pubkey_env = env.get("AGENT_AUDIT_PUBKEY")
        pubkey_path: Path | None
        if pubkey_env:
            pubkey_path = Path(pubkey_env).expanduser()
        else:
            default_pub = audit_dir / _DEFAULT_PUBKEY
            pubkey_path = default_pub if default_pub.exists() else None
        chain_id_override = env.get("AGENT_AUDIT_CHAIN_ID")
        return cls(
            audit_dir=audit_dir,
            signing_key_path=signing_key_path,
            pubkey_path=pubkey_path,
            chain_id_override=chain_id_override,
        )


def parse_hook_input(text: str) -> HookInput:
    """Parse the JSON payload Claude Code sends on stdin."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("hook payload must be a JSON object")
    return HookInput(
        hook_event_name=str(data.get("hook_event_name", "PostToolUse")),
        session_id=str(data.get("session_id", "unknown")),
        tool_name=str(data.get("tool_name", "unknown")),
        tool_input=data.get("tool_input"),
        tool_response=data.get("tool_response"),
        transcript_path=data.get("transcript_path"),
        cwd=data.get("cwd"),
        error=data.get("error"),
        is_interrupt=bool(data.get("is_interrupt", False)),
    )


def infer_tool_call(tool_name: str) -> ToolCall:
    """Detect Claude Code MCP tool names (`mcp__<server>__<name>`) and split.

    Built-in Claude Code tools (Read, Write, Bash, Task, Grep, etc.) get
    `mcp=None`. MCP tools get a populated MCPContext.

    Transport defaults to stdio — accurate for Claude Code's default MCP
    runner. v0.2 may read `.mcp.json` to detect actual transport per server.
    """
    if tool_name.startswith(_MCP_PREFIX):
        parts = tool_name[len(_MCP_PREFIX):].split("__", 1)
        if len(parts) == 2:
            server_alias, real_name = parts
            return ToolCall(
                name=real_name,
                mcp=MCPContext(
                    server_id=f"mcp+stdio://{server_alias}",
                    capability_namespace=MCPCapabilityNamespace.TOOLS,
                    transport=MCPTransport.STDIO,
                ),
            )
    return ToolCall(name=tool_name)


def serialize_tool_response(tool_response: Any) -> Output:
    """Wrap a Claude Code tool_response into an Output, truncating large bodies.

    Large bodies (>64KB after JSON encoding) are truncated, and the full SHA-256
    + byte size are recorded so evidence-of-existence survives even when the
    body itself isn't preserved.
    """
    encoded = json.dumps(
        tool_response, sort_keys=False, ensure_ascii=False, default=str
    )
    size_full = len(encoded.encode("utf-8"))

    if size_full <= _OUTPUT_SIZE_CAP:
        return Output(body=tool_response)

    sha = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    truncated = encoded[: _OUTPUT_SIZE_CAP - 64] + "...[truncated by agent-audit]"
    return Output(
        body=truncated,
        truncated=True,
        sha256_full=sha,
        size_bytes_full=size_full,
    )


def emit_from_hook(hook_input: HookInput, config: HookConfig) -> dict[str, Any] | None:
    """Process one Claude Code hook invocation end-to-end.

    Loads the signing key, opens the sink (which loads the manifest and
    recovers the chain head), builds an AuditRecorder with that chain head
    as `initial_prev_hash`, infers the ToolCall + Output from the payload,
    and signs + writes one record.

    Returns the signed record, or `None` when the payload is not one of the two
    events that report a completed tool call — nothing is written in that case.

    Synchronous — designed for the hook subprocess context where no event
    loop exists. Tests should call from non-async test functions.
    """
    # Positive allowlist, shared with the Claude Agent SDK adapter. Without it,
    # the `if/elif/else` below treats every event that is not the failure event
    # as the success slot — hand it a `PreToolUse` payload (a one-line
    # mis-registration in settings.json; the field names are identical) and it
    # signs `outcome: success` for a tool call that has not run yet.
    if not is_recordable_event(hook_input.hook_event_name):
        return None

    sk = load_signing_key(config.signing_key_path)

    pubkey_pem: bytes | None = None
    if config.pubkey_path is not None and config.pubkey_path.exists():
        pubkey_pem = config.pubkey_path.read_bytes()

    sink = LocalFileSink(dir=config.audit_dir, pubkey_pem=pubkey_pem)

    chain_id = config.chain_id_override or hook_input.session_id
    prior = sink.manifest.chains.get(chain_id)
    initial_prev_hash = prior.head_hash if prior is not None else None

    recorder = AuditRecorder(
        sink=sink,
        signing_key=sk,
        chain_id=chain_id,
        initial_prev_hash=initial_prev_hash,
    )

    tool = infer_tool_call(hook_input.tool_name)

    # PostToolUseFailure carries `error` and no `tool_response`; PostToolUse
    # carries `tool_response` and no `error`. The events are disjoint, so each
    # branch states exactly what the CLI told us — no inference either way.
    outcome: OutcomeContext
    output: Output
    policy: PolicyContext
    if is_failure_event(hook_input.hook_event_name):
        if is_user_denial(hook_input.error):
            # A user denied this call at the permission prompt: the tool NEVER
            # RAN. That prompt is a real verification gate that fired and denied,
            # so record it truthfully — a synthetic Gate(DENY) plus outcome=denied
            # with the SAME policy_id (Payload._outcome_agrees_with_policy checks
            # they match) — NOT error(Interrupt), which would assert the tool ran
            # and faulted. approver=None and evaluation_ms=None: the payload
            # carries no human identity and no gate-evaluation timing, so neither
            # is fabricated. The denial is matched by the anchored rejection
            # sentinel in `_claude_hooks.is_user_denial`, shared with the Claude
            # Agent SDK adapter so the two cannot drift.
            policy = gate(PERMISSION_DENIED_POLICY_ID, GateDecision.DENY)
            outcome = denied(PERMISSION_DENIED_POLICY_ID)
            # A denied tool did not run: no output. Don't fabricate one.
            output = Output(body=None)
        else:
            # A genuine tool fault (or a genuine interrupt): the tool ran and
            # failed, or was cut short. error_type is "ToolFailure"/"Interrupt",
            # not a Python exception class — the CLI hands us a message string,
            # and inventing a type name would be dishonest. is_interrupt only
            # distinguishes a cut-short call from a faulting one HERE, where the
            # error is NOT a denial; it never on its own mints a Gate.
            policy = policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL)
            outcome = error_outcome(
                "Interrupt" if hook_input.is_interrupt else "ToolFailure",
                hook_input.error or "",
            )
            # No output exists on a failure — record its absence, don't fabricate.
            output = Output(body=None)
    elif _is_unrequested_background(hook_input) or is_interrupted(
        hook_input.tool_response
    ):
        # Two payloads arrive on the success slot whose outcome nobody observed.
        #
        # A Bash call the CLI backgrounded that nobody asked to background — a
        # timeout it declined to report as a failure. Nothing in it establishes
        # that the command succeeded.
        #
        # A call the runtime marked `interrupted` — cut short rather than
        # finished. Today the CLI fires no hook at all for one of those (see the
        # blind spot in the README), so this is a guard, not a live path: if such
        # a payload ever does reach us, a success is the one thing it is not.
        policy = policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL)
        outcome = unobserved(UnobservedReason.NO_FAILURE_SIGNAL)
        # The response is thin but not worthless: `backgroundTaskId` names the
        # task that inherited the work and is the only thread an investigator
        # can pull. Keep what the CLI gave us.
        output = serialize_tool_response(hook_input.tool_response)
    else:
        policy = policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL)
        outcome = success()
        output = serialize_tool_response(hook_input.tool_response)

    # step_id ties the record to a position in the agent's execution. Claude
    # Code doesn't expose a numeric step counter to hooks, so we derive a
    # stable identifier from the tool name + record_id is sufficient for
    # ordering (UUIDv7 is time-sortable).
    from uuid import uuid7

    step_id = str(uuid7())

    return recorder.record_sync(
        session_id=hook_input.session_id,
        step_id=step_id,
        tool=tool,
        input=hook_input.tool_input,
        output=output,
        policy=policy,
        outcome=outcome,
    )


__all__ = [
    "HookConfig",
    "HookInput",
    "emit_from_hook",
    "infer_tool_call",
    "parse_hook_input",
    "serialize_tool_response",
]
