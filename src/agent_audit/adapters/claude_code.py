"""Claude Code hooks adapter — agent-audit's primary v0.1 instrumentation path.

Registered as a `PostToolUse` hook in `~/.claude/settings.json` with matcher `*`:

    {
      "hooks": {
        "PostToolUse": [
          { "matcher": "*", "hooks": [
            { "type": "command", "command": "agent-audit hook-record" }
          ]}
        ]
      }
    }

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

from agent_audit.emit import AuditRecorder
from agent_audit.keys import load_signing_key
from agent_audit.schema.v1 import (
    MCPCapabilityNamespace,
    MCPContext,
    MCPTransport,
    NoGateReason,
    Output,
    ToolCall,
    ungated,
)
from agent_audit.sinks.local_file import LocalFileSink

# Claude Code MCP tools follow the convention `mcp__<server>__<tool>`.
_MCP_PREFIX = "mcp__"

# Truncate tool output at 64KB; the hash of the full body is preserved.
_OUTPUT_SIZE_CAP = 64 * 1024

# Default config search paths.
_DEFAULT_AUDIT_DIR = Path("~/.config/agent-audit")
_DEFAULT_SIGNING_KEY = "signing.key"
_DEFAULT_PUBKEY = "signing.pub"


@dataclass(frozen=True)
class HookInput:
    """Parsed Claude Code hook payload (PostToolUse)."""

    hook_event_name: str
    session_id: str
    tool_name: str
    tool_input: Any
    tool_response: Any
    transcript_path: str | None = None
    cwd: str | None = None


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


def emit_from_hook(hook_input: HookInput, config: HookConfig) -> dict[str, Any]:
    """Process one Claude Code hook invocation end-to-end.

    Loads the signing key, opens the sink (which loads the manifest and
    recovers the chain head), builds an AuditRecorder with that chain head
    as `initial_prev_hash`, infers the ToolCall + Output from the payload,
    and signs + writes one record.

    Synchronous — designed for the hook subprocess context where no event
    loop exists. Tests should call from non-async test functions.
    """
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
    output = serialize_tool_response(hook_input.tool_response)

    # step_id ties the record to a position in the agent's execution. Claude
    # Code doesn't expose a numeric step counter to hooks, so we derive a
    # stable identifier from the tool name + record_id is sufficient for
    # ordering (UUIDv7 is time-sortable).
    import uuid6

    step_id = str(uuid6.uuid7())

    return recorder.record_sync(
        session_id=hook_input.session_id,
        step_id=step_id,
        tool=tool,
        input=hook_input.tool_input,
        output=output,
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
    )


__all__ = [
    "HookConfig",
    "HookInput",
    "emit_from_hook",
    "infer_tool_call",
    "parse_hook_input",
    "serialize_tool_response",
]
