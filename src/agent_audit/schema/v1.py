"""v1.0 record schema.

See SIGNING.md for the byte-level canonical form rules. This module defines
the *shape* of records — canonicalization, hashing, and signing live in
agent_audit.canonical and agent_audit.integrity.

Key design choices encoded here:

- Policy is a REQUIRED discriminated union (Gate | Ungated). "No gate applied"
  is itself an asserted record, not absence. This forces every tool call to
  declare its gate status — the gates-not-stages thesis encoded in the schema.
- Time is a structured block with wall, monotonic, and source. Tampering with
  any of the three is detectable because they're all signed together.
- MCP fields are first-class on the tool object (server_id, server_version,
  capability_namespace, transport). Non-MCP tools just omit the mcp object.
- envelope.hash and envelope.signature are Optional during construction; they
  are populated by the signing path in agent_audit.integrity. The canonical
  form for signing excludes both (see SIGNING.md §2.1).
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


SCHEMA_VERSION = "v1.0"
SIG_FORM_VERSION = "v1.0"


# ---------------------------------------------------------------------------
# Time block
# ---------------------------------------------------------------------------


class ClockSource(str, Enum):
    SYSTEM = "system"
    NTP = "ntp"
    TSA = "tsa"


class TimeBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts_utc: str = Field(description="RFC 3339 with nanosecond precision, UTC")
    ts_monotonic_ns: int = Field(ge=0, description="Process-monotonic ns")
    ts_source: ClockSource = ClockSource.SYSTEM


# ---------------------------------------------------------------------------
# Tool identity (with optional MCP subfields)
# ---------------------------------------------------------------------------


class MCPTransport(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"


class MCPCapabilityNamespace(str, Enum):
    TOOLS = "tools"
    RESOURCES = "resources"
    PROMPTS = "prompts"


class MCPContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str = Field(
        description="URI like mcp+stdio://github-mcp-server@1.4.2"
    )
    server_version: str | None = None
    capability_namespace: MCPCapabilityNamespace = MCPCapabilityNamespace.TOOLS
    transport: MCPTransport


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    mcp: MCPContext | None = None


# ---------------------------------------------------------------------------
# Output wrapper (with truncation metadata)
# ---------------------------------------------------------------------------


class Output(BaseModel):
    """Tool output. Truncated at 64KB by default; sha256_full preserves
    evidence-of-existence for the un-truncated body when offloaded.
    """

    model_config = ConfigDict(extra="forbid")

    body: Any = None
    truncated: bool = False
    sha256_full: str | None = None
    size_bytes_full: int | None = None


# ---------------------------------------------------------------------------
# Policy context — REQUIRED discriminated union
# ---------------------------------------------------------------------------


class NoGateReason(str, Enum):
    AUTO_ALLOWED_LOW_RISK = "auto_allowed_low_risk"
    PRE_APPROVED_SESSION = "pre_approved_session"
    POLICY_SKIPPED_OUTSIDE_SCOPE = "policy_skipped_outside_scope"


class GateDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    LOG_ONLY = "log_only"


class Gate(BaseModel):
    """A verification gate fired on this tool call."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["gate"] = "gate"
    policy_id: str
    decision: GateDecision
    approver: str | None = None
    evaluation_ms: int | None = Field(default=None, ge=0)


class Ungated(BaseModel):
    """No gate fired on this tool call — but the *reason* is recorded.

    'No gate applied' is itself a positive assertion in the audit trail.
    Auditors can query 'show me every ungated tool call and why' in one pass.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["none"] = "none"
    reason: NoGateReason


PolicyContext = Annotated[Union[Gate, Ungated], Field(discriminator="kind")]


def gate(
    policy_id: str,
    decision: GateDecision,
    approver: str | None = None,
    evaluation_ms: int | None = None,
) -> Gate:
    """Convenience builder for a gated tool call."""
    return Gate(
        policy_id=policy_id,
        decision=decision,
        approver=approver,
        evaluation_ms=evaluation_ms,
    )


def ungated(reason: NoGateReason) -> Ungated:
    """Convenience builder for an ungated tool call.

    The `reason` argument forces the caller to declare WHY no gate fired.
    """
    return Ungated(reason=reason)


# ---------------------------------------------------------------------------
# Redaction audit trail
# ---------------------------------------------------------------------------


class RedactionEntry(BaseModel):
    """One redaction that fired on this record's input or output."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="JSONPath like $.input.args.email")
    policy: str = Field(description="Policy id like pii.deny.email")


# ---------------------------------------------------------------------------
# Payload, Header, Envelope, Record
# ---------------------------------------------------------------------------


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    time: TimeBlock
    tool: ToolCall
    input: Any = Field(description="Tool args; may contain RedactionMarker dicts")
    output: Output
    policy: PolicyContext
    redaction: list[RedactionEntry] = Field(default_factory=list)


class Header(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    step_id: str
    agent_name: str | None = None
    model: str | None = None
    parent_session_id: str | None = Field(
        default=None,
        description="For Claude Code subagents — the dispatching session",
    )


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    sig_form_version: str = SIG_FORM_VERSION
    record_id: str = Field(description="UUIDv7")
    chain_id: str = Field(description="Scopes the chain; default = session id")
    prev_hash: str | None = Field(
        default=None,
        description="Hex SHA-256 of canonical_for_chain_link(prev_record), null for genesis",
    )
    hash: str | None = Field(
        default=None,
        description="Hex SHA-256 of canonical_for_signing(this_record). Populated by signer.",
    )
    signature: str | None = Field(
        default=None,
        description="Base64 Ed25519 signature over hash bytes. Populated by signer.",
    )
    key_id: str = Field(description="First 16 hex of SHA-256(pubkey_raw_bytes)")


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")

    envelope: Envelope
    header: Header
    payload: Payload


__all__ = [
    "SCHEMA_VERSION",
    "SIG_FORM_VERSION",
    "ClockSource",
    "TimeBlock",
    "MCPTransport",
    "MCPCapabilityNamespace",
    "MCPContext",
    "ToolCall",
    "Output",
    "NoGateReason",
    "GateDecision",
    "Gate",
    "Ungated",
    "PolicyContext",
    "gate",
    "ungated",
    "RedactionEntry",
    "Payload",
    "Header",
    "Envelope",
    "Record",
]
