"""v1.0 record schema.

See SIGNING.md for the byte-level canonical form rules. This module defines
the *shape* of records — canonicalization, hashing, and signing live in
chiplog.canonical and chiplog.integrity.

Key design choices encoded here:

- Policy is a REQUIRED discriminated union (Gate | Ungated). "No gate applied"
  is itself an asserted record, not absence. This forces every tool call to
  declare its gate status — the gates-not-stages thesis encoded in the schema.
- Time is a structured block with wall, monotonic, and source. Tampering with
  any of the three is detectable because they're all signed together.
- MCP fields are first-class on the tool object (server_id, server_version,
  capability_namespace, transport). Non-MCP tools just omit the mcp object.
- envelope.hash and envelope.signature are Optional during construction; they
  are populated by the signing path in chiplog.integrity. The canonical
  form for signing excludes both (see SIGNING.md §2.1).
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SCHEMA_VERSION = "v1.2"
SIG_FORM_VERSION = "v1.0"  # unchanged: canonicalization rules did not change


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
    # Typed `int | str` but STORED as a decimal string. A raw monotonic-ns int
    # crosses 2**53 after ~104 days of host uptime, past which rfc8785 (JCS)
    # refuses it (IntegerDomainError) and the record is silently dropped. A
    # decimal string escapes JCS's float-safe-integer domain forever, at full ns
    # precision, WITHOUT touching sig_form_version (the string still round-trips
    # through the same canonicalization rules). New records store
    # str(monotonic_ns()); the validator accepts an int too so a pre-v1.2 record
    # (int-valued on disk) still validates if anyone model_validates it. The int
    # form is not re-serialised by the verifier — it reads raw dicts — so old
    # records keep their exact signed bytes and stay verifiable.
    ts_monotonic_ns: int | str = Field(description="Process-monotonic ns, decimal")
    ts_source: ClockSource = ClockSource.SYSTEM

    @field_validator("ts_monotonic_ns", mode="before")
    @classmethod
    def _stringify_monotonic_ns(cls, value: object) -> str:
        """Coerce to a non-negative decimal string.

        An int (new construction, or an old int-valued record being validated)
        is stringified. A string is required to be a run of decimal digits, so a
        garbage value is still rejected rather than signed.
        """
        if isinstance(value, bool):
            # bool is an int subclass; a boolean ns count is always a bug.
            raise ValueError("ts_monotonic_ns must be an integer, not a bool")
        if isinstance(value, int):
            if value < 0:
                raise ValueError("ts_monotonic_ns must be >= 0")
            return str(value)
        if isinstance(value, str):
            if not (value.isascii() and value.isdigit()):
                raise ValueError(
                    "ts_monotonic_ns string must be non-negative decimal digits"
                )
            return value
        raise ValueError(
            f"ts_monotonic_ns must be int or decimal str, got {type(value).__name__}"
        )


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

    IMPORTANT — this is a POSITIVE assertion, and asserting it without observing
    the gate mechanism is a fabrication. Every adapter used to hardcode
    `ungated(AUTO_ALLOWED_LOW_RISK)`, which claimed both "no gate fired" AND "low
    risk" over instrumentation points that observe NEITHER (the runtime hook
    payloads carry no per-call gate decision and no risk level — see
    docs/superpowers/specs §5). An adapter that cannot see the gate must use
    `UnobservedPolicy`, not this. `Ungated` is retained because 19,037 signed
    v1.0 records embed it and must keep verifying, and because a real policy
    engine that genuinely observes "no gate fired" would assert it truthfully.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["none"] = "none"
    reason: NoGateReason


class PolicyUnobservedReason(str, Enum):
    """Why the gate status could not be observed at this instrumentation point.

    A closed set — the same discipline as NoGateReason — so the blind spots stay
    few and reviewable.
    """

    # The runtime handed the recorder no gate/permission signal at all: the
    # PostToolUse-style hook payloads carry a session id, a permission MODE, and
    # tool info, but no per-call gate decision and no risk level. The recorder
    # cannot tell whether a gate fired, so it asserts only that it could not tell.
    NO_GATE_SIGNAL = "no_gate_signal"


class UnobservedPolicy(BaseModel):
    """The gate status was NOT observable at this instrumentation point.

    This asserts strictly less than `Ungated`: it does NOT claim a gate did or
    did not fire, and — critically — it makes NO risk claim. It says only that
    the recorder could not observe the gate, and why. That is the honest floor
    for an adapter wired to a runtime that reports no gate decision.

    What it CANNOT know (documented so no reader over-reads it): whether a gate
    actually fired upstream; the approver identity; the risk level. `low_risk`
    was never observable — that is exactly why the old `AUTO_ALLOWED_LOW_RISK`
    default was a fabrication, and why this variant carries no risk field.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["policy_unobserved"] = "policy_unobserved"
    reason: PolicyUnobservedReason


PolicyContext = Annotated[
    Union[Gate, Ungated, UnobservedPolicy], Field(discriminator="kind")
]


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


def policy_unobserved(reason: PolicyUnobservedReason) -> UnobservedPolicy:
    """Convenience builder for an unobservable gate status.

    The `reason` argument forces the caller to declare WHY the gate could not be
    observed. Unlike `ungated`, this asserts no risk level and no gate outcome.
    """
    return UnobservedPolicy(reason=reason)


# ---------------------------------------------------------------------------
# Redaction audit trail
# ---------------------------------------------------------------------------


class RedactionEntry(BaseModel):
    """One redaction that fired on this record's input or output."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="JSONPath like $.input.args.email")
    policy: str = Field(description="Policy id like pii.deny.email")


# ---------------------------------------------------------------------------
# Un-representable-value audit trail
# ---------------------------------------------------------------------------


class UnrepresentableReason(str, Enum):
    """Why a scalar could not be represented in the JCS canonical form.

    A closed set so the blind spots stay few and reviewable — the same
    discipline as NoGateReason and UnrepresentableEntry.
    """

    # abs(int) >= 2**53 — outside JCS's float-safe integer domain.
    INTEGER_OUT_OF_JCS_DOMAIN = "integer_out_of_jcs_domain"
    # nan / +inf / -inf — not representable in JCS at all.
    FLOAT_NOT_FINITE = "float_not_finite"
    # bytes / set / frozenset / any other non-JSON scalar.
    UNSUPPORTED_TYPE = "unsupported_type"
    # A dict key that was not a string (JCS object keys must be strings).
    NON_STRING_DICT_KEY = "non_string_dict_key"


class UnrepresentableEntry(BaseModel):
    """One JCS-hostile value that a normalization pass replaced with a marker.

    Records TYPE + HASH only, NEVER a reconstructed value. The marker proves the
    value existed and distinguishes two different values by hash; it does NOT
    recover the original (the magnitude of an out-of-domain int, or the bytes
    behind a `bytes`, are unrecoverable in a JCS-signable form). This is the
    honest floor, not a limitation to paper over.
    """

    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="JSONPath like $.input.args.count")
    reason: UnrepresentableReason
    py_type: str = Field(description="type(value).__name__, e.g. 'int', 'bytes'")
    sha256: str = Field(description="hex SHA-256 of repr(value)")


# ---------------------------------------------------------------------------
# Outcome — REQUIRED discriminated union
# ---------------------------------------------------------------------------


class Success(BaseModel):
    """The tool call completed and returned a result."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["success"] = "success"


class Error(BaseModel):
    """The tool call raised.

    `message` is typed Any, not str: redaction replaces a matched string with a
    marker dict (see redact.py). Same convention as Payload.input and Output.body.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["error"] = "error"
    error_type: Any = Field(
        description=(
            "The exception class name where the runtime gives one (e.g. "
            "ConnectionError); otherwise a stable label for what the runtime "
            "actually reported (e.g. ToolFailure, Interrupt, when the runtime "
            "hands the adapter a message string rather than an exception). "
            "Never a fabricated type name. Typed Any, not str: exception class "
            "names normally stay plain strings, but a runtime that stuffs PII "
            "into the type must not get a redaction bypass — so the recorder "
            "redacts this field too, replacing a matched string with a marker "
            "dict. Old records keep their str value and canonicalize unchanged."
        )
    )
    message: Any = Field(description="str(exception), or a redaction marker dict")


class Timeout(BaseModel):
    """The tool call exceeded its deadline."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["timeout"] = "timeout"
    elapsed_ms: int = Field(ge=0)


class Denied(BaseModel):
    """A policy gate denied the call; the tool did not run.

    `policy_id` must equal the id of the Gate that denied it — enforced by
    Payload's cross-field validator.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["denied"] = "denied"
    policy_id: str


class UnobservedReason(str, Enum):
    """Why an instrumentation point could not determine the outcome."""

    RUNTIME_LAUNDERS_EXCEPTIONS = "runtime_launders_exceptions"
    NO_FAILURE_SIGNAL = "no_failure_signal"

    # The runtime aborted the call through a CONTROL-FLOW channel rather than
    # completing it. The call neither succeeded nor failed: it did not finish.
    #
    # LangGraph's `GraphBubbleUp` is such a channel — `interrupt()` inside a tool
    # (human-in-the-loop) raises `GraphInterrupt`, and a tool bubbling a
    # navigation Command to the parent graph raises `ParentCommand`. Both are
    # ordinary `Exception` subclasses, so an adapter that reads "an exception
    # crossed this boundary" as evidence of failure signs `error` over a call
    # that did not fail — and, for an interrupt, one that goes on to be
    # RE-EXECUTED from the top and succeed. That is a false failure, and a false
    # failure is exactly as dishonest as a false success.
    CONTROL_FLOW_SIGNAL = "control_flow_signal"


class Unobserved(BaseModel):
    """The instrumentation point cannot determine whether the call succeeded.

    This is an assertion, not silence — the same reasoning that makes Ungated
    carry a reason. A recorder that cannot observe the outcome must say exactly
    that. Signing Success over a call that may have failed would turn an
    ambiguous record into a cryptographically attested false statement, which is
    worse than the gap it replaces.

    Used by adapters whose runtime hides failures from them; see
    adapters/openai_agents.py.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["unobserved"] = "unobserved"
    reason: UnobservedReason


OutcomeContext = Annotated[
    Union[Success, Error, Timeout, Denied, Unobserved], Field(discriminator="kind")
]


def success() -> Success:
    """Convenience builder for a successful tool call."""
    return Success()


def error(error_type: Any, message: Any) -> Error:
    """Convenience builder for a failed tool call."""
    return Error(error_type=error_type, message=message)


def timeout(elapsed_ms: int) -> Timeout:
    """Convenience builder for a timed-out tool call."""
    return Timeout(elapsed_ms=elapsed_ms)


def denied(policy_id: str) -> Denied:
    """Convenience builder for a policy-denied tool call."""
    return Denied(policy_id=policy_id)


def unobserved(reason: UnobservedReason) -> Unobserved:
    """Convenience builder for an outcome the recorder could not observe.

    The `reason` argument forces the caller to declare WHY it cannot tell.
    """
    return Unobserved(reason=reason)


# ---------------------------------------------------------------------------
# Lifecycle events — a distinct record type, NOT a tool call
# ---------------------------------------------------------------------------
#
# 81% of bosun's real trail is node.enter / node.exit / route events that were
# forced into the tool-call schema: a fabricated tool name ("node.enter"), an
# empty output, and the fabricated `ungated(AUTO_ALLOWED_LOW_RISK)` policy. Those
# records stay signature-valid (their bytes are unchanged) but they MISREPRESENT
# policy and pretend a graph event was a tool invocation. This record type lets a
# recorder express a lifecycle event for what it is: it has NO tool, NO policy
# field at all, and NO synthesized outcome — because a node boundary or a routing
# decision is none of those things, and asserting them would be the same class of
# lie the tool-call fabrication is.


class LifecyclePhase(str, Enum):
    """The kind of lifecycle boundary this record marks.

    Exactly the three events bosun's live LangGraph run emits — derived from the
    real trail, not invented. A closed set so the honest transition shape for
    each phase (see LifecycleTransition) stays enumerable and reviewable.
    """

    NODE_ENTER = "node_enter"
    NODE_EXIT = "node_exit"
    ROUTE = "route"


class NodeTransition(BaseModel):
    """A node boundary was crossed: entry into, or exit from, one graph node.

    Carries that node's id — which the instrumentation genuinely observes,
    because it wraps a named node. There is NO from/to pair: a single boundary
    was crossed, and inventing an origin/destination the recorder never saw
    would be a fabrication. Used by NODE_ENTER and NODE_EXIT; the `phase`
    distinguishes which boundary.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["node"] = "node"
    node: str


class RouteTransition(BaseModel):
    """A router CLAIMED it selected an outgoing edge/skill.

    Carries only the router-claimed `chosen` target. It has NO from/to node: a
    route decision names a chosen next step, not a traversal, and the recorder
    did NOT evaluate the routing logic — it copies the choice the router
    reported. The recorder attests that this is the edge/skill the router named,
    NOT that the choice was correct or that any node was actually entered as a
    result.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["route"] = "route"
    chosen: str = Field(
        description="Router-CLAIMED chosen edge/skill; UNVERIFIED by the recorder"
    )


LifecycleTransition = Annotated[
    Union[NodeTransition, RouteTransition], Field(discriminator="kind")
]


def node_transition(node: str) -> NodeTransition:
    """Convenience builder for a node.enter / node.exit transition."""
    return NodeTransition(node=node)


def route_transition(chosen: str) -> RouteTransition:
    """Convenience builder for a route transition (router-claimed chosen edge)."""
    return RouteTransition(chosen=chosen)


class LifecycleEventPayload(BaseModel):
    """A node/router lifecycle event. Deliberately NOT a tool call.

    It carries the phase, the honest per-phase transition (which holds the
    node/step identity — the node id for node phases, the router-claimed chosen
    edge for route), and an `attributes` bag. It has no `tool`, no `policy`, and
    no `outcome`: none of those apply to a graph boundary, and synthesizing them
    is the fabrication this type exists to avoid.

    `attributes` is runtime-REPORTED and UNATTESTED. The recorder copies whatever
    status/risk/duration the runtime hands it (e.g. bosun's node.exit
    `status="ok"`, `duration_ms=42`) verbatim into this bag and makes NO claim
    that any of it is true — it did not measure the duration or verify the
    status. It is signed (so it cannot be altered after the fact) but its
    TRUTH is the runtime's word, not the recorder's attestation. Read the
    signature as "the runtime said this", never as "this happened".

    `redaction` and `unrepresentable` mirror Payload: `attributes` is
    runtime-supplied Any, so it goes through the same redaction and JCS
    normalization as tool input/output — a secret in an attribute is redacted,
    and a JCS-hostile attribute is replaced with an announced marker rather than
    silently dropped or laundered.
    """

    model_config = ConfigDict(extra="forbid")

    time: TimeBlock
    phase: LifecyclePhase
    transition: LifecycleTransition
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Runtime-REPORTED, UNATTESTED status/risk/etc. — signed but "
        "not attested by the recorder",
    )
    redaction: list[RedactionEntry] = Field(default_factory=list)
    unrepresentable: list[UnrepresentableEntry] = Field(default_factory=list)
    # See Payload.redaction_token — the same per-record anti-forgery token, so a
    # tool-supplied marker in `attributes` is distinguishable from a genuine one.
    redaction_token: str | None = None

    @model_validator(mode="after")
    def _phase_agrees_with_transition(self) -> LifecycleEventPayload:
        """A node phase must carry a node transition; route must carry a route
        transition. A phase/transition mismatch would let the record claim a node
        boundary while describing a routing choice (or vice-versa) — a
        self-contradiction, exactly the failure the Payload
        policy/outcome validator guards against.
        """
        is_node_phase = self.phase in (
            LifecyclePhase.NODE_ENTER,
            LifecyclePhase.NODE_EXIT,
        )
        if is_node_phase and not isinstance(self.transition, NodeTransition):
            raise ValueError(
                f"phase {self.phase.value!r} requires a node transition, "
                f"got {type(self.transition).__name__}"
            )
        if self.phase == LifecyclePhase.ROUTE and not isinstance(
            self.transition, RouteTransition
        ):
            raise ValueError(
                "phase 'route' requires a route transition, "
                f"got {type(self.transition).__name__}"
            )
        return self


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
    outcome: OutcomeContext
    redaction: list[RedactionEntry] = Field(default_factory=list)
    # Every JCS-hostile value the normalization pass replaced with a marker
    # (see chiplog.normalize). Default empty — a pre-v1.2 record simply omits
    # it, and the verifier reads raw dicts, so its absence never breaks
    # verification. Announced so no substitution is silent.
    unrepresentable: list[UnrepresentableEntry] = Field(default_factory=list)
    # Per-record anti-forgery token. The recorder mints a fresh unpredictable
    # value per record() call (when redaction is enabled) and stamps it into every
    # genuine redaction marker and redacted-key sentinel. A consumer reconciles
    # markers against this token (see redact.redaction_authenticity): a tool
    # cannot forge a marker that reads as recorder-attested, because it ran BEFORE
    # this token was minted and cannot predict it. Null when redaction is disabled
    # (no markers are produced) and absent on pre-v1.2 records.
    redaction_token: str | None = None

    @model_validator(mode="after")
    def _outcome_agrees_with_policy(self) -> Payload:
        """A denial must be asserted by exactly one pair of fields, in agreement.

        outcome.kind == "denied"  <=>  policy is a Gate with decision == DENY.

        Without this, policy.decision and outcome can disagree about whether the
        call ran. For an audit record, a self-contradicting pair is worse than
        either field alone.
        """
        policy_denies = (
            isinstance(self.policy, Gate) and self.policy.decision == GateDecision.DENY
        )
        outcome_denied = isinstance(self.outcome, Denied)

        if outcome_denied and not policy_denies:
            raise ValueError(
                "outcome is 'denied' but policy is not a Gate with decision='deny'"
            )
        if policy_denies and not outcome_denied:
            raise ValueError(
                "policy gate decision is 'deny' but outcome is not 'denied'"
            )
        if (
            outcome_denied
            and policy_denies
            and isinstance(self.policy, Gate)
            and isinstance(self.outcome, Denied)
            and self.outcome.policy_id != self.policy.policy_id
        ):
            raise ValueError(
                f"denied outcome policy_id {self.outcome.policy_id!r} does not match "
                f"gate policy_id {self.policy.policy_id!r}"
            )
        return self


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


class LifecycleRecord(BaseModel):
    """A signed lifecycle-event record.

    Same envelope + header as a tool-call Record, so it shares the chain, the
    signature semantics, and the canonical form (sig_form_version v1.0) exactly —
    the verifier reads raw dicts and never validates payload shape, so a
    lifecycle record signs and verifies through the identical crypto path. Only
    the payload differs: a LifecycleEventPayload instead of a tool-call Payload.
    """

    model_config = ConfigDict(extra="forbid")

    envelope: Envelope
    header: Header
    payload: LifecycleEventPayload


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
    "PolicyUnobservedReason",
    "UnobservedPolicy",
    "PolicyContext",
    "gate",
    "ungated",
    "policy_unobserved",
    "LifecyclePhase",
    "NodeTransition",
    "RouteTransition",
    "LifecycleTransition",
    "LifecycleEventPayload",
    "LifecycleRecord",
    "node_transition",
    "route_transition",
    "RedactionEntry",
    "UnrepresentableReason",
    "UnrepresentableEntry",
    "Success",
    "Error",
    "Timeout",
    "Denied",
    "Unobserved",
    "UnobservedReason",
    "OutcomeContext",
    "success",
    "error",
    "timeout",
    "denied",
    "unobserved",
    "Payload",
    "Header",
    "Envelope",
    "Record",
]
