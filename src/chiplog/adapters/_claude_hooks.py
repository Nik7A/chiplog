"""Payload semantics shared by the two Claude hook adapters.

The Claude Code CLI adapter (`claude_code`) and the Claude Agent SDK adapter
(`claude_agent_sdk`) are two front doors onto the same runtime: the SDK drives
the same binary the CLI does, and the hook payloads it hands a `HookCallback`
carry the same fields the CLI writes to a hook subprocess's stdin. Anything
that reads meaning out of those fields therefore belongs here, once, so that a
fix to one adapter cannot silently leave the other signing false evidence —
which is exactly what happened when `_is_unrequested_background` was fixed in
`claude_code` alone.
"""

from __future__ import annotations

from typing import Any

# The only two events that describe a tool call that has ALREADY RUN. Every
# other hook event — PreToolUse, Stop, SubagentStop, UserPromptSubmit,
# Notification — says nothing about an outcome, and PreToolUse fires before the
# tool executes at all.
POST_TOOL_USE_EVENT = "PostToolUse"
POST_TOOL_USE_FAILURE_EVENT = "PostToolUseFailure"
_RECORDABLE_EVENTS = frozenset({POST_TOOL_USE_EVENT, POST_TOOL_USE_FAILURE_EVENT})

# The Bash tool is the only tool the runtime can move to the background.
_BASH_TOOL = "Bash"

# Set by the runtime on `tool_response` when it hands the command to a
# background task — both when the caller asked for that and when a timeout
# forced it.
_BACKGROUND_TASK_ID = "backgroundTaskId"

# Set by the CALLER on `tool_input` to request backgrounding up front.
_RUN_IN_BACKGROUND = "run_in_background"

# Set by the runtime on `tool_response` when the call was cut short rather than
# allowed to finish.
_INTERRUPTED = "interrupted"


# ---------------------------------------------------------------------------
# User-denial detection (permission prompt → a truthful Gate(DENY))
# ---------------------------------------------------------------------------
#
# When a user presses "no" at Claude Code's permission prompt, the tool NEVER
# RUNS. The CLI fires PostToolUseFailure with is_interrupt=True and an `error`
# string reporting the rejection. Recording that as error(error_type="Interrupt")
# asserts the tool ran and faulted — a lie: a human denied it. The permission
# prompt IS a real verification gate that fired and denied, so the honest record
# is a synthetic Gate(DENY) + outcome=denied. This predicate is the discriminator
# that lets both Claude adapters build that record without re-introducing a
# fabrication, and it lives here — once — so the two adapters cannot drift.

# The CLI version whose rejection strings were probed to derive the anchor below.
# Pinned by a CI test (test_denial_marker_is_pinned_to_probed_cli_version): if a
# future CLI rewords the rejection lead-sentence, that test fails LOUD rather than
# this predicate silently falling back to error(). See
# .superpowers/sdd/area-denial-report.md for the raw probe.
_PROBED_CLI_VERSION = "2.1.207"

# The single honest policy_id naming the ACTUAL mechanism that denied the call:
# Claude Code's permission prompt. The SAME id goes into both the synthetic
# Gate(DENY) and the Denied outcome, so Payload._outcome_agrees_with_policy is
# satisfied. It is deliberately NOT keyed off is_interrupt: the CLI sets that
# flag for a genuine mid-run interrupt too, so it does not observe the gate.
PERMISSION_DENIED_POLICY_ID = "claude_code:permission_denied"

# The EXACT lead sentences Claude Code CLI 2.1.207 puts at the START of the
# `error` field of a PostToolUseFailure when a tool use was REJECTED — i.e. the
# tool did NOT run. Probed verbatim from the installed CLI binary: all four
# rejection templates begin with one of these two and all contain the shared
# sentence "The tool use was rejected (eg. if it was a file edit, the new_string
# was NOT written to the file)."
#
#   1. "The user doesn't want to proceed with this tool use." — the user pressed
#      "no" at the interactive permission prompt (the case that reaches this hook).
#   2. "Permission for this tool use was denied." — the permission SYSTEM denied
#      it (deny rule / policy). On 2.1.207 this fires PreToolUse / PermissionDenied
#      only and does NOT reach a recording hook; it is included as the honest
#      SUPERSET, so that if any future/other path ever delivers it here it is
#      still recognised as a denial rather than mislabelled a tool fault.
#
# Matched as a PREFIX (str.startswith) on the stripped error — an anchored
# sentinel, NOT a loose "reject"/"deny"/"permission" substring, and NOT
# is_interrupt. The CLI sets is_interrupt=True for a genuine mid-run interrupt
# ("[Request interrupted by user]") too, and groups it WITH the denial strings
# internally, so is_interrupt cannot tell a denial (tool never ran → denied) from
# an interrupt (tool ran, was cut short → error/unobserved). The rejection
# lead-sentence can: it is emitted only when a tool use was rejected and did not
# run. A genuine failure ("Exit code 1") and a genuine interrupt ("[Request
# interrupted by user]") start with neither prefix.
_DENIAL_ERROR_PREFIXES: tuple[str, ...] = (
    "The user doesn't want to proceed with this tool use.",
    "Permission for this tool use was denied.",
)


def is_user_denial(error: Any) -> bool:
    """True when a PostToolUseFailure `error` reports a REJECTED (never-run) tool.

    Anchored to the exact rejection lead-sentences the CLI emits (see
    `_DENIAL_ERROR_PREFIXES`), matched as a prefix on the stripped `error`. A
    denial means the tool did not run, so the recorder can honestly build a
    synthetic `gate(..., DENY)` + `outcome=denied` instead of asserting the tool
    ran and faulted.

    Identity, not fuzziness: `error` must be a `str` and must START WITH one of
    the anchored sentinels. A non-string payload, a genuine tool failure, a
    genuine interrupt, or a message that merely mentions "denied"/"rejected"
    somewhere is NOT a denial and keeps its current honest handling.
    """
    if not isinstance(error, str):
        return False
    stripped = error.strip()
    return any(stripped.startswith(prefix) for prefix in _DENIAL_ERROR_PREFIXES)


def is_recordable_event(hook_event_name: Any) -> bool:
    """True only for the two events that report a completed tool call.

    An adapter that treats "not the failure event" as the success slot signs
    `outcome: success` for anything else it is handed. Feed such an adapter a
    `PreToolUse` payload — a mis-registration in `settings.json` is one line, and
    the field names are identical — and it attests that a tool call succeeded
    *before the tool has run*. That is the same class of defect as signing a
    success for a call the runtime reported as failed, and it is worse in one
    respect: there is no outcome at all to have got wrong.

    So the allowlist is positive, not negative: a payload must name one of the
    two completed-call events to be recorded, and every other event is a no-op.
    Silence about an event we cannot interpret is the correct answer — the audit
    log's value is that everything in it is true.

    Lives here, beside the background discriminator, for the same reason that one
    does: the CLI adapter and the SDK adapter read byte-identical payloads from
    the same runtime, and a rule about what those payloads MEAN must have exactly
    one implementation or the two will drift. They already drifted once.
    """
    return hook_event_name in _RECORDABLE_EVENTS


def is_failure_event(hook_event_name: Any) -> bool:
    """True for the event the runtime uses to report a failed tool call.

    The two events are disjoint: a failed call fires only `PostToolUseFailure`,
    a successful one only `PostToolUse`. That disjointness is what makes
    `PostToolUse -> success` an honest claim rather than a guess — but only for
    payloads that cleared `is_recordable_event` first.
    """
    return bool(hook_event_name == POST_TOOL_USE_FAILURE_EVENT)


def is_unrequested_background(
    tool_name: str, tool_input: Any, tool_response: Any
) -> bool:
    """True when the runtime backgrounded a Bash call the caller did not ask to background.

    A Bash command that blows its `timeout` is not failed. The runtime moves it
    to the background and reports it on `PostToolUse` — the success slot — with
    no `error` key and `interrupted: false`. `PostToolUseFailure` never fires.
    The outcome of such a call is genuinely unknown at this instrumentation
    point: the command may still be running, may fail later, may never finish.
    Signing it `success` would turn an ambiguous record into cryptographically
    attested false evidence. It records `unobserved(no_failure_signal)` instead.

    `backgroundTaskId` alone cannot be the discriminator, because it is ALSO
    present when the caller intentionally backgrounds a command with
    `run_in_background: true`. That call really did succeed — the tool was asked
    to launch a process and it launched one. Treating those as `unobserved`
    would destroy good evidence, which is its own defect.

    So the test is a `backgroundTaskId` the caller never requested. Both halves
    are structural fields the runtime supplied — the response key it set, and the
    input flag it echoed back from the caller. Nothing here is derived.

    What this deliberately does NOT do is compare `duration_ms` against
    `tool_input.timeout` to synthesize a `timeout` outcome. That would be
    *deriving* a conclusion the runtime never reported, and it would break
    silently the day the runtime changes what those fields mean. `unobserved`
    says only what is true: the call was moved to the background, and its
    outcome is not determinable from this hook.

    Probed against Claude Code CLI 2.1.207 and claude-agent-sdk 0.2.118 by
    driving both the forced and the intentional case against a live hook. The
    payloads are the same shape on both, because it is the same runtime.
    """
    if tool_name != _BASH_TOOL:
        return False
    if not isinstance(tool_response, dict):
        return False
    if not tool_response.get(_BACKGROUND_TASK_ID):
        return False

    requested = (
        tool_input.get(_RUN_IN_BACKGROUND) if isinstance(tool_input, dict) else None
    )
    return requested is not True


def is_interrupted(tool_response: Any) -> bool:
    """True when the runtime says this tool call was cut short mid-flight.

    A cheap guard against a payload the adapters should never be handed, and must
    not sign a `success` over if they ever are.

    Today they are not handed one. A tool call the user interrupts fires NO hook
    at all — the CLI's hook dispatcher returns early when the abort signal is set
    — so a partial `rm -rf` or a half-applied migration leaves ZERO trace in the
    audit log. That blind spot cannot be closed from inside a hook; it is
    documented in the README rather than papered over here.

    But the field exists on `tool_response`, the runtime sets it, and the shape
    of the payload is not this library's to guarantee: a future CLI that starts
    delivering the event, a replayed transcript, a wrapper that synthesises one.
    An interrupted call is by definition one whose outcome nobody observed —
    whatever it managed to do before it died is not established by anything in
    the payload — so it records `unobserved(no_failure_signal)`, exactly as the
    backgrounded-Bash case does, and for exactly the same reason.

    Unlike backgrounding, this is not Bash-specific: any tool call can be cut
    short. And unlike backgrounding, there is no legitimate variant to protect —
    nobody asks for an interruption the way they ask for `run_in_background`.

    Identity, not truthiness: `interrupted` is a bool the runtime sets, and a
    non-empty string or a stray `1` in that slot is a payload we do not
    understand rather than a licence to relabel a good record.
    """
    if not isinstance(tool_response, dict):
        return False
    return tool_response.get(_INTERRUPTED) is True


# The event-name constants are module-internal (`_RECORDABLE_EVENTS`,
# `is_failure_event`) and nothing imports them. Exporting names no caller uses
# invites the belief that they are load-bearing API; the predicates are the API.
__all__ = [
    "PERMISSION_DENIED_POLICY_ID",
    "is_failure_event",
    "is_interrupted",
    "is_recordable_event",
    "is_unrequested_background",
    "is_user_denial",
]
