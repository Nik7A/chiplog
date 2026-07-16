"""AuditRecorder — the public entry point for emitting audit records.

Single-chain, async-first. Use `record_sync` from non-async callers
(Claude Code hook handler runs as a one-shot subprocess with no loop).

Internal flow per record:
  1. --- enter the commit section (serialised; see _ChainLock) ---
  2. --- open the construction guard (see RecordBuildError) ---
  3. Redact input + output.body + outcome.message via RedactionConfig
  4. Normalize those same three fields for JCS (normalize_for_canonical):
     replace every un-representable scalar (int >= 2**53, nan/inf, bytes/set,
     non-string dict key) with a faithful, announced marker, so a
     representable-but-hostile value is recorded rather than dropped or laundered
  5. Capture time block (wall + monotonic + clock source)
  6. Assemble Header, Payload (incl. payload.unrepresentable), Envelope
  7. sign_record() → populates envelope.hash + envelope.signature
  8. new_head = compute_chain_link(signed)
  9. If ANY of steps 3-8 raised — a value whose repr() raises, a dict key whose
     str() raises, an int >= 2**53 normalization does not cover, a surrogate str
     signing cannot encode — the record is NOT dropped silently: the chain head is
     poisoned (next record breaks the chain) and a typed RecordBuildError is
     raised. Redaction and normalization are INSIDE this guard, not before it —
     that is the whole fix. See RecordBuildError.
  10. --- close the construction guard ---
  11. Advance chain head = new_head, then await sink.write(signed). The head is
     advanced BEFORE the write so a write failure (SinkError) still leaves the
     head advanced — the next record breaks the chain — rather than rewinding to
     hide it. A write failure keeps its own SinkError type; it is already loud.
  12. --- leave the commit section ---
  13. Return the signed dict

CONCURRENCY — what is guaranteed, and under which call patterns.

One `AuditRecorder` serialises its own records. Steps 2-11 run inside a single
commit section guarded by `_ChainLock`, so for a given recorder:

  - exactly one caller at a time holds the chain head, so no two records can
    claim the same `prev_hash` — the chain cannot fork;
  - `sink.write` is called INSIDE the same section, so write order equals chain
    order. That matters as much as the head itself: `prev_hash` linkage and the
    LocalFileSink's rolling file hash are both order-dependent, and serialising
    only the head assignment would trade a forked chain for a manifest that
    attests a checksum the file does not have;
  - `ts_utc` / `ts_monotonic_ns` are taken inside the section too, so the
    timestamps do not contradict the order the chain asserts.

This holds under all four call patterns the library actually meets:

  - many THREADS calling `record_sync` — LangGraph's `ToolNode` runs parallel
    tool calls through `executor.map(self._run_one, ...)`, and parallel tool
    calls are the default under `create_agent`, so this is what a real agent
    does on its first turn;
  - many COROUTINES calling `record()` on one event loop (`asyncio.gather`, the
    async `ToolNode`);
  - both at once;
  - a SINK WHOSE `write()` SUSPENDS. `LocalFileSink.write` has no await points
    today, so the async path is accidentally atomic; every remote sink on the
    roadmap will yield, and the async `Sink` protocol exists for exactly those.
    The guarantee does not depend on the sink being non-suspending.

Why not the two obvious primitives — both are wrong here, and both were tried:

  - an `asyncio.Lock` provides NO mutual exclusion across threads. `record_sync`
    calls `asyncio.run(self.record(...))`, so every thread drives its OWN event
    loop, and an `asyncio.Lock` is bound to the loop that created it. It would
    silently do nothing on the one path that is broken today.
  - a plain `threading.Lock` held across the `await sink.write(...)` DEADLOCKS
    the loop. Coroutine A takes the lock and suspends inside the sink; coroutine
    B on the same loop blocks the loop's own THREAD waiting for the lock; A can
    never be resumed to release it. Blocking a loop thread on a lock that only a
    coroutine on that loop can release is a deadlock by construction.

`_ChainLock` is what those two constraints leave. See its docstring.

What is NOT guaranteed: two `AuditRecorder`s sharing one chain_id, or two
processes appending to the same log. Cross-process appends are still serialised
only by the `flock` in the `chiplog hook-record` subprocess (cli.py), which
covers the Claude Code hook path and nothing else.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import threading
from collections import deque
from collections.abc import Callable
from concurrent.futures import Future
from types import TracebackType
from typing import Any

from uuid import uuid7

from chiplog.integrity import compute_chain_link, sign_record
from chiplog.keys import SigningKey
from chiplog.normalize import normalize_for_canonical
from chiplog.redact import RedactionConfig, redact_tool, redact_value
from chiplog.schema.v1 import (
    Envelope,
    Error,
    Header,
    LifecycleEventPayload,
    LifecyclePhase,
    LifecycleRecord,
    LifecycleTransition,
    Output,
    OutcomeContext,
    Payload,
    PolicyContext,
    Record,
    RedactionEntry,
    TimeBlock,
    ToolCall,
    UnrepresentableEntry,
)
from chiplog.sinks.base import RedactionStateAware, Sink
from chiplog.time import ClockSource, monotonic_ns, now_utc_rfc3339_ns


class RecordBuildError(Exception):
    """The recorder could not build a faithful signed record and refused to drop
    the tool call silently. The ONE recognisable typed family for a construction
    failure.

    "Construction" is EVERY step of turning the caller's arguments into a signed
    record: redaction, normalization, payload/header/envelope assembly, and
    signing. ANY of them can raise on a hostile value the runtime handed us — a
    dict key whose `str()` raises, a value whose `repr()` raises, a str carrying
    an unpaired UTF-16 surrogate — and NONE of those failures may make a tool
    call that happened vanish from the log.

    So the recorder runs the whole construction inside one guarded section: on any
    failure it FIRST poisons its chain head (so the next record breaks the chain,
    a trace the verifier sees even if the caller swallows this exception — as every
    LangGraph adapter does, to avoid crashing the tool it observes) and THEN raises
    a member of this family. Under-recording is loud and detectable; it is never
    silent.

    `RecordSigningError` is a subclass, raised specifically when the failure
    originates in canonicalization/signing; catching `RecordBuildError` catches
    every construction failure, signing or not.
    """


class RecordSigningError(RecordBuildError):
    """A `RecordBuildError` whose cause is canonicalization/signing specifically.

    Part B (`normalize_for_canonical`) replaces every JCS-hostile value it knows
    about with an announced marker, so the common causes of a signing failure are
    gone. This error is the DEFENSE-IN-DEPTH floor for what it does not catch —
    e.g. a str carrying an unpaired UTF-16 surrogate, which cannot be encoded to
    UTF-8 and which `model_dump` does not launder.

    Kept as a distinct subclass for backward compatibility: callers that catch
    `RecordSigningError` still see a signing failure, and callers that want the
    whole construction-failure family catch `RecordBuildError`. The recorder
    poisons its chain head before raising either, so a swallowed exception still
    leaves a visible chain break at verification time.
    """


def _mint_redaction_token(config: RedactionConfig) -> str | None:
    """Mint a fresh per-record anti-forgery token, or None when redaction is off.

    Minted inside build() — i.e. AFTER the observed tool already ran and produced
    its output — from a CSPRNG, so a tool cannot predict or embed it. Genuine
    redaction markers carry it; a tool-supplied look-alike cannot. Not stored on
    the recorder or the sink, and never read back, so there is no channel through
    which a stale token could be reused. None when disabled: no markers are
    produced, so there is nothing to attest.
    """
    if config.disable:
        return None
    return secrets.token_hex(16)


def _poison_chain_head() -> str:
    """A chain-head value guaranteed not to match any real record's chain link.

    Used when a record could not be signed: the NEXT record inherits this as its
    prev_hash, so the verifier sees a chain break exactly where evidence was lost
    — instead of an invisible hole. Random, so it cannot be forged to look like a
    genuine link. Shaped like a hex SHA-256 so it flows through the schema.
    """
    return hashlib.sha256(
        b"chiplog:record-signing-failure:" + os.urandom(16)
    ).hexdigest()


class _ChainLock:
    """A mutex that is correct across threads AND across event loops.

    The commit section it guards spans `await sink.write(...)`, and its callers
    arrive from three directions at once: coroutines on the caller's loop,
    threads each driving a throwaway loop of their own via `record_sync`, and
    both mixed. Neither stdlib primitive covers that:

      - `asyncio.Lock` is bound to one loop. Threads in `record_sync` each have
        their own, so it excludes nothing between them.
      - `threading.Lock` blocks the calling THREAD. A coroutine that blocks its
        own loop's thread waiting for a lock held by a coroutine suspended on
        that same loop has deadlocked it.

    So: state is guarded by a `threading.Lock` (cross-thread correct), and that
    guard is held only for O(1) bookkeeping — NEVER across an await, which is
    what makes it safe to touch from a loop thread. Waiting is done by AWAITING
    a `concurrent.futures.Future` through `asyncio.wrap_future`, so a waiter
    yields its loop instead of blocking its thread, and the future can be
    completed from any thread or any loop. `acquire` is only ever called from
    inside a running loop (`record_sync` reaches it through `asyncio.run`), so
    every waiter, thread-driven or not, waits by suspending a coroutine. No
    thread ever blocks on a lock a coroutine holds.

    Ownership is HANDED OFF directly on release rather than re-contended for:
    the releaser pops the next waiter and completes its future while still
    holding the guard, so `_held` never drops to False with waiters queued. That
    makes the lock FIFO-fair (no starvation under a hot thread pool) and, more
    importantly, means the grant cannot be stolen by a late arrival between the
    release and the wake-up.
    """

    def __init__(self) -> None:
        # Guards _held and _waiters. Held for O(1) bookkeeping only, never
        # across an await — see the class docstring.
        self._guard = threading.Lock()
        self._held = False
        self._waiters: deque[Future[None]] = deque()

    async def acquire(self) -> None:
        with self._guard:
            if not self._held:
                self._held = True
                return
            waiter: Future[None] = Future()
            self._waiters.append(waiter)

        try:
            await asyncio.wrap_future(waiter)
        except asyncio.CancelledError:
            # Cancelled while queued. Two outcomes are possible and they are not
            # distinguishable from the deque alone, because `wrap_future` cancels
            # the underlying future as it unwinds and `release` skips cancelled
            # waiters — so "not in the deque" does NOT imply "was granted".
            # Asking the future itself, under the guard, is exact: `release`
            # pops and completes in one guarded step, so it is either still
            # queued, or CANCELLED (popped and skipped — we own nothing), or
            # FINISHED (popped and granted — we own the lock and must not
            # silently walk away holding it).
            with self._guard:
                try:
                    self._waiters.remove(waiter)
                except ValueError:
                    granted = waiter.done() and not waiter.cancelled()
                else:
                    granted = False
            if granted:
                self.release()
            raise

    def release(self) -> None:
        with self._guard:
            while self._waiters:
                waiter = self._waiters.popleft()
                # False when the waiter was cancelled while queued: nobody is
                # listening, so skip it and hand off to the next one. `_held`
                # deliberately stays True across the handoff.
                if waiter.set_running_or_notify_cancel():
                    waiter.set_result(None)
                    return
            self._held = False

    async def __aenter__(self) -> None:
        await self.acquire()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()


def _redact_outcome(
    outcome: OutcomeContext, config: RedactionConfig, token: str | None
) -> tuple[OutcomeContext, list[RedactionEntry]]:
    """Redact the runtime-supplied fields of an outcome.

    Only Error carries runtime-supplied text — both `message` AND `error_type`.
    elapsed_ms and policy_id are structural. Without redacting `message` it would
    be a bypass (exception strings routinely embed args, paths, tokens); without
    redacting `error_type` a runtime that stuffs PII into the "type" would bypass
    the policy just as squarely. error_type normally stays a plain string
    (ConnectionError, ToolFailure) — a rule only fires on actual PII.
    """
    if not isinstance(outcome, Error):
        return outcome, []

    redacted_type, type_entries = redact_value(
        outcome.error_type, config, path="$.outcome.error_type", token=token
    )
    redacted_message, msg_entries = redact_value(
        outcome.message, config, path="$.outcome.message", token=token
    )
    return (
        Error(error_type=redacted_type, message=redacted_message),
        type_entries + msg_entries,
    )


def _normalize_outcome(
    outcome: OutcomeContext,
) -> tuple[OutcomeContext, list[UnrepresentableEntry]]:
    """Normalize the free-form outcome fields for JCS.

    Error.error_type and Error.message are both runtime-supplied Any; the other
    outcome variants carry structural fields (elapsed_ms, policy_id, reason) that
    are already JCS-safe. Without this, a nan or a big int inside either field
    would reach canonicalization raw — the same silent-loss hazard as
    input/output.
    """
    if not isinstance(outcome, Error):
        return outcome, []
    norm_type, type_entries = normalize_for_canonical(
        outcome.error_type, "$.outcome.error_type"
    )
    norm_message, msg_entries = normalize_for_canonical(
        outcome.message, "$.outcome.message"
    )
    return (
        Error(error_type=norm_type, message=norm_message),
        type_entries + msg_entries,
    )


class AuditRecorder:
    """Build → redact → sign → write. The public API.

    Args:
        sink: Destination for signed records (anything implementing the
            Sink protocol). For in-process testing use InMemorySink.
        signing_key: SigningKey dataclass — load via keys.load_signing_key.
        redaction_config: Defaults to enabled with DEFAULT_RULES. Pass
            `RedactionConfig(disable=True)` to record full unredacted
            values (the disabled state should itself be recorded in the
            sink's manifest in v0.2's LocalFileSink — see self-audit #12).
        chain_id: Scopes the chain. If None, defaults to the first
            record's session_id (one chain per session).
    """

    def __init__(
        self,
        sink: Sink,
        signing_key: SigningKey,
        redaction_config: RedactionConfig | None = None,
        chain_id: str | None = None,
        initial_prev_hash: str | None = None,
    ) -> None:
        self._sink = sink
        self._signing_key = signing_key
        self._redaction = redaction_config or RedactionConfig()
        self._chain_id = chain_id
        # initial_prev_hash lets a fresh process (e.g. Claude Code hook handler)
        # resume an existing chain by loading the head hash from the sink's
        # manifest. None = start a new chain (genesis record will have prev_hash=null).
        self._prev_hash: str | None = initial_prev_hash
        # Serialises the commit section: take the chain head → sign → advance the
        # head → write. Chain order and write order are the same order because
        # both happen in here. See the module docstring and _ChainLock.
        self._commit_lock = _ChainLock()

    async def record(
        self,
        *,
        session_id: str,
        step_id: str,
        tool: ToolCall,
        input: Any,
        output: Output,
        policy: PolicyContext,
        outcome: OutcomeContext,
        agent_name: str | None = None,
        model: str | None = None,
        parent_session_id: str | None = None,
    ) -> dict[str, Any]:
        """Emit one audit record.

        `policy` and `outcome` are keyword-only and REQUIRED. mypy --strict
        catches either one missing at type-check time — neither "no gate
        applied" nor "unknown outcome" may be asserted by silence.
        """

        def build(chain_id: str, prev_hash: str | None) -> Record:
            # 0. Mint the per-record anti-forgery token. Fresh, unpredictable, and
            # minted HERE — after the tool already ran and produced its output —
            # so a tool cannot embed it. Genuine markers carry it; a tool
            # look-alike cannot. None when redaction is disabled (no markers).
            token = _mint_redaction_token(self._redaction)

            # 1. Redact input, output.body, outcome.error_type, outcome.message,
            # AND the tool IDENTITY (tool.name / mcp.server_id) — plus dict KEYS
            # and non-string scalars within them, each inspected in the exact
            # string form it will take in the signed bytes. Most-restrictive rule
            # wins per value.
            redacted_tool, tool_entries = redact_tool(tool, self._redaction, token)
            redacted_input, input_entries = redact_value(
                input, self._redaction, path="$.input", token=token
            )
            redacted_body, output_entries = redact_value(
                output.body, self._redaction, path="$.output.body", token=token
            )
            redacted_outcome, outcome_entries = _redact_outcome(
                outcome, self._redaction, token
            )
            redaction_entries = (
                tool_entries + input_entries + output_entries + outcome_entries
            )

            # 2. Normalize for JCS — AFTER redaction, so a redacted marker is
            # never re-inspected as a raw value. Replaces every JCS-hostile
            # scalar (int >= 2**53, nan/inf, bytes/set, non-string dict key)
            # with a faithful, announced marker. Runs on the three Any user
            # fields only; the structural fields are already JCS-safe.
            norm_input, input_unrep = normalize_for_canonical(
                redacted_input, "$.input"
            )
            norm_body, output_unrep = normalize_for_canonical(
                redacted_body, "$.output.body"
            )
            norm_outcome, outcome_unrep = _normalize_outcome(redacted_outcome)
            unrepresentable: list[UnrepresentableEntry] = (
                input_unrep + output_unrep + outcome_unrep
            )

            redacted_output = Output(
                body=norm_body,
                truncated=output.truncated,
                sha256_full=output.sha256_full,
                size_bytes_full=output.size_bytes_full,
            )

            payload = Payload(
                time=self._time_block(),
                tool=redacted_tool,
                input=norm_input,
                output=redacted_output,
                policy=policy,
                outcome=norm_outcome,
                redaction=redaction_entries,
                unrepresentable=unrepresentable,
                redaction_token=token,
            )
            return Record(
                envelope=self._envelope(chain_id, prev_hash),
                header=Header(
                    session_id=session_id,
                    step_id=step_id,
                    agent_name=agent_name,
                    model=model,
                    parent_session_id=parent_session_id,
                ),
                payload=payload,
            )

        return await self._emit(build, session_id)

    async def record_event(
        self,
        *,
        session_id: str,
        step_id: str,
        phase: LifecyclePhase,
        transition: LifecycleTransition,
        attributes: dict[str, Any] | None = None,
        agent_name: str | None = None,
        model: str | None = None,
        parent_session_id: str | None = None,
    ) -> dict[str, Any]:
        """Emit one lifecycle-event record (node.enter / node.exit / route).

        NOT a tool call: the record carries no tool, no policy, and no outcome —
        see LifecycleEventPayload. `attributes` is runtime-REPORTED and
        UNATTESTED; the recorder copies it verbatim and makes no claim it is
        true, but still redacts secrets in it and normalizes JCS-hostile values
        so it is signed faithfully rather than dropped or laundered.

        Shares the commit lock, chain, signing, and construction guard with
        `record()`: the payload and TimeBlock are built INSIDE the guard, so a
        hostile attribute value poisons the chain head and raises a typed
        RecordBuildError rather than vanishing (the area-1 guarantee).
        """
        attrs = attributes or {}

        def build(chain_id: str, prev_hash: str | None) -> LifecycleRecord:
            # attributes is runtime-supplied Any → same redaction + JCS
            # normalization as tool input/output. A secret in an attribute is
            # redacted (keys too); a JCS-hostile attribute becomes an announced
            # marker; a tool-supplied marker look-alike is caught by the token.
            token = _mint_redaction_token(self._redaction)
            redacted_attrs, redaction_entries = redact_value(
                attrs, self._redaction, path="$.attributes", token=token
            )
            norm_attrs, unrep = normalize_for_canonical(
                redacted_attrs, "$.attributes"
            )
            payload = LifecycleEventPayload(
                time=self._time_block(),
                phase=phase,
                transition=transition,
                attributes=norm_attrs,
                redaction=redaction_entries,
                unrepresentable=unrep,
                redaction_token=token,
            )
            return LifecycleRecord(
                envelope=self._envelope(chain_id, prev_hash),
                header=Header(
                    session_id=session_id,
                    step_id=step_id,
                    agent_name=agent_name,
                    model=model,
                    parent_session_id=parent_session_id,
                ),
                payload=payload,
            )

        return await self._emit(build, session_id)

    def _time_block(self) -> TimeBlock:
        """Capture the time block. Called INSIDE the construction guard so the
        timestamps agree with the order the chain asserts — a record that links
        after another but claims an earlier ts_utc would make the log argue with
        itself. Decimal-string monotonic ns, not int: a raw int becomes
        un-canonicalizable past 2**53 (~104 days of host uptime). See TimeBlock.
        """
        return TimeBlock(
            ts_utc=now_utc_rfc3339_ns(),
            ts_monotonic_ns=str(monotonic_ns()),
            ts_source=ClockSource.SYSTEM,
        )

    def _envelope(self, chain_id: str, prev_hash: str | None) -> Envelope:
        return Envelope(
            record_id=str(uuid7()),
            chain_id=chain_id,
            prev_hash=prev_hash,
            key_id=self._signing_key.key_id,
        )

    async def _emit(
        self,
        build: Callable[[str, str | None], Record | LifecycleRecord],
        session_id: str,
    ) -> dict[str, Any]:
        """The shared commit section for record() and record_event().

        Everything from construction to the sink write happens under one lock, in
        chain order. `build` does the pure-CPU construction (redact -> normalize
        -> build payload/header/envelope -> assemble the unsigned record); it runs
        INSIDE the construction guard so ANY failure on a hostile caller value
        poisons the chain head (making the loss visible as a chain break the
        verifier sees even if the caller swallows the error) and raises a typed
        RecordBuildError — under-recording is loud, never silent. This is the
        area-1 guarantee, and record_event() inherits it by construction because
        it goes through this exact method.

        The sink write is INSIDE the lock too, not merely after: `prev_hash`
        linkage and the LocalFileSink's rolling file hash are both order-dependent,
        so chain order must equal write order.
        """
        async with self._commit_lock:
            # --- CONSTRUCTION GUARD -----------------------------------------
            try:
                chain_id = self._chain_id or session_id
                record = build(chain_id, self._prev_hash)

                # Sign, then compute the link the next record must chain onto.
                # Normalization made the known JCS-hostile kinds representable,
                # but this can STILL raise on something it does not cover
                # (model_dump launders some kinds; a surrogate str cannot be UTF-8
                # encoded); RecordSigningError names that specific cause and is a
                # member of the RecordBuildError family the outer handler raises
                # for the rest.
                try:
                    signed = sign_record(record, self._signing_key)
                except Exception as exc:
                    raise RecordSigningError(
                        "could not canonicalize/sign this record. "
                        f"Cause: {type(exc).__name__}: {exc}"
                    ) from exc
                new_head = compute_chain_link(signed)
            except Exception as exc:
                # ANY construction failure: poison the head so the loss is visible
                # as a chain break at verification time, then raise a typed error.
                self._prev_hash = _poison_chain_head()
                if isinstance(exc, RecordBuildError):
                    raise
                raise RecordBuildError(
                    "could not build a faithful signed record; refusing to drop it "
                    "silently. The chain head is poisoned so the loss is visible as "
                    "a chain break at verification time. "
                    f"Cause: {type(exc).__name__}: {exc}"
                ) from exc
            # --- END CONSTRUCTION GUARD -------------------------------------

            # The record is fully built and signed. Commit chain_id only now that
            # nothing above can still fail and abandon it.
            if self._chain_id is None:
                self._chain_id = chain_id

            # Advance chain head BEFORE writing — if the write fails, the chain
            # head still advanced, so the next record references a never-persisted
            # previous record and the verifier surfaces the chain break. That is
            # correct: hiding write failures by rewinding the head would silently
            # corrupt future verification. A write failure keeps its own SinkError
            # (already loud, and a documented contract) rather than being rewrapped.
            self._prev_hash = new_head

            # Drive the sink's attested redaction state from what the recorder
            # ACTUALLY did (self._redaction.disable), before the write persists
            # the manifest. This is the honest wiring for leak #1: the manifest's
            # redaction-disabled state is no longer a disconnected constructor
            # flag. DISABLED latches monotonically in the sink. Sinks that do not
            # attest redaction (InMemorySink, remote sinks, test wrappers) do not
            # implement the capability and are left untouched.
            if isinstance(self._sink, RedactionStateAware):
                self._sink.note_redaction_disabled(self._redaction.disable)

            await self._sink.write(signed)

        return signed

    def record_sync(self, **kwargs: Any) -> dict[str, Any]:
        """Sync wrapper for non-async callers (Claude Code hook handlers).

        Raises RuntimeError if called from inside a running event loop —
        prevents silent confusion when used from async code where
        `await recorder.record(...)` is the correct call.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.record(**kwargs))
        raise RuntimeError(
            "record_sync called from a context with a running event loop. "
            "Use 'await recorder.record(...)' instead."
        )

    def record_event_sync(self, **kwargs: Any) -> dict[str, Any]:
        """Sync twin of record_event for non-async callers.

        Same contract as record_sync: raises RuntimeError if called from inside a
        running event loop, so async callers are steered to
        `await recorder.record_event(...)`.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.record_event(**kwargs))
        raise RuntimeError(
            "record_event_sync called from a context with a running event loop. "
            "Use 'await recorder.record_event(...)' instead."
        )

    async def flush(self) -> None:
        """Block until all previously-written records are durable.

        Takes the commit lock, so it also waits out any record() already inside
        the sink. Without that, a flush concurrent with a write could return
        while the record it was supposed to make durable had not yet been handed
        to the sink at all.
        """
        async with self._commit_lock:
            await self._sink.flush()

    async def close(self) -> None:
        """Flush and release the sink. Further record() calls will error.

        Takes the commit lock for the same reason flush() does: closing the sink
        out from under an in-flight write would turn a record that was about to
        be persisted into a SinkError.
        """
        async with self._commit_lock:
            await self._sink.close()


__all__ = ["AuditRecorder", "RecordBuildError", "RecordSigningError"]
