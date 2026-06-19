"""AuditRecorder — the public entry point for emitting audit records.

Single-chain, async-first. Use `record_sync` from non-async callers
(Claude Code hook handler runs as a one-shot subprocess with no loop).

Internal flow per record:
  1. Redact input + output.body via RedactionConfig
  2. Capture time block (wall + monotonic + clock source)
  3. Assemble Payload, Header, Envelope (prev_hash from internal chain head)
  4. sign_record() → populates envelope.hash + envelope.signature
  5. Update internal chain head = compute_chain_link(signed)
  6. await sink.write(signed)
  7. Return the signed dict

Concurrency note: this v0.1 recorder is single-chain and NOT thread-safe.
Concurrent record() calls from the same recorder must be serialized
externally. The Claude Code hook handler (Step 6) uses file-level flock;
the LangGraph adapter (Step 6.5) wraps record() in an asyncio.Lock.
"""

from __future__ import annotations

import asyncio
from typing import Any

import uuid6

from agent_audit.integrity import compute_chain_link, sign_record
from agent_audit.keys import SigningKey
from agent_audit.redact import RedactionConfig, redact_value
from agent_audit.schema.v1 import (
    Envelope,
    Header,
    Output,
    Payload,
    PolicyContext,
    Record,
    TimeBlock,
    ToolCall,
)
from agent_audit.sinks.base import Sink
from agent_audit.time import ClockSource, monotonic_ns, now_utc_rfc3339_ns


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

    async def record(
        self,
        *,
        session_id: str,
        step_id: str,
        tool: ToolCall,
        input: Any,
        output: Output,
        policy: PolicyContext,
        agent_name: str | None = None,
        model: str | None = None,
        parent_session_id: str | None = None,
    ) -> dict[str, Any]:
        """Emit one audit record.

        `policy` is keyword-only and REQUIRED. mypy --strict catches missing
        policy at type-check time — the gates-not-stages thesis encoded in
        the call signature.
        """
        # 1. Redact input + output.body
        redacted_input, input_entries = redact_value(
            input, self._redaction, path="$.input"
        )
        redacted_body, output_entries = redact_value(
            output.body, self._redaction, path="$.output.body"
        )
        redacted_output = Output(
            body=redacted_body,
            truncated=output.truncated,
            sha256_full=output.sha256_full,
            size_bytes_full=output.size_bytes_full,
        )
        redaction_entries = input_entries + output_entries

        # 2. Time block
        time_block = TimeBlock(
            ts_utc=now_utc_rfc3339_ns(),
            ts_monotonic_ns=monotonic_ns(),
            ts_source=ClockSource.SYSTEM,
        )

        # 3. Assemble payload, header, envelope
        payload = Payload(
            time=time_block,
            tool=tool,
            input=redacted_input,
            output=redacted_output,
            policy=policy,
            redaction=redaction_entries,
        )
        header = Header(
            session_id=session_id,
            step_id=step_id,
            agent_name=agent_name,
            model=model,
            parent_session_id=parent_session_id,
        )

        chain_id = self._chain_id or session_id
        if self._chain_id is None:
            self._chain_id = chain_id

        envelope = Envelope(
            record_id=str(uuid6.uuid7()),
            chain_id=chain_id,
            prev_hash=self._prev_hash,
            key_id=self._signing_key.key_id,
        )

        record = Record(envelope=envelope, header=header, payload=payload)

        # 4. Sign
        signed = sign_record(record, self._signing_key)

        # 5. Update chain head BEFORE writing — if write fails, the chain
        # head still advanced, which means the next record will reference a
        # never-persisted previous record. That's correct: a verifier seeing
        # the next record will surface the chain break, which is the right
        # behavior. Hiding write failures by rewinding the chain head would
        # silently corrupt future verification.
        self._prev_hash = compute_chain_link(signed)

        # 6. Write
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

    async def flush(self) -> None:
        """Block until all previously-written records are durable."""
        await self._sink.flush()

    async def close(self) -> None:
        """Flush and release the sink. Further record() calls will error."""
        await self._sink.close()


__all__ = ["AuditRecorder"]
