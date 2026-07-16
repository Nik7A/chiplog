# Changelog

## 0.2.0 — 2026-07-16

### Renamed to chiplog

The project was `agent-audit`. That name belongs to an unrelated static security analyzer on PyPI, and `ai-agent-audit` — matching the old repo — belongs to a different EU AI Act evidence project. Someone reading this repo and running `pip install ai-agent-audit` would have installed neither of them knowingly.

- Distribution: `agent-audit` → `chiplog`. `pip install chiplog`.
- Import: `agent_audit` → `chiplog`. Update your imports.
- CLI: `agent-audit verify` → `chiplog verify`.
- Environment: `AGENT_AUDIT_DIR`, `AGENT_AUDIT_SIGNING_KEY`, `AGENT_AUDIT_PUBKEY`, `AGENT_AUDIT_CHAIN_ID` → `CHIPLOG_*`.
- Default audit directory: `~/.config/agent-audit` → `~/.config/chiplog`. **An existing archive is not moved and not read from the new default.** Either `mv ~/.config/agent-audit ~/.config/chiplog`, or point `CHIPLOG_DIR` at the old path. Records themselves are untouched and verify either way — the signing does not depend on where the file sits.

Batched into 0.2.0 rather than shipped separately: 0.2.0 already breaks `record()`, so this is one migration instead of two.

v0.1's core was defective. This release is the correction, and most of it was
found by running the library against two real agent systems rather than by
reading the code.

If you are on 0.1.x: your records verify, and they will keep verifying. But
every one of them asserts `policy: ungated(auto_allowed_low_risk)` — a risk
judgement no adapter ever made — and depending on your runtime some of them may
say `success` for calls that failed. Nothing in this release rewrites them; the
signatures are the point. Re-record what matters.

### Breaking

- `AuditRecorder.record()` requires `outcome`, keyword-only. Every caller must
  say what it observed. mypy --strict catches a missing one.
- `schema_version` v1.1 → v1.2 (additive). `sig_form_version` stays v1.0, so
  every v1.0 and v1.1 record verifies untouched — the verifier reads raw dicts
  and never validates against the models, which is what makes this safe and is
  pinned by `tests/fixtures/v1_0_record.jsonl`.
- `WALOverflowError` removed. It was exported and never raised: the only trace
  of a write-ahead log the README claimed and the code never had.

### Fixed — records that lied

- **Fabricated policy on every record.** All 17 adapter call sites hardcoded
  `ungated(AUTO_ALLOWED_LOW_RISK)`, asserting both "no gate fired" and "low
  risk". Neither was observed. They now emit `policy_unobserved(no_gate_signal)`.
- **LangGraph signed `success` over failed calls.** `ToolNode` catches a tool's
  exception and *returns* `ToolMessage(status="error")`, so the handler returns
  normally. This is the default path under `create_agent`. The same failure
  nested in a `Command` update or a list return was also signed `success`.
- **LangGraph signed `error` over successful calls.** `interrupt()` raises
  `GraphBubbleUp`, an ordinary Exception, so a tool that paused for human
  approval and then succeeded was recorded as a failure.
- **Claude Code and Claude Agent SDK signed `success` over timed-out Bash.**
  The runtime moves the command to the background and reports an ordinary
  completed call. Now `unobserved(no_failure_signal)`, keyed on a
  `backgroundTaskId` the caller never requested — an intentional background stays
  `success`.
- **A user denying a call was recorded as `error("Interrupt")`** — asserting the
  tool ran and faulted. It never ran. Now `denied` with a real `Gate(DENY)`.
- **OpenAI `AuditHooks` signed `success` for calls it could not see.** The SDK
  converts tool exceptions into ordinary string results before `on_tool_end`
  fires. It now records `unobserved(runtime_launders_exceptions)` on every call.
  Use `@audited_tool` for real outcome coverage on that runtime.

### Fixed — records that vanished

- **A tool call could disappear with no record and no chain break.** A value that
  could not be canonicalized (an int ≥ 2^53, nan, inf, bytes, a non-string dict
  key) raised inside `record()`, and the adapters swallowed it. All construction
  now runs inside one guard: any failure poisons the chain head and raises a
  typed `RecordBuildError`.
- **`ts_monotonic_ns` crossed 2^53 at ~104 days of host uptime**, after which
  every record became unsignable and was dropped. Stored as a decimal string now.
- **The chain forked under concurrent tool calls.** LangGraph runs parallel tool
  calls in threads by default. Measured on 0.1.x: 8 threads, 144 of 200 calls
  raised, `verify` returned CHAIN_BREAK. The commit section is now serialized per
  recorder.

### Fixed — PII reaching signed records

- Non-string dict keys, integer-valued PII, and `Error.error_type` were never
  redacted; `strip_hash` lost to rule ordering and wrote a secret's sha256 into
  the record; `disable=True` wrote cleartext while the manifest attested
  redaction was on; a tool could forge a redaction marker. All closed.
- `DEFAULT_RULES` gains SSN, credit-card (Luhn-anchored), phone, JWT, PEM private
  keys, DB-URL-with-password, Stripe and Google keys.

### Fixed — the verifier

- It could not verify this library's own production data: one file, one key,
  while real chains span daily files and rotate keys. Now takes a directory and a
  keyring, with an honest partial verdict where a key is absent.
- It never read `manifest.json`, so deleting a whole chain — or injecting a
  record — passed with exit 0. The manifest's attestations now have teeth.
- New exit codes: 6 partial, 7 off-canonical, 8 manifest pubkey_id stale,
  9 manifest integrity, 10 redaction forgery. 0–5 keep their meanings.

### Added

- Lifecycle event records (`record_event`) for node enter/exit and routing. These
  carry no tool, no policy and no outcome. Consumers were faking them as tool
  calls.
- `payload.unrepresentable`: a value that cannot be represented in the signed
  form is recorded as its type plus a hash of its repr, and announced. Never a
  fabricated value.

### Performance

v0.2 costs 21–45% more CPU per record than v0.1, scaling with payload — the price
of normalizing and redacting every scalar and key. On an fsync-bound sink it is
mostly masked. One recorder no longer scales with concurrency: 8 callers move the
same 266 rec/s as one, which is the price of a chain that cannot fork. Numbers
and method in [BENCHMARKS.md](BENCHMARKS.md).

### Known limits

See [SCOPE_STATEMENT.md](SCOPE_STATEMENT.md). The sharpest ones: the
serialization guarantee is per-recorder and in-process, so two processes writing
one directory still fork the chain; a Claude Code call interrupted mid-flight
fires no hook and leaves no record; integrity is not liveness — a hook that stops
firing produces a valid, chain-intact log of everything it happened to see.

## 0.1.2 — 2026-06-23

Claude Agent SDK adapter.

## 0.1.1 — 2026-06-23

OpenAI Agents SDK adapter.

## 0.1.0 — 2026-06-22

First public release. Signed, hash-chained JSONL records of agent tool calls;
Claude Code hook and LangGraph adapters; `verify` / `inspect` CLI.
