# Changelog

## 0.2.3 — 2026-07-17

One change, from a host running the library at a load the design never
budgeted for: an agent that opens a fresh chain on every run.

### Changed — the manifest is a checkpoint + a journal, not a full rewrite per record

`LocalFileSink` rewrote the entire `manifest.json` and `F_FULLFSYNC`ed it on
every single record, and `manifest.chains` is never pruned. That is cheap at
one chain a day and quadratic-feeling under per-chain-per-run: a host measured
it at **~90 KB/day of manifest writes against ~0.5 KB/day of actual records —
~179× faster growth**, extrapolating to ~22.5 MB rewritten ~1800 times a day
after 250 busy days. Nothing outside the library could fix it: the rewrite
lives inside the sink, and pruning `chains` would lie about which chains exist.

- `manifest.json` is now a cold **checkpoint**, rewritten only on compaction and
  at construction-time key declaration.
- `manifest.journal` takes one append-only JSON line per record, carrying the
  **resulting** state of the chain and file that record touched — a result, not
  a delta, so replay is "apply in order, last wins" and is idempotent. Reading a
  directory means checkpoint + replay; writing a record means one journal append
  and one fsync — the **same fsync count as before**, and O(1) bytes instead of
  O(manifest).
- Compaction fires at 1000 journal lines and on `close()`: it writes the
  checkpoint, fsyncs, and only **then** drops the journal. A crash in that window
  replays stale-but-idempotent lines onto a newer checkpoint — a no-op, which is
  the whole reason entries state results rather than deltas.
- Re-measured on the claim the report made: **2000 records across 200 chains now
  write `manifest.json` 4 times, not 2000.**

### Fixed — the sink docstring called the manifest a cache; the verifier never agreed

The module docstring described the manifest as "NOT load-bearing for chain
integrity." `verify` has always disagreed: it reports `MANIFEST_INTEGRITY` when
the manifest contradicts the log — an integrity break, never a pass — and treats
`files[].sha256` as the robust anchor. The manifest is an **attestation**, not a
cache, and the docstring now says so. This is a documentation correctness fix,
guarded by a test; it changes no behavior.

### Compatibility

`schema_version` bumps `manifest.v1.0` → `manifest.v2.0`, and here the bump is
**required** (unlike the `pubkeys` change in 0.2.2, which deliberately avoided
one — the cases are not symmetric). A v2 checkpoint's heads lag by up to a
compaction interval, so a v1-only reader would take them as authoritative and
report a **false** `MANIFEST_INTEGRITY` on honest evidence. Refusing to load is
the honest failure. `from_dict` reads both v1.0 (no journal; its heads are
authoritative as written) and v2.0; only v2.0 is written; an unknown version
still raises.

### Deliberately not addressed

Cross-process append safety (still deferred); the pre-existing crash window
between the JSONL record append and the manifest write, which this change
neither closes nor widens (filed separately); signing the manifest; pruning
`chains`.

## 0.2.2 — 2026-07-17

Four defects, all reported by a host putting the library into real use rather
than by reading the code. One of them had already destroyed evidence.

### Fixed — rotation destroyed the previous key's records, permanently

The manifest held a single `pubkey_pem` and `LocalFileSink` overwrote it
unconditionally. Starting a recorder with a different key deleted the previous
public key from the only place it was stored, and every record it had signed
became unverifiable forever — there is no key left to check the signature
against, and nothing recovers it.

This is not a hypothetical. **330 records** on the author's own agent trail are
in exactly that state, signed with a key that exists nowhere:
`unknown_key_id: no public key for key_id=b0ee6d6c582ec87b`. A public key is
not secret; single-copy storage in a mutable field bought nothing.

- `manifest.pubkeys` maps `key_id` → PEM and is append-only. Rotation adds; it
  never replaces. Every record's envelope already carries its `key_id`, so the
  verifier only needed somewhere to look it up. Nothing about the signature
  form changes, and `verify` resolves rotated-away keys from the manifest alone.
- `pubkey_id` / `pubkey_pem` remain, tracking the most recently declared key,
  for verifiers that predate the map. They are no longer the only copy.
- `schema_version` is unchanged, so existing manifests stay readable. One
  written before `pubkeys` migrates on load, deriving the key_id from the PEM
  it stores. Keys already overwritten by a past rotation are gone; nothing can
  bring them back.

Four tests changed, and one of them is the point: the suite already covered
this exact scenario and pinned the loss as correct — it handed the rotated-away
key back to the verifier from outside and asserted the resulting mismatch. In
the real incident nobody had that key to hand back. Three more tests harvested
their "missing key" condition from the destructive overwrite itself. That
condition is real, so it is now created deliberately rather than taken from a bug.

### Fixed — `__version__` was two releases stale, and it is public API

It read `0.1.2` while the distribution was `0.2.1`, and it is in `__all__`, so
anything branching on `chiplog.__version__` got a wrong answer. It is now
derived from the installed dist metadata: the number lives once, in the
packaging config. 0.2.1 established that "keep the version numbers accurate" is
not a rule that holds — the rule that holds removes the second copy.

### Fixed — the sink promised serialisation it does not provide

`_DailyFileState` told callers `LocalFileSink` serialises appends for them with
`_write_lock`, without qualification. It is a `threading.Lock`; the guarantee
stops at the process boundary. Two concurrent writers produced 7 forked chains
across 5825 records on a real trail — nothing corrupted, every resolvable
signature valid, but `verify` reported CHAIN_BREAK over intact evidence, which
teaches an operator to disregard the verifier. The promise now names its scope.
Making appends genuinely cross-process safe is a change to the write path and
is not this release.

### Added — `is_control_flow_signal` is public

A host instrumenting LangGraph nodes needs to tell a node that parked on a
control-flow signal from one that crashed; get it wrong and you sign a false
failure, which is exactly as dishonest as a false success. The predicate was
underscore-prefixed, leaving hosts to import a private name or restate the
boundary themselves — and a hand-rolled restatement misses `GraphDrained`
today. It is now public and in `__all__`. The underscore name remains an alias
for hosts already importing it; it goes in 0.3.

## 0.2.1 — 2026-07-17

### Fixed — the verifier's own report made three false claims

The NON-CLAIMS block that ends every verification report told the reader the
three limits disqualifying this library as primary audit evidence had been
"fixed in v0.2", that "v0.2 closes this with the sidecar signer", and that
"v0.2 adds RFC 3161 TSA timestamps". None of that shipped. v0.2 closed none of
them; the signer and the TSA are still roadmap. `README.md` and `ROADMAP.md`
have said so since 0.2.0 — the report disagreed with both.

This is the worst place in the product to be wrong. The NON-CLAIMS block is
the paragraph an auditor reads to learn what the report does not establish,
and reports are byte-deterministic precisely so they can be pasted verbatim
into an audit appendix. The false claim travelled into that appendix under a
hash that matched across reviewers.

The text was written on 2026-06-19, when v0.2 was still planned to carry the
hardening. Two later passes corrected exactly this class of claim — one in
`README.md`, one across `README.md` and `ROADMAP.md` — and both missed this
one, because it is a string in code rather than prose in a document.

- The block now states each limit as open, without naming any release, and
  points at `ROADMAP.md` for where each one stands.
- `tests/test_report_claims_guard.py` fails if any release reference appears
  in the NON-CLAIMS section of either report. The drift was structural: docs
  are rewritten every release, this constant was not. Keeping the version
  numbers accurate is not a rule that holds; naming no version is.

No change to records, signing, chaining, or verification logic. Records
written by 0.2.0 verify unchanged, and the report's byte-determinism is
unaffected.

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
