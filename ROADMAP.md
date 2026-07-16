# Roadmap

What's shipped, what's next, what we won't build. Updated 2026-07-14.

## Status

v0.1 is a developer preview with no external users.

It was dogfooded against the author's own `cc-fleet-pane` daemon from 2026-06-22 to 2026-07-01: 19,037 signed records, chain intact, `verify` exit 0. What that run does **not** show is more informative than what it does. The hook was registered for `PostToolUse` only, so it recorded 7,022 tool calls and **zero failures** — a valid, verifiable, chain-intact log with no failures in it, which is exactly the "it looks like it is working" failure this library warns about in `README.md`. Recording then stopped on 2026-07-01 without anyone noticing, because the daemon's sessions moved to a profile whose config did not carry the hook. **A log that silently stops is indistinguishable from an agent that did nothing.** That is the strongest argument for the verifier sidecar below, and it is why an audit trail needs a liveness signal rather than only an integrity one.

Looking for one design partner — a Python AI team in a regulated domain (fintech, healthcare, automotive supply chain, or EU AI Act Annex III) with a SOC 2 Type II or ISO 27001 program active or being scoped. This is not a 1.0 commitment-level project. The library produces evidence; it does not produce attestations.

Measured performance baseline: see [`BENCHMARKS.md`](BENCHMARKS.md).

## v0.1 (current)

Shipped:

- Per-tool-call signed JSONL records, one file per UTC day (`audit-YYYY-MM-DD.jsonl`)
- RFC 8785 JCS canonicalization, SHA-256 digest, Ed25519 signature per record
- Hash-chained records: `prev_hash` = SHA-256 of the prior record's canonical-for-chain-link bytes
- `LocalFileSink` with atomic manifest write (tmp + fsync + rename + fsync dir), `F_FULLFSYNC` on macOS, `ENOSPC` raises typed `DiskFullError`
- Pydantic v2 schema, `extra="forbid"`, discriminated `PolicyContext` union (`Gate` | `Ungated`)
- CLI: `verify`, `inspect`, `pubkey-fingerprint`, `hook-record`, stable exit codes 0-5
- Python 3.14, full test suite under `mypy --strict` and `ruff`, stdlib `uuid.uuid7()`

Adapters:

- Claude Code CLI (`chiplog hook-record` under both `PostToolUse` and `PostToolUseFailure`)
- LangChain / LangGraph 1.x (`AuditMiddleware` plus `@audited_tool` decorator on any callable)
- OpenAI Agents SDK (`@audited_tool` on the tool callable; `AuditHooks(RunHooks)` passed to `Runner.run` records `unobserved`) — shipped in v0.1.1
- Claude Agent SDK Python (`AuditHook` registered under both `PostToolUse` and `PostToolUseFailure` in `ClaudeAgentOptions.hooks`) — shipped in v0.1.2

Known weaknesses of v0.1, each closed or explicitly deferred in v0.2:

- Lifecycle events (`Stop`, `SubagentStop`) are not recorded; only tool calls are
- `LocalFileSink` is the only destination; no built-in path to WORM storage
- Verification is on-demand via the CLI; no daemon re-verifies the chain on a schedule
- One Ed25519 signing key per process; no rotation, no per-tenant keys, no HSM

## v0.2 (next)

### Hardening

**S3Sink with Object Lock in COMPLIANCE mode.** v0.1 writes to local disk, which an operator can edit. v0.2 adds a customer-owned destination the operator cannot edit. The library writes; the bucket enforces. Retention windows are set in the customer's bucket policy to match their obligation — HIPAA 164.316(b)(2) at six years, SOC 2 Type II at the audit window (~13 months), EU AI Act Article 12 at six months or longer. Writes happen out of band from the agent's tool-call return path. Region outages and credential rotation degrade to the local sink and replay on recovery.

**Verifier sidecar.** A ~200-line Kubernetes `CronJob` that nightly re-verifies every signature, walks the hash chain end-to-end, anchors the resulting root hash to a signed Git tag and an optional RFC 3161 TSA, and emits one signed daily attestation ingestible by Vanta, Drata, Sprinto, or Auditboard. This is the artifact a SOC 2 CC7.2 reviewer or an EU AI Act Article 12 inspector reads to confirm the record set has not been altered since it was written. The sidecar ships as a separate deliverable on purpose: an audit source that owns its own verifier cannot claim non-repudiation. Verification time scales linearly with chain length; the v0.1 baseline is in [`BENCHMARKS.md`](BENCHMARKS.md).

**Tool-call outcomes — shipped in v0.2.** Every record now carries a typed `outcome` (`success` | `error` | `timeout` | `denied` | `unobserved`) with identical signature and chain semantics. `schema_version` moves to v1.2; `sig_form_version` stays v1.0, so records written under v1.0 remain verifiable unchanged. Narrows the evidence-completeness gap relevant to ISO 27001 A.8.15 (logging) and SOC 2 CC7.2 (detection of anomalies): a log that omits failed actions cannot support either. It closes that gap for the adapters whose runtime exposes outcomes, and states the limit where the runtime does not — `AuditHooks` can only write `unobserved`, neither hook-based adapter has a native timeout signal, and a Bash call the runtime backgrounds on timeout is recorded `unobserved` rather than guessed at by both hook-based adapters (Claude Code CLI and Claude Agent SDK, which share one implementation of that rule). What each adapter can actually observe — and where it says `unobserved` rather than guess — is documented in the README.

**`Stop` and `SubagentStop` event coverage.** Still open. Lifecycle events carry no tool call, so they do not fit the current record shape (`payload.tool`, `payload.input`, and `payload.output` are all required). This needs its own schema slice.

**Interrupted tool calls leave no record.** Still open, and not fixable from inside a hook. When a Claude Code tool call is cancelled mid-flight, the CLI's hook dispatcher returns early once the abort signal is set — neither `PostToolUse` nor `PostToolUseFailure` fires, so no hook runs. A call with real side effects (a partial `rm -rf`, a half-applied migration) is therefore absent from the log entirely. Nothing written is false, but absence from the log does not prove absence of a call, and both hook-based adapters have this gap. Closing it needs a signal the runtime does not currently hand a hook; the alternatives are an out-of-band transcript reconciliation pass or a `PreToolUse` intent record that a later `PostToolUse` resolves — the second doubles the record count and is not obviously worth it. Documented in the README rather than hidden. The adapters already refuse to sign `success` for any payload marked `interrupted`.

**Schema-field alignment with prEN 18229-1, gated on ratification.** The draft European standard for AI system logging is in public-enquiry phase as of June 2026. The schema is forward-compatible today; alignment lands behind a `sig_form_version` bump once the text stabilizes, not before.

**Fresh benchmark — shipped in v0.2**, in [`BENCHMARKS.md`](BENCHMARKS.md), with one honest deviation from what was promised here. The plan said "the delta from the v0.1 baseline on the same reference hardware"; the Hetzner CCX13 reference run was not performed for v0.2. Rather than compare v0.2-on-a-dev-box against the published v0.1-on-Hetzner figures — which would measure the machine rather than the release — the v0.1 baseline was re-measured on the v0.2 machine, and the delta is drawn same-machine-vs-same-machine. The Hetzner v0.1 table is retained as historical and no v0.2 number is claimed for it. The delta is published including the regression it found (v0.2 costs 21–45 % more CPU per record, payload-dependent; mostly masked on an `fsync`-bound sink), and including the fact that one recorder does not scale with concurrency now that the commit section is serialised. Out of scope for v0.2 (explicit): key rotation, per-tenant key isolation, HSM integration. These wait for a design partner with a concrete threat model.

### Adapters

**OpenAI Agents SDK** — **shipped in v0.1.1** (ahead of the original v0.2 plan) as `AuditHooks(RunHooks)`. Picked for runtime adoption and overlap with the regulated-buyer accounts most likely to ask for an audit trail (Klarna in consumer credit, Coinbase in regulated crypto custody, Box in enterprise content). `RunHooks` structurally cannot see a failed tool call — the SDK converts tool exceptions into ordinary string results before the hook fires — so `AuditHooks` records `outcome: unobserved` rather than assert a success it cannot vouch for, and `@audited_tool` on the tool callable is the documented audit-grade path for this runtime. No change to that shape is planned; the limit is in the SDK, not the adapter.

**CrewAI, LlamaIndex, Pydantic-AI** — stubs only, gated on design-partner demand. Each is a single-file adapter against the existing source contract; we will not ship them speculatively.

### Tooling

**Auditor Pack.** A reproducible tarball: signed records, manifest, public key fingerprint, and the chain-verification CLI as a single static binary. Runnable by an external auditor with no Python environment and no access to the customer's repository. Output is a one-page report listing record count, chain status, signature validity, and key fingerprint. Supports SOC 2 walkthrough and ISO 27001 Stage 2 evidence requests.

## Beyond v0.2

Plausible, not committed:

- Schema migration framework for `sig_form_version` bumps, so a record signed under v1 stays verifiable after the schema changes
- Node port as a separate package (Vercel AI SDK, Mastra) once Python ecosystem coverage is solid and the TS supply-chain situation stabilizes
- Microsoft Agent Framework 1.0 adapter once production-user signals appear

## Not planned

- **PII / PHI redaction.** Must happen upstream of the audit boundary. A regex pass inside this library is best-effort and would create a HIPAA 164.502 exposure rather than mitigate one.
- **Adverse-action reason codes / model explainability.** The library records what the agent did, not why it decided. FCRA-style obligations are model governance, not logging.
- **GDPR Article 30 ROPA generation.** ROPA is a DPO artifact. The records support Art 5(2) accountability and Art 32 security of processing.
- **Replacement for LangSmith, Langfuse, Helicone, or Datadog LLM Observability.** Those tools answer "is the agent behaving well." This library answers "can we prove what the agent did six months from now to an auditor." Run both.
- **Native chain verification inside Splunk, Datadog, or Elastic.** SIEM ingestion of the JSONL is straightforward; cryptographic verification is the sidecar's job.
- **Retention enforcement inside the library.** WORM storage enforces retention. A library that could shorten retention is not an audit library.
- **Monitoring, alerting, review workflow.** Bring your own Datadog and PagerDuty.
- **Bundled remote sink.** A source library that owns the destination cannot claim non-repudiation. Destinations are customer infrastructure.
- **Certification under any ratified standard** (SOC 2, ISO 42001, EU AI Act, HIPAA, DORA). Certification is performed by an accredited auditor against the full control environment.
- **US bank model risk management coverage.** Federal Reserve SR 26-2 and OCC 2026-13 explicitly exclude agentic AI from MRM scope as of their 2026 revisions.
- **Vercel AI SDK adapter.** TypeScript-only runtime; waits on the Node port.
- **AutoGen adapter.** Maintenance mode since April 2026; users are steered to Microsoft Agent Framework.
- **Mastra adapter.** TypeScript-only, plus the June 2026 npm supply-chain incident has not settled.

## How to influence this roadmap

One design-partner slot is open for v0.2. Terms: scoped per partner, weighted toward co-development rather than a vendor relationship. Your production failure modes set the v0.2 hardening priorities; your name stays off the page unless you opt in. Reach out — cadence and commercial terms get figured out together. Fit: a Python AI team in a regulated domain with a SOC 2 Type II or ISO 27001 program active or being scoped.

For everyone else: open an issue at `github.com/Nik7A/chiplog`. Adapter requests should include the runtime, your record volume, and the obligation driving the ask.

Contact: [Nikolai Semernia on LinkedIn](https://www.linkedin.com/in/nikolai-semernia).
