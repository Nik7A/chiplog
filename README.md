# ai-agent-audit

*Your AI agent acts on its own. Now you can prove what it did.*

Cryptographically-linked records of AI agent tool calls. A foundation for SOC 2 / ISO 42001 / EU AI Act Article 12 evidence — v0.1 is dogfooding-grade, v0.2 is the regulatory hardening.

**Status:** developer preview, no external users. Dogfooded against the author's own daemon-driven Claude Code agent system from 2026-06-22 to 2026-07-01 (19,037 signed records) and against a LangGraph multi-agent system — which is how most of the defects v0.2 fixes were found. Read [SCOPE_STATEMENT.md](SCOPE_STATEMENT.md) and the limits below before opening an issue.

---

## What this is

A small Python library that captures every tool call your AI agent makes, signs it, hash-chains it to the previous record, and writes it to a JSONL log you can verify offline.

Four instrumentation paths ship today:

1. **Claude Code hooks** — register `agent-audit hook-record` under **both** `PostToolUse` and `PostToolUseFailure` in `~/.claude/settings.json`. Captures every tool call from `claude` / `claude --bg` / Claude Code subagent dispatches, including all MCP server calls (Asana, mem0, Notion, anything you've wired in).
2. **LangGraph adapter** — `AuditMiddleware(AgentMiddleware)` plugged into `create_agent`, or `@audited_tool` on the tool callable for raw `StateGraph` users who don't go through `create_agent`.
3. **OpenAI Agents SDK adapter** — `@audited_tool` (from `agent_audit`) on the tool callable is the audit-grade path. `AuditHooks(RunHooks)` passed to `Runner.run(..., hooks=...)` also records every local tool call the SDK dispatches, but cannot see outcomes — see [What each adapter can see](#what-each-adapter-can-see).
4. **Claude Agent SDK adapter** — `AuditHook` registered under **both** `PostToolUse` and `PostToolUseFailure` in `ClaudeAgentOptions.hooks`. The SDK supplies `session_id` and `tool_use_id` natively.

The `@audited_tool` decorator works on any Python callable — custom agents, direct SDK loops, anything — and is imported from the package root:

```python
from agent_audit import audited_tool
```

The signing spec lives in [SIGNING.md](SIGNING.md) with one worked test vector so a third-party verifier can be built in any language.

## What this isn't

- **Not an observability product.** If you want span-level tracing, eval harnesses, or token cost graphs, use LangSmith, Langfuse, or Datadog Agent Observability. Those produce dashboards. This produces records.
- **Not a GRC platform.** Vanta, Drata, and friends map controls to frameworks. ai-agent-audit produces an artifact those controls can cite. They live upstream of this.
- **Not a SOC 2 magic button.** Your auditor still decides what's acceptable. v0.1 makes the conversation easier; v0.2 is what survives it.
- **Not a coverage of:** model provenance, training data lineage, eval evidence, prompt change management, vendor risk, IR runbooks, DPIA, HITL SOPs, model cards, fairness. See [SCOPE_STATEMENT.md](SCOPE_STATEMENT.md). ai-agent-audit covers one control area.

## v0.1 — what's honest about it

v0.1 has three known limits that disqualify it as primary external-audit evidence today. The fixes are tracked in [ROADMAP.md](ROADMAP.md).

1. **Signing key co-located with the agent process.** A compromised agent can sign forged records.
2. **Writer controls the sink.** LocalFileSink runs in-process with the agent.
3. **No external anchor for the chain head.** A forward-only chain detects tampering but not silent removal of the most recent records.

The recorder prints a `DEV_MODE` banner to stderr on every startup so this is impossible to forget. The verifier report ends with an explicit NON-CLAIMS block. Read [SCOPE_STATEMENT.md](SCOPE_STATEMENT.md) before staking a compliance claim on v0.1.

## What it captures per tool call

- Tool identity (name, version, MCP server URI, capability namespace, transport)
- Input args (PII-redacted by default — deny-list with structured markers)
- Output (capped at 64KB with `sha256_full` + `size_bytes_full` on truncation)
- Agent identity (run ID, step ID, agent name, calling model)
- Signed time (RFC 3339 ns wall clock + monotonic counter + clock source — `system`/`ntp`/`tsa`)
- Policy context — required, as a discriminated union: either `gate(policy_id, decision, approver, evaluation_ms)` or `ungated(reason)`. "No gate" is itself an asserted record, not absence.
- Outcome — required, as a discriminated union: `success` / `error(error_type, message)` / `timeout(elapsed_ms)` / `denied(policy_id)` / `unobserved(reason)`. Same principle as policy context: the record states what the recorder knows, and `unobserved` states that it could not tell. Neither is left to silence.
- Hash chain link to the previous record (SHA-256 over RFC 8785 JCS canonical JSON)
- Ed25519 signature, with `key_id` and `sig_form_version`
- Schema version (semver at envelope root) so future evolution doesn't break old chains. Currently `v1.2`; `sig_form_version` stays `v1.0`, so records written under schema v1.0 and v1.1 verify unchanged

Records are JSON Lines.

## Why hash chain + signed timestamp

A log you can silently edit has zero evidentiary value. With chain + signature, anyone with the public key can verify offline:

- No record was added after the fact
- No record was modified (any byte flip surfaces at the next record's `prev_hash`)
- Records came from the holder of the signing key, not someone else's process

What v0.1 alone does NOT prove (NON-CLAIMS, repeated in every verify report):

- Records were not deleted from the head of the chain → fixed in v0.2 by external anchor
- The signing key was not compromised → fixed in v0.2 by sidecar signer
- The wall clock was correct → fixed in v0.2 by RFC 3161 TSA

## Supported runtimes

| Runtime | Status | Integration |
| --- | --- | --- |
| Any Python callable (custom agents, direct Anthropic / OpenAI SDK loops, in-house frameworks) | Supported | `@audited_tool` decorator (`from agent_audit import audited_tool`) |
| Claude Code CLI | Supported | `agent-audit hook-record` under **both** `PostToolUse` and `PostToolUseFailure` |
| LangChain / LangGraph (1.x) | Supported | `AuditMiddleware` plus `@audited_tool` decorator |
| OpenAI Agents SDK | Supported | `@audited_tool` decorator (the audit-grade path, `from agent_audit import audited_tool`); `AuditHooks(RunHooks)` records `unobserved` only |
| CrewAI | Stub planned for v0.2 | Crew/Task event hooks via `@audited_tool` on tools |
| LlamaIndex (Workflows + Agents) | Stub planned for v0.2 | Workflow step events and `@audited_tool` on tools |
| Claude Agent SDK (Python) | Supported | `AuditHook` under **both** `PostToolUse` and `PostToolUseFailure` in `ClaudeAgentOptions.hooks` |
| Pydantic-AI | Stub planned for v0.2 | Agent run and tool-call hooks |
| Vercel AI SDK | Not planned | TypeScript-only ecosystem; this library is Python. A separate Node port may be evaluated later. |
| Mastra | Not planned | TypeScript-only ecosystem; this library is Python. A separate Node port may be evaluated later. |
| n8n / Make / Zapier | Not planned | Workflow orchestrators, not tool-call runtimes; auditing belongs at the workflow-platform layer rather than inside this library. |
| AutoGen | Not planned | Microsoft moved AutoGen to maintenance mode in April 2026 and steers new builds to Microsoft Agent Framework. |

### What each adapter can see

An audit trail is only as honest as its blind spots are documented. Every record carries an `outcome`. What an adapter can put there depends on what its runtime tells it.

| Adapter | Outcomes it can record |
| --- | --- |
| `@audited_tool` (any Python callable) | `success`, `error`, `timeout` — `timeout` only when the callable itself raises `asyncio.TimeoutError` |
| LangGraph (`AuditMiddleware`, `@audited_tool`) | `success`, `error`, `timeout`, `unobserved` — both read `ToolMessage.status`, so failures LangGraph handles itself rather than raising are recorded as `error` too; a tool suspended by a control-flow signal records `unobserved`; see below |
| OpenAI Agents (`@audited_tool`) | `success`, `error`, `timeout` — same decorator, but on this runtime an SDK-enforced tool timeout arrives as `error(CancelledError)`, not `timeout`; see below |
| OpenAI Agents (`AuditHooks`) | `unobserved` only — see below |
| Claude Agent SDK (`PostToolUse` + `PostToolUseFailure`) | `success`, `error`, `unobserved` — no native timeout signal; a Bash call the runtime backgrounds on timeout records `unobserved`, see below |
| Claude Code CLI (`PostToolUse` + `PostToolUseFailure`) | `success`, `error`, `unobserved` — no native timeout signal; a Bash call the runtime backgrounds on timeout records `unobserved`, see below |

**`AuditHooks` for OpenAI Agents cannot detect failures**, so it never claims a success it cannot vouch for. The SDK catches tool exceptions itself and converts them into ordinary string results (`failure_error_function`) before `on_tool_end` fires, which makes a failed call byte-identical to a successful one from where the hook sits. In the alternative configuration (`failure_error_function=None`) the exception propagates and `on_tool_end` never fires at all. Every record `AuditHooks` writes therefore carries `outcome: unobserved` with the reason `runtime_launders_exceptions`. Use `@audited_tool` on the tool callable for real outcome coverage — it runs inside the SDK's failure handling and sees the live exception.

An `unobserved` outcome is an assertion, not a gap: it states that the recorder could not determine the result from its instrumentation point, and why. That is a boundary you can audit. A `success` written on the same evidence would be a lie.

**A LangGraph tool failure usually does not raise, and both entry points record it as `error` anyway.** LangGraph's `ToolNode` catches the tool's exception and *returns* `ToolMessage(content=<error text>, status="error")` from the same handler `wrap_tool_call` / `awrap_tool_call` wrap. The handler returns normally, so an adapter that equates "returned" with "succeeded" would sign `outcome: success` over the runtime's own error text. `AuditMiddleware` and `@audited_tool` both read `status` — a runtime-set field with the literal values `success` and `error` — and record `error(error_type="ToolFailure")` with the message when it says `error`. This is the default path under `create_agent`: a model calling a tool with arguments that fail validation raises `ToolInvocationError`, which `ToolNode` converts to an error `ToolMessage` rather than propagating. It is also every failure under `ToolNode(..., handle_tool_errors=True)`.

The failure does not always sit at the top level. A tool that returns a `Command` — LangGraph's idiomatic state-update and handoff pattern — carries the failing message inside `Command.update`, and `ToolNode` can hand back a list of both. All three shapes are searched, on both entry points.

`error_type` is `ToolFailure`, not a Python exception class: by the time `ToolNode` has turned the exception into text, the class is gone, and naming one would be fabricating evidence. Detection is structural — `status` on a `ToolMessage`, never the *content* of a message, which would be a guess that misfires the first time a tool legitimately returns the word "error". It requires the `ToolMessage` shape, not merely a `status` field, because `@audited_tool` wraps arbitrary callables: a tool returning an HTTP response or a job record with `status="error"` returned a value, it did not fail, and recording it as a failure would be a false *failure* — the mirror image of the same defect. Exceptions that do propagate (`handle_tool_errors=False`) are recorded as `error` with the real exception type, as before.

**A LangGraph tool that raises has not necessarily failed, and a human-in-the-loop pause is recorded as `unobserved`, not `error`.** This is the same defect from the other side. LangGraph redirects control flow by *raising* `GraphBubbleUp`, an ordinary `Exception` subclass: `interrupt()` inside a tool raises `GraphInterrupt`, which suspends the graph for human input and then **re-executes the tool from the top** on resume; a tool bubbling a navigation `Command` to the parent graph raises `ParentCommand`, which means the tool *succeeded*. An adapter whose `except Exception` treats "an exception crossed this boundary" as evidence of failure would sign `error(error_type="GraphInterrupt")` over a call that did not fail — and, for an approval prompt, over one that goes on to succeed. Both entry points record `unobserved` with the reason `control_flow_signal`: the call was entered, the runtime took control away before any outcome existed, and nobody observed one. The signal is always re-raised, so human-in-the-loop keeps working. Every other LangGraph exception (`InvalidUpdateError`, `GraphRecursionError`, `NodeTimeoutError`) is a genuine failure and is still recorded as `error`.

**A cancelled tool call is recorded as `error(error_type="CancelledError")`, never `timeout`.** Cancellation arrives from outside the callable, and from the inside the *reason* is not observable: an outer deadline, a user interrupt, and a sibling task failing in a `TaskGroup` all look identical. Writing `timeout` there would be a guess, so the record states what was seen — the call was cancelled — and nothing more. The cancellation is always re-raised; the audit layer observes control flow, it never alters it.

This is the normal path on the OpenAI Agents SDK, which enforces its tool timeouts from *outside* the callable (`timeout_behavior` / `ToolTimeoutError`) by cancelling the coroutine. So with `@audited_tool` on that runtime, an SDK-enforced timeout lands as `error(CancelledError)`, not `timeout`. `@audited_tool` emits `timeout` only when the callable itself raises `asyncio.TimeoutError` — from its own `asyncio.wait_for`, for instance.

**Neither hook-based adapter is told that a Bash timeout is a failure, so both record those calls as `unobserved`.** This applies to the Claude Code CLI adapter and the Claude Agent SDK adapter alike — the SDK drives the same binary and hands over the same payload. A `Bash` call that exceeds its `timeout` is moved to the background by the runtime, which then fires an ordinary `PostToolUse` — the *success* event — with no `error` key, `interrupted: false`, empty `stdout`, and a `backgroundTaskId` naming the task that inherited the work. `PostToolUseFailure` never fires. Both adapters record `unobserved` with the reason `no_failure_signal`, because that is the whole truth available at the hook: the command was moved to the background and may still be running, may fail later, may never finish — nothing in the payload establishes that it succeeded.

It is not recorded as `timeout` either. The adapters could infer one by comparing `duration_ms` against `tool_input.timeout`, but that would be *deriving* a conclusion the runtime never reported, and it would break silently the day those fields change meaning. `unobserved` states only what the runtime actually told us.

The discriminator is a `backgroundTaskId` on `tool_response` that the caller did not ask for. A command the caller *intentionally* backgrounds with `run_in_background: true` also comes back with a `backgroundTaskId`, and that call genuinely succeeded — the tool was asked to launch a process and it launched one, so it stays `success`. Both halves of the test are structural fields the runtime supplies; neither is a guess. The two adapters share one implementation of this rule, so they cannot drift apart. Observed on Claude Code CLI 2.1.207 and claude-agent-sdk 0.2.118 by driving both cases against a live hook.

Ordinary tool *failures* — a non-zero exit, a missing file — do arrive on `PostToolUseFailure` and are recorded as `error`. That path is unaffected.

**A tool call you interrupt mid-flight leaves no record at all.** This is the one blind spot the hook adapters cannot close from where they sit. When you cancel a running tool call in Claude Code, the CLI's hook dispatcher returns early once the abort signal is set: neither `PostToolUse` nor `PostToolUseFailure` fires, so no hook runs and nothing is written. A `Bash` command killed halfway through an `rm -rf`, a migration applied to three tables out of five — the side effects happened, and the audit log does not show the call at all. This is a gap in *coverage*, not a false record: everything in the log remains true, but absence from the log does not prove absence of a call. Closing it needs a signal the runtime does not currently give a hook; it is tracked in [ROADMAP.md](ROADMAP.md). The adapters do refuse to sign a `success` for any payload marked `interrupted` — they record `unobserved` — so if the runtime ever does deliver one, it will not be attested as a completed call.

**A tool call you deny at the permission prompt is recorded as `denied`, with a truthful synthetic `Gate(DENY)`.** When you press "no" at Claude Code's permission prompt, the tool never runs, and the CLI fires `PostToolUseFailure` with `is_interrupt: true` and an `error` string reporting the rejection. Recording that as `error(error_type="Interrupt")` would assert the tool *ran and faulted* — it did not; a human denied it. The permission prompt is itself a real verification gate that fired and denied, so both Claude adapters record it as such: `policy = gate("claude_code:permission_denied", decision="deny")` with `outcome = denied("claude_code:permission_denied")` (same `policy_id`; the schema enforces they agree) and `output.body = null` (a denied tool produced no output).

The discriminator is **not** `is_interrupt` — the CLI sets that flag for a genuine mid-run interrupt too, and groups both internally, so it cannot tell a denial (tool never ran) from an interrupt (tool ran, was cut short). It is an **anchored prefix** on the `error` string: the exact rejection lead-sentence the CLI emits (`"The user doesn't want to proceed with this tool use."` / `"Permission for this tool use was denied."`), probed verbatim from CLI 2.1.207 and pinned by a CI test so a future CLI reword fails loud instead of silently falling back to `error`. The rule lives once in `adapters/_claude_hooks`, shared by both Claude adapters so they cannot drift. What the payload does **not** carry is recorded honestly, not fabricated: `approver = null` (no human identity), `evaluation_ms = null` (no gate timing). A **programmatic** deny (a settings deny rule) is *not* observable here — on 2.1.207 it fires `PreToolUse`/`PermissionDenied` only and never reaches a recording hook — and a genuine mid-run interrupt fires no hook at all (the blind spot above).

A policy engine that denies a call before any tool runs still writes its own `denied` record directly, via `recorder.record(outcome=denied(policy_id=...))` alongside the matching `gate(..., decision="deny")`.

Lifecycle events (`Stop`, `SubagentStop`) are not recorded; only tool calls are. Both Claude adapters record `PostToolUse` and `PostToolUseFailure` and nothing else — any other event, including `PreToolUse`, is a no-op rather than a `success` for a call that has not run. See [ROADMAP.md](ROADMAP.md).

## Quickstart — Claude Code (the primary path)

Generate a signing key once:

```bash
mkdir -p ~/.config/agent-audit
python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; \
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption; \
k=Ed25519PrivateKey.generate(); \
open('$HOME/.config/agent-audit/signing.key','wb').write(k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())); \
open('$HOME/.config/agent-audit/signing.pub','wb').write(k.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))"
chmod 0600 ~/.config/agent-audit/signing.key
```

Register the hook in `~/.claude/settings.json` under **both** events:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "agent-audit hook-record" }
        ]
      }
    ],
    "PostToolUseFailure": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "agent-audit hook-record" }
        ]
      }
    ]
  }
}
```

**Register both, or you get zero failure coverage.** The two events are disjoint: a successful call fires only `PostToolUse`, a failed call fires only `PostToolUseFailure` (verified against Claude Code CLI 2.1.207). A `PostToolUse`-only install signs every success and drops every failure on the floor — and it looks like it is working, because the records that do arrive are valid. That is the exact failure mode this library exists to prevent. The same applies to the Claude Agent SDK adapter: register `AuditHook` under both events in `ClaudeAgentOptions.hooks`.

That's it. Every tool call from `claude`, `claude --bg`, and any spawned Claude Code subagents now produces a signed, chained record in `~/.config/agent-audit/audit-YYYY-MM-DD.jsonl`.

Offline verification — anyone with the public key can run:

```bash
# single file (unchanged): one file, one key
agent-audit verify ~/.config/agent-audit/audit-2026-06-19.jsonl \
  --pubkey ~/.config/agent-audit/signing.pub

# whole directory: multi-file chains, rotated keys, manifest cross-check
agent-audit verify ~/.config/agent-audit/
```

Directory mode walks a logical chain across daily files, resolves rotated
signing keys (pass extra `--pubkey` PEMs; the manifest's key is loaded
automatically), and cross-checks `manifest.json`. It reports only facts it can
back: records it can't verify for want of a key are an honest **partial**
(never a blanket pass or fail), records off the manifest-attested canonical path
are labelled `off-canonical-path (reason not observable)` and never blamed on a
guessed cause, and a whole deleted chain or a stale `manifest.pubkey_id` is
surfaced explicitly.

Exit codes: 0 ok; 1 chain break (incl. whole-chain deletion / front-truncation);
2 signature failure; 3 key resolution; 4 malformed; 5 empty; **6 partial**
(some records unverifiable for want of a key); **7 off-canonical** (records that
don't chain — non-zero by design); **8 manifest pubkey_id stale**. The
plain-text report is byte-deterministic so it can go directly into an audit
appendix. Full contract and precedence: `SIGNING.md` §7.5.

## Quickstart — LangGraph (for non-Claude-CLI users)

```python
from langchain.agents import create_agent
from agent_audit import AuditRecorder
from agent_audit.adapters.langgraph import AuditMiddleware
from agent_audit.sinks.local_file import LocalFileSink
from agent_audit.keys import load_signing_key

recorder = AuditRecorder(
    sink=LocalFileSink(dir="./audit"),
    signing_key=load_signing_key("~/.config/agent-audit/signing.key"),
)

agent = create_agent(
    model="claude-opus-4-7",
    tools=[...],
    middleware=[AuditMiddleware(recorder=recorder)],
)
# every tool call from the agent is now recorded
```

For raw `StateGraph` (without `create_agent`), there is no middleware seam to plug into — decorate the tool callables themselves:

```python
from agent_audit import audited_tool

@audited_tool(recorder, session_id="demo")
def lookup_customer(customer_id: str) -> dict:
    ...
# the decorated callable records one entry per call, sync or async,
# wherever the graph invokes it
```

## Quickstart — OpenAI Agents SDK

`@audited_tool` is the audit-grade path here: it runs inside the SDK's failure handling, so it sees the live exception. It is the same runtime-agnostic decorator, imported from the package root — decorate the callable, then hand it to `function_tool` as usual.

```python
from agents import Agent, function_tool
from agent_audit import AuditRecorder, LocalFileSink, audited_tool, load_signing_key

recorder = AuditRecorder(
    sink=LocalFileSink(dir="./audit"),
    signing_key=load_signing_key("~/.config/agent-audit/signing.key"),
)

@function_tool
@audited_tool(recorder, session_id="demo")
def lookup_customer(customer_id: str) -> dict:
    ...

agent = Agent(name="support", tools=[lookup_customer])
```

`AuditHooks(RunHooks)` passed to `Runner.run(..., hooks=...)` records every local tool call the SDK dispatches, but every record it writes carries `outcome: unobserved` — the SDK converts tool exceptions into ordinary strings before the hook fires, so it cannot tell a failure from a success. Use it for call coverage, not outcome coverage. See [What each adapter can see](#what-each-adapter-can-see).

## Sinks

v0.1 ships `LocalFileSink` — daily-rotated JSONL with `fsync`/`F_FULLFSYNC` and a sidecar `manifest.json` written atomically (tmp + fsync + rename + fsync dir). Pluggable via the `Sink` protocol — write your own in ~20 lines. Additional sinks (S3 Object Lock, Postgres with role separation, MultiSink fan-out) are tracked in [ROADMAP.md](ROADMAP.md).

## Performance

One recorder with `LocalFileSink` is bound by per-record `fsync`, in the low hundreds of records/sec on a dev machine and roughly double that on the Linux server class it was originally measured on. That is well above the call rate of any single agent process. Three things are worth knowing before you size anything:

- **A recorder does not scale with concurrency.** v0.2 serialises the whole commit section per recorder so the chain cannot fork, which makes one recorder one writer: 8 concurrent tool calls sustain the same rate as 1. Scale by running more recorders (one per chain), not more callers.
- **v0.2 costs 21–45 % more CPU per record than v0.1** (payload-dependent), from the normalize + redact-every-scalar passes. On an `fsync`-bound sink this is mostly invisible; on a sink that is not `fsync`-bound, it is the cost.
- **Verification is the auditor's wall clock.** `agent-audit verify <dir>` runs a manifest cross-check, a full sha256 pass per file, and every signature. A ~6-month, 10 M-record chain takes on the order of an hour single-process; parallelise by `chain_id`.

Exact figures, both machines, run-to-run spread, and the v0.1→v0.2 delta — including where v0.2 regressed — are in [BENCHMARKS.md](BENCHMARKS.md). Numbers there are labelled by the machine they were measured on; no figure is claimed for hardware it was not run on.

## Why this exists

I spent 8 years at a Munich B2B SaaS (customers included VW, Deutsche Bahn, Commerzbank) getting the org through ISO 27001 + TISAX. I have sat across from external auditors evaluating evidence. The current observability stack for agents is built for the engineer at 11pm debugging, not for the compliance officer at quarter-end producing evidence. These are different artifacts, and treating them as the same is how teams end up handing their auditor a LangSmith export they didn't think would be questioned. It mostly works, until it doesn't.

EU AI Act Article 12 requires automatic event logging for high-risk AI systems. The text is settled (Articles 19/26 set a 6-month minimum retention); the technical standard family (prEN 18229-1, prEN ISO/IEC 24970) is still in draft as of 2026 Q2. SOC 2 audits are starting to ask about AI controls.

This library is the foundation I wanted to build before I shipped that conversation. v0.1 is honest about its scope. v0.2 is what closes the production gap.

## Roadmap and design partner

Full v0.2 plan, the Auditor Pack tooling track, and what's explicitly out of scope are in [ROADMAP.md](ROADMAP.md).

One design-partner slot is open. The fit: AI startup (seed–Series A), building on LangGraph / Claude Agent SDK / OpenAI Agents / MCP, selling into a regulated B2B buyer (fintech, healthtech, legaltech, automotive AI safety, German Mittelstand) with a SOC 2 audit in progress or on the horizon where AI is in scope. In exchange for early integration help and steering the record format, you get v1.0 designed around your real audit conversation — and the consulting time to integrate it. Open an issue with `[design-partner]` in the title, or email.

Contributing? See [CONTRIBUTING.md](CONTRIBUTING.md).

## Author

By **Nikolai Semernia**. Built this because I wanted compliance-grade audit logs for my own autonomous agent system, and the existing observability tools weren't designed for that. Previously led an engineering org through ISO 27001 + TISAX certification — that's where I learned what auditors actually want to see.

[LinkedIn](https://www.linkedin.com/in/nikolai-semernia)

## License

MIT.
