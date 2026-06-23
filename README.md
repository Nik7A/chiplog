# ai-agent-audit

*Your AI agent acts on its own. Now you can prove what it did.*

Cryptographically-linked records of AI agent tool calls. A foundation for SOC 2 / ISO 42001 / EU AI Act Article 12 evidence — v0.1 is dogfooding-grade, v0.2 is the regulatory hardening.

**Status:** v0.1 developer preview, dogfooded on the author's own daemon-driven Claude Code agent system since 2026-06-22. Read [SCOPE_STATEMENT.md](SCOPE_STATEMENT.md) and the v0.1 limits below before opening an issue.

---

## What this is

A small Python library that captures every tool call your AI agent makes, signs it, hash-chains it to the previous record, and writes it to a JSONL log you can verify offline.

Three instrumentation paths ship today:

1. **Claude Code hooks** — register `agent-audit hook-record` as a `PostToolUse` hook in `~/.claude/settings.json`. Captures every tool call from `claude` / `claude --bg` / Claude Code subagent dispatches, including all MCP server calls (Asana, mem0, Notion, anything you've wired in).
2. **LangGraph adapter** — `AuditMiddleware(AgentMiddleware)` plugged into `create_agent`, or `instrument_graph(graph, recorder)` for raw `StateGraph`.
3. **OpenAI Agents SDK adapter** — `AuditHooks(RunHooks)` passed to `Runner.run(..., hooks=...)`. Records every local tool call the SDK dispatches during the run.

A `@audited_tool` decorator works on any Python callable for custom agents and direct SDK loops. The signing spec lives in [SIGNING.md](SIGNING.md) with one worked test vector so a third-party verifier can be built in any language.

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
- Hash chain link to the previous record (SHA-256 over RFC 8785 JCS canonical JSON)
- Ed25519 signature, with `key_id` and `sig_form_version`
- Schema version (semver at envelope root) so future evolution doesn't break old chains

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
| Any Python callable (custom agents, direct Anthropic / OpenAI SDK loops, in-house frameworks) | Supported | `@audited_tool` decorator |
| Claude Code CLI | Supported | `PostToolUse` hook |
| LangChain / LangGraph (1.x) | Supported | `AuditMiddleware` plus `@audited_tool` decorator |
| OpenAI Agents SDK | Supported | `AuditHooks(RunHooks)` plus `@audited_tool` decorator |
| CrewAI | Stub planned for v0.2 | Crew/Task event hooks via `@audited_tool` on tools |
| LlamaIndex (Workflows + Agents) | Stub planned for v0.2 | Workflow step events and `@audited_tool` on tools |
| Claude Agent SDK (Python) | Stub planned for v0.2 | Session and tool-call event tap |
| Pydantic-AI | Stub planned for v0.2 | Agent run and tool-call hooks |
| Vercel AI SDK | Not planned | TypeScript-only ecosystem; this library is Python. A separate Node port may be evaluated later. |
| Mastra | Not planned | TypeScript-only ecosystem; this library is Python. A separate Node port may be evaluated later. |
| n8n / Make / Zapier | Not planned | Workflow orchestrators, not tool-call runtimes; auditing belongs at the workflow-platform layer rather than inside this library. |
| AutoGen | Not planned | Microsoft moved AutoGen to maintenance mode in April 2026 and steers new builds to Microsoft Agent Framework. |

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

Register the hook in `~/.claude/settings.json`:

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
    ]
  }
}
```

That's it. Every tool call from `claude`, `claude --bg`, and any spawned Claude Code subagents now produces a signed, chained record in `~/.config/agent-audit/audit-YYYY-MM-DD.jsonl`.

Offline verification — anyone with the public key can run:

```bash
agent-audit verify ~/.config/agent-audit/audit-2026-06-19.jsonl \
  --pubkey ~/.config/agent-audit/signing.pub
```

Exits 0 on success and 1 / 2 / 3 / 4 / 5 on specific failure modes (chain break / signature failure / key resolution / malformed / empty). The plain-text report is byte-deterministic so it can go directly into an audit appendix.

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

For raw `StateGraph` (without `create_agent`), use the fallback:

```python
from agent_audit.adapters.langgraph import instrument_graph
graph = instrument_graph(graph, recorder)
```

## Sinks

v0.1 ships `LocalFileSink` — daily-rotated JSONL with `fsync`/`F_FULLFSYNC`, sidecar `manifest.json`, on-disk WAL for crash recovery. Pluggable via the `Sink` protocol — write your own in ~20 lines. Additional sinks (S3 Object Lock, Postgres with role separation, MultiSink fan-out) are tracked in [ROADMAP.md](ROADMAP.md).

## Performance

LocalFileSink sustains ~500 rec/sec with per-record fsync on the reference Hetzner CCX13; the verifier processes ~6.6K rec/sec, so a 6-month chain verifies in roughly 25 minutes. Methodology, full numbers, and the network-attached-storage caveat are in [BENCHMARKS.md](BENCHMARKS.md).

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

[LinkedIn](https://www.linkedin.com/in/nikolai-semernia) · [Email](mailto:nsemernia@gmail.com)

## License

MIT.
