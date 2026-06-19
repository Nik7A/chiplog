# agent-audit

Cryptographically-linked records of AI agent tool calls. Forward-compatible foundation for SOC 2 / ISO 42001 / EU AI Act Article 12 evidence — v0.1 is dogfooding-grade, v0.2 is the regulatory hardening.

**Status:** v0.1 developer preview. Looking for one design partner. Read the Scope section and the v0.1 limits before opening an issue.

---

## What this is

A small Python middleware that sits between your AI agent (LangGraph + MCP today; Claude Agent SDK + OpenAI Agents SDK in v0.2) and the tools it calls. Every tool invocation produces a signed, hash-chained JSON record. v0.1 is the foundation; v0.2 adds the trust-boundary hardening (sidecar signer, S3 Object Lock, external anchor) that makes the records acceptable as primary external-audit evidence.

## What this isn't

- **Not an observability product.** If you want span-level tracing, eval harnesses, or token cost graphs, use LangSmith, Langfuse, or Datadog Agent Observability. Those produce dashboards. This produces records.
- **Not a GRC platform.** Vanta, Drata, and friends map controls to frameworks. agent-audit produces an artifact those controls can cite. They live upstream of this.
- **Not a SOC 2 magic button.** Your auditor still decides what's acceptable. v0.1 makes the conversation easier; v0.2 is what survives it.
- **Not a coverage of:** model provenance, training data lineage, eval evidence, prompt change management, vendor risk, IR runbooks, DPIA, HITL SOPs, model cards, fairness. See [SCOPE_STATEMENT.md](SCOPE_STATEMENT.md). agent-audit covers one control area.

## v0.1 — what's honest about it

v0.1 has three known limits that disqualify it as primary external-audit evidence today. They are fixed in v0.2.

1. **Signing key co-located with the agent process.** A compromised agent can sign forged records. v0.2 ships a sidecar signer that moves the key out of process.
2. **Writer controls the sink.** LocalFileSink runs in-process with the agent. v0.2 adds S3 Object Lock (COMPLIANCE mode), PostgresSink with role separation, and MultiSink fan-out.
3. **No external anchor for the chain head.** A forward-only chain detects tampering but not silent removal of the most recent records. v0.2 anchors chain heads via signed Git commits or RFC 3161 TSA.

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

Records are JSON Lines. The signing spec lives in [SIGNING.md](SIGNING.md) with one worked test vector so a third-party verifier can be built in any language.

## Why hash chain + signed timestamp

A log you can silently edit has zero evidentiary value. With chain + signature, anyone with the public key can verify offline:

- No record was added after the fact
- No record was modified (any byte flip surfaces at the next record's `prev_hash`)
- Records came from the holder of the signing key, not someone else's process

What v0.1 alone does NOT prove (NON-CLAIMS, repeated in every verify report):

- Records were not deleted from the head of the chain → fixed in v0.2 by external anchor
- The signing key was not compromised → fixed in v0.2 by sidecar signer
- The wall clock was correct → fixed in v0.2 by RFC 3161 TSA

## Quickstart (LangGraph + MCP)

```python
from langgraph.graph import StateGraph
from agent_audit import AuditRecorder, gate, ungated
from agent_audit.adapters.langgraph import instrument_graph
from agent_audit.adapters.mcp import instrument_mcp_client
from agent_audit.sinks.local_file import LocalFileSink
from agent_audit.keys import load_signing_key

recorder = AuditRecorder(
    sink=LocalFileSink(dir="./audit"),
    signing_key=load_signing_key("~/.config/agent-audit/signing.key"),
)

graph = StateGraph(...)              # your normal graph
graph = instrument_graph(graph, recorder)

# also wrap each MCP session
mcp_session = instrument_mcp_client(mcp_session, recorder)

# every tool call is now recorded
result = graph.invoke({"input": "..."})

# offline verification anyone can run
# $ agent-audit verify ./audit/2026-06-19.jsonl --pubkey ~/.config/agent-audit/signing.pub
```

`agent-audit verify` exits 0 on success and 1/2/3/4/5 on specific failure modes (chain break / signature failure / key resolution / malformed / empty). The plain-text report is byte-deterministic so it can go directly into an audit appendix.

## Sinks

**v0.1:**
- `LocalFileSink` — daily-rotated JSONL with `fsync`/`F_FULLFSYNC`, sidecar `manifest.json`, on-disk WAL for crash recovery

**v0.2:**
- `S3Sink` — S3 Object Lock COMPLIANCE mode + lifecycle to Glacier Deep Archive
- `PostgresSink` — append-only enforcement via DB-level role separation
- `MultiSink` — fan-out with required vs best-effort children

Pluggable via the `Sink` protocol — write your own in ~20 lines.

## Why this exists

I spent 8 years at a Munich B2B SaaS (customers included VW, Deutsche Bahn, Commerzbank) getting the org through ISO 27001 + TISAX. I have sat across from external auditors evaluating evidence. The current observability stack for agents is built for the engineer at 11pm debugging, not for the compliance officer at quarter-end producing evidence. These are different artifacts, and treating them as the same is how teams end up handing their auditor a LangSmith export they didn't think would be questioned. It mostly works, until it doesn't.

EU AI Act Article 12 requires automatic event logging for high-risk AI systems. The text is settled (Articles 19/26 set a 6-month minimum retention); the technical standard family (prEN 18229-1, prEN ISO/IEC 24970) is still in draft as of 2026 Q2. SOC 2 audits are starting to ask about AI controls.

This library is the foundation I wanted to build before I shipped that conversation. v0.1 is honest about its scope. v0.2 is what closes the production gap.

## Status & roadmap

**v0.1 (now):** middleware works, hash chain works, signing works. LangGraph + MCP. LocalFileSink. CLI verifier. DEV_MODE banner. SCOPE_STATEMENT.

**v0.2 (next):** sidecar signer process, S3Sink with Object Lock, PostgresSink with role separation, MultiSink, RFC 3161 TSA timestamps, external chain-head anchoring (Git signed commits), Claude Agent SDK adapter, OpenAI Agents SDK adapter, second design partner integrated.

**Later (when standards stabilize):** prEN 18229-1 export profile, CEN-CENELEC harmonised standards alignment. Tentatively CEN-CENELEC delivery is Q4 2026.

**Not on roadmap:** dashboards, alerting, eval, model governance, training data lineage. Use a real observability tool for those. agent-audit covers one control area on purpose.

## Looking for ONE design partner before v0.2

I'm not selling anything yet. I want to talk to one team:

- AI startup, seed–Series A
- Building on LangGraph / Claude Agent SDK / OpenAI Agents / MCP
- Selling into a regulated B2B buyer (fintech, healthtech, legaltech, automotive AI safety, German Mittelstand)
- SOC 2 audit in progress or on the horizon where AI is in scope

In exchange for early integration help and steering the record format, you get v1.0 designed around your real audit conversation — and the consulting time to integrate it. Open an issue with `[design-partner]` in the title, or email.

## Author

Nikolai Semernia. Software engineer, 10 years in. Most recently 8 years at Scompler in Munich (Senior Eng → Head of Engineering, 6 teams, ~40 people), led the program through ISO 27001 + TISAX certification. Now solo, building agent systems full-time from Cyprus.

[LinkedIn](https://www.linkedin.com/in/nikolai-semernia) · [Email](mailto:nsemernia@gmail.com) · [Site](https://semernia.dev) _(coming)_

## License

MIT.
