# agent-audit — Scope Statement

_v0.1, 2026-06-19. Written BEFORE the code so we don't drift._

This is the contract with anyone who reads the README, opens an issue, or considers using agent-audit for evidence purposes.

---

## What agent-audit IS

A Python library that captures **cryptographically-linked records of every tool call** an AI agent makes (LangGraph, MCP — Claude Agent SDK / OpenAI Agents SDK adapters land in v0.2).

Each record contains: tool identity, MCP server info, input args (PII-redacted), output (capped + hashed), policy decision context, signed timestamp, hash chain link to the previous record, Ed25519 signature.

Records are JSON Lines. They're verifiable offline with a CLI that anyone — including an auditor — can run with only the public key.

## What agent-audit IS NOT (and won't claim to be in v0.1)

### NOT a regulatory-grade evidence system (v0.2 target)

v0.1 limitations that disqualify it from "tamper-evident evidence" in the strict sense:

1. **Signing key co-located with the agent process.** A compromised agent can sign forged records. Real auditor pushback: "your auditor will ask for separation of duties between the producer of evidence and the keeper of the signing key." v0.2 ships the **sidecar signer** that fixes this.
2. **Writer controls the sink.** LocalFileSink runs in the same process as the agent. Real auditor pushback: "logs co-located with the system they monitor can be silently deleted." v0.2 ships **S3 Object Lock COMPLIANCE mode** sink, **PostgresSink with role separation** (the writer role lacks `UPDATE`/`DELETE` at the DB layer), and **external chain-head anchoring** (signed Git commits or RFC 3161 TSA tokens to a third-party authority).
3. **No anti-deletion proof for head/tail.** A single forward-only hash chain detects tampering but not silent removal of the most recent records. Real auditor pushback: "how do you prove records aren't being deleted as your agent runs?" v0.2 adds the **external anchor** that makes head deletion detectable.

Until those three land, the honest framing is **"cryptographically-linked records"** — useful for engineering investigation and internal review, **not** acceptable as primary evidence to an external SOC 2 / ISO 42001 / EU AI Act auditor.

### NOT a coverage of these AI controls (any version)

agent-audit covers ONE control area: evidence of what tool calls an AI agent made, with integrity guarantees on that evidence.

It does NOT cover, and is not designed to cover:

1. **Model provenance** — which model version, where the weights came from, supply-chain attestation. Use OpenSSF, SLSA, model cards.
2. **Training data lineage** — what data the model was trained on, governance over that data. Out of scope for runtime instrumentation entirely.
3. **Eval evidence** — accuracy, robustness, fairness, hallucination rate. Use LangSmith, Langfuse, Arize, Braintrust, W&B Weave.
4. **Prompt change management** — versioning of system prompts, who changed what when. Use a prompt management tool or your existing change-management process.
5. **Vendor risk management** — Anthropic, OpenAI, your MCP server vendors. Use Vanta, Drata, Auditboard.
6. **Incident response runbooks** — what happens when an agent misbehaves. Use PagerDuty, Statuspage, your IR playbook.
7. **Data Protection Impact Assessment (DPIA)** — required under GDPR for high-risk processing. Legal/compliance team output.
8. **Human-in-the-loop standard operating procedures** — when human review is required, escalation paths. Org policy + training.
9. **Model cards** — model intended use, limitations, evaluation. Documentation artifact.
10. **Fairness / bias assessment** — protected class outcome analysis. Eval tooling + statistical testing.

If an auditor asks about any of these, the answer is not "we have agent-audit." The answer is the specific tool or process that covers it. agent-audit slots in alongside those — it doesn't replace them.

## Where it fits in the compliance stack

For an AI startup selling to regulated B2B buyers:

```
┌───────────────────────────────────────────────────┐
│ GRC platform (Vanta / Drata)                      │  ← maps controls to frameworks
├───────────────────────────────────────────────────┤
│ Eval + observability (LangSmith / Langfuse / W&B) │  ← engineering quality
├───────────────────────────────────────────────────┤
│ Vendor risk + DLP + SSO                            │  ← perimeter & people
├───────────────────────────────────────────────────┤
│ ★ agent-audit                                      │  ← runtime evidence of agent tool calls
├───────────────────────────────────────────────────┤
│ MCP servers / LangGraph / Claude Agent SDK         │  ← the agents themselves
└───────────────────────────────────────────────────┘
```

agent-audit produces the artifact other layers cite when an auditor asks **"prove what your AI agents actually did."**

## The honesty test

Before shipping the README, ask:

1. Could a SOC 2 auditor, after reading this README, conclude that agent-audit alone makes a system SOC 2 compliant? **If yes, the README is wrong.**
2. Could a customer integrate agent-audit and then claim EU AI Act Article 12 compliance? **If yes, the README is wrong.**
3. Could a customer use agent-audit's logs as primary evidence in an external audit today (v0.1)? **If yes — only if they also have sidecar signer, S3 Object Lock, and external anchor running. v0.1 alone doesn't ship those. Say so.**

The right framing is: **"agent-audit provides one component of the evidence pipeline. It is forward-compatible with regulatory-grade evidence; v0.1 is the foundation, v0.2 adds the production hardening."**
