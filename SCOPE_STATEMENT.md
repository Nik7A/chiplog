# ai-agent-audit — Scope Statement

_v0.1, 2026-06-19. Written BEFORE the code so we don't drift._

This is the contract with anyone who reads the README, opens an issue, or considers using ai-agent-audit for evidence purposes.

---

## What ai-agent-audit IS

A Python library that captures **cryptographically-linked records of every tool call** an AI agent makes (LangGraph, MCP — Claude Agent SDK / OpenAI Agents SDK adapters land in v0.2).

Each record contains: tool identity, MCP server info, input args (PII-redacted), output (capped + hashed), policy decision context, signed timestamp, hash chain link to the previous record, Ed25519 signature.

Records are JSON Lines. They're verifiable offline with a CLI that anyone — including an auditor — can run with only the public key.

## What ai-agent-audit IS NOT (and won't claim to be in v0.1)

### NOT a regulatory-grade evidence system (v0.2 target)

v0.1 limitations that disqualify it from "tamper-evident evidence" in the strict sense:

1. **Signing key co-located with the agent process.** A compromised agent can sign forged records. Real auditor pushback: "your auditor will ask for separation of duties between the producer of evidence and the keeper of the signing key." v0.2 ships the **sidecar signer** that fixes this.
2. **Writer controls the sink.** LocalFileSink runs in the same process as the agent. Real auditor pushback: "logs co-located with the system they monitor can be silently deleted." v0.2 ships **S3 Object Lock COMPLIANCE mode** sink, **PostgresSink with role separation** (the writer role lacks `UPDATE`/`DELETE` at the DB layer), and **external chain-head anchoring** (signed Git commits or RFC 3161 TSA tokens to a third-party authority).
3. **No anti-deletion proof for head/tail.** A single forward-only hash chain detects tampering but not silent removal of the most recent records. Real auditor pushback: "how do you prove records aren't being deleted as your agent runs?" v0.2 adds the **external anchor** that makes head deletion detectable.

Until those three land, the honest framing is **"cryptographically-linked records"** — useful for engineering investigation and internal review, **not** acceptable as primary evidence to an external SOC 2 / ISO 42001 / EU AI Act auditor.

### Concurrent tool calls: safe within one process, NOT across processes

**Fixed.** A single `AuditRecorder` now serialises its own records. Taking the chain head, signing, advancing the head, and writing to the sink all happen inside one commit section, so no two records can claim the same `prev_hash` and write order always equals chain order. This holds for parallel tool calls in threads (LangGraph's `ToolNode` default under `create_agent`), for coroutines on one event loop, for both at once, and for a sink whose `write()` suspends. Covered by `tests/test_concurrency.py`, which drives a real `create_agent` with parallel tool calls against a real `LocalFileSink` and checks the result with the real verifier.

The previous text of this section described the defect that fix closes: 64 calls across 8 threads produced a chain break and 47 sink errors, and those sink errors propagated into the tool-call path and crashed the tools the recorder was supposed to be silently observing. Both halves are addressed — the chain no longer forks, and a sink failure can no longer crash the tool call, on any path.

**The remaining limit is cross-process, and it is real.** The guarantee is per-recorder, in-process. Two `AuditRecorder` instances writing the same `chain_id`, or two processes appending to the same log directory, are still **not** serialised against each other and will still fork the chain. The only cross-process serialisation in the library is the `flock` in the `agent-audit hook-record` subprocess, which covers the Claude Code hook path and nothing else. Do not point two agent processes at one audit directory.

### Silent evidence loss on un-representable values: Fixed

**Fixed (v0.2, schema v1.2).** A tool arg or output carrying a value RFC 8785
cannot canonicalize — an int `>= 2**53` (including the process-monotonic clock
after ~104 days of uptime), a `nan`/`inf`, `bytes`, a `set`, or a non-string dict
key — used to be lost silently: either canonicalization raised and the record was
dropped with no chain break (adapters swallow the recorder exception), or the
value was silently laundered before signing (`bytes` → a decoded str, `nan` →
`null`, a colliding non-string key destroying a sibling value) and signed as if
genuine. For a tool whose one claim is "no tool call is silently dropped," this
was the highest-severity defect.

Three changes close it, none touching `sig_form_version` (still `v1.0`):
`ts_monotonic_ns` is stored as a decimal string; a normalization pass replaces
each JCS-hostile scalar with a faithful, **announced** marker recording type +
hash (never a reconstructed value — see SIGNING.md §10 for what it cannot
recover); and the recorder now fails **loudly** — poisoning its chain head so a
still-un-canonicalizable record surfaces as a chain break, and raising a typed
`RecordSigningError` — instead of vanishing. Under-recording is now always
detectable.

### Redaction is best-effort, at the boundary — and the disabled state is now attested

**What it is (v0.2, schema v1.2).** A deny-list that redacts matched secrets/PII
in the values **and dict keys** the runtime hands the recorder, at the audit
boundary, before signing. It inspects keys (a dict keyed by a patient email no
longer leaks the email), applies the **most-restrictive** matching rule (a secret
co-occurring with an email is never hashed into the record), redacts
`Error.error_type` as well as messages, and ships conservative anchored rules for
SSN, credit-card (Luhn-anchored), phone, JWT, PEM private keys, DB-URLs with inline
passwords, and Stripe/Google keys, alongside the original email/cloud-token set.

**What it does NOT guarantee.** A deny-list denies only what it recognises — novel
formats, PII in free prose, or a secret split across fields will pass through, and
that is a known limit, not a bug to paper over. Rules are deliberately conservative
(a rule broad enough to eat legitimate tool output is its own failure); tune them
per domain. Redaction happens **at the audit boundary, not upstream**: a secret the
tool already wrote to disk or sent over the wire is out of scope — redaction keeps
it out of the *record*, nothing more.

**Numeric-form PII without a structural anchor is not caught — by design.** Every
value and key is scanned in the exact string form it takes in the signed bytes, so a
credit-card number passed as a JSON *number* is still redacted: the card rule has a
Luhn check that distinguishes it from an arbitrary integer. But an SSN or phone number
passed as a *bare integer* (`123456789`, `4155552671`, no delimiters) is **not**
redacted, because nothing distinguishes it from a database id, an order number, or a
count — and redacting every 9- or 10-digit integer would destroy the log's fidelity,
which is its own failure. The record honestly reflects that a plain number was passed;
it does not falsely attest redaction. Delimited forms (`123-45-6789`, `415-555-2671`)
are strings and *are* caught. If your tools emit identifier-shaped PII as bare numbers,
redact upstream or add a custom rule for your known formats. (Floats are likewise not
deny-scanned, as their JCS form differs from `str()`.)

**The disabled state is now honest.** Previously `RedactionConfig(disable=True)`
wrote everything in the clear while the manifest affirmatively attested
`redaction_disabled: false` — a disconnected flag. Now the recorder drives the
manifest's `redaction_state` (`unknown` | `enabled` | `disabled`) per record;
`disabled` **latches** and never downgrades. Crucially, **absence of an attestation
reads `unknown`, never `enabled`**: an old manifest, or the legacy
`redaction_disabled: false`, does not prove redaction was on. A tool also **cannot
forge** recorder-attested redaction: a per-record token (minted after the observed
tool ran, so unpredictable to it) plus a backing audit entry distinguish a genuine
marker from a tool-supplied look-alike (`redaction_authenticity()`).

### What `policy_unobserved` and lifecycle records CANNOT know (v0.2)

Two v0.2 primitives exist specifically to stop the library asserting things it never observed. Their honesty is defined as much by what they refuse to claim as by what they record.

**`policy_unobserved(NO_GATE_SIGNAL)` makes no risk claim, and no gate claim.** Every adapter used to stamp `ungated(AUTO_ALLOWED_LOW_RISK)` on every record — asserting both "no gate fired" and "low risk" at instrumentation points that observe neither. `UnobservedPolicy` asserts only that the gate status was **not observable**, and why. It **cannot** know: whether a gate fired upstream; the approver's identity; and — the field that was the actual fabrication — the **risk level**. Risk was never observable from a PostToolUse-style hook, so the primitive carries no risk field at all. An auditor reading `policy_unobserved` must read "we could not see the gate here", not "there was no gate" and never "this was safe".

**Lifecycle records' `attributes` are runtime-reported and UNATTESTED.** A `record_event` record (node.enter / node.exit / route) carries no tool, no policy, and no outcome, because a graph boundary is none of those. Its `attributes` bag — status, duration, declared risk, router name — is copied verbatim from the runtime. It is signed (tamper-evident) but **not attested**: the recorder did not measure the duration, verify the status, or evaluate the routing choice. A `route` record attests only the edge the router **claimed** it chose, never that the choice was correct. Read a lifecycle signature as "the runtime said this", never "this happened".

**The ~4,895 pre-existing fake-lifecycle records stay signature-valid but misrepresent the trail.** 81% of one real bosun project's chain recorded lifecycle events as tool calls, each carrying the fabricated policy. This change cannot rewrite frozen bytes; those records still verify. **Verification passing does not make a record truthful** — it proves the bytes are unaltered, not that the claim was ever true. Those records misstate both their type (event, not tool call) and their policy. Only records written through the v0.2 API are honest about it.

### NOT a liveness guarantee

The library proves that the records you have were not altered. It does **not** prove that the records you have are all the records there should be. A hook that is misconfigured, removed, or pointed at the wrong profile produces a perfectly valid, chain-intact log of everything it happened to see — and silence is indistinguishable from an agent that did nothing.

This is not hypothetical: it happened to the author's own dogfood deployment, which recorded 7,022 tool calls and zero failures for ten days (the failure hook was never registered), then stopped recording entirely for thirteen days without anyone noticing. Integrity without liveness is not evidence. The v0.2 verifier sidecar is what closes this.

### NOT a coverage of these AI controls (any version)

ai-agent-audit covers ONE control area: evidence of what tool calls an AI agent made, with integrity guarantees on that evidence.

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

If an auditor asks about any of these, the answer is not "we have ai-agent-audit." The answer is the specific tool or process that covers it. ai-agent-audit slots in alongside those — it doesn't replace them.

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
│ ★ ai-agent-audit                                      │  ← runtime evidence of agent tool calls
├───────────────────────────────────────────────────┤
│ MCP servers / LangGraph / Claude Agent SDK         │  ← the agents themselves
└───────────────────────────────────────────────────┘
```

ai-agent-audit produces the artifact other layers cite when an auditor asks **"prove what your AI agents actually did."**

## The honesty test

Before shipping the README, ask:

1. Could a SOC 2 auditor, after reading this README, conclude that ai-agent-audit alone makes a system SOC 2 compliant? **If yes, the README is wrong.**
2. Could a customer integrate ai-agent-audit and then claim EU AI Act Article 12 compliance? **If yes, the README is wrong.**
3. Could a customer use ai-agent-audit's logs as primary evidence in an external audit today (v0.1)? **If yes — only if they also have sidecar signer, S3 Object Lock, and external anchor running. v0.1 alone doesn't ship those. Say so.**

The right framing is: **"ai-agent-audit provides one component of the evidence pipeline. It is forward-compatible with regulatory-grade evidence; v0.1 is the foundation, v0.2 adds the production hardening."**
