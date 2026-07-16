# SIGNING.md — chiplog canonical signing form

_Version: v1.0. Status: stable for the v0.1 release._

This document specifies the exact byte-level rules for canonicalizing, hashing, signing, and chaining audit records. Any independent implementation that follows these rules will produce records that verify against any other compliant implementation. **The first artifact, not the last** — written before code, so the contract is unambiguous before any line of v1 code exists.

---

## 1. Record structure

Every record is a single JSON object with three top-level keys: `envelope`, `header`, `payload`.

```json
{
  "envelope": {
    "schema_version": "v1.0",
    "sig_form_version": "v1.0",
    "record_id": "01H...",
    "chain_id": "session-abc",
    "prev_hash": "<hex SHA-256 or null>",
    "hash": "<hex SHA-256>",
    "signature": "<base64 Ed25519>",
    "key_id": "<hex>"
  },
  "header": { ... },
  "payload": { ... }
}
```

`envelope.hash` and `envelope.signature` are **computed** fields. `envelope.prev_hash` references the previous record's chain link (definition in §4).

---

## 2. Canonicalization

All canonicalization is **RFC 8785 JCS** (JSON Canonicalization Scheme). Use the `rfc8785` library on PyPI (pure-Python, ~200 LOC, no transitive deps). **Do not roll your own** — naive `json.dumps(sort_keys=True, separators=(',', ':'))` is NOT JCS-compliant and will silently produce signatures that verify locally but fail under independent verification (Unicode NFC normalization, number serialization, escape rules).

Two canonical forms are used:

### 2.1 Signing form (`canonical_for_signing`)

The signing form is the canonicalized JSON bytes of the record with **two fields removed**:

- `envelope.hash`
- `envelope.signature`

Procedure:

1. Take the record object.
2. Construct a copy that has `envelope.hash` and `envelope.signature` **absent** (not `null` — absent).
3. Run `rfc8785.dumps(copy)` to produce the bytes.

### 2.2 Chain-link form (`canonical_for_chain_link`)

The chain-link form is the canonicalized JSON bytes of the **full record**, including `envelope.hash` and `envelope.signature` populated.

1. Take the fully-signed record (with hash and signature set).
2. Run `rfc8785.dumps(record)` to produce the bytes.

---

## 3. Hash and signature

### 3.1 Per-record hash

For each record:

1. Compute `signing_bytes = canonical_for_signing(record)` (per §2.1).
2. Compute `hash_bytes = SHA-256(signing_bytes)` (32 bytes).
3. Set `envelope.hash = hex(hash_bytes)` (64 lowercase hex chars).

### 3.2 Signature

For each record:

1. Sign `hash_bytes` with the Ed25519 private key:
   `signature_bytes = Ed25519_sign(private_key, hash_bytes)` (64 bytes).
2. Set `envelope.signature = base64(signature_bytes)` (88 chars including padding, standard b64).

### 3.3 Why `signature = Ed25519(hash)` and not `Ed25519(canonical_bytes)`

Ed25519 internally hashes its input with SHA-512 anyway. Signing the SHA-256 hash directly:

- Decouples the chain hash function (SHA-256) from Ed25519's internal hashing.
- Makes the signed primitive a fixed 32 bytes, which simplifies tooling and removes a class of "did I sign the right canonical form" bugs.
- Lets verifiers re-compute the hash from the record once and use that one value for both integrity check and signature check.

---

## 4. Chain link

`envelope.prev_hash` references the previous record's **full chain-link form** (per §2.2), not the previous record's `hash` field.

For record N with prior record N−1:

```
prev_hash_N = SHA-256( canonical_for_chain_link(record_N-1) )
```

Note that `record_N-1` is the prior record **after** its hash and signature were set. This means:

- Tampering with `record_N-1.signature` changes its chain-link form, which changes `prev_hash_N`, which breaks the chain.
- A skeptical verifier can independently recompute `prev_hash_N` from the on-disk `record_N-1` and check it matches what record_N claims.

For the first record in a chain (genesis), `prev_hash` is the JSON value `null`.

`envelope.chain_id` is a string that scopes the chain. Default: the originating session id. A new `chain_id` starts a new genesis record.

---

## 5. key_id

`envelope.key_id` is the first 16 hex characters of `SHA-256(public_key_bytes)`, where `public_key_bytes` is the Ed25519 public key in raw 32-byte form.

This lets verifiers select the correct public key when verifying a log that spans multiple signing keys (e.g., key rotation across days). The `key_id` does NOT need to be globally unique across the world — only within the set of pubkeys a given verifier has been given.

---

## 6. Record verification (auditor procedure)

Given a record and a public key whose `key_id` matches `envelope.key_id`:

1. Construct `signing_form` (per §2.1).
2. Compute `expected_hash = hex(SHA-256(signing_form))`.
3. Assert `expected_hash == envelope.hash`. If not → record tampered with after signing.
4. Compute `signature_bytes = base64_decode(envelope.signature)`.
5. Verify `Ed25519_verify(public_key, expected_hash_bytes, signature_bytes)`. If invalid → signature forged or wrong key.

If both checks pass, the record is **integrity-verified**.

---

## 7. Chain verification (auditor procedure)

Given a sequence of records `R0, R1, R2, ...`:

1. Verify each record individually (per §6).
2. Verify `R0.envelope.prev_hash == null`.
3. For each `i ≥ 1`:
   - Compute `chain_link_bytes_i_minus_1 = canonical_for_chain_link(R_{i-1})`.
   - Compute `expected_prev = hex(SHA-256(chain_link_bytes_i_minus_1))`.
   - Assert `expected_prev == R_i.envelope.prev_hash`. If not → record removed, reordered, or its signature tampered.

If all checks pass, the chain is **integrity-verified** and **continuity-verified within the present log**.

### 7.1 What chain verification does NOT prove

This is the v0.1 NON-CLAIMS block, repeated in every verifier report:

- It does **not** prove that records were not deleted from the head (tail) of the chain. A single forward-only hash chain detects in-the-middle removal but not unattested truncation at the end. v0.2 closes this with external anchor.
- It does **not** prove that the signing key was not compromised. A holder of the private key can produce a valid alternative log. v0.2 closes this with the sidecar signer (key out of the agent's trust boundary).
- It does **not** prove that the wall clock (`ts_utc`) was correct. The `ts_source` field declares the trust level (`system` / `ntp` / `tsa`); v0.2 adds RFC 3161 TSA timestamps for true time anchoring.

Note what chain verification also does not prove: that `outcome` is **true**. The signature attests that the recorder wrote that outcome; it says nothing about whether the recorder was right. Outcome honesty is not a cryptographic property — it is a property of the adapters, and it is governed by the invariant in section 7.2.

---

## 7.2 Outcome honesty (normative — binding on every adapter)

The `outcome` field is the one an auditor acts on. A signature over a false outcome is worse than no record at all: it converts an unknown into cryptographically attested false evidence. This section states the rule every adapter MUST follow.

### The invariant

> **Control flow is not an outcome.**
>
> That a call **returned** is not evidence that it succeeded.
> That a call **raised** is not evidence that it failed.
>
> An outcome MUST be derived only from a signal the runtime **designates** as an outcome signal — a status field, an error flag, a dedicated failure event, an exit code. Never from the shape of the control flow that delivered it.

### Rules

1. **Never infer an outcome the runtime did not report.** No sniffing error strings out of a payload; no comparing a duration against a timeout to synthesize `timeout`. Read structural fields the runtime sets (`ToolMessage.status`, `is_error`, `backgroundTaskId`, `interrupted`, `hook_event_name`), not prose.
2. **When the runtime cannot tell you the outcome, say so.** Record `unobserved(reason)`. Never a guessed `success`.
3. **A false failure is exactly as dishonest as a false success.** A legitimate success MUST keep recording `success`; a control-flow signal MUST NOT be recorded as `error`.
4. **Never fabricate a Python exception type.** When the runtime hands over a message rather than an exception, `error_type` is `"ToolFailure"` (or `"Interrupt"`), not an invented class name.
5. **Shared payload semantics live in a shared module** (`adapters/_claude_hooks.py`), so two adapters onto the same runtime cannot drift. They have drifted before.

### Why this section exists

Six times, an adapter signed a false outcome by reading control flow as an outcome — five times signing `success` over a failure the runtime **returned** (LangGraph's `ToolNode` returns `ToolMessage(status="error")` rather than raising; the OpenAI Agents SDK converts tool exceptions to ordinary strings; Claude Code backgrounds a timed-out `Bash` call and reports it on the success hook), and once signing `error` over a **raised** LangGraph `GraphBubbleUp`, which is a human-in-the-loop control-flow signal for a tool that then re-runs and succeeds.

Each of those was found by reading the runtime's own source, and missed by reading the adapter. **Enumerate the runtime's failure-reporting mechanisms from its source before you add or change an adapter's outcome logic.** `tests/test_outcome_honesty_matrix.py` holds that enumeration, per runtime, as an executable table; extend it rather than working around it.

---

## 7.3 Policy honesty — `policy_unobserved` (normative)

`policy` is a positive assertion, exactly like `outcome`. The three variants say three different things, and an adapter MUST pick the one that matches what it actually observed:

- **`Gate{...}`** — a policy engine evaluated this call and the adapter observed its decision, approver, and timing. Assert this only when a gate genuinely fired and the adapter saw it. One such gate is observable from a hook: **Claude Code's interactive permission prompt**. When a user denies a call there, the tool never runs, and the adapter records `gate("claude_code:permission_denied", decision="deny")` paired with `outcome=denied("claude_code:permission_denied")` (§7.4).
- **`Ungated{reason}`** — the adapter observed that **no** gate fired, and records why. This is still a positive claim about the gate mechanism.
- **`UnobservedPolicy{reason}`** — the adapter **could not observe** the gate status at all. It asserts strictly less than `Ungated`: not that a gate did or did not fire, and — critically — **nothing about risk**.

### The rule

> **An adapter that does not observe the gate mechanism MUST record `policy_unobserved`, never `ungated`.**

Every adapter previously hardcoded `ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK)` on every record. That asserted two things at once — "no gate fired" **and** "this call was low risk" — over instrumentation points (PostToolUse-style hooks, LangGraph tool wrappers, OpenAI/Claude SDK hooks) that observe **neither**. The hook payloads carry a session id, a permission *mode*, and tool info; they carry no per-call gate decision and no risk score. `low_risk` was never observable, which is precisely why it was a fabrication. `UnobservedPolicy` carries **no risk field**: it cannot re-acquire that lie.

`Ungated` and `NoGateReason.AUTO_ALLOWED_LOW_RISK` remain in the schema and remain valid on the wire — 19,037 + ~5,300 signed records embed them and must keep verifying — but no adapter in this repo asserts them, and a real policy engine is the only thing that legitimately may.

## 7.4 Denial honesty — user rejection → `Gate(DENY)` + `denied` (normative)

A user pressing "no" at Claude Code's permission prompt is a real gate decision, not a tool fault. The CLI reports it on `PostToolUseFailure` with `is_interrupt: true` and an `error` string, and the naive recording — `error(error_type="Interrupt")` — asserts the tool ran and faulted. It did not: a human denied it, and `outcome=denied` was structurally unreachable because no adapter built a `Gate`.

Both Claude adapters now route a detected denial to `policy = gate("claude_code:permission_denied", decision="deny")` + `outcome = denied("claude_code:permission_denied")` (same `policy_id`, so `Payload._outcome_agrees_with_policy` is satisfied) + `output.body = null`.

### The rule

> **A denial MUST be detected by an anchored sentinel on the runtime's `error` string that observes the gate mechanism — never by `is_interrupt`.**

`is_interrupt` is `true` for a genuine mid-run interrupt as well as a denial (the CLI groups both internally), so keying off it conflates "the tool never ran" with "the tool ran and was cut short". The anchored discriminator is the exact rejection **lead-sentence** the CLI emits — `"The user doesn't want to proceed with this tool use."` or `"Permission for this tool use was denied."` — matched as a prefix on the stripped `error`. Probed verbatim from **Claude Code CLI 2.1.207** and pinned by a CI test, so a future CLI reword fails loud rather than silently falling back to `error`. The rule lives once in `adapters/_claude_hooks` and is shared by both Claude adapters, so they cannot drift.

### What the recorder CANNOT know (recorded honestly, never fabricated)

- **Approver identity** — the payload carries no human identity → `Gate.approver = null`.
- **Gate-evaluation timing** — none is reported → `Gate.evaluation_ms = null`.
- **A programmatic / settings deny is unobservable at this point.** On 2.1.207 it fires `PreToolUse` / `PermissionDenied` only and never reaches `PostToolUse`/`PostToolUseFailure`; the recorded denial is therefore only ever the *interactive* one.
- **A mid-run interrupt fires no hook at all** — the coverage blind spot (§ README); it is not a denial and is never recorded as one.

Adding these fields bumps nothing in the canonical form: `denied` and `Gate` already exist in the v1.0 signing form, `sig_form_version` stays `v1.0`, and every prior signed record verifies unchanged.

---

## 7.4 Lifecycle events are not tool calls (normative)

A node boundary or a routing decision is **not a tool call**. It has no tool, no policy, and no outcome, and forcing it into the tool-call schema fabricates all three. The `LifecycleEventPayload` record type (emitted by `recorder.record_event(...)`, sync twin `record_event_sync`) expresses it honestly:

- **No `tool`, no `policy`, no `outcome`** — a lifecycle record omits these fields entirely. It is a distinct payload shape carrying `phase` (`node_enter` / `node_exit` / `route`), a per-phase `transition`, and an `attributes` bag.
- **The `transition` is honest per phase.** `node_enter` / `node_exit` carry a `NodeTransition{node}` — the node id, which the instrumentation genuinely observes because it wraps a named node, with **no** invented from/to pair. `route` carries a `RouteTransition{chosen}` — only the router-**claimed** chosen edge/skill, with **no** node id; the recorder did not evaluate the routing logic and attests only that this is the edge the router named.
- **`attributes` is runtime-reported and UNATTESTED.** Status, duration, declared risk, router name — whatever the runtime hands over — are copied verbatim into `attributes`. They are **signed** (tamper-evident) but **not attested**: read the signature as "the runtime said this", never as "this happened". In particular a `risk` value here is the skill's self-declared risk, **not** a gate decision and **not** a risk attestation.

A lifecycle record shares the envelope, header, chain, and canonical form (`sig_form_version` v1.0) with a tool-call record — the verifier reads raw dicts and never validates payload shape, so both sign and verify through the identical crypto path. Its `attributes` bag goes through the same redaction and JCS-normalization as tool input/output, inside the same construction guard, so a secret is redacted and a JCS-hostile value becomes an announced marker rather than vanishing.

**The pre-existing fake-lifecycle records stay signature-valid but misrepresent the trail.** ~4,895 real bosun records (81% of one project's chain) recorded `node.enter` / `node.exit` / `route` as tool calls, each carrying the fabricated `ungated(AUTO_ALLOWED_LOW_RISK)` policy. This change does not and cannot rewrite them: their bytes are frozen and they still verify. **Verification passing does not make them truthful** — they misstate both the record type and the policy. Only records written through `record_event` from here on are honest about being lifecycle events.

---

## 7.5 Directory verification (normative — the v0.2 verifier contract)

A real trail is not one file signed by one key. A logical chain spans many daily
`audit-YYYY-MM-DD.jsonl` files (a chain started before UTC midnight keeps its
`chain_id` and continues into the next day's file), signing keys rotate
mid-chain, and the authority on *which* records form the canonical chain is the
sidecar `manifest.json`, **not** the tool. `chiplog verify <DIR>` handles
this; `chiplog verify <FILE> --pubkey P` remains the unchanged single-file,
sequential, log-only contract of §7.

**File ordering.** Files are walked in lexical filename order, which for
`audit-YYYY-MM-DD.jsonl` is chronological (= write) order. Records are grouped by
`chain_id`, preserving cross-file emission order.

**Key resolution.** The verifier pools keys from `--pubkey` PEM files and from
`manifest.pubkey_pem`. Every key id is **DERIVED from the key material** via
`load_public_key`. The manifest's `pubkey_id` field is **never** trusted as a
key identity — it is only compared against the id derived from the stored PEM,
and a disagreement (`manifest.pubkey_id != keyid(manifest.pubkey_pem)`) is
reported as `manifest_pubkey_id_mismatch`. (Real evento data ships this exact
staleness: the sink stamps `pubkey_id` from the first record's key and never
updates it, while `pubkey_pem` is overwritten on key rotation.)

**Canonical path = the manifest's CLAIM.** For each chain the manifest attests a
`genesis_hash`, a `head_hash`, and a `record_count`. The canonical chain is the
unique lineage ending at `head_hash` and walking `prev_hash` pointers back to a
null-prev genesis. Records not on that lineage are **off-canonical**. The
verifier reports their existence as a **fact** and never guesses the cause:
deletion, a concurrent writer, an abandoned retry, and corruption are all
indistinguishable from the log, so the finding is labelled
`off-canonical-path (reason not observable)`.

**Missing keys are an honest PARTIAL.** A record whose `key_id` resolves to no
available key is *unverifiable*, not *failed*. The verdict is
"N of M attested records verified under available keys; K unverifiable (no key)".
PARTIAL requires at least one record to have actually verified; if nothing
verified, the outcome is the KEY_RESOLUTION family, never PARTIAL.

**Manifest absent or corrupt** degrades to log-only verification with an
explicit "manifest cross-check skipped" note (a clean result is labelled
`LOG-ONLY PASS`, and whole-chain deletion is undetectable in that mode). It
never crashes and never treats a missing manifest as a silent pass. This
log-only pass still returns **exit 0** — the same code as a full
manifest-anchored pass — so exit code alone cannot tell them apart. A CI that
requires full-anchor assurance MUST additionally assert `manifest_present ==
true` (JSON) or reject the `LOG-ONLY PASS` verdict (text); in log-only mode
tail- and whole-chain deletion are undetectable.

### Exit codes

Codes 0–5 are the frozen single-file API and keep their exact meanings. Codes
6–9 are new and only arise in directory mode, so no existing contract moves.

| code | name | meaning |
|------|------|---------|
| 0 | ok | every attested record verified and chains to the manifest head |
| 1 | chain_break | in-log discontinuity, **whole-chain deletion**, front-truncation, or a canonical head unreachable from the logs |
| 2 | signature_fail | a record's hash or Ed25519 signature did not verify under a key we hold (tamper) |
| 3 | key_resolution | no attested record could be verified — every key is missing/unloadable |
| 4 | malformed_jsonl | a line would not parse / a record has no envelope |
| 5 | empty | no records at all |
| 6 | partial | ≥1 attested record verified, ≥1 unverifiable for want of a key |
| 7 | off_canonical | ≥1 record is off the manifest-attested canonical path (non-zero **by design** — an auditor must never read exit 0 over a log with records that don't chain) |
| 8 | manifest_pubkey_mismatch | `manifest.pubkey_id` is stale versus the PEM it stores |
| 9 | manifest_integrity | the log disagrees with its own manifest anchor: the per-chain `record_count`, or a per-file `sha256` / `record_count`. Injecting/duplicating a record, or a lie in the manifest count, lands here. Non-zero **by design** — the `record_count` attestation is what makes directory mode stronger than a bare chain, and it must have teeth |

When several conditions hold at once (real evento data trips 6, 7, and 8
simultaneously), the exit code is the single most integrity-critical one, by the
documented precedence `2 > 1 > 9 > 4 > 7 > 8 > 6 > 3 > 5 > 0`. A manifest-integrity
break slots just under `chain_break`: like a chain break it is a hard
disagreement with the anchor, not a soft "records exist but don't chain" signal.
The full report always enumerates **every** finding regardless of which one drove
the exit code.

### Verdicts and their evidence

Every verdict is a fact the verifier can back:

- **verified** — the record's `envelope.hash` recomputes and its signature
  verifies under a pooled key (§6).
- **unverifiable (no key)** — `envelope.key_id` matches no available key; the
  record is neither passed nor failed.
- **off-canonical-path (reason not observable)** — the record's chain-link is
  not on the lineage from the manifest genesis to the manifest head. Canonicity
  is attributed to the manifest's claim, never to the tool's judgement.
- **whole-chain-missing** — the manifest attests a chain whose records are
  wholly absent from the logs (reason not observable — deletion, a removed file,
  a never-written chain, or a mislocated log are indistinguishable here).
- **front-truncation** — walking back from the attested head reaches a record
  whose `prev_hash` names a chain-link no record in the logs carries.
- **manifest_pubkey_id_mismatch** — the derived key id disagrees with the
  claimed one; verification still used the *derived* key.
- **count_mismatch** — the reconstructed canonical length disagrees with the
  chain's `manifest.record_count`; the fact (attested vs reconstructed) is
  reported, non-zero (exit 9), the cause is not guessed.
- **file_sha256_mismatch / file_record_count_mismatch / attested_file_missing**
  — a daily file's actual bytes/line-count disagree with the manifest's per-file
  `files[]` attestation, or an attested file is absent. Non-zero (exit 9); a
  file's bytes changing after the manifest was written is an integrity break.

---

## 8. Worked test vector

This is the canonical example. Two independent implementations of the rules above must produce **byte-identical** signing forms, chain-link forms, hash values, and (given the same private key) signature bytes.

### 8.1 Inputs

```python
# Ed25519 private key (raw 32 bytes, hex)
private_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
# corresponding raw public key (32 bytes, hex)
public_key_hex  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
# derived key_id = first 16 hex of SHA-256(public_key_bytes)
key_id = "<computed: see §5>"
```

### 8.2 Record (pre-sign — note `hash` and `signature` are absent)

```json
{
  "envelope": {
    "chain_id": "test-chain-001",
    "key_id": "<from §5>",
    "prev_hash": null,
    "record_id": "01H4MJ0QH0V8VYG09T9YV9TQNN",
    "schema_version": "v1.0",
    "sig_form_version": "v1.0"
  },
  "header": {
    "agent_name": "test-agent",
    "model": "claude-opus-4-7",
    "session_id": "sess-001",
    "step_id": "step-001"
  },
  "payload": {
    "input": {"file_path": "/etc/hosts"},
    "output": {
      "body": "127.0.0.1 localhost\n",
      "truncated": false
    },
    "policy": {
      "kind": "none",
      "reason": "auto_allowed_low_risk"
    },
    "redaction": [],
    "time": {
      "ts_monotonic_ns": 1000,
      "ts_source": "system",
      "ts_utc": "2026-06-19T20:00:00.000000000Z"
    },
    "tool": {
      "mcp": null,
      "name": "Read"
    }
  }
}
```

### 8.3 Expected outputs

Two implementations following §2 + §3 must compute the same `signing_bytes`, `hash`, and `signature`. The exact bytes are determined by the rules and will be filled in by the test runner once `tests/test_signing_vectors.py` runs (v0.1 includes that test, and the test file's expected values are the canonical fixture).

A test failure here means the canonical form drifted — usually one of:

- `rfc8785` library bug (rare — pin to `>=0.1.4`).
- The `hash` or `signature` field was not absent during signing-form canonicalization (forgot to `pop` them).
- Number normalization (don't pass `Decimal` or numpy floats — convert to native int/float first).
- Unicode normalization on string values not yet in NFC.

---

## 9. Versioning

`schema_version` and `sig_form_version` are independent semver strings stored in each record's envelope. Verifiers MUST dispatch on `sig_form_version` for canonicalization rules, schema_version for field interpretation.

For v0.1 both are `"v1.0"`. Future major changes (`v2.0`) get new canonicalization rules in `chiplog.canonical` and new schema models in `chiplog.schema.v2`. Old records remain verifiable forever because their version string self-describes the rules.

### 9.1 Schema evolution and backward verifiability

**Verification never validates a record against the Pydantic model.** `verify_log`,
`verify_record`, `canonical_for_signing`, and `cli inspect` all operate on raw
dicts, canonicalizing whatever keys are present. The signature covers canonical
bytes, not schema shape.

This is what makes schema evolution safe: a record signed under `schema_version`
v1.0 remains verifiable after v1.1 adds a field, with no dispatch logic, no
second model, and no migration framework — provided `sig_form_version` is
unchanged.

Adding `Record.model_validate` (or any Pydantic parse) to the read path would
silently break verifiability of every record written before the change. Do not
do it. `tests/test_schema_version_compat.py` pins a frozen, genuinely-signed
v1.0 record and fails loudly if this is ever violated.

Changes that DO require a `sig_form_version` bump are changes to the
canonicalization rules themselves — JCS options, the field-exclusion set for
`canonical_for_signing`, or the chain-link byte form. Adding or removing schema
fields does not.

---

## 10. Un-representable values and the no-silent-loss guarantee (schema v1.2)

`sig_form_version` is **unchanged at v1.0** — the canonicalization rules in §2 did
not change. What follows is a schema-level addition (`schema_version` v1.2) that
closes a silent-evidence-loss class. Because the verifier reads raw dicts (§9.1),
records written before v1.2 remain byte-for-byte verifiable.

### 10.1 `ts_monotonic_ns` is a decimal string

JCS serializes numbers as IEEE-754 doubles, so an integer with `abs(value) >= 2**53`
is refused (`rfc8785` raises `IntegerDomainError`). A raw process-monotonic ns
count crosses `2**53` after ~104 days of host uptime — at which point **every**
record became un-signable and, because adapters swallow the recorder exception,
was silently dropped with no chain break.

From v1.2, `ts_monotonic_ns` is stored as a **decimal string** (`"1712345678901234"`),
which carries full ns precision and is outside the float-safe-integer domain
forever. A pre-v1.2 record stored it as an int; that record's signed bytes are
unchanged and it still verifies. The model accepts both forms on input (int is
stringified); the verifier never re-serializes it.

### 10.2 The `unrepresentable` marker

A tool arg or output is arbitrary caller/runtime data and can carry a value JCS
cannot represent: an int `>= 2**53`, a `nan`/`inf`, `bytes`, a `set`, or a
non-string dict key. Left raw, some of these **raise** (silent drop, no chain
break) and others are **silently laundered** by `model_dump` before signing
(`bytes` → a decoded str, `nan` → `null`, `set` → list, and `{None: 'a', 'None':
'b'}` → `{'None': 'b'}` with one value destroyed) — then signed as if genuine.

A normalization pass (`chiplog.normalize`) runs **after redaction** on the
three free-form fields (`input`, `output.body`, `outcome.message`) and replaces
each JCS-hostile scalar with a self-describing marker:

```json
{"__chiplog__": "unrepresentable", "reason": "integer_out_of_jcs_domain",
 "py_type": "int", "sha256": "<hex sha256(repr(value))>"}
```

Every substitution is announced in a new `payload.unrepresentable` list
(`{path, reason, py_type, sha256}`), default empty. `reason` is one of
`integer_out_of_jcs_domain`, `float_not_finite` (nan **and** inf),
`unsupported_type` (bytes/set/other), `non_string_dict_key`.

**What the marker CANNOT recover — stated plainly.** It records TYPE + HASH only,
never a reconstructed value. The original magnitude of an out-of-domain int, or
the bytes behind a `bytes`, is **not recoverable** in a JCS-signable form. The
marker proves the value existed and distinguishes two different values by their
hash; it does not tell you what the value was. That is the honest floor: a value
JCS cannot sign cannot be attested, and inventing a stand-in would be the exact
fabrication this project refuses.

### 10.3 No silent loss — the loud-failure floor

Normalization handles the enumerated kinds, but **canonicalization can still
raise** on something it does not cover (a str with an unpaired UTF-16 surrogate
cannot be UTF-8 encoded, and `model_dump` does not launder it). This is **not**
claimed to be impossible. Instead the recorder guarantees the failure is never
silent: on a signing failure it (a) **poisons its chain head** so the next record
breaks the chain at verification time, and (b) raises a typed `RecordSigningError`
the caller can see. A dropped record therefore always leaves a trace an auditor
or operator can detect — the guarantee the product's one claim rests on.

---

## 11. Implementation notes

- Use `rfc8785>=0.1.4`. Pin it; this is the single foot-gun that produces "verifies locally but fails on the auditor's tool."
- Use `cryptography>=42.0`'s `Ed25519PrivateKey` / `Ed25519PublicKey` from `hazmat.primitives.asymmetric.ed25519`. Ed25519 was FIPS 186-5 approved in Feb 2023, so it's acceptable for SOC 2 / EU AI Act evidence.
- Always use `bytes` for hashing input. Never `str`. `signing_bytes` from `rfc8785.dumps()` is already bytes.
- Hex encoding is lowercase per RFC 4648 §8.
- Base64 encoding is standard (RFC 4648 §4), not URL-safe.

## 12. Redaction contract (schema v1.2 — normative)

Redaction is a **best-effort deny-list applied at the audit boundary**, on the
values (and dict keys) the runtime hands the recorder. It runs inside the
construction guard, **before** JCS normalization, so a redacted marker is never
re-inspected as a raw value. None of it changes the canonical form:
`sig_form_version` stays `v1.0`, and every field below is additive — a pre-v1.2
record simply omits it and canonicalizes exactly as before.

### 12.1 What redaction DOES guarantee

- **Whole-value replacement.** If any rule matches anywhere in a string, the
  entire value becomes a marker `{redacted: true, type, length, policy, sha256?,
  token?}`. Precision is sacrificed to avoid leaking the un-matched remainder.
- **Dict KEYS are inspected, not just values.** A dict keyed by PII (a patient
  email) has its key replaced with an unforgeable sentinel
  (`__chiplog_redacted_key__::<token>::<policy>`); the key material never
  reaches the signed bytes.
- **Most-restrictive rule wins.** When several rules match one value, a
  `strip_hash=True` rule always beats a hashing rule. So a secret co-occurring
  with an email is never hashed into the record via the email rule's `sha256`
  (that hash covers the whole value, secret included). `strip_hash` markers omit
  `sha256` entirely.
- **`Error.error_type` is redacted** (widened to `Any`; old records keep their
  `str` and canonicalize unchanged). A runtime that stuffs PII into the "type"
  gets no bypass. Normal class names (`ConnectionError`) stay plain strings.
- **Anti-forgery — a tool cannot forge recorder-attested redaction.** The
  recorder mints a fresh, unpredictable `payload.redaction_token` per `record()`
  call, **after** the observed tool already ran, and stamps it into every genuine
  marker and sentinel key. `redact.redaction_authenticity(record)` reconciles
  every marker-shaped value found in the data against (a) that token and (b) a
  backing `RedactionEntry` at its path. A tool look-alike carries neither the
  token (it could not predict a value minted after it ran) nor a backing entry,
  so it is reported as forged. A genuine marker validates. The token is null when
  redaction is disabled and absent on pre-v1.2 records; a reader with no token
  degrades to structural reconciliation only, and must not read a tokenless
  marker as cryptographically attested.
- **The disabled state is attested honestly and monotonically.** The recorder —
  not a disconnected constructor flag — drives the sink's manifest
  `redaction_state` (`unknown` | `enabled` | `disabled`) on every record.
  `disabled` **latches**: once any record is written with redaction off, no later
  enabled recorder downgrades it. This was the leak — `disable=True` wrote
  cleartext while the manifest affirmatively attested `redaction_disabled:
  false`.

### 12.2 What redaction does NOT guarantee

- **It is not a classifier.** A deny-list denies only what its rules recognise.
  Novel secret formats, PII in free prose, or a value split across fields will
  pass through. Rules are conservative on purpose (a rule broad enough to eat
  legitimate output is its own failure) — tune `RedactionConfig(rules=...)` per
  domain. See SCOPE_STATEMENT.md.
- **It happens at the audit boundary, not upstream.** A secret the tool already
  wrote to disk, logged, or sent over the wire is outside this layer. Redaction
  keeps the secret out of the *audit record*; it does not un-leak it elsewhere.
- **`redaction_state: unknown` is not `enabled`.** Absence of an attestation
  (any pre-v1.2 manifest, or the old hardcoded `redaction_disabled: false`) reads
  **unknown**. A reader (inspect/report, verifier) must never render it as
  "redaction was on."
