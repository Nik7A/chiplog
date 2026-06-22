# SIGNING.md — ai-agent-audit canonical signing form

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

For v0.1 both are `"v1.0"`. Future major changes (`v2.0`) get new canonicalization rules in `agent_audit.canonical` and new schema models in `agent_audit.schema.v2`. Old records remain verifiable forever because their version string self-describes the rules.

---

## 10. Implementation notes

- Use `rfc8785>=0.1.4`. Pin it; this is the single foot-gun that produces "verifies locally but fails on the auditor's tool."
- Use `cryptography>=42.0`'s `Ed25519PrivateKey` / `Ed25519PublicKey` from `hazmat.primitives.asymmetric.ed25519`. Ed25519 was FIPS 186-5 approved in Feb 2023, so it's acceptable for SOC 2 / EU AI Act evidence.
- Always use `bytes` for hashing input. Never `str`. `signing_bytes` from `rfc8785.dumps()` is already bytes.
- Hex encoding is lowercase per RFC 4648 §8.
- Base64 encoding is standard (RFC 4648 §4), not URL-safe.
