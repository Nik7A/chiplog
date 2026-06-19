"""Pure crypto operations for audit records.

No I/O here — file I/O lives in sinks/, key loading in keys.py. This module is
purely about the bytes: build the canonical form, hash it, sign it, verify it.

The split exists so that:
- Sign and verify paths can run in totally different processes (the verifier
  doesn't need to know how the agent emits records).
- These pure functions can be property-tested (Step 1's canonical foundation
  combined with Step 2's primitives covers the crypto correctness surface).
"""

from __future__ import annotations

import base64
import hashlib
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agent_audit.canonical import canonical_for_chain_link, canonical_for_signing


# ---------------------------------------------------------------------------
# Hash + chain link
# ---------------------------------------------------------------------------


def compute_record_hash(record: Any) -> str:
    """Compute the SHA-256 hex of canonical_for_signing(record).

    This is the value that goes in envelope.hash and that the signature signs.
    See SIGNING.md §3.1.
    """
    signing_bytes = canonical_for_signing(record)
    return hashlib.sha256(signing_bytes).hexdigest()


def compute_chain_link(record: Any) -> str:
    """Compute the SHA-256 hex of canonical_for_chain_link(record).

    This is the value the NEXT record's prev_hash must equal. The record must
    be fully signed (envelope.hash + envelope.signature populated).
    See SIGNING.md §4.
    """
    link_bytes = canonical_for_chain_link(record)
    return hashlib.sha256(link_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


def sign_record(
    record: Any, signing_key: Ed25519PrivateKey, key_id: str
) -> dict[str, Any]:
    """Return a NEW record dict with envelope.hash, envelope.signature, and
    envelope.key_id populated. Does NOT mutate the input.

    Procedure (per SIGNING.md §3):
      1. Set envelope.key_id (it's covered by the signing form).
      2. Strip envelope.hash + envelope.signature if present.
      3. hash_hex = SHA-256(canonical_for_signing(record)).
      4. sig_bytes = Ed25519_sign(signing_key, bytes.fromhex(hash_hex)).
      5. envelope.signature = base64(sig_bytes).
    """
    if hasattr(record, "model_dump"):
        raw: dict[str, Any] = record.model_dump(mode="json")
    elif isinstance(record, dict):
        raw = deepcopy(record)
    else:
        raise TypeError(
            f"record must be Pydantic Record or dict, got {type(record).__name__}"
        )

    env = raw.setdefault("envelope", {})
    if not isinstance(env, dict):
        raise TypeError("record.envelope must be a dict")

    env["key_id"] = key_id
    env.pop("hash", None)
    env.pop("signature", None)

    hash_hex = compute_record_hash(raw)
    env["hash"] = hash_hex

    signature_bytes = signing_key.sign(bytes.fromhex(hash_hex))
    env["signature"] = base64.b64encode(signature_bytes).decode("ascii")

    return raw


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


class VerificationFailure(str, Enum):
    HASH_MISMATCH = "hash_mismatch"
    SIGNATURE_INVALID = "signature_invalid"
    UNKNOWN_KEY_ID = "unknown_key_id"
    MALFORMED_RECORD = "malformed_record"


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a single record (without chain context)."""

    is_valid: bool
    failure: VerificationFailure | None = None
    detail: str | None = None


def _malformed(detail: str) -> VerificationResult:
    return VerificationResult(
        is_valid=False, failure=VerificationFailure.MALFORMED_RECORD, detail=detail
    )


def verify_record(
    record: Any, pubkey_by_id: dict[str, Ed25519PublicKey]
) -> VerificationResult:
    """Verify a single record's integrity (hash + signature).

    Does NOT check prev_hash against an actual prior record — that's the
    chain check's job (lives in verify.py / Step 5). This only confirms:
      1. envelope.hash matches SHA-256(canonical_for_signing(record))
      2. envelope.signature is a valid Ed25519 sig over envelope.hash bytes
         using the pubkey identified by envelope.key_id

    See SIGNING.md §6.
    """
    if hasattr(record, "model_dump"):
        raw: dict[str, Any] = record.model_dump(mode="json")
    elif isinstance(record, dict):
        raw = record
    else:
        return _malformed(
            f"record must be Pydantic Record or dict, got {type(record).__name__}"
        )

    env = raw.get("envelope")
    if not isinstance(env, dict):
        return _malformed("missing or non-dict envelope")

    claimed_hash = env.get("hash")
    claimed_sig_b64 = env.get("signature")
    key_id = env.get("key_id")

    if not isinstance(claimed_hash, str):
        return _malformed("envelope.hash missing or not a string")
    if not isinstance(claimed_sig_b64, str):
        return _malformed("envelope.signature missing or not a string")
    if not isinstance(key_id, str):
        return _malformed("envelope.key_id missing or not a string")

    try:
        expected_hash = compute_record_hash(raw)
    except Exception as e:  # noqa: BLE001 — surface as malformed, not crash
        return _malformed(f"canonicalization failed: {e}")

    if expected_hash != claimed_hash:
        return VerificationResult(
            is_valid=False,
            failure=VerificationFailure.HASH_MISMATCH,
            detail=f"expected {expected_hash}, got {claimed_hash}",
        )

    public_key = pubkey_by_id.get(key_id)
    if public_key is None:
        return VerificationResult(
            is_valid=False,
            failure=VerificationFailure.UNKNOWN_KEY_ID,
            detail=f"no public key for key_id={key_id}",
        )

    try:
        signature_bytes = base64.b64decode(claimed_sig_b64, validate=True)
    except Exception as e:  # noqa: BLE001
        return _malformed(f"signature not valid base64: {e}")

    if len(signature_bytes) != 64:
        return _malformed(
            f"Ed25519 signature must be 64 bytes, got {len(signature_bytes)}"
        )

    try:
        public_key.verify(signature_bytes, bytes.fromhex(expected_hash))
    except InvalidSignature:
        return VerificationResult(
            is_valid=False,
            failure=VerificationFailure.SIGNATURE_INVALID,
            detail="Ed25519 signature does not verify under provided pubkey",
        )

    return VerificationResult(is_valid=True)


__all__ = [
    "VerificationFailure",
    "VerificationResult",
    "compute_chain_link",
    "compute_record_hash",
    "sign_record",
    "verify_record",
]
