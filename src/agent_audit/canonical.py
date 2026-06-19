"""Canonical JSON for hashing and signing.

Two canonical forms are produced, both via RFC 8785 JCS through the `rfc8785`
library. See SIGNING.md §2 for the exact contract.

- `canonical_for_signing(record)` — bytes of record with envelope.hash and
  envelope.signature ABSENT (not null — absent). Used as the SHA-256 input
  that produces the record's hash field. The signature signs that hash.

- `canonical_for_chain_link(record)` — bytes of the fully-populated record
  including envelope.hash and envelope.signature. SHA-256 of this is what
  the NEXT record's prev_hash must equal.

The split exists because the chain link must cover the previous record's
signature so that signature tampering breaks the chain at the next record.
This is the exact foot-gun §10 of SIGNING.md warns about: produce signatures
that verify locally but fail under independent verification.

Verifier dispatch on envelope.sig_form_version is centralized here so that
v2 records (future) can use different canonicalization rules without
invalidating v1 chains.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import rfc8785

from agent_audit.schema.v1 import SIG_FORM_VERSION as V1_SIG_FORM_VERSION


def _record_as_dict(record: Any) -> dict[str, Any]:
    """Accept either a Pydantic Record or a plain dict, return a fresh dict.

    Using `mode='json'` on Pydantic ensures enums become their .value strings,
    timestamps stay strings, etc — matching what the JSON form should look like.
    """
    if hasattr(record, "model_dump"):
        dumped: dict[str, Any] = record.model_dump(mode="json")
        return dumped
    if not isinstance(record, dict):
        raise TypeError(
            f"record must be a Pydantic Record or a dict, got {type(record).__name__}"
        )
    return deepcopy(record)


def canonical_for_signing(record: Any) -> bytes:
    """Return canonical JSON bytes used for the record's hash + signature.

    Excludes envelope.hash and envelope.signature.
    """
    sig_form = _dispatch_version(record)
    if sig_form == V1_SIG_FORM_VERSION:
        return _canonical_for_signing_v1(record)
    raise ValueError(f"Unsupported sig_form_version: {sig_form!r}")


def canonical_for_chain_link(record: Any) -> bytes:
    """Return canonical JSON bytes used as input to SHA-256 → next record's prev_hash.

    Includes the full record (hash + signature populated).
    """
    sig_form = _dispatch_version(record)
    if sig_form == V1_SIG_FORM_VERSION:
        return _canonical_for_chain_link_v1(record)
    raise ValueError(f"Unsupported sig_form_version: {sig_form!r}")


# ---------------------------------------------------------------------------
# v1 implementations
# ---------------------------------------------------------------------------


def _canonical_for_signing_v1(record: Any) -> bytes:
    rec = _record_as_dict(record)
    env = rec.get("envelope")
    if env is None:
        raise ValueError("Record missing 'envelope' top-level key")
    # Absent, not null — see SIGNING.md §2.1.
    env.pop("hash", None)
    env.pop("signature", None)
    return rfc8785.dumps(rec)


def _canonical_for_chain_link_v1(record: Any) -> bytes:
    rec = _record_as_dict(record)
    env = rec.get("envelope")
    if env is None:
        raise ValueError("Record missing 'envelope' top-level key")
    if env.get("hash") is None or env.get("signature") is None:
        raise ValueError(
            "canonical_for_chain_link requires a fully-signed record "
            "(envelope.hash and envelope.signature populated)"
        )
    return rfc8785.dumps(rec)


# ---------------------------------------------------------------------------
# Version dispatch
# ---------------------------------------------------------------------------


def _dispatch_version(record: Any) -> str:
    rec = _record_as_dict(record)
    env = rec.get("envelope") or {}
    sig_form = env.get("sig_form_version")
    if not isinstance(sig_form, str):
        raise ValueError(
            "Record envelope must include 'sig_form_version' (str). "
            "v1 records use 'v1.0'."
        )
    return sig_form


__all__ = ["canonical_for_signing", "canonical_for_chain_link"]
