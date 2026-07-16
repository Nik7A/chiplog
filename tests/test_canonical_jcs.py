"""Step 1 verification: canonical form is deterministic and excludes the right fields.

These tests are the gate for Step 1. Per BUILD_PLAN, Step 1 is not 'done' until
two independent canonicalize calls in different key orders produce byte-identical
hashes against the worked test vector in SIGNING.md §8.
"""

from __future__ import annotations

import hashlib

import pytest

from chiplog.canonical import (
    canonical_for_chain_link,
    canonical_for_signing,
)
from chiplog.schema.v1 import (
    ClockSource,
    Envelope,
    Header,
    NoGateReason,
    Output,
    Payload,
    Record,
    TimeBlock,
    ToolCall,
    success,
    ungated,
)


# ---------------------------------------------------------------------------
# Fixture: the SIGNING.md §8 worked test vector
# ---------------------------------------------------------------------------


def make_test_vector_record() -> Record:
    """Mirror of SIGNING.md §8.2 — used everywhere a canonical example is needed."""
    return Record(
        envelope=Envelope(
            record_id="01H4MJ0QH0V8VYG09T9YV9TQNN",
            chain_id="test-chain-001",
            prev_hash=None,
            key_id="aabbccddeeff0011",
        ),
        header=Header(
            session_id="sess-001",
            step_id="step-001",
            agent_name="test-agent",
            model="claude-opus-4-7",
        ),
        payload=Payload(
            time=TimeBlock(
                ts_utc="2026-06-19T20:00:00.000000000Z",
                ts_monotonic_ns=1000,
                ts_source=ClockSource.SYSTEM,
            ),
            tool=ToolCall(name="Read"),
            input={"file_path": "/etc/hosts"},
            output=Output(body="127.0.0.1 localhost\n", truncated=False),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            outcome=success(),
        ),
    )


# ---------------------------------------------------------------------------
# Determinism — Pydantic dict order should not affect canonical bytes
# ---------------------------------------------------------------------------


def test_signing_form_deterministic_across_dict_construction_orders() -> None:
    """Different dict construction orders for the same logical record must produce
    byte-identical signing forms. This is the RFC 8785 JCS guarantee — verify it
    holds end-to-end through our wrapper.
    """
    rec = make_test_vector_record()
    bytes_pydantic = canonical_for_signing(rec)

    # Reconstruct the same record from a dict, with envelope keys reversed.
    raw = rec.model_dump(mode="json")
    reordered_envelope = dict(reversed(list(raw["envelope"].items())))
    reordered_record = {
        "payload": raw["payload"],  # also top-level order swapped
        "header": raw["header"],
        "envelope": reordered_envelope,
    }
    bytes_reordered = canonical_for_signing(reordered_record)

    assert bytes_pydantic == bytes_reordered


def test_signing_form_excludes_hash_and_signature() -> None:
    """Per SIGNING.md §2.1 — hash and signature fields must be ABSENT, not null."""
    rec = make_test_vector_record()
    bytes_no_hash = canonical_for_signing(rec)

    # Build a record with hash and signature populated as if signing already happened.
    raw = rec.model_dump(mode="json")
    raw["envelope"]["hash"] = "deadbeef" * 8
    raw["envelope"]["signature"] = "A" * 88
    bytes_with_hash = canonical_for_signing(raw)

    # Both must produce the same bytes — the signing form is invariant of those fields.
    assert bytes_no_hash == bytes_with_hash, (
        "canonical_for_signing must produce identical bytes whether hash/signature "
        "are present or absent on the input"
    )


def test_signing_form_byte_stable_across_runs() -> None:
    """Two independent calls produce byte-identical output. This is the foundation
    for the worked test vector in SIGNING.md §8 and the future cross-language verifier.
    """
    rec = make_test_vector_record()
    bytes_a = canonical_for_signing(rec)
    bytes_b = canonical_for_signing(rec)
    assert bytes_a == bytes_b
    assert hashlib.sha256(bytes_a).hexdigest() == hashlib.sha256(bytes_b).hexdigest()


# ---------------------------------------------------------------------------
# Chain link — must include hash + signature, fail loudly if missing
# ---------------------------------------------------------------------------


def test_chain_link_form_requires_signed_record() -> None:
    """canonical_for_chain_link must refuse a record where hash or signature is None.
    Silently producing a chain link from a partially-signed record would let an
    attacker establish a parallel chain — refuse loudly.
    """
    rec = make_test_vector_record()
    with pytest.raises(ValueError, match="fully-signed"):
        canonical_for_chain_link(rec)


def test_chain_link_form_includes_signature() -> None:
    """When the record is fully signed, the chain-link form must differ from the
    signing form precisely because the signature byte is included. Tampering with
    the signature must change the chain-link bytes → break the next prev_hash.
    """
    raw = make_test_vector_record().model_dump(mode="json")
    raw["envelope"]["hash"] = "0" * 64
    raw["envelope"]["signature"] = "A" * 88

    signing_bytes = canonical_for_signing(raw)
    link_bytes = canonical_for_chain_link(raw)

    assert signing_bytes != link_bytes, (
        "chain link form must differ from signing form when record is signed — "
        "otherwise signature tampering would not break the next chain link"
    )

    # And: changing the signature must change the chain link bytes.
    raw2 = dict(raw)
    raw2["envelope"] = dict(raw["envelope"])
    raw2["envelope"]["signature"] = "B" * 88
    link_bytes2 = canonical_for_chain_link(raw2)
    assert link_bytes != link_bytes2


# ---------------------------------------------------------------------------
# Version dispatch — refuse unknown versions, accept v1.0
# ---------------------------------------------------------------------------


def test_dispatch_rejects_unknown_sig_form_version() -> None:
    rec = make_test_vector_record()
    raw = rec.model_dump(mode="json")
    raw["envelope"]["sig_form_version"] = "v999.999"
    with pytest.raises(ValueError, match="Unsupported"):
        canonical_for_signing(raw)


def test_dispatch_requires_envelope() -> None:
    with pytest.raises(ValueError, match="envelope"):
        canonical_for_signing({"header": {}, "payload": {}})


def test_dispatch_requires_sig_form_version() -> None:
    with pytest.raises(ValueError, match="sig_form_version"):
        canonical_for_signing(
            {"envelope": {"record_id": "x", "chain_id": "y", "key_id": "z"}}
        )
