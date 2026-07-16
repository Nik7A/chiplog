"""v0.2 redaction contract — the leak matrix, proven end-to-end.

Every test here drives the REAL recorder (or the real redactor) and asserts the
secret does NOT appear in the signed canonical bytes (json.dumps of the record),
that the redaction is announced in payload.redaction, and — for disable=True —
that the sink's manifest HONESTLY records the disabled state.

The leaks (each was a real, reproduced defect before this wave):
  1. disable=True wrote cleartext while the manifest affirmatively attested
     redaction_disabled: false (sink flag disconnected from the recorder).
  2. dict KEYS were never inspected — a dict keyed by a patient email leaked it.
  3. strip_hash defeated by first-match ordering — a secret co-occurring with an
     email matched the email rule first and its sha256 landed in the record.
  4. DEFAULT_RULES missed SSN / credit-card / phone / JWT / PEM / DB-URL / Stripe
     / Google keys.
  5. Error.error_type bypassed the redactor.
  6. Marker forgery — a tool returning a marker-shaped dict passed through as
     signed "evidence" of redaction with no backing entry.

Plus a NON-over-redaction matrix (benign values must survive) and an
ANTI-FORGERY matrix (a genuine marker validates; a tool look-alike does not).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chiplog.emit import AuditRecorder
from chiplog.integrity import verify_record
from chiplog.keys import SigningKey, compute_key_id
from chiplog.manifest import RedactionState
from chiplog.redact import (
    RedactionConfig,
    redaction_authenticity,
    redact_value,
)
from chiplog.schema.v1 import (
    NoGateReason,
    Output,
    ToolCall,
    error,
    success,
    ungated,
)
from chiplog.sinks.base import InMemorySink
from chiplog.sinks.local_file import LocalFileSink


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


@pytest.fixture
def sink() -> InMemorySink:
    return InMemorySink()


@pytest.fixture
def recorder(sink: InMemorySink, signing_key: SigningKey) -> AuditRecorder:
    return AuditRecorder(sink=sink, signing_key=signing_key)


async def _record(recorder: AuditRecorder, **over: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = dict(
        session_id="sess-1",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )
    kwargs.update(over)
    return await recorder.record(**kwargs)


def _signed_bytes(signed: dict[str, Any]) -> str:
    """The signed canonical payload as text — what an auditor / consumer reads."""
    return json.dumps(signed)


SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"  # canonical AWS example key
SSN = "123-45-6789"
VISA = "4111111111111111"  # passes Luhn
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)


# ---------------------------------------------------------------------------
# Leak 1 — disable=True must be attested HONESTLY in the manifest
# ---------------------------------------------------------------------------


async def test_leak1_disable_true_latches_manifest_disabled(
    tmp_path: Path, signing_key: SigningKey
) -> None:
    sink = LocalFileSink(dir=tmp_path)  # sink default: NOT told anything
    recorder = AuditRecorder(
        sink=sink,
        signing_key=signing_key,
        redaction_config=RedactionConfig(disable=True),
    )
    signed = await _record(recorder, input={"email": "patient@hospital.org"})

    # The record is in the clear (disable=True is honest about THAT)...
    assert signed["payload"]["input"]["email"] == "patient@hospital.org"
    # ...but the manifest must NOT affirmatively attest redaction_disabled=false.
    assert sink.manifest.redaction_state == RedactionState.DISABLED
    assert sink.manifest.redaction_disabled is True


async def test_leak1_disabled_latch_is_monotonic(
    tmp_path: Path, signing_key: SigningKey
) -> None:
    """Once ANY record was written with redaction off, a later enabled recorder
    sharing the sink must NOT downgrade the manifest back to enabled."""
    sink = LocalFileSink(dir=tmp_path)
    off = AuditRecorder(
        sink=sink, signing_key=signing_key,
        redaction_config=RedactionConfig(disable=True),
    )
    await _record(off, session_id="s-off")
    assert sink.manifest.redaction_state == RedactionState.DISABLED

    on = AuditRecorder(sink=sink, signing_key=signing_key)  # redaction ON
    await _record(on, session_id="s-on")
    # Still DISABLED — the latch never downgrades.
    assert sink.manifest.redaction_state == RedactionState.DISABLED


async def test_enabled_recorder_moves_manifest_from_unknown_to_enabled(
    tmp_path: Path, signing_key: SigningKey
) -> None:
    sink = LocalFileSink(dir=tmp_path)
    assert sink.manifest.redaction_state == RedactionState.UNKNOWN
    on = AuditRecorder(sink=sink, signing_key=signing_key)
    await _record(on)
    assert sink.manifest.redaction_state == RedactionState.ENABLED


def test_absent_flag_reads_unknown_not_enabled() -> None:
    """A pre-v1.2 manifest carries no redaction_state — it must read UNKNOWN,
    never 'enabled'. The old hardcoded `redaction_disabled: false` was a lie."""
    from chiplog.manifest import Manifest

    m = Manifest.from_dict({"schema_version": "manifest.v1.0"})
    assert m.redaction_state == RedactionState.UNKNOWN


# ---------------------------------------------------------------------------
# Leak 2 — dict KEYS are inspected
# ---------------------------------------------------------------------------


async def test_leak2_pii_dict_key_is_redacted(recorder: AuditRecorder) -> None:
    # A dict keyed by a patient email — the classic EHR leak.
    signed = await _record(
        recorder, input={"records": {"patient@hospital.org": {"dx": "flu"}}}
    )
    blob = _signed_bytes(signed)
    assert "patient@hospital.org" not in blob
    # The redaction is announced.
    policies = [e["policy"] for e in signed["payload"]["redaction"]]
    assert "pii.deny.email" in policies


# ---------------------------------------------------------------------------
# Leak 3 — most-restrictive rule wins; a secret is never hashed into the record
# ---------------------------------------------------------------------------


async def test_leak3_secret_cooccurring_with_email_is_not_hashed(
    recorder: AuditRecorder,
) -> None:
    value = f"contact me at foo@bar.com with key {SECRET_KEY}"
    signed = await _record(recorder, input={"note": value})
    blob = _signed_bytes(signed)
    assert SECRET_KEY not in blob

    marker = signed["payload"]["input"]["note"]
    assert isinstance(marker, dict) and marker["redacted"] is True
    # The strip_hash rule MUST have won: no sha256 of the (secret-bearing) value.
    assert "sha256" not in marker


def test_leak3_unit_strip_hash_wins_over_email() -> None:
    cfg = RedactionConfig()
    value = f"foo@bar.com {SECRET_KEY}"
    redacted, entries = redact_value(value, cfg, path="$.x")
    assert isinstance(redacted, dict)
    assert "sha256" not in redacted
    assert redacted["policy"] == "pii.deny.aws_access_key"


# ---------------------------------------------------------------------------
# Leak 4 — expanded DEFAULT_RULES
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "policy"),
    [
        (SSN, "pii.deny.ssn"),
        (VISA, "pii.deny.credit_card"),
        ("+14155552671", "pii.deny.phone"),
        ("555-123-4567", "pii.deny.phone"),
        (JWT, "pii.deny.jwt"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n", "pii.deny.pem_private_key"),
        (
            "postgres://admin:s3cr3tp@db.internal:5432/prod",
            "pii.deny.db_url_password",
        ),
        ("sk_live_" + "a" * 24, "pii.deny.stripe_key"),
        ("AIza" + "B" * 35, "pii.deny.google_api_key"),
    ],
)
def test_leak4_new_rules_fire(value: str, policy: str) -> None:
    cfg = RedactionConfig()
    redacted, entries = redact_value(value, cfg, path="$.x")
    assert isinstance(redacted, dict), f"{policy} did not fire on {value!r}"
    assert entries[0].policy == policy


# ---------------------------------------------------------------------------
# Leak 5 — Error.error_type is redacted
# ---------------------------------------------------------------------------


async def test_leak5_error_type_is_redacted(recorder: AuditRecorder) -> None:
    # A runtime that stuffs an email into the "type" (bad, but it happens).
    signed = await _record(
        recorder,
        outcome=error("patient@hospital.org", "boom"),
    )
    blob = _signed_bytes(signed)
    assert "patient@hospital.org" not in blob
    et = signed["payload"]["outcome"]["error_type"]
    assert isinstance(et, dict) and et["redacted"] is True


async def test_normal_error_type_stays_a_plain_string(
    recorder: AuditRecorder,
) -> None:
    signed = await _record(recorder, outcome=error("ConnectionError", "no route"))
    assert signed["payload"]["outcome"]["error_type"] == "ConnectionError"


# ---------------------------------------------------------------------------
# Leak 6 / anti-forgery — a tool cannot forge recorder-attested redaction
# ---------------------------------------------------------------------------


async def test_leak6_tool_supplied_marker_is_detected_as_forged(
    recorder: AuditRecorder,
) -> None:
    forged = {
        "redacted": True,
        "type": "string",
        "length": 11,
        "policy": "pii.deny.email",
        "sha256": "0" * 64,
    }
    signed = await _record(recorder, output=Output(body={"result": forged}))
    audit = redaction_authenticity(signed)
    assert not audit.authentic
    assert audit.forged_paths  # the forged marker is called out


async def test_genuine_marker_validates(recorder: AuditRecorder) -> None:
    signed = await _record(recorder, input={"email": "foo@bar.com"})
    audit = redaction_authenticity(signed)
    assert audit.authentic
    assert audit.forged_paths == []


async def test_genuine_and_forged_together_flags_only_the_forgery(
    recorder: AuditRecorder,
) -> None:
    forged = {"redacted": True, "type": "string", "length": 3, "policy": "x"}
    signed = await _record(
        recorder,
        input={"email": "foo@bar.com"},
        output=Output(body={"fake": forged}),
    )
    audit = redaction_authenticity(signed)
    assert not audit.authentic
    assert any("fake" in p for p in audit.forged_paths)


async def test_tool_replaying_a_stale_token_is_still_forged(
    recorder: AuditRecorder,
) -> None:
    """A tool that scraped a PRIOR record's token from the log cannot reuse it:
    this record's token is fresh, so the stale one mismatches."""
    first = await _record(recorder, input={"email": "a@b.com"})
    stale_token = first["payload"]["redaction_token"]
    assert isinstance(stale_token, str)

    forged = {"redacted": True, "type": "string", "length": 3, "policy": "x",
              "token": stale_token}
    second = await _record(recorder, output=Output(body={"fake": forged}))
    # Fresh per-record token differs from the stale one.
    assert second["payload"]["redaction_token"] != stale_token
    audit = redaction_authenticity(second)
    assert not audit.authentic


async def test_tool_forged_sentinel_key_is_detected(
    recorder: AuditRecorder,
) -> None:
    from chiplog.redact import REDACTED_KEY_PREFIX

    fake_key = f"{REDACTED_KEY_PREFIX}deadbeefdeadbeef::pii.deny.email"
    signed = await _record(recorder, output=Output(body={fake_key: {"x": 1}}))
    audit = redaction_authenticity(signed)
    assert not audit.authentic
    assert any(fake_key in p for p in audit.forged_paths)


async def test_per_record_token_is_unique(recorder: AuditRecorder) -> None:
    a = await _record(recorder, input={"email": "a@b.com"})
    b = await _record(recorder, input={"email": "c@d.com"})
    assert a["payload"]["redaction_token"] != b["payload"]["redaction_token"]


async def test_disabled_record_has_no_token_and_no_markers(
    tmp_path: Path, signing_key: SigningKey
) -> None:
    sink = LocalFileSink(dir=tmp_path)
    rec = AuditRecorder(
        sink=sink, signing_key=signing_key,
        redaction_config=RedactionConfig(disable=True),
    )
    signed = await _record(rec, input={"email": "foo@bar.com"})
    assert signed["payload"]["redaction_token"] is None
    audit = redaction_authenticity(signed)
    assert audit.authentic  # no markers -> trivially authentic
    assert audit.token_present is False


# ---------------------------------------------------------------------------
# Lifecycle attributes go through the same contract
# ---------------------------------------------------------------------------


async def test_lifecycle_attribute_secret_redacted_and_key_inspected(
    recorder: AuditRecorder, signing_key: SigningKey
) -> None:
    from chiplog.schema.v1 import (
        LifecyclePhase,
        node_transition,
    )

    signed = await recorder.record_event(
        session_id="sess-1",
        step_id="step-1",
        phase=LifecyclePhase.NODE_EXIT,
        transition=node_transition("planner"),
        attributes={"contact": "foo@bar.com", "patient@x.org": "flu"},
    )
    blob = json.dumps(signed)
    assert "foo@bar.com" not in blob
    assert "patient@x.org" not in blob
    audit = redaction_authenticity(signed)
    assert audit.authentic
    result = verify_record(signed, {signing_key.key_id: signing_key.public_key})
    assert result.is_valid


# ---------------------------------------------------------------------------
# NON-over-redaction matrix — benign values MUST survive verbatim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "benign",
    [
        "The quick brown fox jumps over the lazy dog.",
        "550e8400-e29b-41d4-a716-446655440000",  # UUID
        "https://example.com/docs/page?ref=home",  # non-secret URL
        "4111111111111112",  # 16 digits, FAILS Luhn -> not a card
        "order 1234 shipped on 2026-07-14",
    ],
)
def test_non_over_redaction(benign: str) -> None:
    cfg = RedactionConfig()
    redacted, entries = redact_value(benign, cfg, path="$.x")
    assert redacted == benign, f"benign value over-redacted: {benign!r}"
    assert entries == []


def test_small_int_and_bool_untouched() -> None:
    cfg = RedactionConfig()
    for v in (42, 0, -7, True, False, None, 3.14):
        redacted, entries = redact_value(v, cfg)
        assert redacted == v
        assert entries == []


# ---------------------------------------------------------------------------
# Records still verify after all the new redaction machinery
# ---------------------------------------------------------------------------


async def test_redacted_record_still_verifies(
    recorder: AuditRecorder, signing_key: SigningKey
) -> None:
    signed = await _record(
        recorder,
        input={"patient@hospital.org": SSN, "note": f"{VISA} and {JWT}"},
        outcome=error("patient@hospital.org", f"ssn {SSN}"),
    )
    result = verify_record(signed, {signing_key.key_id: signing_key.public_key})
    assert result.is_valid
    blob = _signed_bytes(signed)
    for secret in ("patient@hospital.org", SSN, VISA, JWT):
        assert secret not in blob
