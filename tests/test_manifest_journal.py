"""The journal carries resulting state, so replay is idempotent.

The manifest is an attestation, not a cache: verify.py reports MANIFEST_INTEGRITY
when it disagrees with the log. Replay therefore has to reconstruct exactly the
state the old full-rewrite path held — no more, no less.

Idempotence is not a nicety. Compaction writes the checkpoint and only then drops
the journal, so a crash between the two replays lines onto a newer checkpoint.
That is safe only because a line states the result rather than a delta.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chiplog.emit import AuditRecorder
from chiplog.journal import JournalCorruptError, append_entry, replay
from chiplog.keys import SigningKey, compute_key_id
from chiplog.manifest import MANIFEST_SCHEMA_VERSION, JournalEntry, Manifest, RedactionState
from chiplog.schema.v1 import NoGateReason, Output, ToolCall, success, ungated
from chiplog.sinks.local_file import LocalFileSink


def _entry(**over: object) -> JournalEntry:
    base = dict(
        chain_id="c1",
        genesis_hash="g1",
        first_record_id="r1",
        head_hash="h1",
        last_record_id="r1",
        record_count=1,
        file="audit-2026-07-17.jsonl",
        file_sha256="s1",
        file_record_count=1,
        file_first_record_id="r1",
        redaction_disabled=False,
    )
    base.update(over)
    return JournalEntry(**base)  # type: ignore[arg-type]


def test_apply_sets_chain_and_file_state() -> None:
    m = Manifest()
    m.apply_journal_entry(_entry())
    assert m.chains["c1"].head_hash == "h1"
    assert m.chains["c1"].genesis_hash == "g1"
    assert m.chains["c1"].record_count == 1
    assert m.files["audit-2026-07-17.jsonl"].sha256 == "s1"
    assert m.files["audit-2026-07-17.jsonl"].record_count == 1


def test_apply_is_idempotent() -> None:
    m = Manifest()
    e = _entry(head_hash="h2", record_count=2, file_record_count=2)
    m.apply_journal_entry(e)
    m.apply_journal_entry(e)
    assert m.chains["c1"].record_count == 2, "counts must be stated, never incremented"
    assert m.files["audit-2026-07-17.jsonl"].record_count == 2


def test_replaying_an_older_line_after_a_newer_one_cannot_unlatch_redaction() -> None:
    m = Manifest()
    m.apply_journal_entry(_entry(redaction_disabled=True))
    m.apply_journal_entry(_entry(redaction_disabled=False))
    assert m.redaction_state is RedactionState.DISABLED


def test_roundtrips_through_json() -> None:
    e = _entry()
    assert JournalEntry.from_dict(e.to_dict()) == e


def test_append_then_replay_returns_entries_in_order(tmp_path: Path) -> None:
    p = tmp_path / "manifest.journal"
    append_entry(p, _entry(head_hash="h1"))
    append_entry(p, _entry(head_hash="h2"))
    assert [e.head_hash for e in replay(p)] == ["h1", "h2"]


def test_replay_of_a_missing_journal_is_empty(tmp_path: Path) -> None:
    assert replay(tmp_path / "manifest.journal") == []


def test_torn_trailing_line_is_ignored(tmp_path: Path) -> None:
    # Only a crash mid-append produces this. The record it described is either
    # absent from the JSONL or lands in the pre-existing lag window; either way
    # the honest move is to drop the half-written attestation.
    p = tmp_path / "manifest.journal"
    append_entry(p, _entry(head_hash="h1"))
    with p.open("a", encoding="utf-8") as f:
        f.write('{"chain_id": "c1", "head_ha')
    assert [e.head_hash for e in replay(p)] == ["h1"]


def test_corrupt_line_in_the_middle_raises(tmp_path: Path) -> None:
    # Skipping this would silently drop an attestation — the exact failure this
    # library exists to prevent. It must be loud.
    p = tmp_path / "manifest.journal"
    append_entry(p, _entry(head_hash="h1"))
    with p.open("a", encoding="utf-8") as f:
        f.write("{ not json\n")
    append_entry(p, _entry(head_hash="h3"))
    with pytest.raises(JournalCorruptError):
        replay(p)


def test_writes_v2(tmp_path: Path) -> None:
    assert MANIFEST_SCHEMA_VERSION == "manifest.v2.0"
    p = tmp_path / "manifest.json"
    Manifest().save_atomic(p)
    import json as _json

    assert _json.loads(p.read_text())["schema_version"] == "manifest.v2.0"


def test_a_v1_manifest_still_loads_and_its_heads_are_authoritative(tmp_path: Path) -> None:
    # #14's lesson: a bump that orphans existing manifests is not acceptable.
    # v1 predates the journal, so what it says IS the state.
    import json as _json

    p = tmp_path / "manifest.json"
    p.write_text(
        _json.dumps(
            {
                "schema_version": "manifest.v1.0",
                "pubkey_id": None,
                "pubkey_pem": None,
                "pubkeys": {},
                "chains": {
                    "c1": {
                        "chain_id": "c1",
                        "head_hash": "old",
                        "genesis_hash": "g",
                        "record_count": 5,
                        "first_record_id": "r1",
                        "last_record_id": "r5",
                    }
                },
                "files": {},
                "redaction_state": "enabled",
            }
        )
    )
    m = Manifest.load_or_create(p)
    assert m.chains["c1"].head_hash == "old"
    assert m.chains["c1"].record_count == 5


def test_load_replays_the_journal_over_the_checkpoint(tmp_path: Path) -> None:
    p = tmp_path / "manifest.json"
    Manifest().save_atomic(p)
    append_entry(p.parent / "manifest.journal", _entry(head_hash="h9", record_count=9))
    m = Manifest.load_or_create(p)
    assert m.chains["c1"].head_hash == "h9"
    assert m.chains["c1"].record_count == 9


def test_an_unknown_schema_version_still_raises(tmp_path: Path) -> None:
    import json as _json

    p = tmp_path / "manifest.json"
    p.write_text(_json.dumps({"schema_version": "manifest.v9.9", "chains": {}, "files": {}}))
    with pytest.raises(ValueError, match="unsupported manifest schema_version"):
        Manifest.load_or_create(p)


def _mkkey() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


async def _emit(rec: AuditRecorder, n: int) -> None:
    for i in range(n):
        await rec.record(
            session_id="s", step_id=f"step-{i}", tool=ToolCall(name="Read"),
            input={"i": i}, output=Output(body=""),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK), outcome=success(),
        )


async def test_manifest_json_is_not_rewritten_per_record(tmp_path: Path) -> None:
    # The defect. ~1800 full rewrites + fsyncs a day, growing to ~22.5 MB.
    d = tmp_path / "audit"
    sk = _mkkey()
    sink = LocalFileSink(dir=d, pubkey_pem=sk.public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 1)
    mtime_after_first = (d / "manifest.json").stat().st_mtime_ns
    await _emit(rec, 5)
    assert (d / "manifest.json").stat().st_mtime_ns == mtime_after_first


async def test_each_record_appends_one_journal_line(tmp_path: Path) -> None:
    d = tmp_path / "audit"
    sk = _mkkey()
    sink = LocalFileSink(dir=d, pubkey_pem=sk.public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 4)
    assert len(replay(d / "manifest.journal")) == 4
