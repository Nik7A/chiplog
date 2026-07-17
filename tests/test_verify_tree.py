"""v0.2 verifier contract: directory / multi-file / multi-key / manifest-aware.

These tests reproduce, on synthetic fixtures, exactly the conditions found in
bosun's real evento trail:
  - a logical chain that spans several daily files,
  - a signing key that rotates mid-chain,
  - ~part of the chain signed by a key that is no longer available,
  - records that fork off the canonical path the manifest attests,
  - a manifest whose claimed `pubkey_id` is stale versus the PEM it stores,
  - a whole chain deleted from the directory,
  - the genesis record truncated off the front of a chain.

Every verdict the verifier emits must be a fact it can back with evidence, and
it must never guess the CAUSE of an off-canonical record.
"""

from __future__ import annotations

import copy
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from chiplog.cli import (
    EXIT_CHAIN_BREAK,
    EXIT_MANIFEST_INTEGRITY,
    EXIT_MANIFEST_MISMATCH,
    EXIT_OFF_CANONICAL,
    EXIT_OK,
    EXIT_PARTIAL,
    cli,
)
from chiplog.emit import AuditRecorder
from chiplog.integrity import compute_chain_link, sign_record
from chiplog.keys import SigningKey, compute_key_id
from chiplog.manifest import Manifest
from chiplog.schema.v1 import NoGateReason, Output, ToolCall, success, ungated
from chiplog.sinks.local_file import LocalFileSink
from chiplog.verify import (
    ChainCheckOutcome,
    RecordStatus,
    verify_log,
    verify_tree,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Clock:
    """A settable UTC clock for driving LocalFileSink's daily rotation."""

    def __init__(self, when: datetime) -> None:
        self.when = when

    def __call__(self) -> datetime:
        return self.when


def _mkkey() -> tuple[SigningKey, str]:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    kid = compute_key_id(pub)
    return SigningKey(private_key=pk, public_key=pub, key_id=kid), kid


def _pem(sk: SigningKey) -> bytes:
    return sk.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


async def _emit(
    recorder: AuditRecorder, n: int, start: int = 0
) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for i in range(start, start + n):
        rec = await recorder.record(
            session_id="sess",
            step_id=f"step-{i}",
            tool=ToolCall(name="Read"),
            input={"i": i},
            output=Output(body=""),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            outcome=success(),
        )
        out.append(rec)
    return out


def _append_raw_line(path: Path, record: dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def _manifest_dict(dir_: Path) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads((dir_ / "manifest.json").read_text())
    return parsed


def _strip_pubkeys_except(dir_: Path, keep: dict[str, bytes]) -> None:
    """Make a key genuinely absent from the manifest, on purpose.

    Several tests below need a record whose key cannot be resolved. They used to
    get one for free from rotation, because rotation deleted the previous key —
    that was the defect, not a fixture. The condition is real and worth testing,
    so it is now created deliberately rather than harvested from a bug.
    """
    _rewrite_manifest(
        dir_,
        pubkeys={kid: pem.decode() for kid, pem in keep.items()},
    )


def _rewrite_manifest(dir_: Path, **overrides: object) -> None:
    m = json.loads((dir_ / "manifest.json").read_text())
    m.update(overrides)
    (dir_ / "manifest.json").write_text(json.dumps(m, indent=2))


def _materialize_manifest(dir_: Path) -> None:
    """Collapse checkpoint + journal into `manifest.json` and drop the journal.

    Task 4 replaced the per-record manifest rewrite with an append-only
    `manifest.journal`: `manifest.json` alone is now a stale checkpoint, and
    `Manifest.apply_journal_entry` restates a chain/file wholesale, so a live
    journal silently overrides any value hand-edited into the checkpoint
    afterwards. The fixtures below simulate a manifest that lies about the
    log's true state; the lie has to actually be what gets read back, so
    materialize the current (honest) state into the checkpoint and drop the
    journal first — the same collapse `LocalFileSink` compaction performs,
    just invoked by hand here since these tests edit the file directly.
    """
    manifest_path = dir_ / "manifest.json"
    m = Manifest.load_or_create(manifest_path)
    m.save_atomic(manifest_path)
    (dir_ / "manifest.journal").unlink(missing_ok=True)


def _resync_manifest_file(dir_: Path, fpath: Path) -> None:
    """Make the manifest's per-file ``sha256`` honestly attest ``fpath``'s
    current bytes, while leaving ``record_count`` at the canonical tally.

    This reproduces the exact real-evento condition. When an abandoned retry or
    a concurrent writer appends an off-canonical fork line, the file's bytes
    grow — so the manifest's ``sha256`` (written over the final bytes) covers the
    fork and stays silent — but the authoritative writer's ``record_count`` was
    never bumped for that fork, so it remains the CANONICAL count (fewer than the
    physical line count). A faithful fixture must therefore resync only the
    digest and must NOT inflate ``record_count`` to the physical line count;
    otherwise a legitimately-attested fork archive is mislabelled a manifest
    integrity break instead of the honest off-canonical verdict.
    """
    import hashlib

    _materialize_manifest(dir_)
    data = fpath.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    m = json.loads((dir_ / "manifest.json").read_text())
    m["files"][fpath.name]["sha256"] = sha
    (dir_ / "manifest.json").write_text(json.dumps(m, indent=2))


# ---------------------------------------------------------------------------
# Clean directory — backward-compatible happy path
# ---------------------------------------------------------------------------


async def test_clean_single_key_directory_is_ok(tmp_path: Path) -> None:
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 5)

    r = verify_tree(d)
    assert r.outcome == ChainCheckOutcome.OK
    assert r.is_valid
    assert r.total_records == 5
    assert r.canonical_records == 5
    assert r.verified_records == 5
    assert r.off_path_records == 0
    assert len(r.chains) == 1


async def test_chain_spans_multiple_daily_files(tmp_path: Path) -> None:
    """A chain that keeps its chain_id across UTC midnight lands in two files but
    is one logical chain — the verifier walks it in write order across files."""
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    clock = _Clock(datetime(2026, 7, 13, 23, 0, tzinfo=timezone.utc))
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk), clock=clock)
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 3, start=0)
    clock.when = datetime(2026, 7, 14, 1, 0, tzinfo=timezone.utc)  # next day
    await _emit(rec, 4, start=3)

    files = sorted(p.name for p in d.glob("audit-*.jsonl"))
    assert files == ["audit-2026-07-13.jsonl", "audit-2026-07-14.jsonl"]

    r = verify_tree(d)
    assert r.outcome == ChainCheckOutcome.OK
    assert r.total_records == 7
    assert r.canonical_records == 7
    # one logical chain despite two files
    assert len(r.chains) == 1
    assert r.chains[0].records_in_log == 7


async def test_key_rotation_midchain_both_keys_available(tmp_path: Path) -> None:
    sk_a, kid_a = _mkkey()
    sk_b, kid_b = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk_a))
    rec_a = AuditRecorder(sink=sink, signing_key=sk_a, chain_id="c1")
    recs = await _emit(rec_a, 3, start=0)
    head = compute_chain_link(recs[-1])
    # rotate: new sink (writes pem=B), new recorder resuming the same chain head
    sink_b = LocalFileSink(dir=d, pubkey_pem=_pem(sk_b))
    rec_b = AuditRecorder(
        sink=sink_b, signing_key=sk_b, chain_id="c1", initial_prev_hash=head
    )
    await _emit(rec_b, 3, start=3)

    # Nothing passed in. The manifest kept both keys, so it is sufficient on its
    # own — which is the point: in the incident this test used to describe,
    # nobody had the rotated-away key to pass in, because rotation had deleted
    # the only copy. This test used to hand A back to the verifier from outside
    # and assert the resulting mismatch, which pinned that loss as correct.
    r = verify_tree(d)
    assert r.verified_records == 6
    assert r.unverifiable_no_key == 0
    # pubkey_id follows the current key now, so it agrees with pubkey_pem and
    # there is nothing stale to mismatch on.
    assert r.outcome == ChainCheckOutcome.OK
    assert set(_manifest_dict(d)["pubkeys"]) == {kid_a, kid_b}
    assert kid_a in r.available_key_ids
    assert kid_b in r.available_key_ids


# ---------------------------------------------------------------------------
# Missing-key → honest PARTIAL, never blanket pass/fail
# ---------------------------------------------------------------------------


async def test_missing_key_is_partial_not_fail_not_pass(tmp_path: Path) -> None:
    sk_a, _ = _mkkey()  # this key will be "absent" at verify time
    sk_b, kid_b = _mkkey()
    d = tmp_path / "audit"
    sink_a = LocalFileSink(dir=d, pubkey_pem=_pem(sk_a))
    rec_a = AuditRecorder(sink=sink_a, signing_key=sk_a, chain_id="c1")
    recs = await _emit(rec_a, 3, start=0)
    head = compute_chain_link(recs[-1])
    sink_b = LocalFileSink(dir=d, pubkey_pem=_pem(sk_b))
    rec_b = AuditRecorder(
        sink=sink_b, signing_key=sk_b, chain_id="c1", initial_prev_hash=head
    )
    await _emit(rec_b, 4, start=3)

    # Only key B is available. Key A is genuinely absent — dropped from the
    # manifest on purpose, because rotation no longer destroys it for us.
    _strip_pubkeys_except(d, {kid_b: _pem(sk_b)})

    r = verify_tree(d)
    assert r.verified_records == 4
    assert r.unverifiable_no_key == 3
    # not a pass
    assert not r.is_valid
    # not a blanket signature failure
    assert r.outcome != ChainCheckOutcome.SIGNATURE_FAIL
    # partial (>=1 verified, >=1 unverifiable) — but pubkey_id mismatch outranks it
    # for the single exit code; the PARTIAL numbers are still reported.
    assert r.outcome in (
        ChainCheckOutcome.PARTIAL,
        ChainCheckOutcome.MANIFEST_PUBKEY_MISMATCH,
    )


async def test_no_key_at_all_is_key_resolution_not_partial(tmp_path: Path) -> None:
    """If NOTHING verified (every record's key is missing) it maps to the
    KEY_RESOLUTION family, never PARTIAL (PARTIAL requires >=1 real verify)."""
    sk_a, _ = _mkkey()
    sk_b, kid_b = _mkkey()
    d = tmp_path / "audit"
    # write with A, but publish B's pem into the manifest → A records unverifiable,
    # and there are no B records to verify.
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk_a))
    rec = AuditRecorder(sink=sink, signing_key=sk_a, chain_id="c1")
    await _emit(rec, 3)
    # Publish ONLY B (a key that signed nothing here), so A — which signed
    # everything — cannot be resolved. Dropping A has to be explicit now that
    # declaring B no longer deletes it.
    _rewrite_manifest(
        d,
        pubkey_pem=_pem(sk_b).decode(),
        pubkey_id=kid_b,
        pubkeys={kid_b: _pem(sk_b).decode()},
    )

    r = verify_tree(d)
    assert r.verified_records == 0
    assert r.unverifiable_no_key == 3
    assert r.outcome == ChainCheckOutcome.KEY_RESOLUTION


# ---------------------------------------------------------------------------
# Off-canonical records — fact, non-zero, cause NOT guessed
# ---------------------------------------------------------------------------


async def _make_forked_dir(tmp_path: Path) -> tuple[Path, SigningKey]:
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    recs = await _emit(rec, 6)
    # Craft a validly-signed record that forks off record #2's link (not the head).
    fork = copy.deepcopy(recs[2])
    fork["payload"]["input"] = {"forked": True}  # type: ignore[index]
    fork["envelope"]["prev_hash"] = compute_chain_link(recs[1])  # type: ignore[index]
    fork["envelope"].pop("hash", None)  # type: ignore[union-attr]
    fork["envelope"].pop("signature", None)  # type: ignore[union-attr]
    signed_fork = sign_record(fork, sk)
    fpath = next(d.glob("audit-*.jsonl"))
    _append_raw_line(fpath, signed_fork)
    # The sink would have hashed this appended line into the manifest's per-file
    # attestation; do the same so the digest check sees an honest anchor and only
    # the canonical-path walk flags the fork (as in real evento data).
    _resync_manifest_file(d, fpath)
    return d, sk


async def test_off_canonical_record_is_nonzero_with_own_code(tmp_path: Path) -> None:
    d, _ = await _make_forked_dir(tmp_path)
    r = verify_tree(d)
    assert r.off_path_records == 1
    assert r.outcome == ChainCheckOutcome.OFF_CANONICAL
    assert not r.is_valid  # off-path is NEVER a pass


async def test_off_canonical_finding_does_not_guess_cause(tmp_path: Path) -> None:
    d, _ = await _make_forked_dir(tmp_path)
    r = verify_tree(d)
    off = [f for f in r.findings if f.kind == "off_canonical_path"]
    assert off, "expected an off_canonical_path finding"
    detail = off[0].detail
    # It labels the fact and explicitly disclaims knowledge of the cause.
    assert "reason not observable" in detail
    assert "off the canonical path" in detail
    # It attributes canonicity to the MANIFEST's claim, not the tool's judgement.
    assert "manifest attests" in detail


async def _make_multifile_forked_dir(tmp_path: Path) -> tuple[Path, SigningKey]:
    """A faithful miniature of the real evento trail: several daily files, each a
    fully-attested chain, and off-canonical fork lines appended (as an abandoned
    retry / concurrent writer would) so the file's PHYSICAL line count exceeds
    the CANONICAL record_count the manifest attests. The manifest's per-file
    sha256 is resynced over the final bytes (fork included), so the digest anchor
    is honest and silent; only the canonical-path walk sees the forks.
    """
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    clock = _Clock(datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc))
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk), clock=clock)

    # All authoritative (canonical) sink writes happen FIRST — the sink re-saves
    # the whole manifest on every append, so any per-file resync must come after
    # the final write or it is clobbered.
    # Day 1: chain c1, 5 canonical records.
    rec1 = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    recs1 = await _emit(rec1, 5, start=0)
    # Day 2: chain c2, 4 canonical records.
    clock.when = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)
    rec2 = AuditRecorder(sink=sink, signing_key=sk, chain_id="c2")
    recs2 = await _emit(rec2, 4, start=0)

    # Now append off-canonical forks (as an abandoned retry / concurrent writer
    # would, bypassing the counting sink) and resync only the per-file sha256.
    fpath1 = d / "audit-2026-07-06.jsonl"
    for parent_idx in (1, 3):
        fork = copy.deepcopy(recs1[parent_idx + 1])
        fork["payload"]["input"] = {"forked_from": parent_idx}  # type: ignore[index]
        fork["envelope"]["prev_hash"] = compute_chain_link(recs1[parent_idx])  # type: ignore[index]
        fork["envelope"].pop("hash", None)  # type: ignore[union-attr]
        fork["envelope"].pop("signature", None)  # type: ignore[union-attr]
        _append_raw_line(fpath1, sign_record(fork, sk))

    fpath2 = d / "audit-2026-07-07.jsonl"
    fork2 = copy.deepcopy(recs2[1])
    fork2["payload"]["input"] = {"forked": True}  # type: ignore[index]
    fork2["envelope"]["prev_hash"] = compute_chain_link(recs2[0])  # type: ignore[index]
    fork2["envelope"].pop("hash", None)  # type: ignore[union-attr]
    fork2["envelope"].pop("signature", None)  # type: ignore[union-attr]
    _append_raw_line(fpath2, sign_record(fork2, sk))

    _resync_manifest_file(d, fpath1)
    _resync_manifest_file(d, fpath2)

    return d, sk


async def test_fully_attested_fork_archive_is_off_canonical_not_integrity(
    tmp_path: Path,
) -> None:
    """REGRESSION (the evento false-positive): a fork-bearing archive whose
    manifest honestly attests the on-disk bytes — per-file sha256 over the final
    bytes, record_count at the canonical tally — must return OFF_CANONICAL, never
    a manifest-integrity break. The per-file record_count check must compare the
    manifest against the CANONICAL-reconstructed per-file count, not the physical
    line count; otherwise every legitimate fork looks like tampering.
    """
    d, sk = await _make_multifile_forked_dir(tmp_path)
    r = verify_tree(d, {sk.key_id: sk.public_key})

    # Three fork lines total across two files, none on a canonical path.
    assert r.off_path_records == 3
    assert r.outcome == ChainCheckOutcome.OFF_CANONICAL
    assert not r.is_valid  # off-canonical is non-zero, but it is NOT integrity

    # The honest anchors stay SILENT: the physical/canonical divergence is not a
    # per-file record_count mismatch, and the bytes still match the digest.
    bad = {"file_record_count_mismatch", "file_sha256_mismatch", "count_mismatch"}
    offending = [f.kind for f in r.findings if f.kind in bad]
    assert not offending, f"honest anchors must stay silent, got {offending}"


async def test_cli_fully_attested_fork_archive_exit_7(tmp_path: Path) -> None:
    """The CLI must exit 7 (off_canonical), never 9 (manifest_integrity), on a
    faithfully-attested fork archive. Exit 9 outranks 7, so a spurious integrity
    verdict would MASK the honest off-canonical verdict."""
    from click.testing import CliRunner

    d, _ = await _make_multifile_forked_dir(tmp_path)
    # The manifest PEM supplies the verification key; no extra CLI args needed.
    result = CliRunner().invoke(cli, ["verify", str(d)])
    assert result.exit_code == EXIT_OFF_CANONICAL


# ---------------------------------------------------------------------------
# Manifest pubkey_id mismatch (occurs in real evento data)
# ---------------------------------------------------------------------------


async def test_manifest_pubkey_id_mismatch_reported(tmp_path: Path) -> None:
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 4)
    # Corrupt only the CLAIMED id; keep the real PEM.
    _rewrite_manifest(d, pubkey_id="deadbeefdeadbeef")

    r = verify_tree(d)
    finding = [f for f in r.findings if f.kind == "manifest_pubkey_id_mismatch"]
    assert finding, "expected a manifest_pubkey_id_mismatch finding"
    # The key was still DERIVED from the PEM, so verification succeeded.
    assert r.verified_records == 4
    assert r.manifest_pubkey_id_claimed == "deadbeefdeadbeef"
    assert r.manifest_pubkey_id_derived == compute_key_id(sk.public_key)
    assert r.outcome == ChainCheckOutcome.MANIFEST_PUBKEY_MISMATCH


# ---------------------------------------------------------------------------
# Whole-chain deletion — detected via manifest (previously passed exit 0)
# ---------------------------------------------------------------------------


async def test_whole_chain_deletion_detected(tmp_path: Path) -> None:
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    clock = _Clock(datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc))
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk), clock=clock)
    # chain c1 on day 1
    rec1 = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec1, 3, start=0)
    # chain c2 on day 2 (separate file)
    clock.when = datetime(2026, 7, 2, 12, 0, tzinfo=timezone.utc)
    rec2 = AuditRecorder(sink=sink, signing_key=sk, chain_id="c2")
    await _emit(rec2, 3, start=3)

    # Delete the entire day-2 file (whole chain c2 gone). Manifest still attests it.
    (d / "audit-2026-07-02.jsonl").unlink()

    r = verify_tree(d)
    assert any(f.kind == "whole_chain_missing" for f in r.findings)
    assert r.outcome == ChainCheckOutcome.CHAIN_BREAK
    assert not r.is_valid  # explicitly NOT exit 0


# ---------------------------------------------------------------------------
# Front-truncation — genesis dropped
# ---------------------------------------------------------------------------


async def test_front_truncation_detected_in_directory(tmp_path: Path) -> None:
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 5)
    fpath = next(d.glob("audit-*.jsonl"))
    lines = fpath.read_text().splitlines()
    fpath.write_text("\n".join(lines[1:]) + "\n")  # drop genesis

    r = verify_tree(d)
    assert any(f.kind == "front_truncation" for f in r.findings)
    assert r.outcome == ChainCheckOutcome.CHAIN_BREAK


async def test_front_truncation_real_genesis_guard_single_file(
    tmp_path: Path,
) -> None:
    """REAL test for the front-truncation / genesis guard (verify.py genesis
    branch). The old test doctored a SIGNED field, so the signature check fired
    first and the genesis guard was never exercised — a tautology. Here we drop
    the true genesis line so the SECOND record (whose signature is untouched and
    valid) becomes the first-seen record of its chain with a non-null prev_hash.
    That must trip the genesis guard as a CHAIN_BREAK, not a signature failure."""
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    recs = await _emit(rec, 3)
    fpath = next(d.glob("audit-*.jsonl"))
    lines = fpath.read_text().splitlines()
    fpath.write_text("\n".join(lines[1:]) + "\n")  # drop genesis line

    r = verify_log(fpath, {sk.key_id: sk.public_key})
    # The now-first record still has a VALID signature over its own (non-null)
    # prev_hash, so this is NOT a signature failure — it is the genesis guard.
    assert r.outcome == ChainCheckOutcome.CHAIN_BREAK
    assert r.failed_at_offset == 1
    assert "non-null" in (r.failure_detail or "")
    # sanity: the exposed record really is intact under the key
    from chiplog.integrity import verify_record

    exposed = json.loads(lines[1])
    assert verify_record(exposed, {sk.key_id: sk.public_key}).is_valid
    # prove it: the untampered record's own signature verifies, ruling out SIG_FAIL
    assert recs[1]["envelope"]["prev_hash"] is not None  # type: ignore[index]


# ---------------------------------------------------------------------------
# Manifest absent / corrupt — degrade, never crash, never a silent pass
# ---------------------------------------------------------------------------


async def test_manifest_absent_degrades_to_log_only(tmp_path: Path) -> None:
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 4)
    (d / "manifest.json").unlink()

    # Must not crash; must note the skipped cross-check.
    r = verify_tree(d, {sk.key_id: sk.public_key})
    assert r.manifest_present is False
    assert any(f.kind == "manifest_absent" for f in r.findings)


async def test_manifest_corrupt_degrades_to_log_only(tmp_path: Path) -> None:
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 4)
    (d / "manifest.json").write_text("{ this is not valid json ")

    r = verify_tree(d, {sk.key_id: sk.public_key})
    assert r.manifest_present is False
    assert any(f.kind == "manifest_corrupt" for f in r.findings)


# ---------------------------------------------------------------------------
# Tamper still dominates in directory mode
# ---------------------------------------------------------------------------


async def test_tampered_record_is_signature_fail_in_directory(
    tmp_path: Path,
) -> None:
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 4)
    fpath = next(d.glob("audit-*.jsonl"))
    lines = fpath.read_text().splitlines()
    r0 = json.loads(lines[1])
    r0["payload"]["input"] = {"tampered": True}
    lines[1] = json.dumps(r0)
    fpath.write_text("\n".join(lines) + "\n")

    r = verify_tree(d)
    assert r.outcome == ChainCheckOutcome.SIGNATURE_FAIL


def test_record_status_enum_covers_the_four_cases() -> None:
    assert {s.value for s in RecordStatus} == {
        "verified",
        "unverifiable_no_key",
        "invalid",
        "malformed",
    }


# ---------------------------------------------------------------------------
# CLI end-to-end exit codes
# ---------------------------------------------------------------------------


async def test_cli_verify_directory_off_canonical_exit_7(tmp_path: Path) -> None:
    from click.testing import CliRunner

    d, _ = await _make_forked_dir(tmp_path)
    result = CliRunner().invoke(cli, ["verify", str(d)])
    assert result.exit_code == EXIT_OFF_CANONICAL
    assert "OFF-CANONICAL" in result.output


async def test_cli_verify_directory_clean_exit_0(tmp_path: Path) -> None:
    from click.testing import CliRunner

    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 4)
    result = CliRunner().invoke(cli, ["verify", str(d)])
    assert result.exit_code == EXIT_OK
    assert "PASS" in result.output


async def test_cli_verify_directory_whole_chain_deletion_exit_1(
    tmp_path: Path,
) -> None:
    from click.testing import CliRunner

    sk, _ = _mkkey()
    d = tmp_path / "audit"
    clock = _Clock(datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc))
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk), clock=clock)
    rec1 = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec1, 3, start=0)
    clock.when = datetime(2026, 7, 2, 12, 0, tzinfo=timezone.utc)
    rec2 = AuditRecorder(sink=sink, signing_key=sk, chain_id="c2")
    await _emit(rec2, 3, start=3)
    (d / "audit-2026-07-02.jsonl").unlink()

    result = CliRunner().invoke(cli, ["verify", str(d)])
    assert result.exit_code == EXIT_CHAIN_BREAK


async def test_cli_verify_directory_pubkey_mismatch_exit_8(tmp_path: Path) -> None:
    from click.testing import CliRunner

    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id="c1")
    await _emit(rec, 4)
    _rewrite_manifest(d, pubkey_id="deadbeefdeadbeef")
    result = CliRunner().invoke(cli, ["verify", str(d)])
    assert result.exit_code == EXIT_MANIFEST_MISMATCH


async def test_cli_partial_exit_6(tmp_path: Path) -> None:
    """A directory whose only defect is a missing key exits 6 (partial)."""
    from click.testing import CliRunner

    sk_a, _ = _mkkey()
    sk_b, kid_b = _mkkey()
    d = tmp_path / "audit"
    sink_a = LocalFileSink(dir=d, pubkey_pem=_pem(sk_a))
    rec_a = AuditRecorder(sink=sink_a, signing_key=sk_a, chain_id="c1")
    recs = await _emit(rec_a, 3, start=0)
    head = compute_chain_link(recs[-1])
    sink_b = LocalFileSink(dir=d, pubkey_pem=_pem(sk_b))
    rec_b = AuditRecorder(
        sink=sink_b, signing_key=sk_b, chain_id="c1", initial_prev_hash=head
    )
    await _emit(rec_b, 3, start=3)
    # Drop A from the manifest so its 3 records are the only remaining defect.
    # Rotation used to do this to us; now it has to be asked for.
    _strip_pubkeys_except(d, {kid_b: _pem(sk_b)})

    result = CliRunner().invoke(cli, ["verify", str(d)])
    assert result.exit_code == EXIT_PARTIAL
    assert "PARTIAL" in result.output


# ---------------------------------------------------------------------------
# Manifest count/file anchor — injection & count-lies now carry exit teeth
#
# These reproduce the product's worst failure: a tampered log that verifies
# CLEAN (exit 0, is_valid: true). The manifest attests a per-chain record_count
# and per-file sha256 + record_count; the verifier must treat any disagreement
# between the log and its own manifest anchor as a non-zero integrity break.
# ---------------------------------------------------------------------------


async def _clean_dir(
    tmp_path: Path, n: int = 5, chain_id: str = "c1"
) -> tuple[Path, SigningKey]:
    sk, _ = _mkkey()
    d = tmp_path / "audit"
    sink = LocalFileSink(dir=d, pubkey_pem=_pem(sk))
    rec = AuditRecorder(sink=sink, signing_key=sk, chain_id=chain_id)
    await _emit(rec, n)
    return d, sk


async def test_injected_record_overcount_is_nonzero(tmp_path: Path) -> None:
    """Duplicating a record line — the log has MORE records than the manifest
    attests — must NOT verify clean. The duplicate is byte-identical, so it is
    still signature-valid and on the canonical path; only the count anchor
    catches it."""
    d, sk = await _clean_dir(tmp_path, 5)
    fpath = next(d.glob("audit-*.jsonl"))
    lines = fpath.read_text().splitlines()
    fpath.write_text("\n".join(lines + [lines[-1]]) + "\n")  # duplicate the head

    r = verify_tree(d, {sk.key_id: sk.public_key})
    assert not r.is_valid  # the whole point: this is NOT a pass
    assert r.outcome == ChainCheckOutcome.MANIFEST_INTEGRITY
    assert any(f.kind == "count_mismatch" for f in r.findings)


async def test_manifest_record_count_lie_undercount_is_nonzero(
    tmp_path: Path,
) -> None:
    """A manifest that attests MORE canonical records than the log actually
    contains (the count-lie, under-count direction) is an integrity break."""
    d, sk = await _clean_dir(tmp_path, 5)
    _materialize_manifest(d)
    m = json.loads((d / "manifest.json").read_text())
    m["chains"]["c1"]["record_count"] = 99999
    (d / "manifest.json").write_text(json.dumps(m, indent=2))

    r = verify_tree(d, {sk.key_id: sk.public_key})
    assert not r.is_valid
    assert r.outcome == ChainCheckOutcome.MANIFEST_INTEGRITY
    assert any(f.kind == "count_mismatch" for f in r.findings)


async def test_manifest_file_sha256_lie_is_nonzero(tmp_path: Path) -> None:
    """A file whose actual sha256 disagrees with the manifest's per-file
    attestation is an integrity break, even with the chain count intact."""
    d, sk = await _clean_dir(tmp_path, 5)
    _materialize_manifest(d)
    m = json.loads((d / "manifest.json").read_text())
    fname = next(iter(m["files"]))
    m["files"][fname]["sha256"] = "0" * 64  # attest a sha the file does not have
    (d / "manifest.json").write_text(json.dumps(m, indent=2))

    r = verify_tree(d, {sk.key_id: sk.public_key})
    assert not r.is_valid
    assert r.outcome == ChainCheckOutcome.MANIFEST_INTEGRITY
    assert any(f.kind == "file_sha256_mismatch" for f in r.findings)


async def test_manifest_file_record_count_lie_is_nonzero(tmp_path: Path) -> None:
    """A file whose actual line-count disagrees with the manifest's per-file
    record_count is an integrity break (sha256 left honest to isolate the
    count check)."""
    d, sk = await _clean_dir(tmp_path, 5)
    _materialize_manifest(d)
    m = json.loads((d / "manifest.json").read_text())
    fname = next(iter(m["files"]))
    m["files"][fname]["record_count"] = 4  # 5 records are actually present
    (d / "manifest.json").write_text(json.dumps(m, indent=2))

    r = verify_tree(d, {sk.key_id: sk.public_key})
    assert not r.is_valid
    assert r.outcome == ChainCheckOutcome.MANIFEST_INTEGRITY
    assert any(f.kind == "file_record_count_mismatch" for f in r.findings)


async def test_count_mismatch_finding_does_not_guess_cause(tmp_path: Path) -> None:
    """The count anchor states the fact — attested vs reconstructed — and does
    not speculate about why they differ."""
    d, sk = await _clean_dir(tmp_path, 5)
    _materialize_manifest(d)
    m = json.loads((d / "manifest.json").read_text())
    m["chains"]["c1"]["record_count"] = 3
    (d / "manifest.json").write_text(json.dumps(m, indent=2))
    r = verify_tree(d, {sk.key_id: sk.public_key})
    cm = [f for f in r.findings if f.kind == "count_mismatch"]
    assert cm
    detail = cm[0].detail
    assert "manifest attests" in detail
    assert "reconstructed" in detail


async def test_clean_directory_still_passes_with_file_checks(
    tmp_path: Path,
) -> None:
    """An untampered directory whose files exactly match their manifest
    attestation must still be a clean pass — no false positives from the new
    per-file cross-check."""
    d, sk = await _clean_dir(tmp_path, 6)
    r = verify_tree(d, {sk.key_id: sk.public_key})
    assert r.outcome == ChainCheckOutcome.OK
    assert r.is_valid
    assert not any(
        f.kind
        in {"count_mismatch", "file_sha256_mismatch", "file_record_count_mismatch"}
        for f in r.findings
    )


async def test_cli_verify_injected_record_exit_9(tmp_path: Path) -> None:
    from click.testing import CliRunner

    d, _ = await _clean_dir(tmp_path, 5)
    fpath = next(d.glob("audit-*.jsonl"))
    lines = fpath.read_text().splitlines()
    fpath.write_text("\n".join(lines + [lines[-1]]) + "\n")

    result = CliRunner().invoke(cli, ["verify", str(d)])
    assert result.exit_code == EXIT_MANIFEST_INTEGRITY
    assert "PASS" not in result.output.split("VERDICT")[-1]


async def test_cli_verify_manifest_count_lie_exit_9(tmp_path: Path) -> None:
    from click.testing import CliRunner

    d, _ = await _clean_dir(tmp_path, 5)
    _materialize_manifest(d)
    m = json.loads((d / "manifest.json").read_text())
    m["chains"]["c1"]["record_count"] = 99999
    (d / "manifest.json").write_text(json.dumps(m, indent=2))

    result = CliRunner().invoke(cli, ["verify", str(d)])
    assert result.exit_code == EXIT_MANIFEST_INTEGRITY


# ---------------------------------------------------------------------------
# Real-data proof — copy the real archive read-only, never touch the original
# ---------------------------------------------------------------------------

_REAL_ARCHIVE = Path.home() / ".config" / "chiplog"


@pytest.mark.skipif(
    not (_REAL_ARCHIVE / "manifest.json").is_file(),
    reason="no real ~/.config/chiplog archive present",
)
async def test_real_archive_injection_flips_exit(tmp_path: Path) -> None:
    """On a WRITABLE COPY of the real archive (originals never touched): an
    intact copy verifies clean (exit 0), and duplicating a single record line
    flips it to a non-zero manifest-integrity break."""
    d = tmp_path / "realcopy"
    shutil.copytree(_REAL_ARCHIVE, d)
    (d / "state.lock").unlink(missing_ok=True)
    (d / "signing.key").unlink(missing_ok=True)

    intact = verify_tree(d)
    assert intact.outcome == ChainCheckOutcome.OK
    assert intact.is_valid

    newest = sorted(d.glob("audit-*.jsonl"))[-1]
    lines = newest.read_text().splitlines()
    newest.write_text("\n".join(lines + [lines[-1]]) + "\n")

    tampered = verify_tree(d)
    assert tampered.outcome == ChainCheckOutcome.MANIFEST_INTEGRITY
    assert not tampered.is_valid
    assert any(f.kind == "count_mismatch" for f in tampered.findings)
    assert any(f.kind == "file_sha256_mismatch" for f in tampered.findings)
