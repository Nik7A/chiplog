"""Step 4: LocalFileSink — daily rotation, fsync, manifest, DiskFullError.

Covers BUILD_PLAN Step 4 verification gate:
- Records written are visible in JSONL and verifiable after restart
- Manifest tracks per-chain heads and per-file checksums
- Cross-process state recovery via initial_prev_hash from manifest
- Daily rotation (clock injection)
- ENOSPC surfaces as DiskFullError (no silent drop)
- Closed sink rejects writes
- redaction_disabled flag is recorded in manifest (self-audit checklist #12)
"""

from __future__ import annotations

import errno
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from agent_audit.emit import AuditRecorder
from agent_audit.integrity import compute_chain_link, verify_record
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.manifest import Manifest
from agent_audit.redact import RedactionConfig
from agent_audit.schema.v1 import NoGateReason, Output, ToolCall, success, ungated
from agent_audit.sinks.base import DiskFullError, SinkError
from agent_audit.sinks.local_file import LocalFileSink


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


@pytest.fixture
def pubkey_pem(signing_key: SigningKey) -> bytes:
    return signing_key.public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


def _ungated_record_args() -> dict[str, object]:
    return dict(
        session_id="sess-A",
        step_id="step-1",
        tool=ToolCall(name="Read"),
        input={"file_path": "/etc/hosts"},
        output=Output(body="127.0.0.1 localhost"),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )


# ---------------------------------------------------------------------------
# Smoke: write → file exists → record verifies → manifest tracks it
# ---------------------------------------------------------------------------


async def test_write_creates_jsonl_with_signed_record(
    tmp_path: Path, signing_key: SigningKey, pubkey_pem: bytes
) -> None:
    sink = LocalFileSink(dir=tmp_path, pubkey_pem=pubkey_pem)
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)

    signed = await recorder.record(**_ungated_record_args())  # type: ignore[arg-type]

    # File exists, has exactly one line
    jsonl_files = list(tmp_path.glob("audit-*.jsonl"))
    assert len(jsonl_files) == 1
    contents = jsonl_files[0].read_text(encoding="utf-8")
    assert contents.count("\n") == 1

    # Record on disk matches what record() returned
    on_disk = json.loads(contents.splitlines()[0])
    assert on_disk == signed

    # Verifier accepts it
    result = verify_record(signed, {signing_key.key_id: signing_key.public_key})
    assert result.is_valid


async def test_manifest_records_pubkey_chain_and_file_checksum(
    tmp_path: Path, signing_key: SigningKey, pubkey_pem: bytes
) -> None:
    sink = LocalFileSink(dir=tmp_path, pubkey_pem=pubkey_pem)
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)

    signed = await recorder.record(**_ungated_record_args())  # type: ignore[arg-type]

    # Manifest reloaded from disk should match on-disk state
    manifest = Manifest.load_or_create(tmp_path / "manifest.json")
    assert manifest.pubkey_id == signing_key.key_id
    assert manifest.pubkey_pem == pubkey_pem.decode("ascii")

    chain = manifest.chains["sess-A"]
    assert chain.record_count == 1
    assert chain.head_hash == compute_chain_link(signed)
    assert chain.genesis_hash == chain.head_hash
    assert chain.first_record_id == signed["envelope"]["record_id"]
    assert chain.last_record_id == signed["envelope"]["record_id"]

    # File checksum matches file on disk
    jsonl_path = next(tmp_path.glob("audit-*.jsonl"))
    on_disk_sha = hashlib.sha256(jsonl_path.read_bytes()).hexdigest()
    assert manifest.files[jsonl_path.name].sha256 == on_disk_sha
    assert manifest.files[jsonl_path.name].record_count == 1


# ---------------------------------------------------------------------------
# Cross-process recovery via initial_prev_hash
# ---------------------------------------------------------------------------


async def test_second_process_resumes_chain_via_manifest(
    tmp_path: Path, signing_key: SigningKey, pubkey_pem: bytes
) -> None:
    """The Claude Code hook handler runs as a fresh process per tool call.
    Resuming the chain requires reading manifest.chains[chain_id].head_hash
    and passing it to a new AuditRecorder as initial_prev_hash.
    """
    sink_a = LocalFileSink(dir=tmp_path, pubkey_pem=pubkey_pem)
    recorder_a = AuditRecorder(sink=sink_a, signing_key=signing_key)
    r1 = await recorder_a.record(**_ungated_record_args())  # type: ignore[arg-type]
    await recorder_a.close()

    # "Process restart" — fresh sink + fresh recorder.
    sink_b = LocalFileSink(dir=tmp_path, pubkey_pem=pubkey_pem)
    chain_state = sink_b.manifest.chains["sess-A"]
    recorder_b = AuditRecorder(
        sink=sink_b,
        signing_key=signing_key,
        chain_id="sess-A",
        initial_prev_hash=chain_state.head_hash,
    )
    r2 = await recorder_b.record(
        session_id="sess-A",
        step_id="step-2",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )

    # r2.prev_hash must equal compute_chain_link(r1) — chain continues across
    # the simulated process restart.
    assert r2["envelope"]["prev_hash"] == compute_chain_link(r1)

    # Manifest now reflects both records
    final_manifest = Manifest.load_or_create(tmp_path / "manifest.json")
    assert final_manifest.chains["sess-A"].record_count == 2
    assert final_manifest.chains["sess-A"].head_hash == compute_chain_link(r2)


# ---------------------------------------------------------------------------
# Daily rotation via injected clock
# ---------------------------------------------------------------------------


async def test_daily_rotation_writes_to_separate_files(
    tmp_path: Path, signing_key: SigningKey
) -> None:
    today = datetime(2026, 6, 19, 23, 59, 0, tzinfo=timezone.utc)
    tomorrow = today + timedelta(hours=1)

    state = {"now": today}
    sink = LocalFileSink(dir=tmp_path, clock=lambda: state["now"])
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)

    await recorder.record(**_ungated_record_args())  # type: ignore[arg-type]
    state["now"] = tomorrow
    await recorder.record(
        session_id="sess-A",
        step_id="step-2",
        tool=ToolCall(name="Read"),
        input={},
        output=Output(body=""),
        policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        outcome=success(),
    )

    assert (tmp_path / "audit-2026-06-19.jsonl").exists()
    assert (tmp_path / "audit-2026-06-20.jsonl").exists()
    assert (tmp_path / "audit-2026-06-19.jsonl").read_text().count("\n") == 1
    assert (tmp_path / "audit-2026-06-20.jsonl").read_text().count("\n") == 1


# ---------------------------------------------------------------------------
# DiskFullError — never silent drop
# ---------------------------------------------------------------------------


async def test_disk_full_surfaces_as_disk_full_error(
    tmp_path: Path, signing_key: SigningKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = LocalFileSink(dir=tmp_path)
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)

    # Patch the open builtin used in the sinks module to fake ENOSPC.
    real_open = open

    def fake_open(*args: object, **kwargs: object) -> object:
        # Allow reads through; fail on append (write) opens.
        mode = args[1] if len(args) > 1 else kwargs.get("mode", "r")
        if "a" in str(mode) or "w" in str(mode):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        "agent_audit.sinks.local_file.open", fake_open, raising=False
    )

    with pytest.raises(DiskFullError, match="disk space"):
        await recorder.record(**_ungated_record_args())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Closed sink
# ---------------------------------------------------------------------------


async def test_closed_sink_rejects_writes(
    tmp_path: Path, signing_key: SigningKey
) -> None:
    sink = LocalFileSink(dir=tmp_path)
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)
    await recorder.close()

    with pytest.raises(SinkError):
        await recorder.record(**_ungated_record_args())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Self-audit checklist #12: disabled redaction visible in manifest
# ---------------------------------------------------------------------------


async def test_disabled_redaction_is_recorded_in_manifest(
    tmp_path: Path, signing_key: SigningKey
) -> None:
    sink = LocalFileSink(dir=tmp_path, redaction_disabled=True)
    recorder = AuditRecorder(
        sink=sink,
        signing_key=signing_key,
        redaction_config=RedactionConfig(disable=True),
    )
    await recorder.record(**_ungated_record_args())  # type: ignore[arg-type]

    manifest = Manifest.load_or_create(tmp_path / "manifest.json")
    assert manifest.redaction_disabled is True


async def test_default_redaction_state_is_recorded_as_enabled(
    tmp_path: Path, signing_key: SigningKey
) -> None:
    sink = LocalFileSink(dir=tmp_path)
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)
    await recorder.record(**_ungated_record_args())  # type: ignore[arg-type]

    manifest = Manifest.load_or_create(tmp_path / "manifest.json")
    assert manifest.redaction_disabled is False


# ---------------------------------------------------------------------------
# Multi-record file checksum advances correctly
# ---------------------------------------------------------------------------


async def test_rolling_sha256_matches_file_after_many_writes(
    tmp_path: Path, signing_key: SigningKey
) -> None:
    sink = LocalFileSink(dir=tmp_path)
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)

    for i in range(25):
        await recorder.record(
            session_id="sess-A",
            step_id=f"step-{i}",
            tool=ToolCall(name="Read"),
            input={},
            output=Output(body=""),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            outcome=success(),
        )

    jsonl = next(tmp_path.glob("audit-*.jsonl"))
    on_disk_sha = hashlib.sha256(jsonl.read_bytes()).hexdigest()
    manifest = Manifest.load_or_create(tmp_path / "manifest.json")
    assert manifest.files[jsonl.name].sha256 == on_disk_sha
    assert manifest.files[jsonl.name].record_count == 25
    assert manifest.chains["sess-A"].record_count == 25
