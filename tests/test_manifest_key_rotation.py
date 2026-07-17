"""Rotation must not destroy the previous key's records.

The manifest held ONE `pubkey_pem` and `LocalFileSink.__init__` overwrote it
unconditionally. So the moment a recorder started with a different key, the
previous public key was gone from the only place it was stored, and every
record signed with it became permanently unverifiable. Not harder to verify —
there is no key left to check the signature against, and nothing recovers it.

This is not theoretical. On bosun's evento chains, 330 records
(`evento-2026-06-30`, `evento-2026-07-01`, and the first 16 of
`evento-2026-07-02`) are permanently unverifiable, signed with a key that
exists nowhere: `KEY_RESOLUTION at offset 1: unknown_key_id: no public key for
key_id=b0ee6d6c582ec87b`. The destruction is timestamped 2026-07-02T08:38:01Z,
matching the new key's mtime exactly. The host's contribution was minting a new
key when the file was missing — but a host mistake must not be able to destroy
the verifiability of records already written. A single mutable field is what
turned a recoverable host bug into permanent evidence loss.

A public key is not secret. There is no reason for it to be single-copy in a
mutable field.

The test that mattered here is the one that already existed:
`test_key_rotation_midchain_both_keys_available` covered this exact scenario
and pinned the loss as correct — it passed the old key in from outside
(`verify_tree(d, {kid_a: ...})`) and asserted the resulting mismatch. In the
real incident nobody had the old key to pass in; that is the whole point. So
the scenario below deliberately hands `verify_tree` nothing: the manifest is
the offline verifier's only input, and it must be sufficient on its own.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chiplog.emit import AuditRecorder
from chiplog.integrity import compute_chain_link
from chiplog.keys import SigningKey, compute_key_id
from chiplog.manifest import Manifest
from chiplog.schema.v1 import NoGateReason, Output, ToolCall, success, ungated
from chiplog.sinks.local_file import LocalFileSink
from chiplog.verify import ChainCheckOutcome, verify_tree


def _mkkey() -> tuple[SigningKey, str]:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    kid = compute_key_id(pub)
    return SigningKey(private_key=pk, public_key=pub, key_id=kid), kid


def _pem(sk: SigningKey) -> bytes:
    return sk.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


async def _emit(recorder: AuditRecorder, n: int, start: int = 0) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for i in range(start, start + n):
        out.append(
            await recorder.record(
                session_id="sess",
                step_id=f"step-{i}",
                tool=ToolCall(name="Read"),
                input={"i": i},
                output=Output(body=""),
                policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
                outcome=success(),
            )
        )
    return out


async def _rotate(d: Path) -> tuple[str, str]:
    """Write 3 records under key A, then 3 more under key B. Returns (kid_a, kid_b)."""
    sk_a, kid_a = _mkkey()
    sink_a = LocalFileSink(dir=d, pubkey_pem=_pem(sk_a))
    rec_a = AuditRecorder(sink=sink_a, signing_key=sk_a, chain_id="c1")
    recs = await _emit(rec_a, 3)
    head = compute_chain_link(recs[-1])

    sk_b, kid_b = _mkkey()
    sink_b = LocalFileSink(dir=d, pubkey_pem=_pem(sk_b))
    rec_b = AuditRecorder(
        sink=sink_b, signing_key=sk_b, chain_id="c1", initial_prev_hash=head
    )
    await _emit(rec_b, 3, start=3)
    return kid_a, kid_b


async def test_rotation_keeps_the_old_key_in_the_manifest(tmp_path: Path) -> None:
    d = tmp_path / "audit"
    kid_a, kid_b = await _rotate(d)

    m = Manifest.load_or_create(d / "manifest.json")
    assert set(m.pubkeys) == {kid_a, kid_b}, (
        "rotation dropped a key from the manifest. Every record signed with it "
        "is now unverifiable forever — the manifest was the only place it was "
        "stored, and a public key is not secret."
    )


async def test_rotation_leaves_every_record_verifiable_offline(tmp_path: Path) -> None:
    d = tmp_path / "audit"
    await _rotate(d)

    # Nothing passed in: the manifest is the offline verifier's only input.
    r = verify_tree(d)
    assert r.unverifiable_no_key == 0, (
        "records became unverifiable for want of a key the manifest should have kept"
    )
    assert r.verified_records == 6
    assert r.outcome == ChainCheckOutcome.OK
