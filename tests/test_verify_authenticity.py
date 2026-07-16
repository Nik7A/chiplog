"""Wire redaction_authenticity() into the verifier.

Before this fix a tool-supplied look-alike marker was signed into a validly-
signed record and `chiplog verify` returned PASS over it, because the
verifier never called `redaction_authenticity()`. A forged/unbacked marker must
now surface as a finding with a non-zero exit, WITHOUT weakening any existing
verdict (a genuine record still passes).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chiplog.cli import cli
from chiplog.emit import AuditRecorder
from chiplog.keys import SigningKey, compute_key_id
from chiplog.schema.v1 import NoGateReason, Output, ToolCall, success, ungated
from chiplog.sinks.local_file import LocalFileSink
from chiplog.verify import ChainCheckOutcome, verify_log


@pytest.fixture
def kp(tmp_path: Path) -> tuple[SigningKey, Path]:
    pk = Ed25519PrivateKey.generate()
    pub_path = tmp_path / "signing.pub"
    pub_path.write_bytes(
        pk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    pub_path.chmod(0o644)
    pub = pk.public_key()
    sk = SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))
    return sk, pub_path


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


_FORGED = {
    "redacted": True,
    "type": "string",
    "length": 11,
    "policy": "pii.deny.email",
    "sha256": "0" * 64,
}


async def _emit_one(sink_dir: Path, sk: SigningKey, **over: Any) -> Path:
    sink = LocalFileSink(dir=sink_dir)
    recorder = AuditRecorder(sink=sink, signing_key=sk)
    await _record(recorder, **over)
    await recorder.flush()
    return next(sink_dir.glob("audit-*.jsonl"))


async def test_forged_marker_fails_verify_log(
    tmp_path: Path, kp: tuple[SigningKey, Path]
) -> None:
    sk, _ = kp
    # A tool that returns a marker-shaped dict with no backing entry — a forgery.
    log = await _emit_one(tmp_path / "a", sk, output=Output(body={"result": _FORGED}))
    result = verify_log(log, {sk.key_id: sk.public_key})
    assert result.outcome == ChainCheckOutcome.REDACTION_FORGERY
    assert not result.is_valid


async def test_genuine_record_still_passes_verify_log(
    tmp_path: Path, kp: tuple[SigningKey, Path]
) -> None:
    sk, _ = kp
    log = await _emit_one(tmp_path / "a", sk, input={"email": "foo@bar.com"})
    result = verify_log(log, {sk.key_id: sk.public_key})
    assert result.outcome == ChainCheckOutcome.OK
    assert result.is_valid


async def test_forged_marker_nonzero_exit_via_cli(
    tmp_path: Path, kp: tuple[SigningKey, Path]
) -> None:
    sk, pub_path = kp
    log = await _emit_one(tmp_path / "a", sk, output=Output(body={"fake": _FORGED}))
    runner = CliRunner()
    res = runner.invoke(cli, ["verify", str(log), "--pubkey", str(pub_path)])
    assert res.exit_code == 10  # EXIT_REDACTION_FORGERY


async def test_forged_marker_fails_verify_tree(
    tmp_path: Path, kp: tuple[SigningKey, Path]
) -> None:
    sk, pub_path = kp
    sink_dir = tmp_path / "tree"
    await _emit_one(sink_dir, sk, output=Output(body={"fake": _FORGED}))
    runner = CliRunner()
    res = runner.invoke(cli, ["verify", str(sink_dir), "--pubkey", str(pub_path)])
    assert res.exit_code == 10
    assert "redaction_forgery" in res.output or "forg" in res.output.lower()
