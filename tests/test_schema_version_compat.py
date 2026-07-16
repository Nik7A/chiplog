"""A v1.0 record — written before payload.outcome existed — must still verify.

This pins the property that makes the v1.1 schema bump safe: verification
operates on raw dicts and never validates against the Pydantic model. The
signature covers canonical bytes, not schema shape.

If this test fails, someone added model validation to the read path and just
made every previously written record unverifiable. Fix the read path, not
this test. The fixture is frozen bytes and must never be regenerated.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from chiplog.cli import EXIT_OK, cli
from chiplog.keys import load_public_key
from chiplog.verify import ChainCheckOutcome, verify_log

FIXTURES = Path(__file__).parent / "fixtures"


def _pubkeys() -> dict[str, Ed25519PublicKey]:
    """Load the frozen fixture's public key, keyed by key_id."""
    pubkey, key_id = load_public_key(FIXTURES / "v1_0_record.pub")
    return {key_id: pubkey}


def test_frozen_v1_0_record_still_verifies() -> None:
    result = verify_log(FIXTURES / "v1_0_record.jsonl", _pubkeys())
    assert result.outcome == ChainCheckOutcome.OK, result.failure_detail
    assert result.record_count == 1


def test_frozen_v1_0_record_has_no_outcome_field() -> None:
    """Guards the fixture itself: if this fails, the fixture was regenerated."""
    record = json.loads((FIXTURES / "v1_0_record.jsonl").read_text().splitlines()[0])
    assert record["envelope"]["schema_version"] == "v1.0"
    assert "outcome" not in record["payload"]


def test_cli_inspect_reads_frozen_v1_0_record() -> None:
    """SIGNING.md 9.1 lists `cli inspect` among the read paths that never
    validate against the Pydantic model. Pin that here too: if `cmd_inspect`
    ever grows a `Record.model_validate` call, this fails alongside the other
    three read paths covered above."""
    runner = CliRunner()
    result = runner.invoke(cli, ["inspect", str(FIXTURES / "v1_0_record.jsonl")])
    assert result.exit_code == EXIT_OK, result.output
    assert "line 1" in result.output
    assert "tool=read_file" in result.output
