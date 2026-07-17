"""Structural: the NON-CLAIMS block may not name a release.

The NON-CLAIMS block is the one paragraph an auditor reads to learn what a
verification report does NOT establish. Reports are byte-deterministic by
design so they can be pasted verbatim into an audit appendix — so whatever
this block says travels into that appendix under a hash that matches across
reviewers. It is the worst place in the product for a false claim.

Through 0.2.0 it carried three. It said the limits were "fixed in v0.2", that
"v0.2 closes this with the sidecar signer", and that "v0.2 adds RFC 3161 TSA
timestamps". None of it shipped: README and ROADMAP both say v0.2 closed none
of them and carry all three into v0.3. The text was written when v0.2 was
still planned to carry the hardening, and the two later passes that corrected
exactly this class of claim in the docs both missed it, because it is a string
in code rather than prose in a file.

That makes the drift structural, not a typo. The docs are rewritten at every
release and this constant is not, so "keep the version numbers accurate" is a
rule that will fail again the same way. The enforceable rule is that the block
names no release at all: what is unproven today is unproven whichever release
closes it, and where a limit is headed belongs in ROADMAP.md — the document
that actually gets updated.

An earlier test asserted the block was present. Presence was never the
problem. It was present, and it lied.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chiplog.emit import AuditRecorder
from chiplog.keys import SigningKey, compute_key_id
from chiplog.report import format_text_report, format_tree_text_report
from chiplog.schema.v1 import NoGateReason, Output, ToolCall, success, ungated
from chiplog.sinks.local_file import LocalFileSink
from chiplog.verify import verify_log, verify_tree

# Any dotted release reference: v0.2, v1.0, 0.2.1, "v0.3 adds".
_RELEASE = re.compile(r"\bv?\d+\.\d+(?:\.\d+)?\b")

_NON_CLAIMS_MARKER = "does NOT prove"


@pytest.fixture
def sk() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


async def _emit_into(dir_: Path, sk: SigningKey, n: int = 2) -> LocalFileSink:
    sink = LocalFileSink(dir=dir_)
    recorder = AuditRecorder(sink=sink, signing_key=sk)
    for i in range(n):
        await recorder.record(
            session_id="sess",
            step_id=f"step-{i}",
            tool=ToolCall(name="Read"),
            input={"i": i},
            output=Output(body=""),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            outcome=success(),
        )
    return sink


def _non_claims_section(report: str) -> str:
    """The block as an auditor reads it: the marker line to end of report."""
    at = report.find(_NON_CLAIMS_MARKER)
    assert at != -1, "report carries no NON-CLAIMS block at all"
    return report[at:]


def _assert_names_no_release(section: str) -> None:
    found = _RELEASE.findall(section)
    assert not found, (
        f"NON-CLAIMS block names {found} — a report may not tell an auditor "
        f"which release closed, or will close, a limit it cannot prove. "
        f"State the limit as open and point at ROADMAP.md.\n\n{section}"
    )


async def test_log_report_non_claims_names_no_release(
    tmp_path: Path, sk: SigningKey
) -> None:
    await _emit_into(tmp_path / "audit", sk)
    jsonl = next((tmp_path / "audit").glob("audit-*.jsonl"))
    report = format_text_report(verify_log(jsonl, {sk.key_id: sk.public_key}))
    _assert_names_no_release(_non_claims_section(report))


async def test_tree_report_non_claims_names_no_release(
    tmp_path: Path, sk: SigningKey
) -> None:
    d = tmp_path / "audit"
    await _emit_into(d, sk)
    (d / "signing.pub").write_bytes(
        sk.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    report = format_tree_text_report(verify_tree(d))
    _assert_names_no_release(_non_claims_section(report))
