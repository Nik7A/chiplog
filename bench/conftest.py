"""Shared fixtures for the benchmark suite.

These benches measure the current hot path: enter the commit section (_ChainLock)
-> redact -> normalize -> build -> sign -> chain -> sink write.
They are intentionally separate from `tests/` and not collected by the default
`pytest` run (see `testpaths` in pyproject.toml). Run with:

    uv run pytest bench/ --benchmark-only --benchmark-columns=mean,stddev,ops,rounds
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_audit.emit import AuditRecorder
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.schema.v1 import (
    OutcomeContext,
    PolicyContext,
    PolicyUnobservedReason,
    policy_unobserved,
    success,
)
from agent_audit.sinks.base import InMemorySink
from agent_audit.sinks.local_file import LocalFileSink

# The bench models a plain successful tool call with no gate mechanism in front
# of it. Both fields are REQUIRED by `record()` and both are positive assertions,
# so the bench states only what the harness actually observes:
#
#   - outcome: the harness calls no real tool; it constructs the success itself,
#     so `success()` is observed, not assumed.
#   - policy: there is no gate engine in the bench at all. The old
#     `ungated(AUTO_ALLOWED_LOW_RISK)` asserted BOTH "no gate fired" AND "low
#     risk" — neither of which this harness observes. `policy_unobserved` is the
#     honest floor. It carries the same per-record cost through redact /
#     normalize / JCS, so nothing measured is weakened by the swap.
BENCH_POLICY: PolicyContext = policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL)
BENCH_OUTCOME: OutcomeContext = success()


@pytest.fixture(scope="session")
def signing_key() -> SigningKey:
    """One Ed25519 keypair generated in memory for the whole bench session.

    No file I/O, no permission checks — keeps the bench setup time out of
    the measurement.
    """
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    return SigningKey(
        private_key=private,
        public_key=public,
        key_id=compute_key_id(public),
    )


@pytest.fixture(scope="session")
def bench_loop() -> Iterator[asyncio.AbstractEventLoop]:
    """One event loop reused across all bench iterations.

    AuditRecorder.record is async. Reusing one loop avoids the ~100-500us
    asyncio.run() setup cost per iteration, which would otherwise dominate
    sub-millisecond measurements.
    """
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


def _input_payload(size_bytes: int) -> dict[str, object]:
    """Synthetic tool-call input payload of approximately `size_bytes`.

    Shape mimics a realistic MCP tool call: nested dict with a string field
    that absorbs the bulk of the size. Not pathological; not microscopic.
    """
    pad_len = max(0, size_bytes - 200)
    return {
        "method": "search",
        "params": {
            "query": "x" * pad_len,
            "limit": 50,
            "filters": {"status": "active", "tier": ["gold", "platinum"]},
        },
        "request_id": "bench-req-0001",
    }


@pytest.fixture(scope="session", params=[256, 2048, 8192], ids=["256B", "2KB", "8KB"])
def sample_input(request: pytest.FixtureRequest) -> dict[str, object]:
    """Three payload sizes — small, medium, ai-agent-audit's ~8KiB record ceiling."""
    return _input_payload(int(request.param))


@pytest.fixture
def recorder_in_memory(signing_key: SigningKey) -> AuditRecorder:
    """Recorder with zero-I/O sink. Measures pure crypto + canonicalisation."""
    return AuditRecorder(sink=InMemorySink(), signing_key=signing_key)


@pytest.fixture
def recorder_local_file(
    tmp_path: Path, signing_key: SigningKey
) -> AuditRecorder:
    """Recorder with LocalFileSink. Includes JSONL write + F_FULLFSYNC."""
    sink = LocalFileSink(dir=tmp_path / "audit")
    return AuditRecorder(sink=sink, signing_key=signing_key)


@pytest.fixture(scope="session")
def prepopulated_dir(
    tmp_path_factory: pytest.TempPathFactory, signing_key: SigningKey
) -> Path:
    """A 10 000-record audit DIRECTORY (JSONL + manifest) for verifier benches.

    Built once per session. Each record is ~2KB so the file approximates
    a typical day's audit volume on a medium-traffic agent fleet.

    Returns the directory, not the file, because the auditor-facing entry point
    (`verify_tree`) takes a directory: it cross-checks the manifest and digests
    each file. `prepopulated_jsonl` narrows this to the single log file for the
    per-record bench.
    """
    out_dir = tmp_path_factory.mktemp("verifier_corpus")
    sink = LocalFileSink(dir=out_dir)
    recorder = AuditRecorder(sink=sink, signing_key=signing_key)

    payload = _input_payload(2048)

    from agent_audit.schema.v1 import Output, ToolCall

    async def populate() -> None:
        for i in range(10_000):
            await recorder.record(
                session_id="bench-session",
                step_id=f"step-{i:05d}",
                tool=ToolCall(name="bench_tool"),
                input=payload,
                output=Output(body={"ok": True, "row_count": 42}),
                policy=BENCH_POLICY,
                outcome=BENCH_OUTCOME,
            )
        await sink.close()

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(populate())
    finally:
        loop.close()

    if not sorted(out_dir.glob("audit-*.jsonl")):
        raise RuntimeError("verifier corpus generation produced no JSONL file")
    return out_dir


@pytest.fixture(scope="session")
def prepopulated_jsonl(prepopulated_dir: Path) -> Path:
    """The single JSONL log file inside the session corpus directory."""
    jsonl_files = sorted(prepopulated_dir.glob("audit-*.jsonl"))
    if not jsonl_files:
        raise RuntimeError("verifier corpus generation produced no JSONL file")
    return jsonl_files[0]


@pytest.fixture(scope="session")
def prepopulated_pubkey_by_id(
    signing_key: SigningKey,
) -> dict[str, object]:
    """Pubkey lookup dict matching the corpus, indexed by key_id."""
    return {signing_key.key_id: signing_key.public_key}
