"""Bench 2: sustained records/sec at single-core saturation.

This answers "how many concurrent agents can saturate one writer". Each
round writes 1 000 records back-to-back through the LocalFileSink path.
Throughput = 1000 / mean_round_seconds.

Why not InMemorySink for throughput? The crypto ceiling is already in
bench 1's `record_latency_in_memory` group. The interesting throughput
question is what survives F_FULLFSYNC, because that is what a customer
sees.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_audit.emit import AuditRecorder
from agent_audit.schema.v1 import Output, ToolCall

from conftest import BENCH_OUTCOME, BENCH_POLICY

RECORDS_PER_ROUND = 1000
ROUNDS = 5


def _bench_throughput(
    recorder: AuditRecorder,
    sample_input: dict[str, object],
    loop: asyncio.AbstractEventLoop,
) -> None:
    async def write_n() -> None:
        for i in range(RECORDS_PER_ROUND):
            await recorder.record(
                session_id="bench-throughput",
                step_id=f"step-{i}",
                tool=ToolCall(name="bench_tool"),
                input=sample_input,
                output=Output(body={"ok": True}),
                policy=BENCH_POLICY,
                outcome=BENCH_OUTCOME,
            )

    loop.run_until_complete(write_n())


@pytest.mark.benchmark(group="sustained_throughput")
def test_throughput_local_file(
    benchmark: object,
    recorder_local_file: AuditRecorder,
    sample_input: dict[str, object],
    bench_loop: asyncio.AbstractEventLoop,
) -> None:
    """Records/sec sustained through LocalFileSink with F_FULLFSYNC."""
    benchmark.pedantic(  # type: ignore[attr-defined]
        _bench_throughput,
        args=(recorder_local_file, sample_input, bench_loop),
        iterations=1,
        rounds=ROUNDS,
    )
    benchmark.extra_info["records_per_round"] = RECORDS_PER_ROUND  # type: ignore[attr-defined]
    benchmark.extra_info["sink"] = "LocalFileSink"  # type: ignore[attr-defined]
