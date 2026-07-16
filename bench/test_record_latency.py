"""Bench 1: per-record sign+chain+write latency.

Two sinks, three payload sizes — six measurements total. The InMemorySink
result is the "pure crypto" ceiling; the LocalFileSink result includes
F_FULLFSYNC, which is the cost a real customer pays.

Reading the output:
- `mean / iterations` = per-record latency in microseconds
- `ops` = records/sec at single-record cadence (no batching, no parallelism)

`iterations=100` per round amortises the asyncio.run_until_complete overhead;
the inner loop is what we actually want to measure.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_audit.emit import AuditRecorder
from agent_audit.schema.v1 import Output, ToolCall

from conftest import BENCH_OUTCOME, BENCH_POLICY

ITERATIONS_PER_ROUND = 100
ROUNDS = 20


def _bench_records(
    recorder: AuditRecorder,
    sample_input: dict[str, object],
    loop: asyncio.AbstractEventLoop,
) -> None:
    async def write_batch() -> None:
        for _ in range(ITERATIONS_PER_ROUND):
            await recorder.record(
                session_id="bench-latency",
                step_id="step-000",
                tool=ToolCall(name="bench_tool"),
                input=sample_input,
                output=Output(body={"ok": True}),
                policy=BENCH_POLICY,
                outcome=BENCH_OUTCOME,
            )

    loop.run_until_complete(write_batch())


@pytest.mark.benchmark(group="record_latency_in_memory")
def test_latency_in_memory(
    benchmark: object,
    recorder_in_memory: AuditRecorder,
    sample_input: dict[str, object],
    bench_loop: asyncio.AbstractEventLoop,
) -> None:
    """Sign + chain + canonicalise, no disk. Crypto ceiling."""
    benchmark.pedantic(  # type: ignore[attr-defined]
        _bench_records,
        args=(recorder_in_memory, sample_input, bench_loop),
        iterations=1,
        rounds=ROUNDS,
    )
    benchmark.extra_info["records_per_round"] = ITERATIONS_PER_ROUND  # type: ignore[attr-defined]
    benchmark.extra_info["sink"] = "InMemorySink"  # type: ignore[attr-defined]


@pytest.mark.benchmark(group="record_latency_local_file")
def test_latency_local_file(
    benchmark: object,
    recorder_local_file: AuditRecorder,
    sample_input: dict[str, object],
    bench_loop: asyncio.AbstractEventLoop,
) -> None:
    """Sign + chain + canonicalise + JSONL write + F_FULLFSYNC. Real customer path."""
    benchmark.pedantic(  # type: ignore[attr-defined]
        _bench_records,
        args=(recorder_local_file, sample_input, bench_loop),
        iterations=1,
        rounds=ROUNDS,
    )
    benchmark.extra_info["records_per_round"] = ITERATIONS_PER_ROUND  # type: ignore[attr-defined]
    benchmark.extra_info["sink"] = "LocalFileSink"  # type: ignore[attr-defined]
