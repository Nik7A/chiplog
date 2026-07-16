"""Bench 4: throughput when N tool calls hit ONE recorder at once.

This is the bench the v0.1 suite did not have, and the one that matters most
for v0.2. Benches 1-2 drive a single caller, so they never touch the commit
section's contention behaviour — they measure the uncontended path and say
nothing about what happens when a real agent fans out.

A real agent fans out. LangGraph's `ToolNode` runs parallel tool calls through
`executor.map(self._run_one, ...)`, and parallel tool calls are the default
under `create_agent` — so many-threads-one-recorder is the FIRST turn of a real
agent, not an exotic case.

v0.2 serialises the whole commit section per recorder (`_ChainLock`): redact ->
normalize -> build -> sign -> chain -> `sink.write` all run under one holder.
That is deliberate and it is not free: one recorder is now one writer, so its
concurrent ceiling is its serial ceiling, and callers queue. This bench measures
that ceiling honestly rather than letting benches 1-2 imply a number that only
holds for a single caller.

Both concurrency shapes the library actually meets are measured, because they
cost different things:

- THREADS calling `record_sync` — the LangGraph `ToolNode` path. Note this
  includes `asyncio.run()` per call (record_sync spins a throwaway loop). That
  overhead is real and paid by that caller on that path, so it stays in.
- COROUTINES calling `record()` via `asyncio.gather` on one loop — the async
  `ToolNode` path. No per-call loop setup; contention only.

Total records per round matches `test_sustained_throughput.py` (1 000) so the
concurrent number can be read directly against the serial one. Throughput =
1000 / mean_round_seconds.

What this bench does NOT assert: that v0.1's higher concurrent number was
better. v0.1 had no commit section, so concurrent callers there interleaved
`prev_hash` reads and `sink.write` — a forked chain and a manifest attesting a
checksum the file does not have. The v0.2 number is what a chain that cannot
fork costs. See BENCHMARKS.md.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from conftest import BENCH_OUTCOME, BENCH_POLICY

from chiplog.emit import AuditRecorder
from chiplog.schema.v1 import Output, ToolCall

CONCURRENCY = 8
RECORDS_PER_ROUND = 1000
RECORDS_PER_WORKER = RECORDS_PER_ROUND // CONCURRENCY  # 125
ROUNDS = 3


def _record_kwargs(worker: int, i: int, sample_input: dict[str, object]) -> dict[str, Any]:
    return {
        "session_id": "bench-concurrent",
        "step_id": f"w{worker}-step-{i}",
        "tool": ToolCall(name="bench_tool"),
        "input": sample_input,
        "output": Output(body={"ok": True}),
        "policy": BENCH_POLICY,
        "outcome": BENCH_OUTCOME,
    }


def _bench_threads(recorder: AuditRecorder, sample_input: dict[str, object]) -> None:
    """8 OS threads, each driving its own loop via record_sync. LangGraph shape."""

    def worker(w: int) -> None:
        for i in range(RECORDS_PER_WORKER):
            recorder.record_sync(**_record_kwargs(w, i, sample_input))

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        # list() forces every future; an exception in a worker propagates here
        # rather than being silently swallowed into a bogus fast number.
        list(pool.map(worker, range(CONCURRENCY)))


def _bench_coroutines(
    recorder: AuditRecorder,
    sample_input: dict[str, object],
    loop: asyncio.AbstractEventLoop,
) -> None:
    """8 coroutines on ONE loop via gather. Async ToolNode shape."""

    async def worker(w: int) -> None:
        for i in range(RECORDS_PER_WORKER):
            await recorder.record(**_record_kwargs(w, i, sample_input))

    async def run_all() -> None:
        await asyncio.gather(*(worker(w) for w in range(CONCURRENCY)))

    loop.run_until_complete(run_all())


@pytest.mark.benchmark(group="concurrent_throughput_threads")
def test_concurrent_threads_local_file(
    benchmark: object,
    recorder_local_file: AuditRecorder,
    sample_input: dict[str, object],
) -> None:
    """Records/sec with 8 threads contending for one recorder + LocalFileSink."""
    benchmark.pedantic(  # type: ignore[attr-defined]
        _bench_threads,
        args=(recorder_local_file, sample_input),
        iterations=1,
        rounds=ROUNDS,
    )
    benchmark.extra_info["records_per_round"] = RECORDS_PER_ROUND  # type: ignore[attr-defined]
    benchmark.extra_info["concurrency"] = CONCURRENCY  # type: ignore[attr-defined]
    benchmark.extra_info["shape"] = "threads/record_sync"  # type: ignore[attr-defined]
    benchmark.extra_info["sink"] = "LocalFileSink"  # type: ignore[attr-defined]


@pytest.mark.benchmark(group="concurrent_throughput_coroutines")
def test_concurrent_coroutines_local_file(
    benchmark: object,
    recorder_local_file: AuditRecorder,
    sample_input: dict[str, object],
    bench_loop: asyncio.AbstractEventLoop,
) -> None:
    """Records/sec with 8 coroutines contending for one recorder + LocalFileSink."""
    benchmark.pedantic(  # type: ignore[attr-defined]
        _bench_coroutines,
        args=(recorder_local_file, sample_input, bench_loop),
        iterations=1,
        rounds=ROUNDS,
    )
    benchmark.extra_info["records_per_round"] = RECORDS_PER_ROUND  # type: ignore[attr-defined]
    benchmark.extra_info["concurrency"] = CONCURRENCY  # type: ignore[attr-defined]
    benchmark.extra_info["shape"] = "coroutines/gather"  # type: ignore[attr-defined]
    benchmark.extra_info["sink"] = "LocalFileSink"  # type: ignore[attr-defined]
