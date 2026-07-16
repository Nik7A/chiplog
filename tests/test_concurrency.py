"""Concurrency hazard tests — the chain must survive parallel tool calls.

Every test here drives the REAL runtime against a REAL `LocalFileSink` and
checks the result with the REAL `verify_log`. Nothing is faked except the chat
model, because a chat model is the one component whose output we must pin to
get a deterministic parallel-tool-call turn.

The four call patterns the recorder must be correct under, one test each:

  1. many threads calling `record_sync` — LangGraph's `ToolNode` runs parallel
     tool calls through `executor.map(self._run_one, ...)`, i.e. in threads, and
     parallel tool calls are the DEFAULT under `create_agent`. This is the
     pattern a real agent hits on turn one.
  2. many coroutines calling `record()` on one event loop — `asyncio.gather`,
     the async `ToolNode`.
  3. both at once.
  4. a sink whose `write()` genuinely SUSPENDS. `LocalFileSink.write` has no
     await points, so the async path would pass patterns 2 and 3 even with a
     broken recorder, purely by accident. S3/Postgres sinks are on the roadmap
     and the `Sink` protocol is async precisely for them, so the suspending
     sink is what actually exercises the async path.

Two invariants are asserted everywhere, and they are not the same invariant:

  - `verify_log(...) == OK` — the chain did not fork. Catches a `prev_hash`
    read-modify-write race.
  - the manifest's recorded `sha256` equals the SHA-256 of the bytes actually on
    disk — the manifest does not attest a checksum the file does not have.
    Catches the sink's rolling-hash context being updated in a different order
    than bytes were appended to the file. A fix that serialises chain-head
    assignment but not the sink write trades a fork for a false manifest, and
    only this second assertion would notice.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from chiplog.adapters.langgraph import AuditMiddleware
from chiplog.emit import AuditRecorder
from chiplog.integrity import compute_chain_link
from chiplog.keys import SigningKey, compute_key_id, load_public_key
from chiplog.manifest import Manifest
from chiplog.schema.v1 import (
    NoGateReason,
    Output,
    ToolCall,
    success,
    ungated,
)
from chiplog.sinks.base import InMemorySink, Sink, SinkError
from chiplog.sinks.local_file import LocalFileSink
from chiplog.verify import ChainCheckOutcome, verify_log

# ---------------------------------------------------------------------------
# Shared harness
# ---------------------------------------------------------------------------


@pytest.fixture
def hostile_scheduler() -> Iterator[None]:
    """Preempt threads aggressively for the duration of one test.

    CPython switches threads every 5ms by default. The races this file is about
    live in windows tens of microseconds wide, so at the stock interval a losing
    interleave is possible but rare — which produces the worst kind of test: one
    that passes against BROKEN code most of the time and fails on CI once a month.

    Dropping the switch interval does not fake anything and does not touch the
    code under test. It just stops the scheduler from hiding a real bug, so that
    "this test passes" means "the lock works" rather than "we were not preempted".
    """
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        yield
    finally:
        sys.setswitchinterval(previous)


def _write_keypair(tmp_path: Path) -> tuple[SigningKey, Path]:
    """Real Ed25519 keypair on disk — the verifier reads the .pub back."""
    pk = Ed25519PrivateKey.generate()
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    priv.write_bytes(pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    priv.chmod(0o600)
    pub.write_bytes(
        pk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    public = pk.public_key()
    return SigningKey(private_key=pk, public_key=public, key_id=compute_key_id(public)), pub


def _the_jsonl(audit_dir: Path) -> Path:
    files = sorted(audit_dir.glob("audit-*.jsonl"))
    assert len(files) == 1, f"expected exactly one daily file, got {files}"
    return files[0]


def _assert_chain_ok(audit_dir: Path, pub: Path, expected_records: int) -> None:
    """The two invariants. Both, always — see the module docstring."""
    jsonl = _the_jsonl(audit_dir)
    pubkey, key_id = load_public_key(pub)

    result = verify_log(jsonl, {key_id: pubkey})
    assert result.outcome is ChainCheckOutcome.OK, (
        f"verify_log: {result.outcome.value} at line {result.failed_at_offset}: "
        f"{result.failure_detail}"
    )
    assert result.record_count == expected_records, (
        f"expected {expected_records} records on disk, got {result.record_count}"
    )

    # Exactly one genesis. A forked chain shows up here as a second record
    # claiming prev_hash=null, which is the signature of the read-modify-write.
    genesis = [
        line
        for line in jsonl.read_text().splitlines()
        if line and json.loads(line)["envelope"]["prev_hash"] is None
    ]
    assert len(genesis) == 1, f"expected 1 genesis record, found {len(genesis)}"

    manifest = Manifest.load_or_create(audit_dir / "manifest.json")
    on_disk = hashlib.sha256(jsonl.read_bytes()).hexdigest()
    attested = manifest.files[jsonl.name].sha256
    assert attested == on_disk, (
        "manifest attests a checksum the file on disk does not have: "
        f"manifest={attested} actual={on_disk}"
    )
    assert manifest.files[jsonl.name].record_count == expected_records


class SuspendingSink:
    """A sink whose `write()` genuinely suspends, wrapping a real LocalFileSink.

    `LocalFileSink.write` has no await points: a coroutine inside it runs to
    completion without ever yielding to the loop, so on one event loop it is
    accidentally atomic. Every S3/Postgres sink on the roadmap will yield, which
    is the entire reason the `Sink` protocol is async. This sink yields — twice,
    on both sides of the real write — so the async tests exercise the interleave
    the real world will produce rather than the one today's sink hides.
    """

    def __init__(self, inner: LocalFileSink) -> None:
        self._inner = inner
        self.concurrent_writers = 0
        self.max_concurrent_writers = 0

    async def write(self, record: dict[str, Any]) -> None:
        self.concurrent_writers += 1
        self.max_concurrent_writers = max(
            self.max_concurrent_writers, self.concurrent_writers
        )
        try:
            await asyncio.sleep(0)
            await self._inner.write(record)
            await asyncio.sleep(0)
        finally:
            self.concurrent_writers -= 1

    async def flush(self) -> None:
        await self._inner.flush()

    async def close(self) -> None:
        await self._inner.close()


class ExplodingSink:
    """Every write raises. Models a degraded sink (disk full, S3 5xx)."""

    def __init__(self) -> None:
        self.attempts = 0

    async def write(self, record: dict[str, Any]) -> None:
        self.attempts += 1
        raise SinkError("simulated sink failure")

    async def flush(self) -> None:
        return

    async def close(self) -> None:
        return


def _record_kwargs(n: int) -> dict[str, Any]:
    return {
        "session_id": "concurrency",
        "step_id": f"step-{n}",
        "tool": ToolCall(name="stress"),
        "input": {"n": n},
        "output": Output(body={"n": n}),
        "policy": ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        "outcome": success(),
    }


# ---------------------------------------------------------------------------
# Pattern 1 — the real one. Parallel tool calls under a real create_agent.
# ---------------------------------------------------------------------------


class _ParallelToolCallModel:
    """Chat model that emits N tool calls in ONE AIMessage, then stops.

    Faked because a real model's decision to call tools in parallel is exactly
    the thing that must not be left to chance in a regression test. Everything
    downstream of it — ToolNode, its thread pool, the middleware, the recorder,
    the sink, the verifier — is real.
    """

    def __init__(self, messages: list[Any]) -> None:
        self._messages = list(messages)
        self._idx = 0

    def bind_tools(self, tools: list[Any], **kwargs: Any) -> _ParallelToolCallModel:
        return self

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        msg = self._messages[self._idx]
        self._idx += 1
        return msg

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        return self.invoke(input, config, **kwargs)


PARALLEL_TOOL_CALLS = 8


def test_real_create_agent_parallel_tool_calls_keep_the_chain_verifiable(
    tmp_path: Path, hostile_scheduler: None
) -> None:
    """THE hazard. A real agent, two tools, called in parallel on one turn.

    LangGraph's `ToolNode._func` dispatches every tool call in the turn through
    `executor.map(self._run_one, ...)` — a ThreadPoolExecutor — and `_run_one` is
    what calls our `wrap_tool_call`. So this test puts N threads inside
    `AuditRecorder.record_sync` at once with nothing faked below the model.

    Eight parallel calls rather than two: two is enough to fork the chain and is
    what a real turn typically looks like, but a two-thread race that loses is a
    flaky test, not a passing one. Eight makes the interleave reliable without
    changing anything about what is being tested.
    """
    from langchain.agents import create_agent
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool

    sk, pub = _write_keypair(tmp_path)
    audit_dir = tmp_path / "audit"
    sink = LocalFileSink(dir=audit_dir, pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(sink=sink, signing_key=sk, chain_id="parallel")

    barrier = threading.Barrier(PARALLEL_TOOL_CALLS, timeout=10)

    @tool
    def alpha(text: str) -> str:
        """Alpha tool."""
        barrier.wait()
        return f"alpha: {text}"

    @tool
    def beta(text: str) -> str:
        """Beta tool."""
        barrier.wait()
        return f"beta: {text}"

    # One AIMessage carrying every call — this is what "parallel tool calls"
    # means to LangGraph, and it is create_agent's default behaviour.
    tool_calls = [
        {
            "name": "alpha" if i % 2 == 0 else "beta",
            "args": {"text": f"call-{i}"},
            "id": f"call-{i}",
            "type": "tool_call",
        }
        for i in range(PARALLEL_TOOL_CALLS)
    ]
    model = _ParallelToolCallModel(
        [AIMessage(content="", tool_calls=tool_calls), AIMessage(content="done")]
    )

    agent = create_agent(
        model=model,  # type: ignore[arg-type]
        tools=[alpha, beta],
        middleware=[AuditMiddleware(recorder, session_id="parallel-session")],
    )

    # The barrier inside the tools guarantees all N tool bodies are in flight
    # before any of them returns, so all N threads reach the recorder together.
    # If the audit layer crashes the tool call (a SinkError escaping the success
    # path), this invoke raises — which is itself the fourth defect.
    agent.invoke({"messages": [{"role": "user", "content": "go"}]})

    _assert_chain_ok(audit_dir, pub, PARALLEL_TOOL_CALLS)


# ---------------------------------------------------------------------------
# Pattern 1, isolated — threads on record_sync, no agent in the way.
# ---------------------------------------------------------------------------


def test_threaded_record_sync_stress_keeps_the_chain_verifiable(
    tmp_path: Path, hostile_scheduler: None
) -> None:
    """64 record_sync calls across 8 threads — the measured reproduction.

    Every thread runs `asyncio.run(self.record(...))`, so every thread has its
    OWN event loop. Any serialisation built on an `asyncio.Lock` is bound to the
    loop that created it and gives zero mutual exclusion here; this test is what
    says so out loud.

    `hostile_scheduler` is load-bearing, and finding that out is the reason it
    exists. The unguarded window — read the chain head, sign, write the head back
    — is only tens of microseconds of pure-Python work, while CPython switches
    threads every 5ms by default. At the stock interval a thread almost never
    gets preempted inside the window, so this test PASSED with the commit lock
    deleted: not because the code was correct, but because the scheduler happened
    not to look. A concurrency test that can only fail on an unlucky day is not a
    regression test. The fixture drops the switch interval so the interleave is
    reliably attempted; it changes nothing about the code under test.
    """
    sk, pub = _write_keypair(tmp_path)
    audit_dir = tmp_path / "audit"
    sink = LocalFileSink(dir=audit_dir, pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(sink=sink, signing_key=sk, chain_id="threads")

    total, workers = 64, 8
    start = threading.Barrier(workers, timeout=30)
    failures: list[BaseException] = []

    def worker(worker_id: int) -> None:
        start.wait()
        for i in range(total // workers):
            try:
                recorder.record_sync(**_record_kwargs(worker_id * 100 + i))
            except BaseException as exc:  # noqa: BLE001 — collected, then asserted
                failures.append(exc)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(worker, range(workers)))

    assert not failures, f"{len(failures)} record_sync calls raised: {failures[:3]}"
    _assert_chain_ok(audit_dir, pub, total)


# ---------------------------------------------------------------------------
# Pattern 2 + 4 — coroutines on one loop, sink that genuinely suspends.
# ---------------------------------------------------------------------------


async def test_async_gather_with_suspending_sink_keeps_the_chain_verifiable(
    tmp_path: Path,
) -> None:
    """32 coroutines, one loop, a sink whose write() yields mid-write.

    This is the test that today's async path would pass by accident with a
    LocalFileSink (no await points → never yields → accidentally atomic) and
    fails honestly with a sink that behaves like every real one will.

    `max_concurrent_writers == 1` is asserted, not incidental: chain order must
    EQUAL write order (`prev_hash` linkage and the sink's rolling hash are both
    order-dependent), and two writes overlapping inside the sink is precisely
    what would let the file's byte order diverge from the chain's link order.
    """
    sk, pub = _write_keypair(tmp_path)
    audit_dir = tmp_path / "audit"
    inner = LocalFileSink(dir=audit_dir, pubkey_pem=pub.read_bytes())
    sink = SuspendingSink(inner)
    recorder = AuditRecorder(sink=sink, signing_key=sk, chain_id="async")

    total = 32
    await asyncio.gather(*(recorder.record(**_record_kwargs(i)) for i in range(total)))

    assert sink.max_concurrent_writers == 1, (
        f"{sink.max_concurrent_writers} writes were inside the sink at once — "
        "chain order can no longer be trusted to equal write order"
    )
    _assert_chain_ok(audit_dir, pub, total)


async def test_async_chain_order_equals_file_order(tmp_path: Path) -> None:
    """The link order in the file must be the file's own line order.

    Serialising chain-head assignment without serialising the sink write would
    still pass a naive "no duplicate genesis" check while writing the records
    out of order. `verify_log` walks the file top to bottom, so it catches it —
    this test states the property directly so a failure names the cause.
    """
    sk, pub = _write_keypair(tmp_path)
    audit_dir = tmp_path / "audit"
    sink = SuspendingSink(LocalFileSink(dir=audit_dir, pubkey_pem=pub.read_bytes()))
    recorder = AuditRecorder(sink=sink, signing_key=sk, chain_id="order")

    await asyncio.gather(*(recorder.record(**_record_kwargs(i)) for i in range(24)))

    records = [
        json.loads(line)
        for line in _the_jsonl(audit_dir).read_text().splitlines()
        if line
    ]
    # prev_hash links to the CHAIN LINK of the previous record, which is not the
    # same value as its envelope.hash (the link covers the signature too — see
    # SIGNING.md §4). compute_chain_link is what the verifier itself walks with.
    prev: str | None = None
    for i, rec in enumerate(records):
        assert rec["envelope"]["prev_hash"] == prev, (
            f"line {i}: prev_hash {rec['envelope']['prev_hash']!r} does not "
            f"link to the record on the previous line ({prev!r})"
        )
        prev = compute_chain_link(rec)


# ---------------------------------------------------------------------------
# Pattern 3 — threads and coroutines at the same time, on the same recorder.
# ---------------------------------------------------------------------------


async def test_threads_and_coroutines_at_once_keep_the_chain_verifiable(
    tmp_path: Path, hostile_scheduler: None
) -> None:
    """`record_sync` from threads while `record()` runs on the main loop.

    The mixed case is its own hazard: a thread's `record_sync` drives a fresh
    loop of its own, so any serialisation must be visible to a foreign loop, and
    a coroutine waiting on the main loop must not block the thread the main loop
    runs on (a `threading.Lock` held across the sink's await would deadlock it).
    """
    sk, pub = _write_keypair(tmp_path)
    audit_dir = tmp_path / "audit"
    sink = SuspendingSink(LocalFileSink(dir=audit_dir, pubkey_pem=pub.read_bytes()))
    recorder = AuditRecorder(sink=sink, signing_key=sk, chain_id="mixed")

    from_threads, from_coros, workers = 32, 32, 8
    failures: list[BaseException] = []

    def worker(worker_id: int) -> None:
        for i in range(from_threads // workers):
            try:
                recorder.record_sync(**_record_kwargs(1000 + worker_id * 10 + i))
            except BaseException as exc:  # noqa: BLE001 — collected, then asserted
                failures.append(exc)

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        thread_side = [
            loop.run_in_executor(pool, worker, w) for w in range(workers)
        ]
        coro_side = [recorder.record(**_record_kwargs(i)) for i in range(from_coros)]
        await asyncio.gather(*thread_side, *coro_side)

    assert not failures, f"{len(failures)} record_sync calls raised: {failures[:3]}"
    _assert_chain_ok(audit_dir, pub, from_threads + from_coros)


# ---------------------------------------------------------------------------
# The audit layer must not crash the tool call it is observing.
# ---------------------------------------------------------------------------


def test_sink_failure_on_success_path_does_not_crash_the_sync_tool_call() -> None:
    """A degraded sink must not replace the tool's result with an exception.

    The adapter's own docstring promises "an audit layer observes control flow,
    it never alters it". The failure paths keep that promise; the success path
    did not — an unguarded recorder call there turns any sink failure into a
    crashed tool. That is how 47 SinkErrors reached the tool-call path in the
    measured run: the concurrency bug produced the sink failures, and the
    unguarded success path is what let them out.

    A dropped record is not lost evidence: the recorder advances its chain head
    before writing, so a failed write surfaces as a chain break at verification
    time — visible, and without destroying the run it was auditing.
    """
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    sk = SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))
    sink = ExplodingSink()
    recorder = AuditRecorder(sink=sink, signing_key=sk)
    middleware = AuditMiddleware(recorder, session_id="degraded")

    class _Request:
        tool_call = {"name": "echo", "args": {"text": "hi"}, "id": "c1"}

    sentinel = "the tool's real result"
    result = middleware.wrap_tool_call(_Request(), lambda _req: sentinel)

    assert result == sentinel
    assert sink.attempts == 1


async def test_sink_failure_on_success_path_does_not_crash_the_async_tool_call() -> None:
    """Same guarantee on `awrap_tool_call`."""
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    sk = SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))
    sink = ExplodingSink()
    recorder = AuditRecorder(sink=sink, signing_key=sk)
    middleware = AuditMiddleware(recorder, session_id="degraded")

    class _Request:
        tool_call = {"name": "echo", "args": {"text": "hi"}, "id": "c1"}

    sentinel = "the tool's real result"

    async def handler(_req: Any) -> str:
        return sentinel

    result = await middleware.awrap_tool_call(_Request(), handler)

    assert result == sentinel
    assert sink.attempts == 1


def test_sink_failure_on_returned_failure_path_does_not_crash_the_tool_call() -> None:
    """The runtime-returned-failure branch is a success-shaped RETURN too.

    ToolNode's default handler catches the tool's exception and hands the failure
    back as a return value. The audit layer must record that failure and then get
    out of the way — passing the failure through unaltered. If the recorder
    itself fails there, replacing the runtime's error message with an audit-layer
    exception would destroy the very evidence of what the tool did.
    """
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    sk = SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))
    sink = ExplodingSink()
    recorder = AuditRecorder(sink=sink, signing_key=sk)
    middleware = AuditMiddleware(recorder, session_id="degraded")

    class _Request:
        tool_call = {"name": "echo", "args": {}, "id": "c1"}

    class _FailedToolMessage:
        status = "error"
        type = "tool"
        content = "ValidationError: bad args"

    failure = _FailedToolMessage()
    result = middleware.wrap_tool_call(_Request(), lambda _req: failure)

    assert result is failure
    assert sink.attempts == 1


# ---------------------------------------------------------------------------
# Manifest.save_atomic — the fixed temp path is a race by construction.
# ---------------------------------------------------------------------------


def test_manifest_save_atomic_survives_concurrent_writers(
    tmp_path: Path, hostile_scheduler: None
) -> None:
    """Concurrent `save_atomic` calls must not destroy each other's temp file.

    A FIXED temp path (`manifest.json.tmp`) means writer A's `os.replace` can
    consume writer B's half-written temp file — or vanish from under B, whose
    own `os.replace` then raises FileNotFoundError. In the sink that surfaces as
    a SinkError, which is how a manifest race becomes a crashed tool call.

    The sink serialises its own writes, so this is defence in depth: `Manifest`
    is a public class, and a temp path that is not unique per writer is a bug
    whether or not something upstream happens to be preventing the interleave.
    """
    path = tmp_path / "manifest.json"
    Manifest().save_atomic(path)

    failures: list[BaseException] = []
    start = threading.Barrier(16, timeout=30)

    def writer(n: int) -> None:
        m = Manifest(pubkey_id=f"key-{n}")
        start.wait()
        for _ in range(20):
            try:
                m.save_atomic(path)
            except BaseException as exc:  # noqa: BLE001 — collected, then asserted
                failures.append(exc)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(writer, range(16)))

    assert not failures, f"{len(failures)} save_atomic calls raised: {failures[:3]}"

    # Whoever won last, the file must be a complete, loadable manifest — never a
    # truncated one — and no temp file may be left behind.
    Manifest.load_or_create(path)
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "manifest.json"]
    assert not leftovers, f"temp files left behind: {leftovers}"


@pytest.mark.parametrize("workers", [8])
def test_local_file_sink_manifest_checksum_matches_disk_under_threads(
    tmp_path: Path, workers: int, hostile_scheduler: None
) -> None:
    """The sink's rolling hash must track the file's actual byte order.

    `_DailyFileState.append_line` appends bytes and THEN updates the hash
    context. Two threads interleaving between those two steps produce a hash
    context fed A-then-B while the file holds B-then-A: the manifest then attests
    a checksum the file does not have — a signed audit trail whose own sidecar is
    wrong. Driving the sink directly, with no recorder above it to serialise for
    it, is the point.
    """
    sk, _pub = _write_keypair(tmp_path)
    audit_dir = tmp_path / "audit"
    sink = LocalFileSink(dir=audit_dir)

    # Real signed records: the sink computes a chain link over every record it
    # writes, so a hand-rolled dict would fail canonicalisation long before it
    # reached the hazard this test is about.
    signed = [
        AuditRecorder(sink=InMemorySink(), signing_key=sk).record_sync(
            **_record_kwargs(i)
        )
        for i in range(workers * 8)
    ]

    def writer(n: int) -> None:
        for i in range(8):
            asyncio.run(sink.write(signed[n * 8 + i]))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(writer, range(workers)))

    jsonl = _the_jsonl(audit_dir)
    manifest = Manifest.load_or_create(audit_dir / "manifest.json")
    on_disk = hashlib.sha256(jsonl.read_bytes()).hexdigest()
    assert manifest.files[jsonl.name].sha256 == on_disk, (
        "manifest attests a checksum the file on disk does not have"
    )
    assert manifest.files[jsonl.name].record_count == workers * 8
    assert len(jsonl.read_text().splitlines()) == workers * 8


def test_sink_protocol_is_satisfied_by_the_test_doubles() -> None:
    """The doubles above are real Sinks, not shapes that merely look like one."""
    assert isinstance(ExplodingSink(), Sink)
