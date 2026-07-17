"""Structural: where the sink claims to serialise appends, it must name the boundary.

`_DailyFileState` tells its caller that interleaved appends would corrupt the
rolling hash, and then reassures them: "`LocalFileSink` guarantees that with
`_write_lock`, which is why `append_line` does no locking of its own." Read
that and you conclude serialisation is handled. It is a `threading.Lock`. It
handles nothing across processes.

`emit.py` states the truth in the same codebase — "What is NOT guaranteed: ...
two processes appending to the same log" — so the library knows. It documents
the limit accurately in one file and promises the opposite in another, and a
caller reading the sink's own docstring to decide whether they need their own
locking gets the wrong answer.

That is not hypothetical. Two bosun workers appending to one chain produced 7
forked chains across 5825 records (forensics, 2026-07-17). Nothing was
corrupted — 0 dangling `prev_hash`, every resolvable signature verified — but
`verify` reported CHAIN_BREAK over intact evidence, which is worse than a clean
failure: it teaches the operator to disregard the verifier.

This guard is prose-shaped because the defect is prose-shaped, the same way
`test_report_claims_guard.py` is. A docstring that makes a concurrency promise
has to say where the promise stops; the word this checks for is the cheapest
proxy for that, and if a rewrite drops it the test should fail and make someone
re-read the claim.

It does NOT pin that appends are cross-process safe — they are not. Making them
so is a real change to the sink's write path, and it is deliberately not this.
"""

from __future__ import annotations

import threading
from pathlib import Path

from chiplog.sinks import local_file


def _the_promise() -> str:
    """The paragraph that makes the serialisation claim, not the whole docstring.

    Anchoring to the paragraph matters: the docstring elsewhere says "previous
    process wrote to it today", so a naive search for the word across the whole
    text passes while the claim itself stays unqualified — which is how the
    first draft of this guard went green against a docstring that still lied.
    """
    doc = local_file._DailyFileState.__doc__
    assert doc is not None, "_DailyFileState lost its docstring"
    paras = [p for p in doc.split("\n\n") if "_write_lock" in p]
    assert len(paras) == 1, (
        "this guard is anchored to the one paragraph that promises "
        f"serialisation; found {len(paras)}. If the claim moved or split, "
        "move the guard with it rather than loosening it"
    )
    return paras[0]


def test_the_lock_backing_the_promise_is_process_local(tmp_path: Path) -> None:
    # The premise of this guard. If this ever becomes a cross-process lock,
    # the docstring rule below should be revisited, not silenced.
    sink = local_file.LocalFileSink(dir=tmp_path / "audit")
    assert isinstance(sink._write_lock, type(threading.Lock()))


def test_serialisation_promise_names_its_boundary() -> None:
    promise = _the_promise()
    assert "process" in promise.lower(), (
        "_DailyFileState tells callers LocalFileSink serialises appends for them, "
        "and _write_lock is a threading.Lock — so the promise holds only within "
        "one process. Say so in the paragraph that makes it. A caller who "
        "believes the unqualified version writes from a second process and gets "
        "a forked chain that verify reports as CHAIN_BREAK over intact evidence. "
        "See emit.py's accurate statement of the same limit.\n\n" + promise
    )
