"""Bench 3: verifier records/sec on a pre-populated 10 000-record corpus.

Answers "auditor wants to verify N months of records — how long?". This is
pure CPU + memory; no fsync, no writes. Single-threaded.

TWO numbers, because they answer different questions and only one of them is
what an auditor actually waits on:

- `verify_record` per-record: hash + signature only, records already parsed and
  in memory. This is the crypto ceiling and the number the v0.1 suite reported.
  Kept unchanged so the v0.1 -> v0.2 delta is apples-to-apples.
- `verify_tree` end-to-end: what `agent-audit verify <dir>` actually does —
  load the manifest, digest every file (a second full streaming pass for
  sha256), walk each chain, reconstruct the canonical form, and check every
  signature, all from disk. v0.2 added the manifest cross-checks and the digest
  pass, so this is strictly more work than v0.1 did, and it is the number the
  README's "a 6-month chain verifies in N minutes" claim depends on. v0.1 had
  no `verify_tree`, so this row has no v0.1 counterpart — it is not a
  regression, it is a check that did not exist.

Throughput target: under five minutes for one day of records on a 2-vCPU pod.
With 10K records / round, throughput >= 33 rec/s would clear five minutes per
10K; realistic numbers should land 1-2 orders higher.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit.integrity import verify_record
from agent_audit.verify import verify_tree

ROUNDS = 5


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _verify_all(
    records: list[dict[str, object]], pubkey_by_id: dict[str, object]
) -> None:
    for rec in records:
        result = verify_record(rec, pubkey_by_id)  # type: ignore[arg-type]
        if not result.is_valid:
            raise AssertionError(
                f"verifier returned invalid result on bench corpus: {result.failure}"
            )


@pytest.mark.benchmark(group="verifier_throughput")
def test_verifier_throughput(
    benchmark: object,
    prepopulated_jsonl: Path,
    prepopulated_pubkey_by_id: dict[str, object],
) -> None:
    """Verify a 10 000-record JSONL file end-to-end."""
    records = _load_jsonl(prepopulated_jsonl)
    if len(records) < 9_000:
        raise RuntimeError(
            f"verifier corpus underpopulated: expected ~10000 records, got {len(records)}"
        )

    benchmark.pedantic(  # type: ignore[attr-defined]
        _verify_all,
        args=(records, prepopulated_pubkey_by_id),
        iterations=1,
        rounds=ROUNDS,
    )
    benchmark.extra_info["records_in_corpus"] = len(records)  # type: ignore[attr-defined]


def _verify_tree(root: Path, pubkey_by_id: dict[str, object]) -> None:
    result = verify_tree(root, extra_pubkeys=pubkey_by_id)  # type: ignore[arg-type]
    if not result.is_valid:
        raise AssertionError(
            f"verify_tree returned invalid result on bench corpus: {result.findings}"
        )


@pytest.mark.benchmark(group="verifier_throughput_tree")
def test_verifier_tree_throughput(
    benchmark: object,
    prepopulated_dir: Path,
    prepopulated_pubkey_by_id: dict[str, object],
) -> None:
    """Full auditor path: manifest cross-check + per-file sha256 + chain + sigs."""
    benchmark.pedantic(  # type: ignore[attr-defined]
        _verify_tree,
        args=(prepopulated_dir, prepopulated_pubkey_by_id),
        iterations=1,
        rounds=ROUNDS,
    )
    benchmark.extra_info["records_in_corpus"] = 10_000  # type: ignore[attr-defined]
    benchmark.extra_info["path"] = "verify_tree (end-to-end, from disk)"  # type: ignore[attr-defined]
