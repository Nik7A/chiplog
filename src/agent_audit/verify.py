"""Streaming JSONL verifier — validates a full audit log end-to-end.

Reads records one at a time, holds only the per-chain head in memory at any
moment. Verifying a 1M-record log uses constant memory.

Returns a structured LogVerificationResult that report.py formats as either
plain text (auditor-facing) or JSON (machine-facing).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_audit.integrity import (
    VerificationFailure,
    compute_chain_link,
    verify_record,
)


class ChainCheckOutcome(str, Enum):
    """Verifier outcome — maps 1:1 to the CLI exit code (see cli.py)."""

    OK = "ok"
    CHAIN_BREAK = "chain_break"
    SIGNATURE_FAIL = "signature_fail"
    KEY_RESOLUTION = "key_resolution"
    MALFORMED_JSONL = "malformed_jsonl"
    EMPTY = "empty"


@dataclass
class LogVerificationResult:
    """Full result of verifying one JSONL log file."""

    path: str
    outcome: ChainCheckOutcome
    record_count: int = 0
    chains_seen: list[str] = field(default_factory=list)
    failed_at_offset: int | None = None
    failed_at_record_id: str | None = None
    failure_detail: str | None = None

    @property
    def is_valid(self) -> bool:
        return self.outcome == ChainCheckOutcome.OK


_RECORD_FAILURE_TO_OUTCOME: dict[VerificationFailure, ChainCheckOutcome] = {
    VerificationFailure.HASH_MISMATCH: ChainCheckOutcome.SIGNATURE_FAIL,
    VerificationFailure.SIGNATURE_INVALID: ChainCheckOutcome.SIGNATURE_FAIL,
    VerificationFailure.UNKNOWN_KEY_ID: ChainCheckOutcome.KEY_RESOLUTION,
    VerificationFailure.MALFORMED_RECORD: ChainCheckOutcome.MALFORMED_JSONL,
}


def verify_log(
    path: str | Path,
    pubkey_by_id: dict[str, Ed25519PublicKey],
) -> LogVerificationResult:
    """Verify a JSONL log end-to-end. Streaming; O(1) memory in record count."""
    path_str = str(path)
    chain_heads: dict[str, str] = {}
    chains_seen: list[str] = []
    record_count = 0

    try:
        f = open(path, encoding="utf-8")
    except OSError as e:
        return LogVerificationResult(
            path=path_str,
            outcome=ChainCheckOutcome.MALFORMED_JSONL,
            failure_detail=f"could not open log file: {e}",
        )

    try:
        had_any_line = False
        for line_num, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n").rstrip("\r")
            if not line:
                continue
            had_any_line = True

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                return LogVerificationResult(
                    path=path_str,
                    outcome=ChainCheckOutcome.MALFORMED_JSONL,
                    record_count=record_count,
                    chains_seen=chains_seen,
                    failed_at_offset=line_num,
                    failure_detail=f"JSON parse error: {e}",
                )

            # 1. Per-record signature + hash
            rr = verify_record(record, pubkey_by_id)
            if not rr.is_valid:
                assert rr.failure is not None
                rec_id = (
                    record["envelope"].get("record_id")
                    if isinstance(record, dict) and isinstance(record.get("envelope"), dict)
                    else None
                )
                return LogVerificationResult(
                    path=path_str,
                    outcome=_RECORD_FAILURE_TO_OUTCOME[rr.failure],
                    record_count=record_count,
                    chains_seen=chains_seen,
                    failed_at_offset=line_num,
                    failed_at_record_id=rec_id,
                    failure_detail=f"{rr.failure.value}: {rr.detail}",
                )

            # 2. Chain continuity
            env = record["envelope"]
            chain_id = env["chain_id"]
            claimed_prev = env.get("prev_hash")

            if chain_id not in chain_heads:
                chains_seen.append(chain_id)
                if claimed_prev is not None:
                    return LogVerificationResult(
                        path=path_str,
                        outcome=ChainCheckOutcome.CHAIN_BREAK,
                        record_count=record_count,
                        chains_seen=chains_seen,
                        failed_at_offset=line_num,
                        failed_at_record_id=env.get("record_id"),
                        failure_detail=(
                            f"first record in chain {chain_id!r} has non-null "
                            f"prev_hash {claimed_prev!r}"
                        ),
                    )
            else:
                expected_prev = chain_heads[chain_id]
                if claimed_prev != expected_prev:
                    return LogVerificationResult(
                        path=path_str,
                        outcome=ChainCheckOutcome.CHAIN_BREAK,
                        record_count=record_count,
                        chains_seen=chains_seen,
                        failed_at_offset=line_num,
                        failed_at_record_id=env.get("record_id"),
                        failure_detail=(
                            f"chain {chain_id!r}: claimed prev_hash {claimed_prev!r}, "
                            f"expected {expected_prev!r}"
                        ),
                    )

            chain_heads[chain_id] = compute_chain_link(record)
            record_count += 1
    finally:
        f.close()

    if not had_any_line or record_count == 0:
        return LogVerificationResult(
            path=path_str,
            outcome=ChainCheckOutcome.EMPTY,
            failure_detail="empty log — this is NOT a passing audit",
        )

    return LogVerificationResult(
        path=path_str,
        outcome=ChainCheckOutcome.OK,
        record_count=record_count,
        chains_seen=chains_seen,
    )


__all__ = [
    "ChainCheckOutcome",
    "LogVerificationResult",
    "verify_log",
]
