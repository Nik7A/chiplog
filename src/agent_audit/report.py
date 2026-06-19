"""Auditor-facing verification report formatters.

Plain-text reports are BYTE-DETERMINISTIC — no ANSI escapes, no localized
numbers, no clock-derived timestamps. The same LogVerificationResult run
twice produces identical bytes. Auditors can include the report verbatim
in their PDF appendix and the hash will match across reviewers.

Every report ends with the NON-CLAIMS block — what v0.1 does NOT prove.
This is the same disclaimer the README and SCOPE_STATEMENT carry: removing
it would create a misleading deliverable.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from agent_audit.verify import LogVerificationResult

_REPORT_WIDTH = 78

_NON_CLAIMS = """\
What this report does NOT prove (v0.1 limitations — fixed in v0.2):

- It does NOT prove that records were not deleted from the head or tail
  of the chain. A single forward-only hash chain detects in-the-middle
  removal; tail-truncation requires an external anchor.

- It does NOT prove that the signing key was not compromised. A holder
  of the private key can produce a valid alternative log. v0.2 closes
  this with the sidecar signer (key out of the agent's trust boundary).

- It does NOT prove that the wall clock (ts_utc) was correct. The
  ts_source field declares trust level (system/ntp/tsa); v0.2 adds
  RFC 3161 TSA timestamps for true time anchoring.
"""


def format_text_report(result: LogVerificationResult) -> str:
    """Deterministic plain-text report — byte-identical across runs."""
    lines: list[str] = []
    sep = "=" * _REPORT_WIDTH

    lines.append("agent-audit verification report")
    lines.append(sep)
    lines.append("")
    lines.append(f"path:           {result.path}")
    lines.append(f"outcome:        {result.outcome.value}")
    lines.append(f"records:        {result.record_count}")
    lines.append(f"chains seen:    {len(result.chains_seen)}")
    for cid in result.chains_seen:
        lines.append(f"  - {cid}")

    if not result.is_valid:
        lines.append("")
        if result.failed_at_offset is not None:
            lines.append(f"failure offset: line {result.failed_at_offset}")
        if result.failed_at_record_id is not None:
            lines.append(f"failure record: {result.failed_at_record_id}")
        if result.failure_detail is not None:
            lines.append(f"detail:         {result.failure_detail}")

    lines.append("")
    if result.is_valid:
        lines.append("VERDICT: PASS — chain integrity verified within this log")
    else:
        lines.append(f"VERDICT: FAIL — {result.outcome.value}")

    lines.append("")
    lines.append(sep)
    lines.append(_NON_CLAIMS.rstrip())

    return "\n".join(lines) + "\n"


def format_json_report(result: LogVerificationResult) -> str:
    """Machine-readable report — sorted keys for byte-determinism."""
    data = asdict(result)
    data["outcome"] = result.outcome.value
    data["is_valid"] = result.is_valid
    return json.dumps(data, sort_keys=True, indent=2) + "\n"


__all__ = ["format_json_report", "format_text_report"]
