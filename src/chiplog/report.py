"""Auditor-facing verification report formatters.

Plain-text reports are BYTE-DETERMINISTIC — no ANSI escapes, no localized
numbers, no clock-derived timestamps. The same LogVerificationResult run
twice produces identical bytes. Auditors can include the report verbatim
in their PDF appendix and the hash will match across reviewers.

Every report ends with the NON-CLAIMS block — what this report does NOT
prove. This is the same disclaimer the README and SCOPE_STATEMENT carry:
removing it would create a misleading deliverable, and so would naming a
release in it. See tests/test_report_claims_guard.py.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from chiplog.verify import (
    LogVerificationResult,
    TreeVerificationResult,
)

_REPORT_WIDTH = 78

_NON_CLAIMS = """\
What this report does NOT prove. Every limit below is open in the release
that produced this report; none of them is closed:

- It does NOT prove that records were not deleted from the head or tail
  of the chain. A single forward-only hash chain detects in-the-middle
  removal; tail-truncation requires an external anchor.

- It does NOT prove that the signing key was not compromised. A holder
  of the private key can produce a valid alternative log. Closing this
  needs a signer outside the agent's trust boundary.

- It does NOT prove that the wall clock (ts_utc) was correct. The
  ts_source field declares trust level (system/ntp/tsa); true time
  anchoring needs an RFC 3161 timestamp authority.

Read SCOPE_STATEMENT.md before staking a compliance claim on this report,
and ROADMAP.md for where each limit stands.
"""


def format_text_report(result: LogVerificationResult) -> str:
    """Deterministic plain-text report — byte-identical across runs."""
    lines: list[str] = []
    sep = "=" * _REPORT_WIDTH

    lines.append("chiplog verification report")
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


# ---------------------------------------------------------------------------
# Directory / manifest-aware report (v0.2)
# ---------------------------------------------------------------------------


def _tree_verdict_line(result: TreeVerificationResult) -> str:
    """One honest verdict line for a whole-directory verification.

    The verdict describes exactly what was and was not established. It never
    reads "PASS" over off-canonical or unverifiable records, and never "FAIL"
    over records that are merely unverifiable for want of a key.
    """
    o = result.outcome.value
    if result.is_valid and not result.manifest_present:
        return (
            "VERDICT: LOG-ONLY PASS — records present verify and chain sequentially; "
            "manifest cross-check skipped (whole-chain deletion NOT detectable)"
        )
    if result.is_valid:
        return "VERDICT: PASS — every attested record verified and chains to the manifest head"
    if result.outcome.value == "partial":
        return (
            f"VERDICT: PARTIAL — {result.verified_records} of {result.canonical_records} "
            f"attested records verified under available keys; "
            f"{result.unverifiable_no_key} unverifiable (no key)"
        )
    if result.outcome.value == "off_canonical":
        return (
            f"VERDICT: OFF-CANONICAL — {result.off_path_records} record(s) are off the "
            f"canonical path the manifest attests (reason not observable). "
            f"Of attested records, {result.verified_records} verified, "
            f"{result.unverifiable_no_key} unverifiable (no key)"
        )
    if result.outcome.value == "manifest_integrity":
        return (
            "VERDICT: MANIFEST-INTEGRITY BREAK — the log disagrees with its own "
            "manifest anchor (per-chain record_count or per-file sha256 / "
            "record_count); see findings above. This is NOT a pass"
        )
    if result.outcome.value == "redaction_forgery":
        return (
            "VERDICT: REDACTION-FORGERY BREAK — a validly-signed record carries a "
            "tool-forged redaction marker (no backing entry, or a token that does "
            "not match the record's); see findings above. This is NOT a pass"
        )
    return f"VERDICT: {o.upper()} — see findings above"


def format_tree_text_report(result: TreeVerificationResult) -> str:
    """Deterministic plain-text report for a directory verification.

    Byte-identical across runs (findings are emitted in discovery order, which is
    itself deterministic: files sorted by date, chains sorted by id).
    """
    lines: list[str] = []
    sep = "=" * _REPORT_WIDTH

    lines.append("chiplog directory verification report")
    lines.append(sep)
    lines.append("")
    lines.append(f"root:               {result.root}")
    lines.append(f"outcome:            {result.outcome.value}")
    lines.append(f"files:              {len(result.files)}")
    lines.append(f"manifest present:   {result.manifest_present}")
    lines.append(
        f"manifest pubkey_id: claimed={result.manifest_pubkey_id_claimed} "
        f"derived={result.manifest_pubkey_id_derived}"
    )
    lines.append(
        f"redaction state:    {result.manifest_redaction_state} "
        f"(unknown = not attested, NOT 'enabled')"
    )
    lines.append(f"keys available:     {', '.join(result.available_key_ids) or '(none)'}")
    lines.append(f"records total:      {result.total_records}")
    lines.append(f"records canonical:  {result.canonical_records}")
    lines.append(f"  verified:         {result.verified_records}")
    lines.append(f"  unverifiable:     {result.unverifiable_no_key} (no key)")
    lines.append(f"off-canonical:      {result.off_path_records}")

    lines.append("")
    lines.append("chains:")
    for c in result.chains:
        lines.append(
            f"  - {c.chain_id}: manifest={c.manifest_record_count} "
            f"log={c.records_in_log} canonical={c.canonical_count} "
            f"verified={c.canonical_verified} "
            f"unverifiable={c.canonical_unverifiable_no_key} "
            f"off_path={c.off_path_records} "
            f"head_reached={c.head_reached} genesis_ok={c.genesis_verified}"
        )

    if result.findings:
        lines.append("")
        lines.append("findings (facts, most-specific first):")
        for f in result.findings:
            scope = f" [{f.chain_id}]" if f.chain_id else ""
            lines.append(f"  - {f.kind}{scope}: {f.detail}")

    lines.append("")
    lines.append(_tree_verdict_line(result))

    lines.append("")
    lines.append(sep)
    lines.append(_NON_CLAIMS.rstrip())

    return "\n".join(lines) + "\n"


def format_tree_json_report(result: TreeVerificationResult) -> str:
    """Machine-readable directory report — sorted keys for byte-determinism."""
    data = asdict(result)
    data["outcome"] = result.outcome.value
    data["is_valid"] = result.is_valid
    return json.dumps(data, sort_keys=True, indent=2) + "\n"


__all__ = [
    "format_json_report",
    "format_text_report",
    "format_tree_json_report",
    "format_tree_text_report",
]
