"""Streaming JSONL verifier — validates a full audit log end-to-end.

Reads records one at a time, holds only the per-chain head in memory at any
moment. Verifying a 1M-record log uses constant memory.

Returns a structured LogVerificationResult that report.py formats as either
plain text (auditor-facing) or JSON (machine-facing).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from chiplog.integrity import (
    VerificationFailure,
    compute_chain_link,
    verify_record,
)
from chiplog.keys import load_public_key_from_pem
from chiplog.redact import redaction_authenticity


class ChainCheckOutcome(str, Enum):
    """Verifier outcome — maps 1:1 to the CLI exit code (see cli.py).

    Codes 0–5 (OK … EMPTY) are the DOCUMENTED, STABLE single-file API and keep
    their historical exit numbers. The remaining members are v0.2 additions
    for conditions that only arise in directory / manifest-aware verification;
    each gets a NEW exit number so existing exit-code contracts are untouched.
    """

    OK = "ok"
    CHAIN_BREAK = "chain_break"
    SIGNATURE_FAIL = "signature_fail"
    KEY_RESOLUTION = "key_resolution"
    MALFORMED_JSONL = "malformed_jsonl"
    EMPTY = "empty"
    # v0.2 additions (directory / manifest mode only)
    PARTIAL = "partial"
    OFF_CANONICAL = "off_canonical"
    MANIFEST_PUBKEY_MISMATCH = "manifest_pubkey_mismatch"
    # The manifest's own attestation about the log — the per-chain record_count,
    # or a per-file sha256 / record_count — disagrees with what the log actually
    # contains. Injecting or duplicating a record, or a lie in the manifest's
    # count, lands here. An integrity break, never a pass.
    MANIFEST_INTEGRITY = "manifest_integrity"
    # A validly-signed record carries a redaction marker (or redacted-key
    # sentinel) that is NOT recorder-attested: a tool-supplied look-alike with no
    # backing entry, or one bearing a token that does not match the record's. The
    # signature is genuine (the recorder signed whatever the tool handed it), but
    # the "evidence of redaction" is forged. redaction_authenticity() surfaces it;
    # the verifier must not read PASS over it. See cli.py exit code 10.
    REDACTION_FORGERY = "redaction_forgery"


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

            # 3. Redaction authenticity — a validly-signed record must not carry a
            # tool-forged redaction marker / redacted-key sentinel. The signature
            # is genuine; the "evidence of redaction" is not. Checked after the
            # chain check so a chain break (more integrity-critical) is reported
            # first if both hold on the same record.
            authenticity = redaction_authenticity(record)
            if not authenticity.authentic:
                return LogVerificationResult(
                    path=path_str,
                    outcome=ChainCheckOutcome.REDACTION_FORGERY,
                    record_count=record_count,
                    chains_seen=chains_seen,
                    failed_at_offset=line_num,
                    failed_at_record_id=env.get("record_id"),
                    failure_detail=(
                        "unbacked/forged redaction marker(s) at "
                        f"{authenticity.forged_paths} — a validly-signed record "
                        "carries redaction evidence the recorder did not produce"
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


# ===========================================================================
# Directory / manifest-aware verification (v0.2)
# ===========================================================================
#
# The single-file `verify_log` above is the frozen backward-compatible API. It
# assumes one file, one sequential chain per chain_id, and one key. Real
# production trails (e.g. bosun's) break all three assumptions: a logical chain
# spans several daily files, signing keys rotate mid-chain, and the manifest —
# not the tool — is the authority on which records form the canonical chain.
#
# `verify_tree` handles that world. It reports ONLY facts it can back with
# evidence:
#   - a record's signature verified / did not verify / is unverifiable (no key);
#   - a record is or is not on the canonical path the MANIFEST attests;
#   - the manifest's claimed pubkey_id disagrees with the key it stores;
#   - a chain the manifest attests is wholly absent from the logs.
# It never guesses the CAUSE of an off-canonical record (deletion? concurrent
# writer? corruption?) — that is not observable from the log.


class RecordStatus(str, Enum):
    """Per-record signature verification status within a tree walk."""

    VERIFIED = "verified"
    UNVERIFIABLE_NO_KEY = "unverifiable_no_key"
    INVALID = "invalid"  # hash mismatch or signature does not verify (tamper)
    MALFORMED = "malformed"


@dataclass(frozen=True)
class Finding:
    """A single fact the verifier can back with evidence.

    `kind` is a stable machine slug; `detail` is human-readable. Findings never
    assert a cause the log does not record — an off-canonical record is labelled
    exactly that, with "reason not observable".
    """

    kind: str
    detail: str
    chain_id: str | None = None
    record_id: str | None = None


@dataclass
class ChainSummary:
    """Per-chain reconstruction result, defined against the manifest's claim."""

    chain_id: str
    in_manifest: bool
    manifest_record_count: int | None
    records_in_log: int
    canonical_count: int
    canonical_verified: int
    canonical_unverifiable_no_key: int
    off_path_records: int
    genesis_verified: bool
    head_reached: bool


@dataclass
class TreeVerificationResult:
    """Full result of verifying a directory / set of daily audit files."""

    root: str
    outcome: ChainCheckOutcome
    files: list[str] = field(default_factory=list)
    manifest_present: bool = False
    manifest_pubkey_id_claimed: str | None = None
    manifest_pubkey_id_derived: str | None = None
    # The recorder-attested redaction state ("unknown" | "enabled" | "disabled").
    # Absence of the field in the manifest reads "unknown", NEVER "enabled" — an
    # old `redaction_disabled: false` was a disconnected default, not an
    # attestation. See manifest.RedactionState and SCOPE_STATEMENT.md.
    manifest_redaction_state: str = "unknown"
    available_key_ids: list[str] = field(default_factory=list)
    total_records: int = 0
    canonical_records: int = 0
    verified_records: int = 0
    unverifiable_no_key: int = 0
    off_path_records: int = 0
    chains: list[ChainSummary] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return self.outcome == ChainCheckOutcome.OK


# The daily-file naming rule, learned from the real data: files are
# `audit-YYYY-MM-DD.jsonl`. An ISO date sorts lexically in chronological order,
# so a plain sorted glob yields the correct emission order across the tree, and
# a chain that spills past UTC midnight into the next day's file is walked in
# the order it was written.
_LOG_GLOB = "audit-*.jsonl"


def discover_log_files(root: Path) -> list[Path]:
    """Return the daily audit files under `root` in chronological (write) order."""
    return sorted(root.glob(_LOG_GLOB))


@dataclass
class _Entry:
    """One parsed record plus everything a chain walk needs about it."""

    record: dict[str, object]
    link: str
    prev: str | None
    record_id: str | None
    status: RecordStatus
    source_file: str


def _classify(
    record: dict[str, object], pubkeys: dict[str, Ed25519PublicKey]
) -> RecordStatus:
    rr = verify_record(record, pubkeys)
    if rr.is_valid:
        return RecordStatus.VERIFIED
    if rr.failure == VerificationFailure.UNKNOWN_KEY_ID:
        return RecordStatus.UNVERIFIABLE_NO_KEY
    if rr.failure == VerificationFailure.MALFORMED_RECORD:
        return RecordStatus.MALFORMED
    # HASH_MISMATCH or SIGNATURE_INVALID — we hold the key and it did not verify.
    return RecordStatus.INVALID


def _reconstruct_canonical(
    entries: list[_Entry],
    manifest_head: str | None,
    manifest_genesis: str | None,
) -> tuple[set[str], bool, bool, list[Finding]]:
    """Reconstruct the canonical path a manifest attests, back-to-front.

    Canonicity is defined by the manifest's CLAIM, never by the tool: the
    canonical chain is the unique lineage that ends at ``manifest_head`` and
    walks prev_hash pointers back to a null-prev genesis. Records not on that
    lineage are off-canonical — the walk reports their count as a fact and does
    not speculate why they exist.

    Returns (canonical_links, head_reached, genesis_verified, findings).
    """
    by_link: dict[str, _Entry] = {e.link: e for e in entries}
    findings: list[Finding] = []

    if manifest_head is None:
        return set(), False, False, findings

    head = by_link.get(manifest_head)
    if head is None:
        findings.append(
            Finding(
                kind="canonical_head_unreachable",
                detail=(
                    f"manifest attests head_hash {manifest_head} but no record in "
                    "the logs has that chain-link — head truncated or missing"
                ),
            )
        )
        return set(), False, False, findings

    canonical: set[str] = set()
    cur: _Entry | None = head
    genesis_verified = False
    while cur is not None:
        canonical.add(cur.link)
        if cur.prev is None:
            genesis_verified = manifest_genesis is None or cur.link == manifest_genesis
            if not genesis_verified:
                findings.append(
                    Finding(
                        kind="genesis_mismatch",
                        detail=(
                            f"genesis link {cur.link} does not match manifest "
                            f"genesis_hash {manifest_genesis}"
                        ),
                        record_id=cur.record_id,
                    )
                )
            break
        parent = by_link.get(cur.prev)
        if parent is None:
            findings.append(
                Finding(
                    kind="front_truncation",
                    detail=(
                        f"record {cur.record_id} claims prev_hash {cur.prev} but no "
                        "record with that chain-link is present — the front of the "
                        "canonical chain was truncated (reason not observable)"
                    ),
                    record_id=cur.record_id,
                )
            )
            break
        cur = parent

    return canonical, True, genesis_verified, findings


def _read_manifest_redaction_state(manifest: dict[str, object] | None) -> str:
    """Read the manifest's attested redaction state, honestly.

    Mirrors manifest.Manifest._read_redaction_state so the verifier and the
    recorder agree on the bridge: a v1.2 `redaction_state` is used verbatim; an
    old `redaction_disabled: true` still reads "disabled"; everything else —
    including an old `redaction_disabled: false` — reads "unknown", NEVER
    "enabled". Absence is not evidence of redaction.
    """
    if manifest is None:
        return "unknown"
    raw = manifest.get("redaction_state")
    if isinstance(raw, str) and raw in ("unknown", "enabled", "disabled"):
        return raw
    if manifest.get("redaction_disabled") is True:
        return "disabled"
    return "unknown"


def _load_manifest_raw(root: Path) -> tuple[dict[str, object] | None, Finding | None]:
    """Best-effort manifest load. Never raises: a corrupt/absent manifest DEGRADES
    to log-only verification with an explicit finding, and is NEVER a pass."""
    path = root / "manifest.json"
    if not path.is_file():
        return None, Finding(
            kind="manifest_absent",
            detail=(
                "no manifest.json in directory — manifest cross-check skipped; "
                "verification is log-only and cannot detect whole-chain deletion"
            ),
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return None, Finding(
            kind="manifest_corrupt",
            detail=(
                f"manifest.json could not be read ({e}) — manifest cross-check "
                "skipped; verification is log-only"
            ),
        )
    if not isinstance(data, dict):
        return None, Finding(
            kind="manifest_corrupt",
            detail="manifest.json is not a JSON object — cross-check skipped",
        )
    return data, None


def _file_digest(path: Path) -> str:
    """SHA-256 of a daily log file's raw bytes.

    Matches how ``LocalFileSink`` builds the manifest's per-file ``sha256``: it
    is taken over the exact bytes on disk, fork lines included. Streamed so a
    multi-MB daily file costs O(1) memory. This is the ROBUST anchor: it fires
    only when the bytes themselves changed after the manifest was written, and
    stays silent on a legitimately-attested fork archive (where the digest was
    written over the final bytes).
    """
    h = hashlib.sha256()
    with path.open("rb") as fb:
        while True:
            chunk = fb.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _check_manifest_files(
    root: Path,
    manifest: dict[str, object] | None,
    canonical_per_file: dict[str, int],
) -> tuple[list[Finding], bool]:
    """Cross-check each file the manifest attests against the bytes on disk.

    The manifest's ``files[]`` block records, per daily file, a ``sha256`` and a
    ``record_count``. Both are checked, but against DIFFERENT notions of the file:

    - ``sha256`` is compared to the digest of the raw bytes on disk. A change to
      the bytes after the manifest was written is a tamper — the robust anchor.
    - ``record_count`` holds the CANONICAL record count (the tally the manifest's
      authoritative writer kept), so it is compared to the verifier's
      canonical-reconstructed per-file count — the number of records in this file
      that sit on a manifest-attested canonical chain path — NOT the physical
      line count. A file legitimately carries off-canonical fork lines (abandoned
      retries, concurrent writers) whose bytes the ``sha256`` already covers; the
      physical line count then exceeds the canonical count by design, and
      comparing against it would false-positive on honest data. Comparing against
      the canonical count instead fires only when the count anchor is genuinely
      contradicted (an injected/duplicated CANONICAL record, or a lie in the
      attested count).

    A file the manifest attests but that is absent is an integrity break. Returns
    (findings, any_mismatch); when the manifest carries no ``files`` block (older
    manifests may not) it reports nothing and relies on the chain-level
    record_count cross-check instead.
    """
    findings: list[Finding] = []
    any_mismatch = False
    if manifest is None:
        return findings, False
    raw_files = manifest.get("files")
    if not isinstance(raw_files, dict):
        return findings, False

    for fname, meta in raw_files.items():
        if not isinstance(fname, str) or not isinstance(meta, dict):
            continue
        fpath = root / fname
        if not fpath.is_file():
            any_mismatch = True
            findings.append(
                Finding(
                    kind="attested_file_missing",
                    detail=(
                        f"manifest attests file {fname!r} but it is absent from "
                        "the directory (reason not observable — deletion, a moved "
                        "file, or a never-written file are indistinguishable here)"
                    ),
                )
            )
            continue
        attested_sha = meta.get("sha256")
        attested_count = meta.get("record_count")
        actual_sha = _file_digest(fpath)
        canonical_count = canonical_per_file.get(fname, 0)
        if isinstance(attested_sha, str) and actual_sha != attested_sha:
            any_mismatch = True
            findings.append(
                Finding(
                    kind="file_sha256_mismatch",
                    detail=(
                        f"file {fname!r}: actual sha256 {actual_sha} does not match "
                        f"the manifest attestation {attested_sha} — the file's bytes "
                        "changed after the manifest was written"
                    ),
                )
            )
        if isinstance(attested_count, int) and canonical_count != attested_count:
            any_mismatch = True
            findings.append(
                Finding(
                    kind="file_record_count_mismatch",
                    detail=(
                        f"file {fname!r}: {canonical_count} canonical record(s) "
                        f"reconstructed on a manifest-attested path but the manifest "
                        f"attests {attested_count} (off-canonical fork lines, if any, "
                        "are excluded — they are covered by the sha256 anchor)"
                    ),
                )
            )
    return findings, any_mismatch


def verify_tree(
    root: str | Path,
    extra_pubkeys: dict[str, Ed25519PublicKey] | None = None,
) -> TreeVerificationResult:
    """Verify a whole audit directory: multi-file chains, rotated keys, manifest.

    Keys are pooled from two sources, both real key MATERIAL run through
    ``load_public_key``: the caller's ``extra_pubkeys`` (from ``--pubkey`` PEM
    files) and the PEM embedded in ``manifest.pubkey_pem``. The manifest's
    ``pubkey_id`` field is NEVER trusted as a key identity — it is only compared
    against the id DERIVED from the stored PEM, and a disagreement is reported.
    """
    root = Path(root)
    pubkeys: dict[str, Ed25519PublicKey] = dict(extra_pubkeys or {})
    findings: list[Finding] = []

    manifest, manifest_finding = _load_manifest_raw(root)
    if manifest_finding is not None:
        findings.append(manifest_finding)

    manifest_pubkey_id_claimed: str | None = None
    manifest_pubkey_id_derived: str | None = None
    manifest_redaction_state = _read_manifest_redaction_state(manifest)
    if manifest is not None:
        claimed = manifest.get("pubkey_id")
        manifest_pubkey_id_claimed = claimed if isinstance(claimed, str) else None

        # Every key that ever declared itself to this directory. A rotated-away
        # key is only here because the manifest stopped overwriting the scalar
        # `pubkey_pem` — before that, its records were unverifiable forever. The
        # id is derived from each PEM rather than trusted from its map key, on
        # the same principle that `pubkey_id` is never trusted below.
        stored = manifest.get("pubkeys")
        if isinstance(stored, dict):
            for claimed_id, stored_pem in stored.items():
                if not isinstance(stored_pem, str) or not stored_pem.strip():
                    continue
                try:
                    key, derived = load_public_key_from_pem(stored_pem)
                except (ValueError, TypeError) as e:
                    findings.append(
                        Finding(
                            kind="manifest_pubkey_unloadable",
                            detail=(
                                f"manifest.pubkeys[{claimed_id!r}] could not be "
                                f"loaded: {e}"
                            ),
                        )
                    )
                    continue
                pubkeys.setdefault(derived, key)

        pem = manifest.get("pubkey_pem")
        if isinstance(pem, str) and pem.strip():
            try:
                key, derived = load_public_key_from_pem(pem)
            except (ValueError, TypeError) as e:
                findings.append(
                    Finding(
                        kind="manifest_pubkey_unloadable",
                        detail=f"manifest.pubkey_pem could not be loaded: {e}",
                    )
                )
            else:
                manifest_pubkey_id_derived = derived
                pubkeys.setdefault(derived, key)
                if (
                    manifest_pubkey_id_claimed is not None
                    and manifest_pubkey_id_claimed != derived
                ):
                    findings.append(
                        Finding(
                            kind="manifest_pubkey_id_mismatch",
                            detail=(
                                f"manifest claims pubkey_id {manifest_pubkey_id_claimed}"
                                f" but the PEM it stores derives {derived}; the claimed"
                                " id is stale and was NOT used for verification"
                            ),
                        )
                    )

    files = discover_log_files(root)

    # Group records by chain_id, preserving cross-file emission order. Chains are
    # bounded by one project-day, so holding a chain's entries in memory is fine.
    chains_in_log: dict[str, list[_Entry]] = {}
    any_malformed_json = False
    any_redaction_forgery = False
    for fp in files:
        try:
            fh = fp.open(encoding="utf-8")
        except OSError as e:
            findings.append(
                Finding(kind="file_unreadable", detail=f"could not open {fp}: {e}")
            )
            continue
        with fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n").rstrip("\r")
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    any_malformed_json = True
                    findings.append(
                        Finding(
                            kind="malformed_jsonl",
                            detail=f"{fp.name}: JSON parse error: {e}",
                        )
                    )
                    continue
                if not isinstance(record, dict):
                    any_malformed_json = True
                    findings.append(
                        Finding(
                            kind="malformed_record",
                            detail=f"{fp.name}: record is not a JSON object",
                        )
                    )
                    continue
                env = record.get("envelope")
                if not isinstance(env, dict):
                    findings.append(
                        Finding(
                            kind="malformed_record",
                            detail=f"{fp.name}: record missing envelope",
                        )
                    )
                    continue
                chain_id = env.get("chain_id")
                if not isinstance(chain_id, str):
                    findings.append(
                        Finding(
                            kind="malformed_record",
                            detail=f"{fp.name}: envelope.chain_id missing",
                        )
                    )
                    continue
                status = _classify(record, pubkeys)
                # Redaction authenticity: a validly-signed record must not carry a
                # tool-forged redaction marker / redacted-key sentinel. Reported as
                # a finding; a genuine record (or one with no markers) is silent.
                authenticity = redaction_authenticity(record)
                if not authenticity.authentic:
                    any_redaction_forgery = True
                    findings.append(
                        Finding(
                            kind="redaction_forgery",
                            detail=(
                                f"{fp.name}: unbacked/forged redaction marker(s) at "
                                f"{authenticity.forged_paths} — a validly-signed "
                                "record carries redaction evidence the recorder did "
                                "not produce"
                            ),
                            chain_id=chain_id,
                            record_id=(
                                env.get("record_id")
                                if isinstance(env.get("record_id"), str)
                                else None
                            ),
                        )
                    )
                try:
                    link = compute_chain_link(record)
                except Exception as e:  # noqa: BLE001 — surface, do not crash
                    findings.append(
                        Finding(
                            kind="malformed_record",
                            detail=f"{fp.name}: cannot canonicalize record: {e}",
                            chain_id=chain_id,
                        )
                    )
                    continue
                prev = env.get("prev_hash")
                rec_id = env.get("record_id")
                chains_in_log.setdefault(chain_id, []).append(
                    _Entry(
                        record=record,
                        link=link,
                        prev=prev if isinstance(prev, str) else None,
                        record_id=rec_id if isinstance(rec_id, str) else None,
                        status=status,
                        source_file=fp.name,
                    )
                )

    manifest_chains: dict[str, dict[str, object]] = {}
    if manifest is not None:
        raw_chains = manifest.get("chains")
        if isinstance(raw_chains, dict):
            for cid, cstate in raw_chains.items():
                if isinstance(cid, str) and isinstance(cstate, dict):
                    manifest_chains[cid] = cstate

    summaries: list[ChainSummary] = []
    total_records = 0
    canonical_records = 0
    verified_records = 0
    unverifiable_no_key = 0
    off_path_records = 0
    any_invalid_sig = False
    any_chain_break = False
    any_off_path = False
    any_count_mismatch = False
    # Per-file tally of records that sit on a manifest-attested canonical path.
    # This — not the physical line count — is what the manifest's files[]
    # record_count attests, so it is what the per-file count anchor compares to.
    canonical_per_file: dict[str, int] = {}

    # Iterate over the union of chains the manifest attests and chains seen in
    # the logs, in a deterministic order.
    all_chain_ids = sorted(set(manifest_chains) | set(chains_in_log))
    for cid in all_chain_ids:
        entries = chains_in_log.get(cid, [])
        total_records += len(entries)
        in_manifest = cid in manifest_chains
        cstate = manifest_chains.get(cid, {})
        m_count_raw = cstate.get("record_count")
        m_count = m_count_raw if isinstance(m_count_raw, int) else None
        m_head = cstate.get("head_hash")
        m_head = m_head if isinstance(m_head, str) else None
        m_gen = cstate.get("genesis_hash")
        m_gen = m_gen if isinstance(m_gen, str) else None

        for ent in entries:
            if ent.status == RecordStatus.INVALID:
                any_invalid_sig = True

        if in_manifest and not entries:
            # The manifest attests this chain, the logs have none of it.
            any_chain_break = True
            findings.append(
                Finding(
                    kind="whole_chain_missing",
                    detail=(
                        f"manifest attests chain {cid!r} with {m_count} records "
                        f"(head {m_head}) but the logs contain NONE of it "
                        "(reason not observable — deletion, a removed file, a "
                        "never-written chain, or a mislocated log are "
                        "indistinguishable here)"
                    ),
                    chain_id=cid,
                )
            )
            summaries.append(
                ChainSummary(
                    chain_id=cid,
                    in_manifest=True,
                    manifest_record_count=m_count,
                    records_in_log=0,
                    canonical_count=0,
                    canonical_verified=0,
                    canonical_unverifiable_no_key=0,
                    off_path_records=0,
                    genesis_verified=False,
                    head_reached=False,
                )
            )
            continue

        if not in_manifest:
            # Records exist for a chain the manifest never attested. We cannot
            # define a canonical path from a claim that does not exist; report
            # the fact and fall back to a sequential continuity check.
            findings.append(
                Finding(
                    kind="chain_not_in_manifest",
                    detail=(
                        f"chain {cid!r} appears in the logs ({len(entries)} records)"
                        " but the manifest does not attest it — cannot cross-check"
                        " a canonical path"
                    ),
                    chain_id=cid,
                )
            )
            canonical_links, head_reached, gen_ok, seq_off = _sequential_walk(entries)
            chain_findings = seq_off
        else:
            canonical_links, head_reached, gen_ok, chain_findings = (
                _reconstruct_canonical(entries, m_head, m_gen)
            )

        break_kinds = {
            "canonical_head_unreachable",
            "front_truncation",
            "genesis_mismatch",
            "sequential_break",
        }
        for cf in chain_findings:
            findings.append(
                Finding(
                    kind=cf.kind,
                    detail=cf.detail,
                    chain_id=cid,
                    record_id=cf.record_id,
                )
            )
            if cf.kind in break_kinds:
                any_chain_break = True

        c_count = 0
        c_verified = 0
        c_unverifiable = 0
        c_offpath = 0
        for ent in entries:
            on_path = ent.link in canonical_links
            if on_path:
                c_count += 1
                canonical_per_file[ent.source_file] = (
                    canonical_per_file.get(ent.source_file, 0) + 1
                )
                if ent.status == RecordStatus.VERIFIED:
                    c_verified += 1
                elif ent.status == RecordStatus.UNVERIFIABLE_NO_KEY:
                    c_unverifiable += 1
            elif head_reached:
                # Only count as off-path when we actually have a canonical path
                # to be "off" of; a broken/unreachable head is a chain_break,
                # reported above, not thousands of off-path records.
                c_offpath += 1

        if c_offpath and head_reached:
            any_off_path = True
            findings.append(
                Finding(
                    kind="off_canonical_path",
                    detail=(
                        f"{c_offpath} record(s) in chain {cid!r} are off the canonical"
                        " path the manifest attests (reason not observable — the log"
                        " does not record whether they are abandoned retries,"
                        " concurrent writers, partial deletion, or corruption)"
                    ),
                    chain_id=cid,
                )
            )
        if in_manifest and m_count is not None and head_reached and c_count != m_count:
            any_count_mismatch = True
            findings.append(
                Finding(
                    kind="count_mismatch",
                    detail=(
                        f"chain {cid!r}: manifest attests {m_count} canonical records"
                        f" but {c_count} were reconstructed on the attested path"
                        " (reason not observable)"
                    ),
                    chain_id=cid,
                )
            )

        canonical_records += c_count
        verified_records += c_verified
        unverifiable_no_key += c_unverifiable
        off_path_records += c_offpath
        summaries.append(
            ChainSummary(
                chain_id=cid,
                in_manifest=in_manifest,
                manifest_record_count=m_count,
                records_in_log=len(entries),
                canonical_count=c_count,
                canonical_verified=c_verified,
                canonical_unverifiable_no_key=c_unverifiable,
                off_path_records=c_offpath,
                genesis_verified=gen_ok,
                head_reached=head_reached,
            )
        )

    # Cross-check the manifest's per-file attestation against the bytes on disk:
    # sha256 against the raw bytes (fork lines included), and record_count against
    # the canonical-reconstructed per-file tally built above (NOT the physical
    # line count, which legitimately exceeds it whenever off-canonical forks sit
    # on disk). It catches a duplicated/edited canonical line or a count-lie while
    # staying silent on a faithfully-attested fork archive.
    file_findings, any_file_mismatch = _check_manifest_files(
        root, manifest, canonical_per_file
    )
    findings.extend(file_findings)

    mismatch = any(
        f.kind == "manifest_pubkey_id_mismatch" for f in findings
    )
    outcome = _aggregate_outcome(
        total_records=total_records,
        verified=verified_records,
        unverifiable=unverifiable_no_key,
        any_invalid_sig=any_invalid_sig,
        any_chain_break=any_chain_break,
        any_malformed_json=any_malformed_json,
        any_off_path=any_off_path,
        manifest_pubkey_mismatch=mismatch,
        manifest_integrity_break=any_count_mismatch or any_file_mismatch,
        any_redaction_forgery=any_redaction_forgery,
    )

    return TreeVerificationResult(
        root=str(root),
        outcome=outcome,
        files=[f.name for f in files],
        manifest_present=manifest is not None,
        manifest_pubkey_id_claimed=manifest_pubkey_id_claimed,
        manifest_pubkey_id_derived=manifest_pubkey_id_derived,
        manifest_redaction_state=manifest_redaction_state,
        available_key_ids=sorted(pubkeys),
        total_records=total_records,
        canonical_records=canonical_records,
        verified_records=verified_records,
        unverifiable_no_key=unverifiable_no_key,
        off_path_records=off_path_records,
        chains=summaries,
        findings=findings,
    )


def _sequential_walk(
    entries: list[_Entry],
) -> tuple[set[str], bool, bool, list[Finding]]:
    """Fallback for a chain not attested by any manifest: walk sequentially and
    treat the first record as genesis. Returns the same shape as
    `_reconstruct_canonical`. Every record that continues the sequential head is
    "canonical"; a discontinuity is reported as a sequential_break."""
    canonical: set[str] = set()
    findings: list[Finding] = []
    head: str | None = None
    gen_ok = True
    for i, e in enumerate(entries):
        if head is None:
            gen_ok = e.prev is None
            if not gen_ok:
                findings.append(
                    Finding(
                        kind="sequential_break",
                        detail=(
                            f"first record of unattested chain has non-null prev_hash "
                            f"{e.prev}"
                        ),
                        record_id=e.record_id,
                    )
                )
            canonical.add(e.link)
            head = e.link
        elif e.prev == head:
            canonical.add(e.link)
            head = e.link
        else:
            findings.append(
                Finding(
                    kind="sequential_break",
                    detail=(
                        f"record {i} of unattested chain claims prev_hash {e.prev}, "
                        f"expected {head}"
                    ),
                    record_id=e.record_id,
                )
            )
    return canonical, True, gen_ok, findings


# Precedence for collapsing many simultaneous conditions into one exit code.
# DOCUMENTED (see SIGNING.md §7.3 and cli.py): the most integrity-critical
# condition wins. Off-canonical records are non-zero by owner decision — an
# auditor must never read exit 0 over a log containing records that do not chain.
# A manifest-integrity break (the log disagrees with its own manifest's
# record_count / per-file digest) slots just under CHAIN_BREAK: like a chain
# break it is a hard integrity disagreement with the anchor, and it must never
# read as a pass. A redaction-forgery break (a validly-signed record carries a
# tool-forged redaction marker) slots just above manifest-integrity — same tier:
# a content-integrity break that must never read as a pass.
def _aggregate_outcome(
    *,
    total_records: int,
    verified: int,
    unverifiable: int,
    any_invalid_sig: bool,
    any_chain_break: bool,
    any_malformed_json: bool,
    any_off_path: bool,
    manifest_pubkey_mismatch: bool,
    manifest_integrity_break: bool,
    any_redaction_forgery: bool,
) -> ChainCheckOutcome:
    if any_invalid_sig:
        return ChainCheckOutcome.SIGNATURE_FAIL
    if any_chain_break:
        return ChainCheckOutcome.CHAIN_BREAK
    # A forged redaction marker in a validly-signed record is a content-integrity
    # break — the signed "evidence of redaction" is fabricated. It slots with the
    # other integrity breaks (above malformed/off-canonical), and never a pass.
    if any_redaction_forgery:
        return ChainCheckOutcome.REDACTION_FORGERY
    if manifest_integrity_break:
        return ChainCheckOutcome.MANIFEST_INTEGRITY
    if any_malformed_json:
        return ChainCheckOutcome.MALFORMED_JSONL
    if any_off_path:
        return ChainCheckOutcome.OFF_CANONICAL
    if manifest_pubkey_mismatch:
        return ChainCheckOutcome.MANIFEST_PUBKEY_MISMATCH
    if verified > 0 and unverifiable > 0:
        return ChainCheckOutcome.PARTIAL
    if verified == 0 and unverifiable > 0:
        return ChainCheckOutcome.KEY_RESOLUTION
    if total_records == 0:
        return ChainCheckOutcome.EMPTY
    return ChainCheckOutcome.OK


__all__ = [
    "ChainCheckOutcome",
    "ChainSummary",
    "Finding",
    "LogVerificationResult",
    "RecordStatus",
    "TreeVerificationResult",
    "discover_log_files",
    "verify_log",
    "verify_tree",
]
