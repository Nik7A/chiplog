"""agent-audit CLI — verify / inspect / pubkey-fingerprint.

Exit codes are STABLE and documented in SIGNING.md:
  0 — ok
  1 — chain break
  2 — signature failure (record hash or Ed25519 verify)
  3 — key resolution failure (unknown key_id or unloadable pubkey)
  4 — malformed JSONL (parse error or schema mismatch)
  5 — empty log

v0.2 adds three codes for conditions that only arise in directory / manifest
verification (a single file cannot exhibit them, so codes 0–5 keep their exact
meanings):
  6 — partial verification (>=1 attested record verified, >=1 unverifiable for
      want of a key). If NOTHING verified, that is code 3, not 6.
  7 — off-canonical records present (records that do not chain onto the path the
      manifest attests). Non-zero by design: an auditor must never read exit 0
      over a log containing records that don't chain.
  8 — manifest pubkey_id is stale (disagrees with the key material it stores).
  9 — manifest-integrity break: the log disagrees with its own manifest anchor —
      the per-chain record_count, or a per-file sha256 / record_count. Injecting
      or duplicating a record, or a lie in the manifest's count, lands here.
 10 — redaction-forgery break: a validly-signed record carries a tool-forged
      redaction marker / redacted-key sentinel (no backing entry, or a token that
      does not match the record's). The signature is genuine but the "evidence of
      redaction" is fabricated; redaction_authenticity() surfaces it. Applies to
      both single-file and directory verification.

When several conditions hold at once, the exit code is the most integrity-
critical one (precedence: 2 > 1 > 10 > 9 > 4 > 7 > 8 > 6 > 3 > 5 > 0); the full
report still enumerates every finding.

Note on directory mode with an absent/corrupt manifest: verification DEGRADES to
log-only and returns exit 0 (the records present verify and chain), the SAME code
as a full manifest-anchored pass. That is deliberate for backward compatibility,
but it means exit code alone cannot distinguish the two. A CI that needs full
manifest-anchored assurance MUST also assert `manifest_present == true` (JSON) or
reject the "LOG-ONLY PASS" verdict (text) — in log-only mode, tail- and
whole-chain deletion are undetectable.

CI integrations and audit scripts depend on these — do not renumber.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from agent_audit.adapters.claude_code import (
    HookConfig,
    emit_from_hook,
    parse_hook_input,
)
from agent_audit.keys import load_public_key
from agent_audit.report import (
    format_json_report,
    format_text_report,
    format_tree_json_report,
    format_tree_text_report,
)
from agent_audit.verify import ChainCheckOutcome, verify_log, verify_tree

EXIT_OK = 0
EXIT_CHAIN_BREAK = 1
EXIT_SIGNATURE_FAIL = 2
EXIT_KEY_RESOLUTION = 3
EXIT_MALFORMED = 4
EXIT_EMPTY = 5
EXIT_PARTIAL = 6
EXIT_OFF_CANONICAL = 7
EXIT_MANIFEST_MISMATCH = 8
EXIT_MANIFEST_INTEGRITY = 9
EXIT_REDACTION_FORGERY = 10

_OUTCOME_TO_EXIT: dict[ChainCheckOutcome, int] = {
    ChainCheckOutcome.OK: EXIT_OK,
    ChainCheckOutcome.CHAIN_BREAK: EXIT_CHAIN_BREAK,
    ChainCheckOutcome.SIGNATURE_FAIL: EXIT_SIGNATURE_FAIL,
    ChainCheckOutcome.KEY_RESOLUTION: EXIT_KEY_RESOLUTION,
    ChainCheckOutcome.MALFORMED_JSONL: EXIT_MALFORMED,
    ChainCheckOutcome.EMPTY: EXIT_EMPTY,
    ChainCheckOutcome.PARTIAL: EXIT_PARTIAL,
    ChainCheckOutcome.OFF_CANONICAL: EXIT_OFF_CANONICAL,
    ChainCheckOutcome.MANIFEST_PUBKEY_MISMATCH: EXIT_MANIFEST_MISMATCH,
    ChainCheckOutcome.MANIFEST_INTEGRITY: EXIT_MANIFEST_INTEGRITY,
    ChainCheckOutcome.REDACTION_FORGERY: EXIT_REDACTION_FORGERY,
}


@click.group()
def cli() -> None:
    """agent-audit — verify and inspect AI agent audit trails."""


@cli.command("verify")
@click.argument(
    "log_path",
    type=click.Path(exists=True, dir_okay=True, readable=True, path_type=Path),
)
@click.option(
    "--pubkey",
    "pubkey_paths",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    multiple=True,
    help=(
        "Path to an Ed25519 public-key PEM file. Repeatable — pass one per "
        "signing key when a chain rotates keys. In directory mode the key stored "
        "in the manifest is loaded automatically, so --pubkey is optional there."
    ),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["report", "json"], case_sensitive=False),
    default="report",
    show_default=True,
    help="Output format. 'report' is byte-deterministic plain text.",
)
def cmd_verify(log_path: Path, pubkey_paths: tuple[Path, ...], fmt: str) -> None:
    """Verify an audit trail.

    LOG_PATH may be a single JSONL file (the original single-file, single-key
    contract, unchanged) or a DIRECTORY of daily `audit-YYYY-MM-DD.jsonl` files
    with a `manifest.json`. Directory mode walks logical chains across files,
    resolves rotated keys, and cross-checks the manifest.
    """
    # Load every provided pubkey into a keyid -> key pool (rotated-key support).
    pubkeys = {}
    for p in pubkey_paths:
        try:
            key, key_id = load_public_key(p)
        except (OSError, ValueError, TypeError) as e:
            click.echo(f"agent-audit: failed to load public key {p}: {e}", err=True)
            sys.exit(EXIT_KEY_RESOLUTION)
        pubkeys[key_id] = key

    if log_path.is_dir():
        tree = verify_tree(log_path, pubkeys)
        if fmt == "report":
            click.echo(format_tree_text_report(tree), nl=False)
        else:
            click.echo(format_tree_json_report(tree), nl=False)
        sys.exit(_OUTCOME_TO_EXIT[tree.outcome])

    # Single-file mode — identical semantics to v0.1.
    if not pubkeys:
        click.echo(
            "agent-audit: --pubkey is required when verifying a single file",
            err=True,
        )
        sys.exit(EXIT_KEY_RESOLUTION)

    result = verify_log(log_path, pubkeys)

    if fmt == "report":
        click.echo(format_text_report(result), nl=False)
    else:
        click.echo(format_json_report(result), nl=False)

    sys.exit(_OUTCOME_TO_EXIT[result.outcome])


@cli.command("pubkey-fingerprint")
@click.argument(
    "pubkey_path",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
)
def cmd_pubkey_fingerprint(pubkey_path: Path) -> None:
    """Print the key_id (first 16 hex of SHA-256(pubkey_raw)) for a PEM file."""
    try:
        _, key_id = load_public_key(pubkey_path)
    except (OSError, ValueError, TypeError) as e:
        click.echo(f"agent-audit: failed to load public key: {e}", err=True)
        sys.exit(EXIT_KEY_RESOLUTION)
    click.echo(key_id)


def cmd_inspect(log_path: Path, head: int = 10) -> None:
    """Print a one-line summary per record (tool, chain, policy, outcome).

    Plain function (not a click.Command) so it can be called and tested
    directly, e.g. ``cmd_inspect(log_path, head=10)``. The ``inspect`` CLI
    subcommand below is a thin click wrapper around it.

    Deliberately reads raw dicts and never validates against the ``Record``
    Pydantic model — that is what keeps pre-v1.1 records (missing
    ``payload.outcome``) inspectable. Every field access below uses the
    ``.get(..., "?")`` fallback convention for exactly this reason.
    """
    shown = 0
    with open(log_path, encoding="utf-8") as f:
        for line_num, raw in enumerate(f, start=1):
            if shown >= head:
                break
            line = raw.rstrip("\n").rstrip("\r")
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                click.echo(f"line {line_num}: <malformed JSON>")
                shown += 1
                continue
            env = record.get("envelope", {}) or {}
            header = record.get("header", {}) or {}
            payload = record.get("payload", {}) or {}
            tool = (payload.get("tool") or {}).get("name", "?")
            policy_kind = (payload.get("policy") or {}).get("kind", "?")
            outcome_kind = (payload.get("outcome") or {}).get("kind", "?")
            click.echo(
                f"line {line_num}: chain={env.get('chain_id', '?')!s} "
                f"step={header.get('step_id', '?')!s} tool={tool!s} "
                f"policy={policy_kind!s} outcome={outcome_kind!s}"
            )
            shown += 1


@cli.command("inspect")
@click.argument(
    "log_path",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
)
@click.option(
    "--head",
    type=int,
    default=10,
    show_default=True,
    help="Show first N records.",
)
def _cmd_inspect(log_path: Path, head: int) -> None:
    """Print a one-line summary per record (tool, chain, policy, outcome)."""
    cmd_inspect(log_path, head)


@cli.command("hook-record")
@click.option(
    "--chain-id",
    "chain_id",
    type=str,
    default=None,
    help=(
        "Override chain_id for all hook records. Use a stable string "
        "(e.g. 'daemon-global') to write a single linked chain across many "
        "sessions, instead of one chain per session_id. Takes precedence "
        "over the AGENT_AUDIT_CHAIN_ID environment variable."
    ),
)
def cmd_hook_record(chain_id: str | None) -> None:
    """Read Claude Code hook JSON from stdin and emit one audit record.

    Designed to be registered as a `PostToolUse` hook in
    `~/.claude/settings.json`. Concurrent hook firings (parallel `Task`
    spawns in Claude Code) are serialised via flock on
    `<audit_dir>/state.lock` so the chain head stays consistent.

    Config (CLI flag > env > default):
      --chain-id               (overrides env)
      AGENT_AUDIT_DIR          (default: ~/.config/agent-audit)
      AGENT_AUDIT_SIGNING_KEY  (default: <dir>/signing.key)
      AGENT_AUDIT_PUBKEY       (default: <dir>/signing.pub, if it exists)
      AGENT_AUDIT_CHAIN_ID     (default: hook payload's session_id)
    """
    import dataclasses
    import fcntl

    raw = sys.stdin.read()
    hook_input = parse_hook_input(raw)
    config = HookConfig.from_env()
    if chain_id is not None:
        config = dataclasses.replace(config, chain_id_override=chain_id)

    config.audit_dir.mkdir(parents=True, exist_ok=True)
    lock_path = config.audit_dir / "state.lock"

    with open(lock_path, "w") as lockf:
        fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
        try:
            emit_from_hook(hook_input, config)
        finally:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)

    sys.exit(EXIT_OK)


def main() -> None:
    """Console-script entry point. See pyproject.toml [project.scripts]."""
    cli()


__all__ = [
    "EXIT_CHAIN_BREAK",
    "EXIT_EMPTY",
    "EXIT_KEY_RESOLUTION",
    "EXIT_MALFORMED",
    "EXIT_MANIFEST_INTEGRITY",
    "EXIT_MANIFEST_MISMATCH",
    "EXIT_OFF_CANONICAL",
    "EXIT_OK",
    "EXIT_PARTIAL",
    "EXIT_REDACTION_FORGERY",
    "EXIT_SIGNATURE_FAIL",
    "cli",
    "main",
]


if __name__ == "__main__":
    main()
