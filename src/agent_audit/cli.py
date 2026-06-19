"""agent-audit CLI — verify / inspect / pubkey-fingerprint.

Exit codes are STABLE and documented in SIGNING.md:
  0 — ok
  1 — chain break
  2 — signature failure (record hash or Ed25519 verify)
  3 — key resolution failure (unknown key_id or unloadable pubkey)
  4 — malformed JSONL (parse error or schema mismatch)
  5 — empty log

CI integrations and audit scripts depend on these — do not renumber.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from agent_audit.keys import load_public_key
from agent_audit.report import format_json_report, format_text_report
from agent_audit.verify import ChainCheckOutcome, verify_log

EXIT_OK = 0
EXIT_CHAIN_BREAK = 1
EXIT_SIGNATURE_FAIL = 2
EXIT_KEY_RESOLUTION = 3
EXIT_MALFORMED = 4
EXIT_EMPTY = 5

_OUTCOME_TO_EXIT: dict[ChainCheckOutcome, int] = {
    ChainCheckOutcome.OK: EXIT_OK,
    ChainCheckOutcome.CHAIN_BREAK: EXIT_CHAIN_BREAK,
    ChainCheckOutcome.SIGNATURE_FAIL: EXIT_SIGNATURE_FAIL,
    ChainCheckOutcome.KEY_RESOLUTION: EXIT_KEY_RESOLUTION,
    ChainCheckOutcome.MALFORMED_JSONL: EXIT_MALFORMED,
    ChainCheckOutcome.EMPTY: EXIT_EMPTY,
}


@click.group()
def cli() -> None:
    """agent-audit — verify and inspect AI agent audit trails."""


@cli.command("verify")
@click.argument(
    "log_path",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
)
@click.option(
    "--pubkey",
    "pubkey_path",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    required=True,
    help="Path to Ed25519 public-key PEM file.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["report", "json"], case_sensitive=False),
    default="report",
    show_default=True,
    help="Output format. 'report' is byte-deterministic plain text.",
)
def cmd_verify(log_path: Path, pubkey_path: Path, fmt: str) -> None:
    """Verify an audit JSONL log against an Ed25519 public key."""
    try:
        pubkey, key_id = load_public_key(pubkey_path)
    except (OSError, ValueError, TypeError) as e:
        click.echo(f"agent-audit: failed to load public key: {e}", err=True)
        sys.exit(EXIT_KEY_RESOLUTION)

    result = verify_log(log_path, {key_id: pubkey})

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
def cmd_inspect(log_path: Path, head: int) -> None:
    """Print a one-line summary per record (tool, chain, policy)."""
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
            click.echo(
                f"line {line_num}: chain={env.get('chain_id', '?')!s} "
                f"step={header.get('step_id', '?')!s} tool={tool!s} "
                f"policy={policy_kind!s}"
            )
            shown += 1


def main() -> None:
    """Console-script entry point. See pyproject.toml [project.scripts]."""
    cli()


__all__ = [
    "EXIT_CHAIN_BREAK",
    "EXIT_EMPTY",
    "EXIT_KEY_RESOLUTION",
    "EXIT_MALFORMED",
    "EXIT_OK",
    "EXIT_SIGNATURE_FAIL",
    "cli",
    "main",
]
