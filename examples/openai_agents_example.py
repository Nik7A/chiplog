"""Runnable example: instrumenting an OpenAI Agents SDK runtime with AuditHooks.

This script:
  1. Generates a throwaway Ed25519 signing key in a temp dir
  2. Builds an AuditRecorder backed by a LocalFileSink
  3. Demonstrates the production wiring — what users actually paste into
     their code (Runner.run(..., hooks=AuditHooks(recorder=...))) — as
     reference, without invoking it (the SDK needs an OPENAI_API_KEY for
     a real run)
  4. Drives AuditHooks directly through its lifecycle with two synthetic
     tool-call invocations, mirroring what the SDK would feed it during
     a real run
  5. Reads the resulting JSONL audit log + runs `agent-audit verify`
  6. Prints a one-line summary per record

Run with:  python examples/openai_agents_example.py
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from agent_audit import AuditRecorder, LocalFileSink, load_signing_key
from agent_audit.adapters.openai_agents import AuditHooks


# ---------------------------------------------------------------------------
# Reference: production wiring (commented out — needs OPENAI_API_KEY to run)
# ---------------------------------------------------------------------------
#
# from agents import Agent, Runner, function_tool
#
# @function_tool
# def add_numbers(a: int, b: int) -> int:
#     return a + b
#
# agent = Agent(
#     name="calculator",
#     instructions="You are a calculator. Use the add_numbers tool.",
#     tools=[add_numbers],
# )
#
# result = await Runner.run(
#     starting_agent=agent,
#     input="What is 17 + 25?",
#     hooks=AuditHooks(recorder=recorder, session_id="calc-session"),
# )
#
# After the run, ./audit/audit-YYYY-MM-DD.jsonl contains a signed record
# for every tool call the SDK dispatched during the run.

# ---------------------------------------------------------------------------
# Synthetic invocation (runs without OPENAI_API_KEY): drives AuditHooks
# directly with stand-in objects shaped like what the SDK would pass.
# ---------------------------------------------------------------------------


@dataclass
class _StubTool:
    name: str


@dataclass
class _StubAgent:
    name: str


@dataclass
class _StubToolContext:
    tool_name: str
    tool_arguments: str
    tool_call_id: str = "call-stub-001"


def _generate_keypair(out_dir: Path) -> Path:
    """Generate ephemeral Ed25519 key, return the private-key path."""
    pk = Ed25519PrivateKey.generate()
    priv_path = out_dir / "signing.key"
    pub_path = out_dir / "signing.pub"
    priv_path.write_bytes(
        pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    pub_path.write_bytes(
        pk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    priv_path.chmod(0o600)
    return priv_path


async def _drive_hooks(hooks: AuditHooks) -> None:
    agent = _StubAgent(name="finance_assistant")

    # First tool call — a document search
    await hooks.on_tool_end(
        context=_StubToolContext(
            tool_name="search_documents",
            tool_arguments=json.dumps({"query": "Q4 2025 VAT invoices", "limit": 50}),
        ),
        agent=agent,
        tool=_StubTool(name="search_documents"),
        result="matched 12 invoices in /finance/2025/q4",
    )

    # Second tool call — a row lookup
    await hooks.on_tool_end(
        context=_StubToolContext(
            tool_name="fetch_row",
            tool_arguments=json.dumps({"table": "invoices", "id": 9981}),
        ),
        agent=agent,
        tool=_StubTool(name="fetch_row"),
        result={"id": 9981, "total_eur": 1842.50, "vendor": "ACME GmbH"},
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        signing_key_path = _generate_keypair(tmp_dir)
        audit_dir = tmp_dir / "audit"

        recorder = AuditRecorder(
            sink=LocalFileSink(dir=audit_dir),
            signing_key=load_signing_key(signing_key_path),
        )
        hooks = AuditHooks(recorder=recorder, session_id="example-session")

        asyncio.run(_drive_hooks(hooks))

        # Locate the produced JSONL
        jsonl_files = sorted(audit_dir.glob("audit-*.jsonl"))
        if not jsonl_files:
            print("ERROR: no audit JSONL produced", file=sys.stderr)
            sys.exit(1)
        jsonl_path = jsonl_files[0]

        # Run the CLI verifier against the public key
        pubkey_path = signing_key_path.with_suffix(".pub")
        verify = subprocess.run(
            [
                "agent-audit",
                "verify",
                str(jsonl_path),
                "--pubkey",
                str(pubkey_path),
            ],
            capture_output=True,
            text=True,
        )
        if verify.returncode != 0:
            print("VERIFY FAILED:", verify.stdout, verify.stderr, file=sys.stderr)
            sys.exit(verify.returncode)

        print(f"Wrote {jsonl_path}")
        print(verify.stdout.strip())
        print()
        print("Records:")
        for i, line in enumerate(jsonl_path.read_text().splitlines(), start=1):
            rec = json.loads(line)
            tool = rec["payload"]["tool"]["name"]
            agent = rec["header"]["agent_name"]
            print(f"  {i}. tool={tool!r} agent={agent!r}")


if __name__ == "__main__":
    main()
