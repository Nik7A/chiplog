"""Runnable example: instrumenting a Claude Agent SDK session with AuditHook.

This script:
  1. Generates a throwaway Ed25519 signing key in a temp dir
  2. Builds an AuditRecorder backed by a LocalFileSink
  3. Demonstrates the production wiring (commented out — needs an
     ANTHROPIC_API_KEY or a configured CLI for a real ClaudeSDKClient run)
  4. Drives AuditHook directly through its callback with two synthetic
     ``PostToolUse`` inputs, mirroring what the SDK feeds it during a real
     session
  5. Reads the resulting JSONL audit log + runs `chiplog verify`
  6. Prints a one-line summary per record

Run with:  python examples/claude_agent_sdk_example.py
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from chiplog import AuditRecorder, LocalFileSink, load_signing_key
from chiplog.adapters.claude_agent_sdk import AuditHook


# ---------------------------------------------------------------------------
# Reference: production wiring (commented out — needs API access)
# ---------------------------------------------------------------------------
#
# from claude_agent_sdk import (
#     ClaudeAgentOptions, ClaudeSDKClient, HookMatcher,
# )
#
# options = ClaudeAgentOptions(
#     hooks={
#         "PostToolUse": [
#             HookMatcher(matcher="*", hooks=[AuditHook(recorder=recorder)]),
#         ],
#     },
# )
# client = ClaudeSDKClient(options=options)
# async for message in client.query("Read /etc/hosts"):
#     ...
#
# Every successful tool call dispatched during the session lands as a signed
# record in ./audit/audit-YYYY-MM-DD.jsonl. session_id and tool_use_id come
# from the SDK directly — no need to thread them through manually.


def _generate_keypair(out_dir: Path) -> Path:
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


async def _drive_hook(hook: AuditHook) -> None:
    """Two synthetic PostToolUse inputs shaped like the real SDK payload."""
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "session_id": "example-session",
            "transcript_path": "/tmp/example-transcript.jsonl",
            "cwd": "/workspace",
            "tool_use_id": "toolu_001_read",
            "tool_name": "Read",
            "tool_input": {"file_path": "/etc/hosts"},
            "tool_response": "127.0.0.1 localhost\n::1 localhost",
        },
        tool_use_id="toolu_001_read",
        context={},
    )
    await hook(
        hook_input={
            "hook_event_name": "PostToolUse",
            "session_id": "example-session",
            "transcript_path": "/tmp/example-transcript.jsonl",
            "cwd": "/workspace",
            "tool_use_id": "toolu_002_bash",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la /workspace"},
            "tool_response": "total 24\ndrwxr-xr-x  3 user  group   96 Jun 23 11:00 .",
        },
        tool_use_id="toolu_002_bash",
        context={},
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
        hook = AuditHook(recorder=recorder)

        asyncio.run(_drive_hook(hook))

        jsonl_files = sorted(audit_dir.glob("audit-*.jsonl"))
        if not jsonl_files:
            print("ERROR: no audit JSONL produced", file=sys.stderr)
            sys.exit(1)
        jsonl_path = jsonl_files[0]

        pubkey_path = signing_key_path.with_suffix(".pub")
        verify = subprocess.run(
            [
                "chiplog",
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
            sid = rec["header"]["session_id"]
            step = rec["header"]["step_id"]
            print(f"  {i}. session={sid!r} step={step!r} tool={tool!r}")


if __name__ == "__main__":
    main()
