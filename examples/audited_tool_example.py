"""Runnable example: instrumenting plain Python functions with @audited_tool.

This is the minimal entry point for users who DON'T use Claude Code, LangGraph,
or any other framework — just plain Python functions they want recorded.

This script:
  1. Generates a throwaway Ed25519 signing key in a temp dir
  2. Builds an AuditRecorder backed by a LocalFileSink
  3. Defines two normal Python functions decorated with @audited_tool
  4. Calls them like ordinary code
  5. Reads the resulting JSONL audit log + runs `agent-audit verify`
  6. Prints a one-line summary per record

Run with:  python examples/audited_tool_example.py

Output: every decorated call produces one signed, chained record. Pass-through
return values are preserved — the decorator is invisible to the caller. PII in
arguments is redacted by default (email / AWS keys / OpenAI keys / etc); add
your own rules via RedactionConfig if you want custom patterns.
"""

from __future__ import annotations

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

from agent_audit import AuditRecorder, LocalFileSink, audited_tool, load_signing_key


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="agent-audit-tool-"))
    print(f"working dir: {workspace}")

    # --- 1. dev signing key ----------------------------------------------
    pk = Ed25519PrivateKey.generate()
    priv = workspace / "signing.key"
    pub = workspace / "signing.pub"
    priv.write_bytes(pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    priv.chmod(0o600)
    pub.write_bytes(
        pk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    # --- 2. recorder backed by LocalFileSink ------------------------------
    audit_dir = workspace / "audit"
    sink = LocalFileSink(dir=audit_dir, pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(
        sink=sink,
        signing_key=load_signing_key(priv),
        chain_id="tool-demo",
    )

    # --- 3. plain Python functions, decorated -----------------------------
    @audited_tool(recorder, session_id="demo-session")
    def lookup_customer(customer_id: str) -> dict[str, str]:
        """Pretend to look up a customer record."""
        return {"id": customer_id, "name": "Acme Corp", "tier": "enterprise"}

    @audited_tool(recorder, session_id="demo-session")
    def notify(channel: str, message: str) -> bool:
        """Pretend to send a notification."""
        # message contains a deliberate email so the redactor fires
        return True

    # --- 4. call them normally — decorator is invisible -------------------
    print("\ncalling decorated functions...")
    customer = lookup_customer(customer_id="cus_12345")
    print(f"  lookup_customer → {customer}")
    notified = notify(
        channel="#ops",
        message="customer cus_12345 hit a limit, ping foo@example.com",
    )
    print(f"  notify → {notified}")

    # --- 5. inspect the audit log + verify --------------------------------
    jsonl = next(audit_dir.glob("audit-*.jsonl"))
    print(f"\naudit log:  {jsonl}")
    print(f"records:    {sum(1 for line in jsonl.read_text().splitlines() if line)}")

    verify = subprocess.run(
        [sys.executable, "-m", "agent_audit.cli", "verify", str(jsonl), "--pubkey", str(pub)],
        capture_output=True,
        text=True,
    )
    print(f"\nverifier exit code: {verify.returncode}")
    print(verify.stdout)

    # --- 6. summary per record + the redaction trail ----------------------
    print("record summary:")
    for line_num, line in enumerate(jsonl.read_text().splitlines(), start=1):
        if not line:
            continue
        rec = json.loads(line)
        tool_name = rec["payload"]["tool"]["name"]
        redactions = rec["payload"]["redaction"]
        print(f"  {line_num}. tool={tool_name} redactions={len(redactions)}")
        for r in redactions:
            print(f"       - {r['path']} → policy={r['policy']}")

    return verify.returncode


if __name__ == "__main__":
    sys.exit(main())
