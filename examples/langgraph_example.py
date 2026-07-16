"""Runnable example: instrumenting a LangGraph create_agent with AuditMiddleware.

This script:
  1. Generates a throwaway Ed25519 signing key in a temp dir
  2. Builds an AuditRecorder backed by a LocalFileSink
  3. Constructs a tiny `create_agent` with one tool (`add_numbers`) and
     attaches AuditMiddleware
  4. Runs the agent with a fake tool-calling chat model so it executes
     without an external API key
  5. Reads the resulting JSONL audit log + runs `chiplog verify`
  6. Prints a one-line summary per record

Run with:  python examples/langgraph_example.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from langchain.agents import create_agent
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from chiplog import AuditRecorder, LocalFileSink, load_signing_key
from chiplog.adapters.langgraph import AuditMiddleware


class FakeToolCallingChatModel:
    """Tool-calling stand-in for create_agent — no external API needed.

    Yields a pre-configured sequence of AIMessages: first one carries a
    tool_calls payload (create_agent dispatches to the tool), second is
    plain text (the agent terminates).
    """

    def __init__(self, messages: list[Any]) -> None:
        self._messages = list(messages)
        self._idx = 0

    def bind_tools(self, tools: list[Any], **_: Any) -> FakeToolCallingChatModel:
        return self

    def invoke(self, _input: Any, _config: Any = None, **_: Any) -> Any:
        msg = self._messages[self._idx]
        self._idx += 1
        return msg


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="chiplog-langgraph-"))
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
        chain_id="example",
    )

    # --- 3. tool + middleware + agent -------------------------------------
    @tool
    def add_numbers(x: int, y: int) -> int:
        """Add two numbers."""
        return x + y

    tool_call_message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "add_numbers",
                "args": {"x": 7, "y": 35},
                "id": "call-1",
                "type": "tool_call",
            }
        ],
    )
    final_message = AIMessage(content="The answer is 42.")

    agent = create_agent(
        model=FakeToolCallingChatModel([tool_call_message, final_message]),
        tools=[add_numbers],
        middleware=[AuditMiddleware(recorder, session_id="example-session")],
    )

    # --- 4. run the agent -------------------------------------------------
    print("\nrunning agent...")
    result = agent.invoke({"messages": [{"role": "user", "content": "what is 7 + 35?"}]})
    final = result["messages"][-1]
    print(f"agent final: {getattr(final, 'content', final)!r}")

    # --- 5. verify the audit log ------------------------------------------
    jsonl = next(audit_dir.glob("audit-*.jsonl"))
    print(f"\naudit log:  {jsonl}")
    print(f"records:    {sum(1 for line in jsonl.read_text().splitlines() if line)}")

    verify = subprocess.run(
        [sys.executable, "-m", "chiplog.cli", "verify", str(jsonl), "--pubkey", str(pub)],
        capture_output=True,
        text=True,
    )
    print(f"\nverifier exit code: {verify.returncode}")
    print(verify.stdout)

    # --- 6. one-line summary per record -----------------------------------
    print("record summary:")
    for line_num, line in enumerate(jsonl.read_text().splitlines(), start=1):
        if not line:
            continue
        rec = json.loads(line)
        tool_name = rec["payload"]["tool"]["name"]
        body = rec["payload"]["output"]["body"]
        policy = rec["payload"]["policy"]["kind"]
        print(f"  {line_num}. tool={tool_name} output={body!r} policy={policy}")

    return verify.returncode


if __name__ == "__main__":
    sys.exit(main())
