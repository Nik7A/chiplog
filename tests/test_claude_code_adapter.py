"""Step 6: Claude Code hooks adapter tests.

Covers:
- infer_tool_call for built-ins, single-segment MCP names, and underscored MCP names
- parse_hook_input handles full and minimal payloads
- serialize_tool_response truncates >64KB with sha256_full + size_bytes_full preserved
- emit_from_hook writes a verifiable signed record + populates manifest
- Two consecutive hook invocations share a chain via the manifest
  (the central Claude Code "fresh process per tool call" scenario)
- AGENT_AUDIT_CHAIN_ID env overrides session-scoped chains (Nikolai's daemon)
- CLI hook-record subcommand: stdin → JSONL line + exit 0
- Concurrent CLI hook-record invocations don't corrupt the chain (flock works)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from agent_audit.adapters.claude_code import (
    HookConfig,
    HookInput,
    emit_from_hook,
    infer_tool_call,
    parse_hook_input,
    serialize_tool_response,
)
from agent_audit.cli import cli
from agent_audit.integrity import compute_chain_link, verify_record
from agent_audit.keys import compute_key_id
from agent_audit.manifest import Manifest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def key_files(tmp_path: Path) -> tuple[Path, Path]:
    """Write signing.key (0600) + signing.pub (0644) under tmp_path."""
    pk = Ed25519PrivateKey.generate()
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    priv.write_bytes(
        pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    priv.chmod(0o600)
    pub.write_bytes(
        pk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    pub.chmod(0o644)
    return priv, pub


# ---------------------------------------------------------------------------
# infer_tool_call
# ---------------------------------------------------------------------------


def test_infer_tool_call_builtin_has_no_mcp() -> None:
    tc = infer_tool_call("Read")
    assert tc.name == "Read"
    assert tc.mcp is None


def test_infer_tool_call_mcp_notion() -> None:
    tc = infer_tool_call("mcp__notion__create-pages")
    assert tc.name == "create-pages"
    assert tc.mcp is not None
    assert "notion" in tc.mcp.server_id
    assert tc.mcp.server_id.startswith("mcp+stdio://")


def test_infer_tool_call_mcp_with_underscored_name() -> None:
    """Real Claude Code MCP names: server names with single _, tool names
    with single _. The split must take only the first `__` after the
    server slot so `create_task` doesn't get re-split."""
    tc = infer_tool_call("mcp__asana__create_task")
    assert tc.name == "create_task"
    assert tc.mcp is not None
    assert "asana" in tc.mcp.server_id


def test_infer_tool_call_just_prefix_falls_back_to_builtin() -> None:
    """Pathological `mcp__` alone (no server, no tool) — don't crash, treat
    as a literal tool name."""
    tc = infer_tool_call("mcp__")
    assert tc.name == "mcp__"
    assert tc.mcp is None


# ---------------------------------------------------------------------------
# parse_hook_input
# ---------------------------------------------------------------------------


def test_parse_hook_input_full_payload() -> None:
    raw = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "sess-123",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/home/user",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_response": "file1\nfile2\n",
        }
    )
    hi = parse_hook_input(raw)
    assert hi.hook_event_name == "PostToolUse"
    assert hi.session_id == "sess-123"
    assert hi.tool_name == "Bash"
    assert hi.tool_input == {"command": "ls"}


def test_parse_hook_input_minimal_payload() -> None:
    """Missing optional fields default sensibly rather than crashing."""
    hi = parse_hook_input(json.dumps({"session_id": "x", "tool_name": "Read"}))
    assert hi.session_id == "x"
    assert hi.tool_name == "Read"
    assert hi.tool_input is None
    assert hi.tool_response is None


def test_parse_hook_input_rejects_non_object() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        parse_hook_input(json.dumps(["not", "an", "object"]))


# ---------------------------------------------------------------------------
# serialize_tool_response
# ---------------------------------------------------------------------------


def test_serialize_small_response_passes_through() -> None:
    out = serialize_tool_response("small response")
    assert out.body == "small response"
    assert out.truncated is False
    assert out.sha256_full is None


def test_serialize_large_response_is_truncated_with_hash_preserved() -> None:
    big = "x" * (100 * 1024)
    out = serialize_tool_response(big)
    assert out.truncated is True
    assert out.sha256_full is not None
    assert out.size_bytes_full is not None
    assert out.size_bytes_full > 64 * 1024
    assert isinstance(out.body, str)
    assert "truncated" in out.body


def test_serialize_dict_passes_through_as_dict() -> None:
    out = serialize_tool_response({"file": "/tmp/x", "lines": 42})
    assert isinstance(out.body, dict)
    assert out.body == {"file": "/tmp/x", "lines": 42}
    assert out.truncated is False


# ---------------------------------------------------------------------------
# emit_from_hook end-to-end
# ---------------------------------------------------------------------------


def test_emit_from_hook_writes_verifiable_record(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    hi = HookInput(
        hook_event_name="PostToolUse",
        session_id="sess-1",
        tool_name="Read",
        tool_input={"file_path": "/etc/hosts"},
        tool_response="127.0.0.1 localhost",
    )
    signed = emit_from_hook(hi, config)

    assert signed["envelope"]["chain_id"] == "sess-1"
    assert signed["payload"]["tool"]["name"] == "Read"
    assert signed["payload"]["tool"]["mcp"] is None
    assert signed["payload"]["policy"]["kind"] == "none"

    # On disk
    jsonl = next(audit_dir.glob("audit-*.jsonl"))
    on_disk = json.loads(jsonl.read_text().splitlines()[0])
    assert on_disk == signed

    # Verifies
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    pubkey = load_pem_public_key(pub.read_bytes())
    key_id = compute_key_id(pubkey)  # type: ignore[arg-type]
    assert verify_record(signed, {key_id: pubkey}).is_valid  # type: ignore[dict-item]


def test_emit_from_hook_mcp_tool_populates_mcp_fields(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    hi = HookInput(
        hook_event_name="PostToolUse",
        session_id="sess-1",
        tool_name="mcp__asana__create_task",
        tool_input={"name": "test ticket"},
        tool_response={"task_id": "T-100"},
    )
    signed = emit_from_hook(hi, config)
    tool = signed["payload"]["tool"]
    assert tool["name"] == "create_task"
    assert tool["mcp"] is not None
    assert "asana" in tool["mcp"]["server_id"]
    assert tool["mcp"]["transport"] == "stdio"


def test_two_hook_invocations_share_chain_via_manifest(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """Central Claude Code scenario: each hook runs as a fresh process. The
    chain head must persist across processes via the manifest."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    hi1 = HookInput(
        "PostToolUse", "sess-1", "Read", {"file_path": "/etc/hosts"}, "..."
    )
    hi2 = HookInput(
        "PostToolUse", "sess-1", "Write", {"file_path": "/tmp/x"}, "ok"
    )
    r1 = emit_from_hook(hi1, config)
    r2 = emit_from_hook(hi2, config)

    assert r2["envelope"]["prev_hash"] == compute_chain_link(r1)


def test_chain_id_env_override_creates_global_chain(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """AGENT_AUDIT_CHAIN_ID overrides session-scoped chains — used by
    Nikolai's daemon to keep one global chain across many sessions."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(
        audit_dir=audit_dir,
        signing_key_path=priv,
        pubkey_path=pub,
        chain_id_override="daemon-global",
    )

    r1 = emit_from_hook(
        HookInput("PostToolUse", "sess-A", "Read", {}, ""), config
    )
    r2 = emit_from_hook(
        HookInput("PostToolUse", "sess-B", "Write", {}, ""), config
    )

    assert r1["envelope"]["chain_id"] == "daemon-global"
    assert r2["envelope"]["chain_id"] == "daemon-global"
    assert r2["envelope"]["prev_hash"] == compute_chain_link(r1)


def test_emit_populates_pubkey_pem_in_manifest(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """The manifest must carry the pubkey PEM so a verifier needs nothing
    but the audit dir to run `agent-audit verify`."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)
    emit_from_hook(
        HookInput("PostToolUse", "sess-1", "Read", {}, ""), config
    )
    manifest = Manifest.load_or_create(audit_dir / "manifest.json")
    assert manifest.pubkey_pem is not None
    assert "PUBLIC KEY" in manifest.pubkey_pem


# ---------------------------------------------------------------------------
# HookConfig.from_env
# ---------------------------------------------------------------------------


def test_from_env_defaults_to_user_config_dir() -> None:
    config = HookConfig.from_env({})
    assert str(config.audit_dir).endswith("/.config/agent-audit")
    assert config.signing_key_path.name == "signing.key"
    assert config.chain_id_override is None


def test_from_env_respects_overrides(tmp_path: Path) -> None:
    config = HookConfig.from_env(
        {
            "AGENT_AUDIT_DIR": str(tmp_path),
            "AGENT_AUDIT_CHAIN_ID": "my-chain",
        }
    )
    assert config.audit_dir == tmp_path
    assert config.signing_key_path == tmp_path / "signing.key"
    assert config.chain_id_override == "my-chain"


# ---------------------------------------------------------------------------
# CLI hook-record
# ---------------------------------------------------------------------------


def test_cli_hook_record_writes_and_exits_0(
    tmp_path: Path,
    key_files: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("AGENT_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("AGENT_AUDIT_SIGNING_KEY", str(priv))
    monkeypatch.setenv("AGENT_AUDIT_PUBKEY", str(pub))

    payload = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "sess-cli",
            "tool_name": "Read",
            "tool_input": {"file_path": "/etc/hosts"},
            "tool_response": "127.0.0.1 localhost\n",
        }
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["hook-record"], input=payload)

    assert result.exit_code == 0, result.output
    jsonl = next(audit_dir.glob("audit-*.jsonl"))
    record = json.loads(jsonl.read_text().splitlines()[0])
    assert record["payload"]["tool"]["name"] == "Read"


def test_cli_hook_record_subagent_dispatch_via_task_tool(
    tmp_path: Path,
    key_files: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the parent agent dispatches a subagent, the parent fires a
    PostToolUse with tool_name='Task'. The subagent's own tool calls fire
    their OWN hooks with the subagent's session_id."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("AGENT_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("AGENT_AUDIT_SIGNING_KEY", str(priv))
    monkeypatch.setenv("AGENT_AUDIT_PUBKEY", str(pub))
    monkeypatch.setenv("AGENT_AUDIT_CHAIN_ID", "daemon-global")

    parent = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "parent-sess",
            "tool_name": "Task",
            "tool_input": {"description": "Refactor module X"},
            "tool_response": {"agent": "backend-eng", "status": "spawned"},
        }
    )
    subagent = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "sub-sess",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/x.py"},
            "tool_response": "def x(): ...",
        }
    )

    runner = CliRunner()
    assert runner.invoke(cli, ["hook-record"], input=parent).exit_code == 0
    assert runner.invoke(cli, ["hook-record"], input=subagent).exit_code == 0

    lines = next(audit_dir.glob("audit-*.jsonl")).read_text().splitlines()
    records = [json.loads(line) for line in lines]
    assert len(records) == 2
    # Same global chain — both records linked
    assert records[0]["envelope"]["chain_id"] == "daemon-global"
    assert records[1]["envelope"]["chain_id"] == "daemon-global"
    assert records[1]["envelope"]["prev_hash"] == compute_chain_link(records[0])
    # Sessions are distinct in the header (the dispatch tree is reconstructable)
    assert records[0]["header"]["session_id"] == "parent-sess"
    assert records[1]["header"]["session_id"] == "sub-sess"


# ---------------------------------------------------------------------------
# flock — concurrent subprocess invocations
# ---------------------------------------------------------------------------


def test_concurrent_cli_hook_record_via_subprocesses_serializes_via_flock(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """Real subprocess concurrency: spawn 5 `agent-audit hook-record`
    processes simultaneously and check the chain validates end-to-end
    with all 5 records present.

    This proves flock serialises the concurrent invocations — without it,
    interleaved reads of `manifest.chains[chain_id].head_hash` would cause
    multiple records to share a `prev_hash` and the chain would break.
    """
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    env = {
        **{k: v for k, v in __import__("os").environ.items()},
        "AGENT_AUDIT_DIR": str(audit_dir),
        "AGENT_AUDIT_SIGNING_KEY": str(priv),
        "AGENT_AUDIT_PUBKEY": str(pub),
        "AGENT_AUDIT_CHAIN_ID": "concurrent-test",
    }

    payloads = [
        json.dumps(
            {
                "hook_event_name": "PostToolUse",
                "session_id": f"sess-{i}",
                "tool_name": "Read",
                "tool_input": {"file_path": f"/tmp/file-{i}"},
                "tool_response": f"content-{i}",
            }
        )
        for i in range(5)
    ]

    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "agent_audit.cli", "hook-record"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        for _ in range(5)
    ]
    for proc, payload in zip(procs, payloads):
        proc.stdin.write(payload.encode("utf-8"))  # type: ignore[union-attr]
        proc.stdin.close()  # type: ignore[union-attr]

    for proc in procs:
        rc = proc.wait(timeout=10)
        assert rc == 0, proc.stderr.read().decode()  # type: ignore[union-attr]

    # All 5 records present
    jsonl = next(audit_dir.glob("audit-*.jsonl"))
    lines = jsonl.read_text().splitlines()
    assert len(lines) == 5

    # Chain validates — verifier on the full file
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_audit.cli",
            "verify",
            str(jsonl),
            "--pubkey",
            str(pub),
        ],
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()
