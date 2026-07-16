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
- A Bash call the CLI backgrounds on timeout records `unobserved`, not `success`
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
    # The hook payload carries no gate decision and no risk level, so the adapter
    # asserts only that the gate status was unobservable — never the old
    # fabricated ungated(AUTO_ALLOWED_LOW_RISK).
    assert signed["payload"]["policy"] == {
        "kind": "policy_unobserved",
        "reason": "no_gate_signal",
    }

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
# PostToolUseFailure
#
# The payloads below are verbatim captures from Claude Code CLI 2.1.207,
# recorded by registering a probe hook under both PostToolUse and
# PostToolUseFailure and forcing real tool failures. Findings:
#
#   - A failed tool call fires PostToolUseFailure ONLY (no PostToolUse).
#   - A successful tool call fires PostToolUse ONLY (no PostToolUseFailure).
#   - The failure payload carries `error` (str) and `is_interrupt` (bool),
#     and has NO `tool_response` key.
#
# The two events are disjoint, so `PostToolUse -> success()` is an honest
# claim: the CLI does have a failure signal, and it lands elsewhere.
# ---------------------------------------------------------------------------


def test_parse_hook_input_reads_failure_payload() -> None:
    """Verbatim PostToolUseFailure payload from the CLI (Bash `false`)."""
    hi = parse_hook_input(
        json.dumps(
            {
                "session_id": "bc800581-421b-4a21-978c-12797ce3abcc",
                "transcript_path": "/Users/nik7a/.claude/projects/x/y.jsonl",
                "cwd": "/tmp/work",
                "hook_event_name": "PostToolUseFailure",
                "tool_name": "Bash",
                "tool_input": {"command": "false", "description": "Run the false command"},
                "tool_use_id": "toolu_01R4hEZimiq6kXV5zUeY3FpE",
                "error": "Exit code 1",
                "is_interrupt": False,
                "duration_ms": 816,
            }
        )
    )
    assert hi.hook_event_name == "PostToolUseFailure"
    assert hi.error == "Exit code 1"
    assert hi.is_interrupt is False
    # The CLI sends no tool_response on a failure — there is no output to record.
    assert hi.tool_response is None


def test_parse_hook_input_success_payload_has_no_error() -> None:
    """Verbatim PostToolUse payload from the CLI (Bash `echo hello`)."""
    hi = parse_hook_input(
        json.dumps(
            {
                "session_id": "580bf474-085f-48fd-b1ba-17ce8f5f6335",
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello", "description": "Echo hello"},
                "tool_response": {
                    "stdout": "hello",
                    "stderr": "",
                    "interrupted": False,
                    "isImage": False,
                },
                "tool_use_id": "toolu_01XrZwPKamLgzjtubTAaTmjx",
                "duration_ms": 722,
            }
        )
    )
    assert hi.hook_event_name == "PostToolUse"
    assert hi.error is None
    assert hi.is_interrupt is False
    assert hi.tool_response == {
        "stdout": "hello",
        "stderr": "",
        "interrupted": False,
        "isImage": False,
    }


def test_emit_from_hook_records_error_outcome(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    hi = HookInput(
        hook_event_name="PostToolUseFailure",
        session_id="cc-1",
        tool_name="Bash",
        tool_input={"command": "false"},
        tool_response=None,
        error="Exit code 1",
    )
    signed = emit_from_hook(hi, config)

    assert signed["payload"]["outcome"]["kind"] == "error"
    assert signed["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert signed["payload"]["outcome"]["message"] == "Exit code 1"
    # No output exists on a failure — don't invent an empty one.
    assert signed["payload"]["output"]["body"] is None
    assert signed["payload"]["output"]["truncated"] is False


def test_emit_from_hook_genuine_interrupt_string_stays_error(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """A GENUINE mid-run interrupt (the CLI's `[Request interrupted by user]`
    string) is NOT a permission denial: the tool may have partially run. It sets
    `is_interrupt=True` just like a denial does — which is exactly why is_interrupt
    cannot be the discriminator — but it lacks the rejection lead-sentence, so it
    keeps the honest `error(error_type='Interrupt')` behaviour and must NOT be
    rerouted to `denied`. (Today no hook fires for a real interrupt; this guards a
    replayed/synthesised payload.)"""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    hi = HookInput(
        hook_event_name="PostToolUseFailure",
        session_id="cc-1",
        tool_name="Bash",
        tool_input={"command": "sleep 300"},
        tool_response=None,
        error="[Request interrupted by user for tool use]",
        is_interrupt=True,
    )
    signed = emit_from_hook(hi, config)

    assert signed["payload"]["outcome"]["kind"] == "error"
    assert signed["payload"]["outcome"]["error_type"] == "Interrupt"
    assert signed["payload"]["outcome"]["message"] == (
        "[Request interrupted by user for tool use]"
    )
    # Not a denial: is_interrupt=True must not, on its own, mint a Gate(DENY).
    assert signed["payload"]["policy"]["kind"] == "policy_unobserved"


def test_emit_from_hook_failure_record_verifies_and_chains(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """A failure record is a first-class link: signed, verifiable, chained."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    ok = emit_from_hook(
        HookInput("PostToolUse", "cc-1", "Read", {"file_path": "/etc/hosts"}, "127.0.0.1"),
        config,
    )
    failed = emit_from_hook(
        HookInput(
            hook_event_name="PostToolUseFailure",
            session_id="cc-1",
            tool_name="Read",
            tool_input={"file_path": "/nonexistent/x.txt"},
            tool_response=None,
            error="File does not exist.",
        ),
        config,
    )

    assert failed["envelope"]["prev_hash"] == compute_chain_link(ok)

    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    pubkey = load_pem_public_key(pub.read_bytes())
    key_id = compute_key_id(pubkey)  # type: ignore[arg-type]
    assert verify_record(failed, {key_id: pubkey}).is_valid  # type: ignore[dict-item]


def test_emit_from_hook_still_records_success(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    signed = emit_from_hook(
        HookInput(
            hook_event_name="PostToolUse",
            session_id="cc-1",
            tool_name="Read",
            tool_input={"file_path": "/tmp/x"},
            tool_response="contents",
        ),
        config,
    )
    assert signed["payload"]["outcome"] == {"kind": "success"}
    assert signed["payload"]["output"]["body"] == "contents"


# ---------------------------------------------------------------------------
# Event allowlist
#
# emit_from_hook used to treat every event that was not PostToolUseFailure as
# the success slot. Registered (or mis-registered) on PreToolUse, it would sign
# `outcome: success` for a tool call that HAS NOT RUN YET. The claude-agent-sdk
# adapter already no-ops outside {PostToolUse, PostToolUseFailure}; the rule now
# lives in the shared `_claude_hooks` module so the two cannot drift apart.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event", ["PreToolUse", "Stop", "SubagentStop", "UserPromptSubmit", "", "Notification"]
)
def test_emit_from_hook_never_records_non_post_tool_use_events(
    tmp_path: Path, key_files: tuple[Path, Path], event: str
) -> None:
    """Only PostToolUse / PostToolUseFailure describe a completed tool call.
    Any other event says nothing about an outcome, so nothing may be signed."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    result = emit_from_hook(
        HookInput(
            hook_event_name=event,
            session_id="cc-pre",
            tool_name="Bash",
            tool_input={"command": "rm -rf /important"},
            tool_response=None,
        ),
        config,
    )

    assert result is None, f"{event} produced a signed record: {result!r}"
    written = list(audit_dir.glob("audit-*.jsonl"))
    assert not written or not written[0].read_text().strip(), (
        f"{event} wrote to the audit log; a tool call that has not completed "
        "must never be attested"
    )


def test_both_claude_adapters_share_one_event_allowlist() -> None:
    """The two adapters read the same runtime's payloads. The rule that decides
    which events describe a completed tool call must have exactly one home."""
    from agent_audit.adapters import _claude_hooks

    assert _claude_hooks.is_recordable_event("PostToolUse")
    assert _claude_hooks.is_recordable_event("PostToolUseFailure")
    assert not _claude_hooks.is_recordable_event("PreToolUse")
    assert not _claude_hooks.is_recordable_event(None)
    assert _claude_hooks.is_failure_event("PostToolUseFailure")
    assert not _claude_hooks.is_failure_event("PostToolUse")


def test_cli_hook_record_handles_failure_payload(
    tmp_path: Path,
    key_files: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end through the real hook entry point the CLI invokes."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("AGENT_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("AGENT_AUDIT_SIGNING_KEY", str(priv))
    monkeypatch.setenv("AGENT_AUDIT_PUBKEY", str(pub))

    payload = json.dumps(
        {
            "hook_event_name": "PostToolUseFailure",
            "session_id": "sess-fail",
            "tool_name": "Bash",
            "tool_input": {"command": "false"},
            "error": "Exit code 1",
            "is_interrupt": False,
        }
    )
    result = CliRunner().invoke(cli, ["hook-record"], input=payload)
    assert result.exit_code == 0, result.output

    record = json.loads(
        next(audit_dir.glob("audit-*.jsonl")).read_text().splitlines()[0]
    )
    assert record["payload"]["outcome"]["kind"] == "error"
    assert record["payload"]["outcome"]["error_type"] == "ToolFailure"


# ---------------------------------------------------------------------------
# Backgrounded Bash calls — the CLI has no timeout failure signal
#
# The payloads below are verbatim captures from Claude Code CLI 2.1.207,
# recorded by registering a probe hook under both PostToolUse and
# PostToolUseFailure in a scratch settings file and driving `claude -p`.
#
# A Bash call that exceeds its `timeout` does NOT fire PostToolUseFailure.
# The CLI moves the command to the background and fires an ordinary
# PostToolUse — the SUCCESS slot — with no `error` key, `interrupted: false`,
# empty stdout, and a `backgroundTaskId`. Signing that as `success` would turn
# a call whose outcome nobody observed into attested false evidence.
#
# But `backgroundTaskId` alone is not the discriminator: it is ALSO present
# when the caller intentionally backgrounds a command with
# `tool_input.run_in_background: true`, and that call genuinely succeeded —
# the tool did what it was asked to do, namely launch the process. Recording
# those as `unobserved` would destroy good evidence.
#
# The probe showed the two cases differ in `tool_input`, which is the caller's
# own request echoed back:
#
#   CLI-forced background (timeout):  tool_input has `timeout`, NO
#                                     `run_in_background`; tool_response has
#                                     `backgroundTaskId`.
#   Intentional background:           tool_input has `run_in_background: true`;
#                                     tool_response has `backgroundTaskId`.
#   Ordinary fast command (control):  tool_response has NO `backgroundTaskId`.
#
# So the discriminator is: a `backgroundTaskId` the caller did not ask for.
# Both halves are structural fields the runtime supplied — nothing is derived.
# In particular we do NOT compare `duration_ms` against `tool_input.timeout` to
# synthesize a `timeout` outcome: that would be deriving a conclusion the
# runtime never reported, and it would break silently if the CLI changed those
# fields' meaning. `unobserved` states exactly what is true — the call was
# moved to the background and its outcome is not determinable from this hook.
# ---------------------------------------------------------------------------


def test_parse_hook_input_reads_cli_backgrounded_timeout_payload() -> None:
    """Verbatim PostToolUse payload for a Bash call the CLI backgrounded after
    the command blew its `timeout`. Note the event slot: PostToolUse, the
    success channel. No `error`, no `is_interrupt`."""
    hi = parse_hook_input(
        json.dumps(
            {
                "session_id": "0791c422-0a93-40e9-8c37-ce0dffdc97e9",
                "cwd": "/tmp/work",
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {
                    "command": "python3 -c 'import time; time.sleep(60)'",
                    "timeout": 3000,
                    "description": "Sleep 60 seconds via python",
                },
                "tool_response": {
                    "stdout": "",
                    "stderr": "",
                    "interrupted": False,
                    "isImage": False,
                    "noOutputExpected": False,
                    "backgroundTaskId": "bqxz5l7ce",
                },
                "tool_use_id": "toolu_016D1dgj4sFsnkQkruQZuekF",
                "duration_ms": 3788,
            }
        )
    )
    assert hi.hook_event_name == "PostToolUse"
    assert hi.error is None
    assert hi.is_interrupt is False
    # The CLI reports it as an ordinary completed call. Nothing in the event
    # slot says the command failed — the only trace is backgroundTaskId.
    assert hi.tool_response["backgroundTaskId"] == "bqxz5l7ce"
    assert "run_in_background" not in hi.tool_input


def test_emit_from_hook_cli_backgrounded_timeout_is_unobserved(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """THE BUG. A Bash command that blew its timeout arrives on PostToolUse and
    was signed as `success`. The command may still be running, may have failed,
    may never finish — the hook cannot tell. `unobserved` is the honest record.
    """
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    hi = HookInput(
        hook_event_name="PostToolUse",
        session_id="cc-1",
        tool_name="Bash",
        tool_input={
            "command": "python3 -c 'import time; time.sleep(60)'",
            "timeout": 3000,
        },
        tool_response={
            "stdout": "",
            "stderr": "",
            "interrupted": False,
            "backgroundTaskId": "bqxz5l7ce",
        },
    )
    signed = emit_from_hook(hi, config)

    assert signed["payload"]["outcome"]["kind"] == "unobserved"
    assert signed["payload"]["outcome"]["reason"] == "no_failure_signal"
    # Not success, and not a synthesized timeout — the CLI never reported one.
    assert signed["payload"]["outcome"]["kind"] != "success"
    assert signed["payload"]["outcome"]["kind"] != "timeout"

    # The tool_response the CLI did give us is still evidence: the
    # backgroundTaskId names the task that inherited the work, and it is the
    # only thread an investigator can pull. Keep it.
    assert signed["payload"]["output"]["body"]["backgroundTaskId"] == "bqxz5l7ce"


def test_emit_from_hook_intentional_background_is_success(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """Verbatim capture: the caller asked for `run_in_background: true`. The
    tool call succeeded — it launched the process, which is exactly what was
    requested. Recording this as `unobserved` would destroy good evidence.

    This is what stops the timeout fix from over-reaching: `backgroundTaskId`
    is present here too, so it cannot be the discriminator on its own.
    """
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    hi = HookInput(
        hook_event_name="PostToolUse",
        session_id="cc-1",
        tool_name="Bash",
        tool_input={
            "command": "python3 -c 'import time; time.sleep(60)'",
            "description": "Sleep for 60 seconds in background",
            "run_in_background": True,
        },
        tool_response={
            "stdout": "",
            "stderr": "",
            "interrupted": False,
            "backgroundTaskId": "b2twld3af",
        },
    )
    signed = emit_from_hook(hi, config)

    assert signed["payload"]["outcome"] == {"kind": "success"}
    assert signed["payload"]["output"]["body"]["backgroundTaskId"] == "b2twld3af"


def test_emit_from_hook_ordinary_bash_success_has_no_background_task(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """Control, verbatim from the same probe: a fast command carries no
    `backgroundTaskId` at all and stays `success`."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    signed = emit_from_hook(
        HookInput(
            hook_event_name="PostToolUse",
            session_id="cc-1",
            tool_name="Bash",
            tool_input={"command": "echo control-probe"},
            tool_response={
                "stdout": "control-probe",
                "stderr": "",
                "interrupted": False,
                "isImage": False,
                "noOutputExpected": False,
            },
        ),
        config,
    )
    assert signed["payload"]["outcome"] == {"kind": "success"}


def test_background_detection_does_not_touch_non_bash_tools(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """A non-Bash tool whose output happens to contain the string
    `backgroundTaskId` is not a backgrounded Bash call. The discriminator reads
    the runtime's structural field on the Bash tool, not any dict key anywhere.
    """
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    signed = emit_from_hook(
        HookInput(
            hook_event_name="PostToolUse",
            session_id="cc-1",
            tool_name="Read",
            tool_input={"file_path": "/tmp/notes.md"},
            tool_response="the CLI sets backgroundTaskId when it backgrounds a task",
        ),
        config,
    )
    assert signed["payload"]["outcome"] == {"kind": "success"}


def test_unobserved_record_verifies_and_chains(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """An unobserved record is a first-class link: signed, verifiable, chained.
    An outcome nobody could observe is still evidence that the call happened."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    ok = emit_from_hook(
        HookInput("PostToolUse", "cc-1", "Read", {"file_path": "/etc/hosts"}, "127.0.0.1"),
        config,
    )
    backgrounded = emit_from_hook(
        HookInput(
            hook_event_name="PostToolUse",
            session_id="cc-1",
            tool_name="Bash",
            tool_input={"command": "sleep 60", "timeout": 3000},
            tool_response={"stdout": "", "backgroundTaskId": "bqxz5l7ce"},
        ),
        config,
    )

    assert backgrounded["payload"]["outcome"]["kind"] == "unobserved"
    assert backgrounded["envelope"]["prev_hash"] == compute_chain_link(ok)

    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    pubkey = load_pem_public_key(pub.read_bytes())
    key_id = compute_key_id(pubkey)  # type: ignore[arg-type]
    assert verify_record(backgrounded, {key_id: pubkey}).is_valid  # type: ignore[dict-item]


def test_cli_hook_record_handles_backgrounded_timeout_payload(
    tmp_path: Path,
    key_files: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end through the real hook entry point the CLI invokes, with the
    verbatim probe payload on stdin."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("AGENT_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("AGENT_AUDIT_SIGNING_KEY", str(priv))
    monkeypatch.setenv("AGENT_AUDIT_PUBKEY", str(pub))

    payload = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "sess-bg",
            "tool_name": "Bash",
            "tool_input": {
                "command": "python3 -c 'import time; time.sleep(60)'",
                "timeout": 3000,
                "description": "Sleep 60 seconds via python",
            },
            "tool_response": {
                "stdout": "",
                "stderr": "",
                "interrupted": False,
                "isImage": False,
                "noOutputExpected": False,
                "backgroundTaskId": "bqxz5l7ce",
            },
            "duration_ms": 3788,
        }
    )
    result = CliRunner().invoke(cli, ["hook-record"], input=payload)
    assert result.exit_code == 0, result.output

    record = json.loads(
        next(audit_dir.glob("audit-*.jsonl")).read_text().splitlines()[0]
    )
    assert record["payload"]["outcome"]["kind"] == "unobserved"
    assert record["payload"]["outcome"]["reason"] == "no_failure_signal"


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


def test_cli_hook_record_chain_id_flag_overrides_session(
    tmp_path: Path,
    key_files: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`--chain-id` on the CLI overrides session-scoped chains and beats env."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("AGENT_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("AGENT_AUDIT_SIGNING_KEY", str(priv))
    monkeypatch.setenv("AGENT_AUDIT_PUBKEY", str(pub))
    monkeypatch.setenv("AGENT_AUDIT_CHAIN_ID", "from-env")

    payload = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "sess-from-payload",
            "tool_name": "Read",
            "tool_input": {},
            "tool_response": "",
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        cli, ["hook-record", "--chain-id", "from-cli"], input=payload
    )
    assert result.exit_code == 0, result.output

    record = json.loads(
        next(audit_dir.glob("audit-*.jsonl")).read_text().splitlines()[0]
    )
    # CLI flag wins over env var ("from-env") and over session_id payload field.
    assert record["envelope"]["chain_id"] == "from-cli"
    # session_id stays in the header — header.session_id is identity, chain_id is grouping.
    assert record["header"]["session_id"] == "sess-from-payload"


def test_cli_hook_record_no_flag_falls_back_to_env(
    tmp_path: Path,
    key_files: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without --chain-id, AGENT_AUDIT_CHAIN_ID still wins over session_id."""
    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("AGENT_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("AGENT_AUDIT_SIGNING_KEY", str(priv))
    monkeypatch.setenv("AGENT_AUDIT_PUBKEY", str(pub))
    monkeypatch.setenv("AGENT_AUDIT_CHAIN_ID", "from-env-only")

    payload = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "sess-x",
            "tool_name": "Read",
            "tool_input": {},
            "tool_response": "",
        }
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["hook-record"], input=payload)
    assert result.exit_code == 0

    record = json.loads(
        next(audit_dir.glob("audit-*.jsonl")).read_text().splitlines()[0]
    )
    assert record["envelope"]["chain_id"] == "from-env-only"


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


# ---------------------------------------------------------------------------
# An INTERRUPTED tool call must never be signed as `success`
#
# A tool call the user cancels mid-flight fires NO hook at all: the CLI's hook
# dispatcher returns early when the abort signal is set, so a partial `rm -rf`
# or a half-applied migration leaves ZERO trace in the audit log. This library
# cannot fix that from inside a hook — it is a documented blind spot, not a bug
# these adapters can close.
#
# What it CAN do is refuse to sign a success for an interrupted call if such a
# payload ever does reach it — a future CLI that starts delivering the event, a
# replayed transcript, a wrapper that synthesises one. `interrupted: true` on
# `tool_response` is a structural field the runtime sets, and a call that was cut
# short is precisely a call whose outcome nobody observed. Same reasoning, same
# outcome, as the backgrounded-Bash case: unobserved(no_failure_signal).
# ---------------------------------------------------------------------------


def test_emit_from_hook_interrupted_tool_response_is_unobserved(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """`interrupted: true` on the SUCCESS slot. The command was cut short — what
    it did before it died is not established by anything in this payload."""
    priv, pub = key_files
    config = HookConfig(
        audit_dir=tmp_path / "audit", signing_key_path=priv, pubkey_path=pub
    )

    hi = HookInput(
        hook_event_name="PostToolUse",
        session_id="cc-int",
        tool_name="Bash",
        tool_input={"command": "rm -rf ./build"},
        tool_response={"stdout": "", "stderr": "", "interrupted": True},
    )
    signed = emit_from_hook(hi, config)

    outcome = signed["payload"]["outcome"]
    assert outcome["kind"] == "unobserved", (
        "signed a success for a tool call that was interrupted mid-flight"
    )
    assert outcome["reason"] == "no_failure_signal"
    assert outcome["kind"] != "success"


def test_emit_from_hook_interrupted_applies_to_every_tool_not_just_bash(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """Unlike backgrounding, interruption is not Bash-specific — any tool call
    can be cut short."""
    priv, pub = key_files
    config = HookConfig(
        audit_dir=tmp_path / "audit", signing_key_path=priv, pubkey_path=pub
    )

    hi = HookInput(
        hook_event_name="PostToolUse",
        session_id="cc-int2",
        tool_name="Edit",
        tool_input={"file_path": "/etc/hosts"},
        tool_response={"interrupted": True},
    )
    signed = emit_from_hook(hi, config)

    assert signed["payload"]["outcome"]["kind"] == "unobserved"
    assert signed["payload"]["outcome"]["reason"] == "no_failure_signal"


def test_emit_from_hook_interrupted_false_stays_success(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """Control: `interrupted: false` is what an ordinary completed call carries.
    It must stay `success` — this guard must not devalue good evidence."""
    priv, pub = key_files
    config = HookConfig(
        audit_dir=tmp_path / "audit", signing_key_path=priv, pubkey_path=pub
    )

    hi = HookInput(
        hook_event_name="PostToolUse",
        session_id="cc-int3",
        tool_name="Bash",
        tool_input={"command": "echo ok"},
        tool_response={"stdout": "ok", "stderr": "", "interrupted": False},
    )
    signed = emit_from_hook(hi, config)

    assert signed["payload"]["outcome"] == {"kind": "success"}


# ---------------------------------------------------------------------------
# User DENIAL at the permission prompt → outcome=denied + a truthful Gate(DENY)
#
# When a user presses "no" at Claude Code's permission prompt, the tool NEVER
# RUNS. The CLI fires PostToolUseFailure with is_interrupt=True and an `error`
# string that begins with the rejection lead-sentence. Recording that as
# error(error_type="Interrupt") asserts the tool ran and faulted — a lie. The
# permission prompt IS a real verification gate that fired and denied, so the
# honest record is a synthetic Gate(DENY) + outcome=denied.
#
# The discriminator is the ANCHORED rejection lead-sentence (probed verbatim from
# CLI 2.1.207; see .superpowers/sdd/area-denial-report.md), NOT is_interrupt —
# the CLI sets is_interrupt=True for a genuine mid-run interrupt too, so keying
# off it would conflate "user denied, tool never ran" with "tool ran, was cut
# short". The rule lives once in adapters/_claude_hooks so both Claude adapters
# cannot drift.
# ---------------------------------------------------------------------------


# The exact `error` prefix a user denial carries on CLI 2.1.207 (verbatim from
# the installed binary). Both denial families are exercised.
_DENIAL_ERROR_USER_REJECTED = (
    "The user doesn't want to proceed with this tool use. The tool use was "
    "rejected (eg. if it was a file edit, the new_string was NOT written to the "
    "file). STOP what you are doing and wait for the user to tell you how to "
    "proceed."
)
_DENIAL_ERROR_PERMISSION_DENIED = (
    "Permission for this tool use was denied. The tool use was rejected (eg. if "
    "it was a file edit, the new_string was NOT written to the file). Try a "
    "different approach or report the limitation to complete your task."
)


def test_emit_from_hook_user_denial_records_denied_with_gate(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """THE FIX. A denied tool call → outcome=denied, a Gate(DENY) with matching
    policy_id, output.body=None, and it SIGNS and VERIFIES (the cross-field
    validator Payload._outcome_agrees_with_policy is satisfied)."""
    from agent_audit.adapters._claude_hooks import PERMISSION_DENIED_POLICY_ID

    priv, pub = key_files
    audit_dir = tmp_path / "audit"
    config = HookConfig(audit_dir=audit_dir, signing_key_path=priv, pubkey_path=pub)

    hi = HookInput(
        hook_event_name="PostToolUseFailure",
        session_id="cc-deny",
        tool_name="Bash",
        tool_input={"command": "rm -rf ./build"},
        tool_response=None,
        error=_DENIAL_ERROR_USER_REJECTED,
        is_interrupt=True,
    )
    signed = emit_from_hook(hi, config)

    outcome = signed["payload"]["outcome"]
    policy = signed["payload"]["policy"]

    assert outcome["kind"] == "denied"
    assert outcome["policy_id"] == PERMISSION_DENIED_POLICY_ID
    assert policy["kind"] == "gate"
    assert policy["decision"] == "deny"
    assert policy["policy_id"] == PERMISSION_DENIED_POLICY_ID
    # No human identity and no timing are in the payload — do not fabricate them.
    assert policy["approver"] is None
    assert policy["evaluation_ms"] is None
    # A denied tool did not run: no output.
    assert signed["payload"]["output"]["body"] is None
    # Not the old lie.
    assert outcome["kind"] != "error"

    # Signs and verifies end-to-end.
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    pubkey = load_pem_public_key(pub.read_bytes())
    key_id = compute_key_id(pubkey)  # type: ignore[arg-type]
    assert verify_record(signed, {key_id: pubkey}).is_valid  # type: ignore[dict-item]


def test_emit_from_hook_permission_denied_family_also_maps_to_denied(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """The honest superset: the `Permission for this tool use was denied.` family
    (which fires only PreToolUse on 2.1.207 and normally never reaches a recording
    hook) is STILL a denial if it ever arrives here."""
    from agent_audit.adapters._claude_hooks import PERMISSION_DENIED_POLICY_ID

    priv, pub = key_files
    config = HookConfig(
        audit_dir=tmp_path / "audit", signing_key_path=priv, pubkey_path=pub
    )
    hi = HookInput(
        hook_event_name="PostToolUseFailure",
        session_id="cc-deny2",
        tool_name="Write",
        tool_input={"file_path": "/etc/hosts"},
        tool_response=None,
        error=_DENIAL_ERROR_PERMISSION_DENIED,
        is_interrupt=False,
    )
    signed = emit_from_hook(hi, config)
    assert signed["payload"]["outcome"]["kind"] == "denied"
    assert signed["payload"]["outcome"]["policy_id"] == PERMISSION_DENIED_POLICY_ID
    assert signed["payload"]["policy"]["decision"] == "deny"


def test_emit_from_hook_genuine_failure_stays_error_not_denied(
    tmp_path: Path, key_files: tuple[Path, Path]
) -> None:
    """The predicate must not over-match: a genuine tool failure (`Exit code 1`,
    verbatim from the CLI probe) stays error(...), never denied."""
    priv, pub = key_files
    config = HookConfig(
        audit_dir=tmp_path / "audit", signing_key_path=priv, pubkey_path=pub
    )
    hi = HookInput(
        hook_event_name="PostToolUseFailure",
        session_id="cc-fail",
        tool_name="Bash",
        tool_input={"command": "false"},
        tool_response=None,
        error="Exit code 1",
        is_interrupt=False,
    )
    signed = emit_from_hook(hi, config)
    assert signed["payload"]["outcome"]["kind"] == "error"
    assert signed["payload"]["outcome"]["kind"] != "denied"
    assert signed["payload"]["outcome"]["error_type"] == "ToolFailure"
    assert signed["payload"]["policy"]["kind"] == "policy_unobserved"


def test_denial_marker_is_pinned_to_probed_cli_version() -> None:
    """CI version-pin. A future CLI that rewords the rejection lead-sentence must
    fail LOUD here instead of silently falling back to error(). Observed CLI
    version: 2.1.207 (see .superpowers/sdd/area-denial-report.md).

    If this test fails after a CLI upgrade: re-probe the new CLI, update the
    prefixes in adapters/_claude_hooks._DENIAL_ERROR_PREFIXES, and update the
    pinned version here — do NOT loosen the match.
    """
    from agent_audit.adapters import _claude_hooks

    assert _claude_hooks._PROBED_CLI_VERSION == "2.1.207"
    assert _claude_hooks._DENIAL_ERROR_PREFIXES == (
        "The user doesn't want to proceed with this tool use.",
        "Permission for this tool use was denied.",
    )
    # The exact 2.1.207 error strings must be recognised as denials...
    assert _claude_hooks.is_user_denial(_DENIAL_ERROR_USER_REJECTED)
    assert _claude_hooks.is_user_denial(_DENIAL_ERROR_PERMISSION_DENIED)
    # ...and the policy id names the real mechanism, not is_interrupt.
    assert _claude_hooks.PERMISSION_DENIED_POLICY_ID == "claude_code:permission_denied"


def test_is_user_denial_does_not_match_failures_or_interrupts() -> None:
    """Anchored, not loose. The predicate matches ONLY the rejection lead-sentence
    — never a genuine failure, a genuine interrupt, or a bare keyword."""
    from agent_audit.adapters._claude_hooks import is_user_denial

    assert not is_user_denial("Exit code 1")
    assert not is_user_denial("[Request interrupted by user]")
    assert not is_user_denial("[Request interrupted by user for tool use]")
    # A cancel string the CLI groups with interrupts (not a rejection): left as-is.
    assert not is_user_denial(
        "The user doesn't want to take this action right now. STOP what you are "
        "doing and wait for the user to tell you how to proceed."
    )
    # Loose keywords must not trip it.
    assert not is_user_denial("permission denied while opening file")
    assert not is_user_denial("connection rejected by peer")
    assert not is_user_denial(None)
    assert not is_user_denial({"error": "rejected"})
