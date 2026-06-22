#!/bin/sh
# Synthetic Claude Code hook smoke test.
#
# What it does:
#   1. Pipes a fake PostToolUse JSON payload to `agent-audit hook-record`
#   2. Runs `agent-audit verify` on the resulting log
#   3. Prints a one-line summary per record via jq (if installed)
#
# Why you'd run it:
#   - To confirm `agent-audit hook-record` works on your machine BEFORE
#     wiring it into ~/.claude/settings.json
#   - To produce a sample audit log without spawning a real Claude Code
#     session
#   - As a CI smoke test for the hook handler path
#
# Requires:
#   - agent-audit installed and on PATH (or adjust the commands below)
#   - signing.key + signing.pub at ~/.config/agent-audit/
#     (or set AGENT_AUDIT_DIR / AGENT_AUDIT_SIGNING_KEY / AGENT_AUDIT_PUBKEY)
#
# If you don't have a signing key yet, generate one:
#   mkdir -p ~/.config/agent-audit && python3 -c "
#   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
#   from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
#   k = Ed25519PrivateKey.generate()
#   open('${HOME}/.config/agent-audit/signing.key','wb').write(k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
#   open('${HOME}/.config/agent-audit/signing.pub','wb').write(k.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))"
#   chmod 0600 ~/.config/agent-audit/signing.key

set -eu

AUDIT_DIR="${AGENT_AUDIT_DIR:-$HOME/.config/agent-audit}"
PUBKEY="${AGENT_AUDIT_PUBKEY:-$AUDIT_DIR/signing.pub}"
TODAY="$(date -u +%Y-%m-%d)"
LOG="$AUDIT_DIR/audit-$TODAY.jsonl"
CHAIN_ID="${AGENT_AUDIT_CHAIN_ID:-dogfood-smoke}"

echo "=== 1. pipe synthetic PostToolUse payload ==="
agent-audit hook-record --chain-id "$CHAIN_ID" <<EOF
{"hook_event_name":"PostToolUse","session_id":"smoke-$$","tool_name":"Read","tool_input":{"file_path":"/etc/hosts"},"tool_response":"127.0.0.1 localhost"}
EOF
echo "hook-record exit: $?"
echo

echo "=== 2. pipe a second one (MCP call) ==="
agent-audit hook-record --chain-id "$CHAIN_ID" <<EOF
{"hook_event_name":"PostToolUse","session_id":"smoke-$$","tool_name":"mcp__example__get_thing","tool_input":{"id":"42"},"tool_response":{"name":"the thing","ok":true}}
EOF
echo "hook-record exit: $?"
echo

echo "=== 3. verify the resulting log ==="
agent-audit verify "$LOG" --pubkey "$PUBKEY"
echo

if command -v jq >/dev/null 2>&1; then
    echo "=== 4. one-line summary per record ==="
    jq -c 'select(.envelope.chain_id == "'"$CHAIN_ID"'") | {tool: .payload.tool.name, mcp: .payload.tool.mcp.server_id, session: .header.session_id}' "$LOG"
else
    echo "(install jq for record summaries)"
fi
