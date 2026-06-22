# examples/

Runnable demos + config snippets. Each example is **self-contained**: it
generates its own throwaway signing key in a temp dir, produces a tiny
audit log, and exits 0 only if `agent-audit verify` accepts the result.
None require an API key.

| File | What it shows | When to read it |
|------|---------------|------------------|
| `claude_code_settings.json` | Config snippet to drop into `~/.claude/settings.json`. Registers `agent-audit hook-record` as a `PostToolUse` hook for every tool call from Claude Code (interactive + `claude --bg` + subagents). | You want to instrument an existing Claude Code workflow. |
| `claude_code_dogfood.sh` | Shell script that pipes a synthetic Claude Code hook payload through `agent-audit hook-record` and then verifies the resulting log. No real Claude session needed. | You want to confirm `hook-record` works on your machine **before** wiring it into your Claude Code settings. Also useful as a CI smoke test. |
| `langgraph_example.py` | End-to-end demo: builds a real `langchain.agents.create_agent` with `AuditMiddleware` attached, uses a tiny fake chat model so it runs without an API key, invokes one tool, verifies the log. | You're on LangGraph (not Claude CLI) and want to see how the middleware path works. |
| `audited_tool_example.py` | Minimal demo: decorate plain Python functions with `@audited_tool` and call them like normal. No LangGraph, no Claude — just the decorator. | You want audit recording in plain Python code (cron jobs, scripts, internal automation). |

## Quick start

If you just want to see something work right now:

```bash
# minimum runnable demo, no install, no key setup needed
python examples/audited_tool_example.py
```

That generates a temp signing key, records two decorated function calls,
and runs `agent-audit verify` — exit code 0 means the whole pipeline (sign,
chain, persist, verify) works on your box.

## Common gotchas

- **`agent-audit` not on PATH.** All examples assume the binary is reachable.
  If you installed via `uv tool install` / `pipx install` / activated venv, you
  should be fine. If it errors, either activate your venv first or substitute
  `python -m agent_audit.cli ...` for `agent-audit ...` in the script.
- **No signing key.** `claude_code_dogfood.sh` expects `~/.config/agent-audit/signing.key`
  to already exist. The other examples generate one for you. The header
  comment of `claude_code_dogfood.sh` has a one-liner to create the key
  if you need it.
- **Stale chain head.** If you re-run the dogfood script after editing audit
  records by hand, the chain may detect tampering. That's the design — if
  you want a clean restart, `rm ~/.config/agent-audit/audit-*.jsonl ~/.config/agent-audit/manifest.json`
  (NOT the signing key — that stays).
