"""Deny-list PII redaction for tool call input/output.

Best-effort deny-list at the AUDIT BOUNDARY: it redacts what its rules match in
the values (and KEYS) the runtime hands the recorder. It does NOT reach upstream
(a secret already written to disk by the tool is not this layer's to catch) and a
deny-list can only deny what it recognises — see SCOPE_STATEMENT.md.

Design notes (v0.2 contract):
- Whole-value replacement: if ANY rule matches anywhere in a string field, the
  entire field is replaced with a structured marker. Scorched-earth on purpose —
  losing precision beats leaking.
- Recursion through dict / list / tuple with JSONPath-shaped path tracking.
- Dict KEYS are inspected, not just values. A PII key (a dict keyed by a patient
  email) is redacted to an unforgeable sentinel key so the key material never
  reaches the signed bytes.
- MOST-RESTRICTIVE rule wins. When several rules match one value, a
  `strip_hash=True` rule always beats a hashing rule, so a secret co-occurring
  with (say) an email is never hashed into the record via the email rule's
  sha256. First-match ordering — the old behaviour — leaked exactly that.
- Anti-forgery: a genuine marker carries the record's per-record `token` (minted
  by the recorder, unknowable to a tool that ran BEFORE it was minted) AND has a
  backing RedactionEntry at its path. `redaction_authenticity()` distinguishes a
  recorder-produced marker from a tool-supplied look-alike.
- High-sensitivity rules (secrets, low-entropy PII) set `strip_hash=True` so the
  marker omits sha256 — hashing a low-entropy or already-leaked value is itself
  a leak.

For custom rules, construct `RedactionConfig(rules=(*DEFAULT_RULES, my_rule))` or
replace the list entirely.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agent_audit.schema.v1 import RedactionEntry, ToolCall

# Marker / sentinel shape. Module constants so tests and readers share one source.
MARKER_TOKEN_KEY = "token"
# A redacted dict KEY becomes this sentinel string. It embeds the per-record token
# so a tool cannot forge a key that reads as recorder-redacted:
#   __agent_audit_redacted_key__::<token>::<policy>[::dup<n>]
REDACTED_KEY_PREFIX = "__agent_audit_redacted_key__::"
# A redacted STRING-TYPED field (tool.name, mcp.server_id) becomes this sentinel.
# Those fields are typed `str` in the schema, so a match cannot be replaced with a
# marker dict — it is replaced with this string, which carries the per-record token
# and the policy and no key/secret material:
#   __agent_audit_redacted_value__::<token>::<policy>
REDACTED_VALUE_PREFIX = "__agent_audit_redacted_value__::"


@dataclass(frozen=True)
class RedactionRule:
    """One deny-list rule.

    Attributes:
        policy_id: Stable identifier surfaced in the redaction audit
            (e.g. "pii.deny.email"). Dotted lowercase by convention.
        pattern: Compiled regex. If it matches anywhere in a string value the
            entire value is replaced with a marker.
        strip_hash: If True the marker omits sha256. Set for high-sensitivity
            rules where even a hash is too much (low-entropy secrets, tokens
            brute-forceable from their hash, or PII like an SSN). A strip_hash
            rule is treated as MORE RESTRICTIVE than a hashing rule.
        predicate: Optional extra check on the matched substring. Used to cut
            false positives a regex alone cannot (e.g. a Luhn check on a
            credit-card candidate). The rule fires only if the pattern matches
            AND the predicate returns True.
    """

    policy_id: str
    pattern: re.Pattern[str]
    strip_hash: bool = False
    predicate: Callable[[str], bool] | None = None

    def matches(self, value: str) -> bool:
        m = self.pattern.search(value)
        if m is None:
            return False
        if self.predicate is None:
            return True
        return self.predicate(m.group(0))


def _luhn_ok(candidate: str) -> bool:
    """Luhn checksum over the digits of a credit-card candidate.

    Anchors the credit-card rule: a 13-19 digit run with a card-like prefix that
    ALSO passes Luhn is overwhelmingly a real card, whereas a random number of
    the same length usually is not. Conservative by construction.
    """
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


DEFAULT_RULES: tuple[RedactionRule, ...] = (
    # --- Hashing rule (email keeps a sha256 so identical values correlate) -----
    # The `(?<!/)` guard stops a URL's userinfo (`scheme://user@host`, no
    # password) being mistaken for an email: in an authority the local part sits
    # immediately after a `/`, which a real email address never does. A URL that
    # DOES carry a password (`scheme://user:pass@host`) is still a leak — it is
    # caught by the strip_hash `url_credentials` rule below, which wins under
    # most-restrictive, so the password is never hashed in via this rule.
    RedactionRule(
        "pii.deny.email",
        re.compile(r"(?<!/)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    # --- Cloud / provider secrets (strip_hash: even a hash is a leak) ----------
    RedactionRule(
        "pii.deny.aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        strip_hash=True,
    ),
    RedactionRule(
        "pii.deny.github_pat_fine_grained",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        strip_hash=True,
    ),
    RedactionRule(
        "pii.deny.github_pat_classic",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        strip_hash=True,
    ),
    # Anthropic before OpenAI: `sk-ant-...` should report the more specific
    # policy (it wouldn't match the OpenAI pattern anyway — the dashes stop it —
    # but the ordering documents intent, and most-restrictive keeps it stable).
    RedactionRule(
        "pii.deny.anthropic_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        strip_hash=True,
    ),
    RedactionRule(
        "pii.deny.openai_key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        strip_hash=True,
    ),
    RedactionRule(
        "pii.deny.slack_token",
        re.compile(r"\bxox[bopas]-\d+-\d+-\d+-[a-zA-Z0-9]+\b"),
        strip_hash=True,
    ),
    # Stripe secret / restricted keys (underscore form; not the dashed OpenAI one).
    RedactionRule(
        "pii.deny.stripe_key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        strip_hash=True,
    ),
    # Google API keys.
    RedactionRule(
        "pii.deny.google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        strip_hash=True,
    ),
    # A JWT (three base64url segments; header + payload both start `eyJ`, the
    # base64 of `{"`). Signed tokens carry credentials — treat as a secret.
    RedactionRule(
        "pii.deny.jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"
        ),
        strip_hash=True,
    ),
    # A PEM private-key block header — matches the guard line, redacting the value.
    RedactionRule(
        "pii.deny.pem_private_key",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
        strip_hash=True,
    ),
    # A DB connection URL with an INLINE password (scheme://user:pass@host).
    # Anchored on a db scheme AND embedded credentials, so an ordinary URL is
    # never matched.
    RedactionRule(
        "pii.deny.db_url_password",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp)"
            r"://[^\s:/@]+:[^\s:/@]+@",
        ),
        strip_hash=True,
    ),
    # ANY URL that embeds credentials (`scheme://user:password@host`) — the
    # general case of the db-specific rule above, so a password/token in an https
    # or other URL is still redacted. Anchored on `user:pass@` so a bare userinfo
    # (`scheme://user@host`, no password) is NOT matched — that is not a
    # credential leak, and the email rule's `(?<!/)` guard leaves it alone too.
    # Declared AFTER db_url_password so a db URL reports the more specific policy
    # (both strip_hash; equal restrictiveness resolves to declaration order).
    RedactionRule(
        "pii.deny.url_credentials",
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@"),
        strip_hash=True,
    ),
    # --- Low-entropy PII (strip_hash: a hash of a 9-digit SSN is reversible) ---
    RedactionRule(
        "pii.deny.ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        strip_hash=True,
    ),
    RedactionRule(
        "pii.deny.credit_card",
        re.compile(
            r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b"
        ),
        strip_hash=True,
        predicate=_luhn_ok,
    ),
    # E.164 (+ and 10-15 digits) or US dashed (NNN-NNN-NNNN). Requires the + or
    # the dashes, so a bare run of digits is not swept up.
    RedactionRule(
        "pii.deny.phone",
        re.compile(r"(?:\+[1-9]\d{9,14}\b)|(?:\b\d{3}-\d{3}-\d{4}\b)"),
        strip_hash=True,
    ),
)


@dataclass
class RedactionConfig:
    """User-facing config for the redactor.

    Default: enabled, with DEFAULT_RULES. Set `disable=True` to record full
    unredacted values — but the recorder now DRIVES the sink's manifest so a
    disabled redactor is attested honestly (never a silent, affirmative "off").
    """

    rules: tuple[RedactionRule, ...] = field(default=DEFAULT_RULES)
    disable: bool = False


def _make_marker(
    value: str,
    rule: RedactionRule,
    token: str | None,
    *,
    py_type: str = "string",
) -> dict[str, Any]:
    """Build a redaction marker over `value`'s signed string form.

    `value` is ALWAYS the exact string that would otherwise appear in the signed
    canonical bytes — for a `str` it is the value itself, for a non-string scalar
    (an integer PAN) it is `str(scalar)`, which is what JCS emits. `py_type`
    records the original Python type so the marker stays honest about what was
    redacted; `length` and any `sha256` are over the signed string form.
    """
    marker: dict[str, Any] = {
        "redacted": True,
        "type": py_type,
        "length": len(value),
        "policy": rule.policy_id,
    }
    if not rule.strip_hash:
        marker["sha256"] = hashlib.sha256(value.encode("utf-8")).hexdigest()
    # The per-record anti-forgery token. Present only when the recorder minted
    # one (redaction enabled). A standalone redact_value() call (unit tests) and
    # a disabled recorder pass token=None, so the marker carries no token and is
    # not claimed to be recorder-attested.
    if token is not None:
        marker[MARKER_TOKEN_KEY] = token
    return marker


def _most_restrictive(value: str, config: RedactionConfig) -> RedactionRule | None:
    """Return the winning rule for a value, or None if nothing matches.

    A `strip_hash=True` rule always beats a hashing rule (it is more
    restrictive), so a secret co-occurring with a hashed pattern (e.g. an email)
    is never hashed into the record. Among rules of equal restrictiveness the
    first in declaration order wins, keeping the choice deterministic.
    """
    first_match: RedactionRule | None = None
    for rule in config.rules:
        if not rule.matches(value):
            continue
        if rule.strip_hash:
            return rule
        if first_match is None:
            first_match = rule
    return first_match


def _redact_key(key: str, rule: RedactionRule, token: str | None) -> str:
    """A redacted dict key: an unforgeable sentinel that carries no key material.

    The original key (which matched a PII rule) is dropped entirely — hashing it
    back in would re-leak a low-entropy value — and replaced with a sentinel that
    embeds the per-record token and the policy. A tool cannot mint this (it does
    not know the token), so the sentinel is recorder-attested by construction.
    """
    tok = token if token is not None else "none"
    return f"{REDACTED_KEY_PREFIX}{tok}::{rule.policy_id}"


def _redact_str_field(rule: RedactionRule, token: str | None) -> str:
    """A redacted STRING-typed field (tool.name, mcp.server_id).

    Those fields must stay `str` per the schema, so — like a redacted key — the
    matched material is dropped and replaced with an unforgeable sentinel string
    that carries only the per-record token and the policy.
    """
    tok = token if token is not None else "none"
    return f"{REDACTED_VALUE_PREFIX}{tok}::{rule.policy_id}"


def _signed_key_str(key: Any) -> str:
    """The exact string form a dict key takes in the signed canonical bytes.

    JCS object keys MUST be strings; `normalize_for_canonical` stringifies a
    non-string key with `str(key)` before signing. Redaction inspects that SAME
    string so a key that is a secret is caught in the form it would be signed as
    — closing the non-string-key bypass at its root rather than per type.
    """
    return key if isinstance(key, str) else str(key)


def redact_value(
    value: Any,
    config: RedactionConfig,
    path: str = "$",
    *,
    token: str | None = None,
) -> tuple[Any, list[RedactionEntry]]:
    """Recursively redact a value. Returns (redacted_value, audit entries).

    `path` uses JSONPath-shaped notation: `$.input.args.email`, `$.output.body[3]`.
    `token` is the recorder's per-record anti-forgery token; genuine markers and
    redacted keys carry it. Callers outside the recorder omit it.
    """
    if config.disable:
        return value, []

    if isinstance(value, str):
        rule = _most_restrictive(value, config)
        if rule is not None:
            return _make_marker(value, rule, token), [
                RedactionEntry(path=path, policy=rule.policy_id)
            ]
        return value, []

    if isinstance(value, dict):
        return _redact_dict(value, config, path, token)

    if isinstance(value, (list, tuple)):
        # A tuple is walked exactly like a list and returned as a list — JSON has
        # no tuple, and `normalize_for_canonical` converts it downstream anyway.
        # Recursing (rather than treating it as an opaque primitive) is what keeps
        # a secret inside a positional argument redacted.
        result_list: list[Any] = []
        list_entries: list[RedactionEntry] = []
        for i, item in enumerate(value):
            redacted_item, entries = redact_value(
                item, config, f"{path}[{i}]", token=token
            )
            result_list.append(redacted_item)
            list_entries.extend(entries)
        return result_list, list_entries

    # Non-string SCALARS that will be SIGNED must be inspected in the exact form
    # they will take in the canonical bytes. JCS emits an integer as its decimal
    # digits, so an integer-valued PAN would otherwise be signed cleartext while
    # its string twin is redacted — a pure type bypass. Match the deny-list
    # against `str(value)`; the anchored numeric rules (credit_card needs a
    # card-prefixed Luhn-valid run; ssn/phone need separators) fire only on real
    # PII, so a Snowflake id, a count, a timestamp, or a small int passes through.
    # `bool` is an `int` subclass but is never PII, so it is excluded.
    if isinstance(value, int) and not isinstance(value, bool):
        signed_str = str(value)
        rule = _most_restrictive(signed_str, config)
        if rule is not None:
            return _make_marker(signed_str, rule, token, py_type="int"), [
                RedactionEntry(path=path, policy=rule.policy_id)
            ]
        return value, []

    # remaining primitives (float, None) — no redaction. A float's JCS form is
    # not its `str()`, and the numeric PII rules are anchored on integer digit
    # runs, so deny-scanning floats would inspect the wrong string; left as-is.
    return value, []


def _redact_dict(
    value: dict[Any, Any],
    config: RedactionConfig,
    path: str,
    token: str | None,
) -> tuple[dict[str, Any], list[RedactionEntry]]:
    """Redact a dict, inspecting KEYS as well as values.

    A key that matches a rule is itself PII (a dict keyed by a patient email, or
    keyed by a secret handed in as `bytes`/`int`). Its material must not survive,
    so the key is replaced with an unforgeable sentinel and the substitution
    announced; the value continues to be redacted normally under the new key.
    Collisions (two redacted keys, same policy) are disambiguated so no value is
    silently overwritten.

    KEYS ARE INSPECTED IN THEIR SIGNED STRING FORM. A non-string key would be
    stringified by `normalize_for_canonical` (`str(key)`) before signing, so
    redaction matches that same `str(key)` — a `bytes`/`int` key that is a secret
    is caught in the exact form it would be signed as. A non-string key that does
    NOT match any rule is left untouched here (the original key object is kept),
    so normalize still stringifies it and announces it as a non-string-dict-key
    substitution — benign non-string keys are never over-redacted.
    """
    result: dict[str, Any] = {}
    entries: list[RedactionEntry] = []

    for k, v in value.items():
        key_rule = _most_restrictive(_signed_key_str(k), config)

        if key_rule is not None:
            new_key = _redact_key(k, key_rule, token)
            dup = 1
            while new_key in result:
                new_key = f"{_redact_key(k, key_rule, token)}::dup{dup}"
                dup += 1
            child_path = f"{path}.{new_key}"
            entries.append(RedactionEntry(path=child_path, policy=key_rule.policy_id))
            redacted_v, v_entries = redact_value(
                v, config, child_path, token=token
            )
            result[new_key] = redacted_v
            entries.extend(v_entries)
        else:
            child_path = f"{path}.{k}"
            redacted_v, v_entries = redact_value(
                v, config, child_path, token=token
            )
            result[k] = redacted_v
            entries.extend(v_entries)

    return result, entries


def redact_tool(
    tool: ToolCall, config: RedactionConfig, token: str | None = None
) -> tuple[ToolCall, list[RedactionEntry]]:
    """Redact the tool IDENTITY fields — `tool.name` and the `mcp` subfields.

    These are signed like any other value, but the recorder passed the ToolCall
    straight into the payload, so a secret in `tool.name` or `mcp.server_id` was
    signed cleartext — the third face of the same type-bypass class. They are
    `str`-typed in the schema, so a match is replaced with an unforgeable string
    sentinel (not a marker dict) and the substitution announced at
    `$.tool.name` / `$.tool.mcp.server_id` / `$.tool.mcp.server_version`. A normal
    tool name matches nothing and is returned untouched.
    """
    if config.disable:
        return tool, []

    entries: list[RedactionEntry] = []

    name = tool.name
    name_rule = _most_restrictive(name, config)
    if name_rule is not None:
        name = _redact_str_field(name_rule, token)
        entries.append(RedactionEntry(path="$.tool.name", policy=name_rule.policy_id))

    mcp = tool.mcp
    if mcp is not None:
        new_fields: dict[str, str] = {}
        for field_name, field_path in (
            ("server_id", "$.tool.mcp.server_id"),
            ("server_version", "$.tool.mcp.server_version"),
        ):
            field_value = getattr(mcp, field_name)
            if not isinstance(field_value, str):
                continue
            field_rule = _most_restrictive(field_value, config)
            if field_rule is not None:
                new_fields[field_name] = _redact_str_field(field_rule, token)
                entries.append(
                    RedactionEntry(path=field_path, policy=field_rule.policy_id)
                )
        if new_fields:
            mcp = mcp.model_copy(update=new_fields)

    if not entries:
        return tool, []
    return ToolCall(name=name, mcp=mcp), entries


# ---------------------------------------------------------------------------
# Anti-forgery: is a marker in the signed data recorder-attested, or a tool
# look-alike?
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RedactionAuthenticity:
    """Verdict on whether the redaction markers in a record are recorder-attested.

    - `authentic`: every marker / redacted-key found in the record's data is
      backed (carries the record's token where a token is present, AND has a
      RedactionEntry at its path). A record with no markers is trivially
      authentic.
    - `forged_paths`: paths of marker-shaped values that a tool could have
      injected — no backing entry, or a token that does not match the record's.
    - `genuine_paths`: paths that check out.
    - `token_present`: whether the record published a redaction_token (v1.2+ and
      redaction enabled). When absent (pre-v1.2 or redaction disabled) the check
      degrades to structural reconciliation against the announced entries.
    """

    authentic: bool
    forged_paths: list[str]
    genuine_paths: list[str]
    token_present: bool


def _looks_like_marker(value: Any) -> bool:
    return isinstance(value, dict) and value.get("redacted") is True


def _sentinel_token(sentinel_key: str) -> str | None:
    """Extract the token a redacted-key sentinel claims, or None if malformed."""
    rest = sentinel_key[len(REDACTED_KEY_PREFIX):]
    head = rest.split("::", 1)[0]
    return head or None


def redaction_authenticity(record: dict[str, Any]) -> RedactionAuthenticity:
    """Audit the redaction markers embedded in a signed record.

    Walks the runtime-supplied fields (input, output.body, outcome, and lifecycle
    attributes) for marker-shaped values and redacted-key sentinels, and checks
    each against the record's published token and announced RedactionEntry paths.
    A tool-supplied look-alike is detected because it cannot carry the record's
    token (minted after the tool ran) and has no backing entry.
    """
    payload = record.get("payload") or {}
    published_token = payload.get("redaction_token")
    entry_paths = {
        e.get("path")
        for e in (payload.get("redaction") or [])
        if isinstance(e, dict)
    }

    forged: list[str] = []
    genuine: list[str] = []

    def check(marker_token: str | None, at_path: str) -> None:
        has_entry = at_path in entry_paths
        if published_token is not None:
            ok = marker_token == published_token and has_entry
        else:
            # Pre-token record: only structural reconciliation is possible.
            ok = has_entry
        (genuine if ok else forged).append(at_path)

    def walk(value: Any, at_path: str) -> None:
        if _looks_like_marker(value):
            check(value.get(MARKER_TOKEN_KEY), at_path)
            return  # a marker's internals are metadata, not nested data
        if isinstance(value, dict):
            for k, v in value.items():
                child = f"{at_path}.{k}"
                if isinstance(k, str) and k.startswith(REDACTED_KEY_PREFIX):
                    check(_sentinel_token(k), child)
                walk(v, child)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                walk(item, f"{at_path}[{i}]")

    walk(payload.get("input"), "$.input")
    output = payload.get("output") or {}
    walk(output.get("body"), "$.output.body")
    outcome = payload.get("outcome") or {}
    if isinstance(outcome, dict):
        walk(outcome.get("error_type"), "$.outcome.error_type")
        walk(outcome.get("message"), "$.outcome.message")
    walk(payload.get("attributes"), "$.attributes")

    return RedactionAuthenticity(
        authentic=not forged,
        forged_paths=forged,
        genuine_paths=genuine,
        token_present=published_token is not None,
    )


__all__ = [
    "DEFAULT_RULES",
    "MARKER_TOKEN_KEY",
    "REDACTED_KEY_PREFIX",
    "REDACTED_VALUE_PREFIX",
    "RedactionAuthenticity",
    "RedactionConfig",
    "RedactionRule",
    "redact_tool",
    "redact_value",
    "redaction_authenticity",
]
