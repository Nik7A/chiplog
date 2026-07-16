"""Step 3: PII redaction tests.

Covers: default rules fire on common patterns, paths track JSONPath shape,
high-sensitivity rules omit sha256, disable=True is a true no-op, and
redaction is deterministic across runs (foundation for replay-safe idempotent
flows).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from chiplog.redact import (
    DEFAULT_RULES,
    RedactionConfig,
    RedactionRule,
    redact_value,
)


# ---------------------------------------------------------------------------
# Default-rule fires
# ---------------------------------------------------------------------------


def test_email_replaces_entire_value() -> None:
    config = RedactionConfig()
    value = "please email me at foo@bar.com about it"
    redacted, entries = redact_value(value, config, path="$.input.message")

    assert isinstance(redacted, dict)
    assert redacted["redacted"] is True
    assert redacted["type"] == "string"
    assert redacted["policy"] == "pii.deny.email"
    assert redacted["length"] == len(value)
    assert redacted["sha256"] == hashlib.sha256(value.encode("utf-8")).hexdigest()

    assert len(entries) == 1
    assert entries[0].path == "$.input.message"
    assert entries[0].policy == "pii.deny.email"


def test_aws_access_key_redacted_without_sha256() -> None:
    """strip_hash=True for AWS access keys — even a hash of a known key is a leak."""
    config = RedactionConfig()
    redacted, _ = redact_value("AKIAIOSFODNN7EXAMPLE", config)

    assert isinstance(redacted, dict)
    assert redacted["redacted"] is True
    assert redacted["policy"] == "pii.deny.aws_access_key"
    assert "sha256" not in redacted


def test_anthropic_key_redacted_before_openai_pattern() -> None:
    """Anthropic rule sits before OpenAI in DEFAULT_RULES so the more
    specific policy wins. Test verifies the iteration order remains correct.
    """
    config = RedactionConfig()
    redacted, _ = redact_value("sk-ant-1234567890abcdefghij", config)
    assert isinstance(redacted, dict)
    assert redacted["policy"] == "pii.deny.anthropic_key"


def test_openai_key_redacted() -> None:
    config = RedactionConfig()
    redacted, _ = redact_value("sk-1234567890abcdefghij", config)
    assert isinstance(redacted, dict)
    assert redacted["policy"] == "pii.deny.openai_key"


def test_github_pat_classic_redacted() -> None:
    config = RedactionConfig()
    value = "ghp_" + "a" * 36
    redacted, _ = redact_value(value, config)
    assert isinstance(redacted, dict)
    assert redacted["policy"] == "pii.deny.github_pat_classic"


# ---------------------------------------------------------------------------
# Non-matches stay unchanged
# ---------------------------------------------------------------------------


def test_clean_string_unchanged() -> None:
    config = RedactionConfig()
    redacted, entries = redact_value("hello world, no secrets here", config)
    assert redacted == "hello world, no secrets here"
    assert entries == []


def test_primitives_unchanged() -> None:
    config = RedactionConfig()
    for v in [42, 3.14, True, False, None]:
        redacted, entries = redact_value(v, config)
        assert redacted == v
        assert entries == []


# ---------------------------------------------------------------------------
# Path tracking
# ---------------------------------------------------------------------------


def test_nested_dict_path() -> None:
    config = RedactionConfig()
    value = {"user": {"email": "foo@bar.com", "name": "Foo"}}
    redacted, entries = redact_value(value, config, path="$")

    assert isinstance(redacted["user"]["email"], dict)
    assert redacted["user"]["name"] == "Foo"
    assert len(entries) == 1
    assert entries[0].path == "$.user.email"


def test_list_path_uses_brackets() -> None:
    config = RedactionConfig()
    value = ["foo@bar.com", "clean", "AKIAIOSFODNN7EXAMPLE"]
    redacted, entries = redact_value(value, config, path="$.args")

    assert isinstance(redacted[0], dict)
    assert redacted[1] == "clean"
    assert isinstance(redacted[2], dict)
    paths = sorted(e.path for e in entries)
    assert paths == ["$.args[0]", "$.args[2]"]


def test_dict_with_list_with_dict_path_chain() -> None:
    """Path tracking through interleaved dict + list nesting."""
    config = RedactionConfig()
    value = {"items": [{"contact": "foo@bar.com"}, {"contact": "ok"}]}
    redacted, entries = redact_value(value, config, path="$.payload")

    assert len(entries) == 1
    assert entries[0].path == "$.payload.items[0].contact"
    assert isinstance(redacted["items"][0]["contact"], dict)
    assert redacted["items"][1]["contact"] == "ok"


# ---------------------------------------------------------------------------
# Disable + custom rule + determinism
# ---------------------------------------------------------------------------


def test_disable_is_a_true_noop() -> None:
    config = RedactionConfig(disable=True)
    value = {"email": "foo@bar.com", "key": "AKIAIOSFODNN7EXAMPLE"}
    redacted, entries = redact_value(value, config)
    assert redacted == value
    assert entries == []


def test_custom_rule_appends_to_defaults() -> None:
    """User can prepend their own rule. Test that the custom rule fires."""
    custom = RedactionRule(
        "custom.ticket_ref",
        re.compile(r"\bTICKET-\d{4,}\b"),
    )
    config = RedactionConfig(rules=(custom, *DEFAULT_RULES))
    redacted, entries = redact_value("working on TICKET-1234 today", config)
    assert isinstance(redacted, dict)
    assert entries[0].policy == "custom.ticket_ref"


def test_redaction_is_deterministic() -> None:
    """Same input → same output. Foundation for replay-safe idempotent flows
    where a re-pulled Asana ticket must produce the same canonical hash."""
    config = RedactionConfig()
    value: dict[str, Any] = {
        "emails": ["a@b.com", "c@d.com"],
        "key": "AKIAIOSFODNN7EXAMPLE",
        "msg": "hello",
    }
    a, _ = redact_value(value, config)
    b, _ = redact_value(value, config)
    assert a == b


def test_word_boundary_avoids_partial_matches() -> None:
    """'fooAKIA1234...EXAMPLE' embedded in larger string still matches AWS
    pattern via word boundary; but 'XAKIA' inside an identifier should not.
    Verify the regex behaves as intended on a realistic edge case."""
    config = RedactionConfig()

    # Bare identifier that LOOKS like an access key prefix — should NOT match
    redacted_safe, entries_safe = redact_value("XAKIAIOSFODNN7EXAMPLEX", config)
    assert redacted_safe == "XAKIAIOSFODNN7EXAMPLEX"
    assert entries_safe == []

    # Real access key in a sentence — SHOULD match
    redacted_hit, entries_hit = redact_value(
        "key is AKIAIOSFODNN7EXAMPLE for prod", config
    )
    assert isinstance(redacted_hit, dict)
    assert entries_hit[0].policy == "pii.deny.aws_access_key"
