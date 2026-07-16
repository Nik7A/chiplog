"""UnobservedPolicy — the honest 'gate status was not observable' primitive.

The bug it replaces: every adapter hardcoded `ungated(AUTO_ALLOWED_LOW_RISK)`,
which positively asserts TWO things the instrumentation never observed — that no
gate fired AND that the call was low risk. `UnobservedPolicy` asserts only that
the gate status could not be observed, and why. It makes NO risk claim.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from chiplog.emit import AuditRecorder
from chiplog.integrity import verify_record
from chiplog.keys import SigningKey, compute_key_id
from chiplog.schema.v1 import (
    Output,
    PolicyUnobservedReason,
    ToolCall,
    UnobservedPolicy,
    policy_unobserved,
    success,
)
from chiplog.sinks.base import InMemorySink


def _signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


def test_builder_returns_unobserved_policy() -> None:
    p = policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL)
    assert isinstance(p, UnobservedPolicy)
    assert p.kind == "policy_unobserved"
    assert p.reason == PolicyUnobservedReason.NO_GATE_SIGNAL


def test_enum_value_is_stable_wire_string() -> None:
    assert PolicyUnobservedReason.NO_GATE_SIGNAL.value == "no_gate_signal"


def test_unobserved_policy_makes_no_risk_claim() -> None:
    """The whole point: the serialized form carries a reason and NOTHING that
    asserts a risk level. If a `risk`/`low_risk` field ever appears here, the
    primitive has re-acquired the lie it exists to kill."""
    dumped = policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL).model_dump()
    assert dumped == {"kind": "policy_unobserved", "reason": "no_gate_signal"}
    assert "risk" not in dumped
    assert "low_risk" not in json.dumps(dumped)


async def test_record_carries_unobserved_policy_and_verifies() -> None:
    sink = InMemorySink()
    key = _signing_key()
    rec = AuditRecorder(sink=sink, signing_key=key)
    signed = await rec.record(
        session_id="s",
        step_id="1",
        tool=ToolCall(name="t"),
        input={"a": 1},
        output=Output(body="ok"),
        policy=policy_unobserved(PolicyUnobservedReason.NO_GATE_SIGNAL),
        outcome=success(),
    )
    assert signed["payload"]["policy"] == {
        "kind": "policy_unobserved",
        "reason": "no_gate_signal",
    }
    result = verify_record(signed, {key.key_id: key.public_key})
    assert result.is_valid


def test_policy_context_discriminates_the_three_variants() -> None:
    """PolicyContext accepts all three kinds via its discriminator; a bogus kind
    is rejected rather than silently coerced."""
    from chiplog.schema.v1 import Payload

    def _payload(policy_dict: dict[str, object]) -> Payload:
        return Payload.model_validate(
            {
                "time": {
                    "ts_utc": "2026-07-15T00:00:00.000000000Z",
                    "ts_monotonic_ns": "1",
                },
                "tool": {"name": "t"},
                "input": {},
                "output": {},
                "policy": policy_dict,
                "outcome": {"kind": "success"},
            }
        )

    assert isinstance(
        _payload({"kind": "policy_unobserved", "reason": "no_gate_signal"}).policy,
        UnobservedPolicy,
    )
    with pytest.raises(ValidationError):
        _payload({"kind": "not_a_real_kind", "reason": "no_gate_signal"})


def test_adapters_no_longer_hardcode_auto_allowed_low_risk() -> None:
    """No adapter may assert the fabricated `ungated(AUTO_ALLOWED_LOW_RISK)`
    policy — that is the 100%-of-records lie this task removes. They must use
    `policy_unobserved(NO_GATE_SIGNAL)` instead."""
    adapters_dir = Path(__file__).resolve().parents[1] / "src" / "chiplog" / "adapters"
    offenders: list[str] = []
    for py in adapters_dir.glob("*.py"):
        text = py.read_text()
        if "AUTO_ALLOWED_LOW_RISK" in text:
            offenders.append(py.name)
    assert offenders == [], (
        f"adapters still assert the fabricated low-risk policy: {offenders}"
    )


def test_unobserved_policy_rejects_unknown_field_extra_forbid() -> None:
    """A risk/decision must never be smuggled into policy_unobserved via an extra field."""
    import pytest
    from pydantic import ValidationError
    from chiplog.schema.v1 import UnobservedPolicy, PolicyUnobservedReason

    with pytest.raises(ValidationError):
        UnobservedPolicy.model_validate(
            {"kind": "policy_unobserved", "reason": PolicyUnobservedReason.NO_GATE_SIGNAL.value, "risk": "low"}
        )
