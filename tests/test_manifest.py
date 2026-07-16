"""Step 4: Manifest serialization, atomic save, and schema_version rejection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chiplog.manifest import (
    MANIFEST_SCHEMA_VERSION,
    ChainState,
    FileChecksum,
    Manifest,
    RedactionState,
)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_manifest_round_trip_via_dict() -> None:
    m = Manifest(
        pubkey_id="aabbccddeeff0011",
        pubkey_pem="-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n",
        chains={
            "sess-1": ChainState(
                chain_id="sess-1",
                head_hash="aa" * 32,
                genesis_hash="bb" * 32,
                record_count=10,
                first_record_id="01H...",
                last_record_id="01H...",
            )
        },
        files={
            "audit-2026-06-19.jsonl": FileChecksum(
                sha256="cc" * 32, record_count=10, first_record_id="x", last_record_id="y"
            )
        },
        redaction_state=RedactionState.DISABLED,
    )

    restored = Manifest.from_dict(m.to_dict())
    assert restored == m
    # The tri-state survives the round trip, and the compat accessor agrees.
    assert restored.redaction_state == RedactionState.DISABLED
    assert restored.redaction_disabled is True


def test_manifest_load_or_create_returns_fresh_when_absent(tmp_path: Path) -> None:
    m = Manifest.load_or_create(tmp_path / "manifest.json")
    assert m.schema_version == MANIFEST_SCHEMA_VERSION
    assert m.chains == {}
    assert m.files == {}
    assert m.redaction_disabled is False


def test_manifest_load_or_create_reads_existing(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    original = Manifest(pubkey_id="abc")
    original.save_atomic(path)

    loaded = Manifest.load_or_create(path)
    assert loaded.pubkey_id == "abc"


# ---------------------------------------------------------------------------
# Atomic save
# ---------------------------------------------------------------------------


def test_save_atomic_writes_target_and_cleans_tmp(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    Manifest(pubkey_id="xyz").save_atomic(path)

    assert path.exists()
    assert not (tmp_path / "manifest.json.tmp").exists()


def test_save_atomic_is_idempotent(tmp_path: Path) -> None:
    """Re-saving the same manifest produces byte-identical output (modulo
    indentation), which makes downstream tooling deterministic."""
    path = tmp_path / "manifest.json"
    m = Manifest(pubkey_id="xyz", chains={"a": ChainState(chain_id="a")})
    m.save_atomic(path)
    first = path.read_bytes()
    m.save_atomic(path)
    second = path.read_bytes()
    assert first == second


def test_save_atomic_overwrites_existing(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    Manifest(pubkey_id="old").save_atomic(path)
    Manifest(pubkey_id="new").save_atomic(path)

    loaded = Manifest.load_or_create(path)
    assert loaded.pubkey_id == "new"


# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------


def test_manifest_rejects_unsupported_schema_version() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        Manifest.from_dict(
            {
                "schema_version": "manifest.v999.0",
                "pubkey_id": "x",
                "pubkey_pem": None,
                "chains": {},
                "files": {},
                "redaction_disabled": False,
            }
        )


def test_load_or_create_surfaces_corruption(tmp_path: Path) -> None:
    """A truncated/garbled manifest must surface ValueError, not silently
    look like a fresh manifest."""
    path = tmp_path / "manifest.json"
    path.write_text("{not json")

    with pytest.raises(ValueError, match="failed to load manifest"):
        Manifest.load_or_create(path)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


def test_chain_state_defaults_match_genesis() -> None:
    c = ChainState(chain_id="x")
    assert c.head_hash is None
    assert c.genesis_hash is None
    assert c.record_count == 0


def test_manifest_default_schema_version_is_current() -> None:
    assert Manifest().schema_version == MANIFEST_SCHEMA_VERSION


def test_manifest_to_dict_is_json_serializable() -> None:
    m = Manifest(pubkey_id="x", chains={"a": ChainState(chain_id="a")})
    # Should not raise
    json.dumps(m.to_dict())
