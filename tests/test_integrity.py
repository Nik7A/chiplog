"""Step 2 verification: crypto primitives + key loading.

Covers BUILD_PLAN Step 2 verification gate:
- sign-verify round trip
- flip one byte → HASH_MISMATCH (caught in the SAME record; chain-level "fails
  at exactly N+1" is the chain verification's job in Step 5)
- forged signature → SIGNATURE_INVALID
- wrong-key-id → UNKNOWN_KEY_ID
- private-as-public load → refused loud
- public-as-private load → refused loud
- chmod 0644 on signing key → refused loud
- chain link covers signature (foundation of chain integrity)
- cross-process bytes contract via PEM round-trip
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_public_key,
)

from agent_audit.canonical import canonical_for_signing
from agent_audit.integrity import (
    VerificationFailure,
    compute_chain_link,
    compute_record_hash,
    sign_record,
    verify_record,
)
from agent_audit.keys import (
    SigningKey,
    compute_key_id,
    load_public_key,
    load_signing_key,
)
from tests.test_canonical_jcs import make_test_vector_record


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_key_in_memory() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


@pytest.fixture
def key_files(tmp_path: Path) -> tuple[Path, Path]:
    """Write signing.key (0600) + signing.pub (0644) to tmp. Return (priv, pub)."""
    pk = Ed25519PrivateKey.generate()

    priv_path = tmp_path / "signing.key"
    pub_path = tmp_path / "signing.pub"

    priv_path.write_bytes(
        pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    priv_path.chmod(0o600)

    pub_path.write_bytes(
        pk.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
    )
    pub_path.chmod(0o644)

    return priv_path, pub_path


# ---------------------------------------------------------------------------
# compute_record_hash sanity
# ---------------------------------------------------------------------------


def test_compute_record_hash_matches_sha256_of_signing_form() -> None:
    rec = make_test_vector_record()
    expected = hashlib.sha256(canonical_for_signing(rec)).hexdigest()
    assert compute_record_hash(rec) == expected


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


def test_sign_verify_round_trip(signing_key_in_memory: SigningKey) -> None:
    sk = signing_key_in_memory
    rec = make_test_vector_record()
    signed = sign_record(rec, sk)

    result = verify_record(signed, pubkey_by_id={sk.key_id: sk.public_key})
    assert result.is_valid
    assert result.failure is None


def test_sign_does_not_mutate_input(signing_key_in_memory: SigningKey) -> None:
    """sign_record must not modify its argument — it returns a NEW dict.

    Mutating an in-flight Pydantic Record (or shared dict) could cause races
    with concurrent emitters. Pure return ensures the input is safe to reuse.
    """
    sk = signing_key_in_memory
    rec_dict = make_test_vector_record().model_dump(mode="json")
    snapshot = {k: dict(v) if isinstance(v, dict) else v for k, v in rec_dict.items()}

    sign_record(rec_dict, sk)

    assert rec_dict["envelope"] == snapshot["envelope"]


def test_sign_record_refuses_non_signing_key_type() -> None:
    """Passing a raw Ed25519PrivateKey (instead of SigningKey dataclass) must
    refuse loud. Prevents the entire 'mismatched (priv_key, key_id) pair'
    foot-gun class by construction — flagged by the Step 2 security review.
    """
    raw_priv = Ed25519PrivateKey.generate()
    with pytest.raises(TypeError, match="SigningKey"):
        sign_record(make_test_vector_record(), raw_priv)  # type: ignore[arg-type]


def test_sign_record_refuses_deeply_nested_input(
    signing_key_in_memory: SigningKey,
) -> None:
    """A misbehaving MCP server returning a pathologically nested dict must
    NOT crash the emitter with RecursionError mid-call (which would silently
    skip the audit record for exactly the call most worth auditing). Convert
    to a ValueError that the recorder can surface cleanly. Flagged by the
    Step 2 security review.
    """
    import sys
    from typing import Any

    rec = make_test_vector_record().model_dump(mode="json")
    nested: dict[str, Any] = {}
    cur = nested
    for _ in range(sys.getrecursionlimit() + 50):
        cur["a"] = {}
        cur = cur["a"]
    rec["payload"]["input"] = nested

    with pytest.raises(ValueError, match="deeply nested"):
        sign_record(rec, signing_key_in_memory)


# ---------------------------------------------------------------------------
# Tampering detection (single-record)
# ---------------------------------------------------------------------------


def test_tampered_input_field_detected_as_hash_mismatch(
    signing_key_in_memory: SigningKey,
) -> None:
    """Flip one byte in input.args. Verifier must catch as HASH_MISMATCH."""
    sk = signing_key_in_memory
    signed = sign_record(make_test_vector_record(), sk)

    signed["payload"]["input"]["file_path"] = "/etc/passwd"

    result = verify_record(signed, pubkey_by_id={sk.key_id: sk.public_key})
    assert not result.is_valid
    assert result.failure == VerificationFailure.HASH_MISMATCH


def test_tampered_envelope_key_id_detected(
    signing_key_in_memory: SigningKey,
) -> None:
    """key_id is in the signing form, so tampering with it after signing breaks
    the hash. (And changes which pubkey would be looked up — but the hash check
    fires first.)
    """
    sk = signing_key_in_memory
    signed = sign_record(make_test_vector_record(), sk)
    signed["envelope"]["key_id"] = "deadbeefdeadbeef"

    result = verify_record(
        signed,
        pubkey_by_id={
            sk.key_id: sk.public_key,
            "deadbeefdeadbeef": sk.public_key,
        },
    )
    assert not result.is_valid
    assert result.failure == VerificationFailure.HASH_MISMATCH


def test_forged_signature_detected_as_signature_invalid(
    signing_key_in_memory: SigningKey,
) -> None:
    """Replace signature with valid-shaped-but-bogus bytes. Hash stays consistent
    so the hash check passes; the signature check fails."""
    sk = signing_key_in_memory
    signed = sign_record(make_test_vector_record(), sk)
    signed["envelope"]["signature"] = base64.b64encode(b"\x00" * 64).decode()

    result = verify_record(signed, pubkey_by_id={sk.key_id: sk.public_key})
    assert not result.is_valid
    assert result.failure == VerificationFailure.SIGNATURE_INVALID


def test_signature_wrong_length_is_malformed(
    signing_key_in_memory: SigningKey,
) -> None:
    """A 63-byte signature is impossible for valid Ed25519 — refuse loud,
    don't silently fail signature verification."""
    sk = signing_key_in_memory
    signed = sign_record(make_test_vector_record(), sk)
    signed["envelope"]["signature"] = base64.b64encode(b"\x00" * 63).decode()

    result = verify_record(signed, pubkey_by_id={sk.key_id: sk.public_key})
    assert not result.is_valid
    assert result.failure == VerificationFailure.MALFORMED_RECORD


def test_unknown_key_id_detected(signing_key_in_memory: SigningKey) -> None:
    sk = signing_key_in_memory
    signed = sign_record(make_test_vector_record(), sk)

    result = verify_record(signed, pubkey_by_id={})
    assert not result.is_valid
    assert result.failure == VerificationFailure.UNKNOWN_KEY_ID


def test_malformed_record_missing_envelope() -> None:
    result = verify_record({"header": {}, "payload": {}}, pubkey_by_id={})
    assert not result.is_valid
    assert result.failure == VerificationFailure.MALFORMED_RECORD


# ---------------------------------------------------------------------------
# Chain link
# ---------------------------------------------------------------------------


def test_chain_link_changes_when_signature_changes(
    signing_key_in_memory: SigningKey,
) -> None:
    """Foundation of the chain integrity: chain link MUST include the signature
    so that signature tampering breaks the next record's prev_hash check.
    """
    sk = signing_key_in_memory
    signed = sign_record(make_test_vector_record(), sk)
    chain_a = compute_chain_link(signed)

    forged = {k: dict(v) if isinstance(v, dict) else v for k, v in signed.items()}
    forged["envelope"] = dict(signed["envelope"])
    forged["envelope"]["signature"] = base64.b64encode(b"\x99" * 64).decode()
    chain_b = compute_chain_link(forged)

    assert chain_a != chain_b


# ---------------------------------------------------------------------------
# Cross-process bytes contract (PEM round-trip simulating two processes)
# ---------------------------------------------------------------------------


def test_sign_with_one_key_object_verify_with_pem_loaded_pubkey(
    signing_key_in_memory: SigningKey,
) -> None:
    """The verifier may have only the public PEM, never seeing the signer's
    in-memory key object. This test simulates that scenario: sign with the
    fresh Ed25519PrivateKey, then verify with the public key reloaded from
    its PEM serialization.
    """
    sk = signing_key_in_memory
    signed = sign_record(make_test_vector_record(), sk)

    pub_pem = sk.public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    reloaded_pub = load_pem_public_key(pub_pem)
    # mypy: load_pem_public_key returns a PublicKeyTypes union; we know it's Ed25519
    assert hasattr(reloaded_pub, "verify")

    result = verify_record(signed, pubkey_by_id={sk.key_id: reloaded_pub})  # type: ignore[dict-item]
    assert result.is_valid


# ---------------------------------------------------------------------------
# Key loading foot-guns
# ---------------------------------------------------------------------------


def test_load_signing_key_happy_path(key_files: tuple[Path, Path]) -> None:
    priv_path, _ = key_files
    sk = load_signing_key(priv_path)
    assert isinstance(sk, SigningKey)
    assert len(sk.key_id) == 16
    assert sk.key_id == compute_key_id(sk.public_key)


def test_load_signing_key_refuses_0644(key_files: tuple[Path, Path]) -> None:
    priv_path, _ = key_files
    priv_path.chmod(0o644)
    with pytest.raises(PermissionError, match="0600"):
        load_signing_key(priv_path)


def test_load_signing_key_refuses_0640(key_files: tuple[Path, Path]) -> None:
    """Even group-readable is refused — only owner-rw-only passes."""
    priv_path, _ = key_files
    priv_path.chmod(0o640)
    with pytest.raises(PermissionError, match="0600"):
        load_signing_key(priv_path)


def test_load_signing_key_refuses_public_pem(key_files: tuple[Path, Path]) -> None:
    """Loading what looks like a public-key PEM as a signing key must refuse loud."""
    _, pub_path = key_files
    # The fixture made it 0644; chmod down so we get past the perm check
    # and exercise the content check.
    pub_path.chmod(0o600)
    with pytest.raises(ValueError, match="PUBLIC KEY"):
        load_signing_key(pub_path)


def test_load_public_key_refuses_private_pem(key_files: tuple[Path, Path]) -> None:
    """Loading a private-key PEM as a public key must refuse loud."""
    priv_path, _ = key_files
    with pytest.raises(ValueError, match="PRIVATE KEY"):
        load_public_key(priv_path)


def test_load_public_key_happy_path(key_files: tuple[Path, Path]) -> None:
    _, pub_path = key_files
    pub, key_id = load_public_key(pub_path)
    assert len(key_id) == 16
    # Reloading produces the same key_id (it's a function of the bytes)
    pub_2, key_id_2 = load_public_key(pub_path)
    assert key_id == key_id_2


def test_key_id_derives_from_pubkey(key_files: tuple[Path, Path]) -> None:
    """The signing key's key_id must match the public key's key_id — they're
    derived from the same underlying public bytes."""
    priv_path, pub_path = key_files
    sk = load_signing_key(priv_path)
    _, pub_key_id = load_public_key(pub_path)
    assert sk.key_id == pub_key_id
