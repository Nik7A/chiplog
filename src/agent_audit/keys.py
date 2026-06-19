"""Ed25519 key loading with audit-grade safety checks.

Refuses to load:
- Private key files with mode != 0600 (or owner != current uid)
- A public-key PEM via `load_signing_key` (loud ValueError, not silent confusion)
- A private-key PEM via `load_public_key` (same)
- Any non-Ed25519 key material

These checks are intentional foot-blockers, not paranoia. Audit-grade keys that
live next to the agent (the v0.1 limitation declared in SCOPE_STATEMENT.md) are
already a known weakness; refusing 0644 keys is the bare minimum to surface
an accidental mistake before it produces unsigned-evidence theater.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def compute_key_id(public_key: Ed25519PublicKey) -> str:
    """Per SIGNING.md §5 — first 16 hex chars of SHA-256(public_key_raw_bytes).

    The raw form is 32 bytes; the SHA-256 gives 64 hex chars; we truncate to 16.
    Collisions are theoretically possible but irrelevant in practice for the
    per-verifier scope this maps to.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


@dataclass(frozen=True)
class SigningKey:
    """A loaded Ed25519 signing key with its derived key_id and public key."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    key_id: str


def _enforce_private_perms(path: Path) -> None:
    """Refuse to use a private key file with insecure perms or wrong owner."""
    st = path.stat()

    if st.st_uid != os.getuid():
        raise PermissionError(
            f"refusing to load {path}: file is owned by uid={st.st_uid}, "
            f"current uid={os.getuid()}"
        )

    mode = stat.S_IMODE(st.st_mode)
    if mode != 0o600:
        raise PermissionError(
            f"refusing to load {path}: mode {oct(mode)} is not 0600. "
            f"Run: chmod 0600 {path}"
        )


def load_signing_key(path: str | Path) -> SigningKey:
    """Load an Ed25519 private key from a PEM file.

    Refuses files with mode != 0600. Refuses public-key PEMs with a clear
    message rather than letting the cryptography library raise a confusing
    error mid-parse.
    """
    p = Path(path).expanduser()
    _enforce_private_perms(p)

    data = p.read_bytes()

    if b"PUBLIC KEY" in data and b"PRIVATE KEY" not in data:
        raise ValueError(
            f"refusing to load {p}: file looks like a public-key PEM "
            "(contains 'PUBLIC KEY' but not 'PRIVATE KEY'). "
            "Use load_public_key for those."
        )

    private_key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError(
            f"key in {p} is not Ed25519 — got {type(private_key).__name__}"
        )

    public_key = private_key.public_key()
    return SigningKey(
        private_key=private_key,
        public_key=public_key,
        key_id=compute_key_id(public_key),
    )


def load_public_key(path: str | Path) -> tuple[Ed25519PublicKey, str]:
    """Load an Ed25519 public key from a PEM file. Returns (public_key, key_id).

    Refuses private-key PEMs to prevent foot-guns where someone accidentally
    publishes a public key file that's actually a private key.
    """
    p = Path(path).expanduser()
    data = p.read_bytes()

    if b"PRIVATE KEY" in data:
        raise ValueError(
            f"refusing to load {p} as a public key: file contains 'PRIVATE KEY'. "
            "Use load_signing_key for private keys; export the public key separately."
        )

    public_key = serialization.load_pem_public_key(data)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError(
            f"key in {p} is not Ed25519 — got {type(public_key).__name__}"
        )

    return public_key, compute_key_id(public_key)


__all__ = ["SigningKey", "compute_key_id", "load_public_key", "load_signing_key"]
