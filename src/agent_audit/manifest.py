"""Manifest sidecar for LocalFileSink.

Tracks per-chain head state and per-file SHA-256 checksums so a verifier
(and the Claude Code hook handler reloading state across invocations)
doesn't have to re-walk every JSONL file to know where to resume.

Important: the manifest is NOT the source of chain truth. The JSONL files
are. v0.1 trusts the manifest because the LocalFileSink updates it atomically
on every write. v0.2 will add a "rebuild manifest from JSONL" recovery path
for the case where the manifest is deleted, corrupted, or out-of-sync.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA_VERSION = "manifest.v1.0"


@dataclass
class ChainState:
    """Per-chain head state.

    Persists across processes: the Claude Code hook handler reloads this on
    each invocation so the next record's prev_hash matches the prior one,
    even though the hook process itself is brand new.
    """

    chain_id: str
    head_hash: str | None = None
    genesis_hash: str | None = None
    record_count: int = 0
    first_record_id: str | None = None
    last_record_id: str | None = None


@dataclass
class FileChecksum:
    """SHA-256 of one daily JSONL file, updated rolling on each write."""

    sha256: str
    record_count: int = 0
    first_record_id: str | None = None
    last_record_id: str | None = None


@dataclass
class Manifest:
    """Persistent state for LocalFileSink."""

    schema_version: str = MANIFEST_SCHEMA_VERSION
    pubkey_id: str | None = None
    pubkey_pem: str | None = None
    chains: dict[str, ChainState] = field(default_factory=dict)
    files: dict[str, FileChecksum] = field(default_factory=dict)
    # Self-audit checklist item #12: a disabled redactor must surface in the
    # manifest so audit-time inspection catches it. NEVER silently off.
    redaction_disabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "pubkey_id": self.pubkey_id,
            "pubkey_pem": self.pubkey_pem,
            "chains": {k: asdict(v) for k, v in self.chains.items()},
            "files": {k: asdict(v) for k, v in self.files.items()},
            "redaction_disabled": self.redaction_disabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Manifest:
        schema_version = data.get("schema_version", MANIFEST_SCHEMA_VERSION)
        if schema_version != MANIFEST_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported manifest schema_version {schema_version!r}; "
                f"this build supports {MANIFEST_SCHEMA_VERSION!r}"
            )
        return cls(
            schema_version=schema_version,
            pubkey_id=data.get("pubkey_id"),
            pubkey_pem=data.get("pubkey_pem"),
            chains={
                k: ChainState(**v) for k, v in data.get("chains", {}).items()
            },
            files={
                k: FileChecksum(**v) for k, v in data.get("files", {}).items()
            },
            redaction_disabled=bool(data.get("redaction_disabled", False)),
        )

    @classmethod
    def load_or_create(cls, path: Path) -> Manifest:
        """Load from disk if it exists; otherwise return a fresh instance."""
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                raise ValueError(
                    f"failed to load manifest {path}: {e}. "
                    "Delete the manifest and re-run if you intentionally want "
                    "a fresh chain — but be aware this loses chain continuity."
                ) from e
            return cls.from_dict(data)
        return cls()

    def save_atomic(self, path: Path) -> None:
        """Write manifest atomically: write .tmp, fsync, rename, fsync dir.

        On POSIX, rename is atomic — if the process is killed mid-rename, the
        target either still has the old content or has the new content, never
        a partial write.
        """
        tmp = path.with_suffix(path.suffix + ".tmp")
        text = json.dumps(self.to_dict(), indent=2, sort_keys=True)

        fd = os.open(
            str(tmp),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        os.replace(tmp, path)

        # fsync the directory so the rename is durable.
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


__all__ = [
    "MANIFEST_SCHEMA_VERSION",
    "ChainState",
    "FileChecksum",
    "Manifest",
]
