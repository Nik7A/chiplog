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
import tempfile
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from chiplog.keys import load_public_key_from_pem

MANIFEST_SCHEMA_VERSION = "manifest.v1.0"


class RedactionState(str, Enum):
    """The recorder-attested redaction state of a log directory.

    Tri-state, and that matters: the old boolean `redaction_disabled` could not
    tell "someone confirmed redaction was ON" apart from "nobody wired the flag,
    so it defaulted to false" — and reading the latter as "redaction was enabled"
    is exactly the affirmative lie this wave removes.

      - UNKNOWN: no recorder ever attested a state here. A pre-v1.2 manifest (no
        `redaction_state` field) reads UNKNOWN, NEVER "enabled". Absence is not
        evidence of redaction.
      - ENABLED: a recorder wrote at least one record with redaction ON, and none
        with it OFF.
      - DISABLED: at least one record was written with redaction OFF. This LATCHES
        (see `latch`): once true it never downgrades, because a single cleartext
        record means the log is not a fully-redacted artifact and no later
        enabled recorder can make that untrue.

    Ordering of severity (monotonic latch): UNKNOWN < ENABLED < DISABLED.
    """

    UNKNOWN = "unknown"
    ENABLED = "enabled"
    DISABLED = "disabled"

    def latch(self, observed_disabled: bool) -> RedactionState:
        """Fold one record's observed redaction state in, monotonically.

        DISABLED is absorbing. From UNKNOWN/ENABLED, an enabled write reaches
        ENABLED and a disabled write reaches DISABLED. The state only ever moves
        UNKNOWN -> ENABLED -> DISABLED, never back.
        """
        if self is RedactionState.DISABLED or observed_disabled:
            return RedactionState.DISABLED
        return RedactionState.ENABLED


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
    # The most recently declared key. Both track the CURRENT key and are
    # overwritten on rotation — which is safe only because `pubkeys` below keeps
    # every key that ever signed here. They exist for verifiers that predate
    # `pubkeys`; `pubkeys` is the authoritative set.
    pubkey_id: str | None = None
    pubkey_pem: str | None = None
    # key_id -> public key PEM, for EVERY key that has declared itself to this
    # directory. Append-only: rotation adds, it never replaces.
    #
    # This was one mutable `pubkey_pem`, and rotation overwrote it. The previous
    # key vanished from the only place it was stored and its records became
    # permanently unverifiable — 330 of them, once, on real evidence. A public
    # key is not secret, so single-copy storage bought nothing and cost
    # everything. Every record's envelope carries its own `key_id`, so the
    # verifier only ever needed somewhere to look the id up.
    pubkeys: dict[str, str] = field(default_factory=dict)
    chains: dict[str, ChainState] = field(default_factory=dict)
    files: dict[str, FileChecksum] = field(default_factory=dict)
    # Self-audit checklist item #12: the redaction state must surface in the
    # manifest so audit-time inspection catches a disabled redactor. Tri-state
    # (see RedactionState): DISABLED latches, and absence reads UNKNOWN — NEVER
    # a silent affirmative "enabled". The recorder DRIVES this per record via
    # LocalFileSink.note_redaction_disabled; it is no longer a disconnected,
    # manually-set constructor flag (that disconnection was the leak).
    redaction_state: RedactionState = RedactionState.UNKNOWN

    @property
    def redaction_disabled(self) -> bool:
        """Backward-compatible boolean view: True only when DISABLED is latched.

        UNKNOWN and ENABLED both read False here, but they are NOT the same — a
        reader that must distinguish "confirmed enabled" from "never attested"
        reads `redaction_state`. This accessor exists so older callers keep
        working, not as the honest surface.
        """
        return self.redaction_state is RedactionState.DISABLED

    def note_redaction_disabled(self, observed_disabled: bool) -> None:
        """Fold one record's observed redaction state into the latch."""
        self.redaction_state = self.redaction_state.latch(observed_disabled)

    def declare_pubkey(self, pem: str) -> str:
        """Record a public key as having signed here. Returns its key_id.

        Appends. A key already known is not re-added, and no key is ever
        replaced: the previous one stays verifiable forever, which is the whole
        point of the map. `pubkey_id` / `pubkey_pem` follow the current key for
        readers that predate `pubkeys`.
        """
        _, key_id = load_public_key_from_pem(pem)
        self.pubkeys.setdefault(key_id, pem)
        self.pubkey_id = key_id
        self.pubkey_pem = pem
        return key_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "pubkey_id": self.pubkey_id,
            "pubkey_pem": self.pubkey_pem,
            "pubkeys": dict(self.pubkeys),
            "chains": {k: asdict(v) for k, v in self.chains.items()},
            "files": {k: asdict(v) for k, v in self.files.items()},
            "redaction_state": self.redaction_state.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Manifest:
        schema_version = data.get("schema_version", MANIFEST_SCHEMA_VERSION)
        if schema_version != MANIFEST_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported manifest schema_version {schema_version!r}; "
                f"this build supports {MANIFEST_SCHEMA_VERSION!r}"
            )
        # Migrate a manifest written before `pubkeys` existed: its single
        # `pubkey_pem` is a key that really did sign here, so it belongs in the
        # map. Its id is derived from the PEM itself rather than read from
        # `pubkey_id`, which was set-once and may name a different key entirely.
        # Only keys still present can be recovered — a PEM already overwritten
        # by a rotation is gone, and nothing here can bring it back.
        pubkeys: dict[str, str] = dict(data.get("pubkeys", {}))
        legacy_pem = data.get("pubkey_pem")
        if legacy_pem and not pubkeys:
            try:
                _, legacy_id = load_public_key_from_pem(legacy_pem)
            except Exception:
                # An unreadable PEM is the verifier's problem to report, not
                # ours to raise on: refusing to load the manifest here would
                # take the chain heads down with it.
                pass
            else:
                pubkeys[legacy_id] = legacy_pem
        return cls(
            schema_version=schema_version,
            pubkey_id=data.get("pubkey_id"),
            pubkey_pem=legacy_pem,
            pubkeys=pubkeys,
            chains={
                k: ChainState(**v) for k, v in data.get("chains", {}).items()
            },
            files={
                k: FileChecksum(**v) for k, v in data.get("files", {}).items()
            },
            redaction_state=cls._read_redaction_state(data),
        )

    @staticmethod
    def _read_redaction_state(data: dict[str, Any]) -> RedactionState:
        """Read the redaction state, honestly bridging the pre-v1.2 boolean.

        - A v1.2 manifest carries `redaction_state` — use it verbatim.
        - A pre-v1.2 manifest carries only the old `redaction_disabled` bool.
          `true` still means DISABLED (that WAS observed). But `false` on an old
          manifest is the disconnected default — it does NOT attest ENABLED, so
          it reads UNKNOWN. Absence of either field reads UNKNOWN.
        """
        raw = data.get("redaction_state")
        if isinstance(raw, str):
            try:
                return RedactionState(raw)
            except ValueError:
                return RedactionState.UNKNOWN
        if data.get("redaction_disabled") is True:
            return RedactionState.DISABLED
        return RedactionState.UNKNOWN

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
        """Write manifest atomically: write a private temp file, fsync, rename.

        On POSIX, rename is atomic — if the process is killed mid-rename, the
        target either still has the old content or has the new content, never
        a partial write.

        The temp file MUST be unique per writer, which is why this uses
        `mkstemp` rather than a derived name like `manifest.json.tmp`. With a
        fixed temp path, two concurrent writers share one temp file: A truncates
        it while B is still writing (so A's `os.replace` can publish B's
        half-written bytes), and whichever writer replaces first removes the temp
        file out from under the other, whose own `os.replace` then raises
        FileNotFoundError. In LocalFileSink that surfaces as a SinkError — which
        is how a manifest race turns into a crashed tool call. `mkstemp` also
        creates with O_EXCL, so it cannot collide with an existing file.

        Uniqueness makes the *temp file* private to one writer; it does not order
        the *renames*. Concurrent writers still race to publish and last-writer-
        wins, which is fine here — every writer publishes a complete, self-
        consistent manifest, and LocalFileSink serialises its own writes anyway
        so the last one to land is the newest. What is no longer possible is a
        torn manifest or a spurious failure.
        """
        text = json.dumps(self.to_dict(), indent=2, sort_keys=True)

        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=f"{path.name}.", suffix=".tmp"
        )
        tmp = Path(tmp_name)
        try:
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, text.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)

            os.replace(tmp, path)
        except BaseException:
            # Never leave a temp file behind on a failed save — a directory
            # slowly filling with `manifest.json.*.tmp` is its own incident, and
            # ENOSPC (the error most likely to land here) would be made worse by
            # the debris of every previous attempt.
            tmp.unlink(missing_ok=True)
            raise

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
    "RedactionState",
]
