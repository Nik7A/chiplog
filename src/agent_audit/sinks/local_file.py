"""LocalFileSink — daily-rotated JSONL with per-write fsync + manifest.

Each write:
  1. Append the JSON-encoded record + newline to today's `audit-YYYY-MM-DD.jsonl`.
  2. fsync (F_FULLFSYNC on macOS for true platter durability).
  3. Update in-memory manifest: chain head, file checksum, pubkey info.
  4. Atomically write the manifest to `manifest.json`.

Rolling SHA-256 per daily file avoids O(N²) re-hashing on large logs.

DiskFullError is raised on `ENOSPC` — the agent halts loudly rather than
silently dropping. v0.1 has no buffering: each write either fully persists
or raises.

The manifest is NOT load-bearing for chain integrity (the JSONL files are
the source of truth). It exists so the Claude Code hook handler — which
runs as a fresh process per tool call — can recover the chain head without
walking every JSONL file on every invocation.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent_audit.integrity import compute_chain_link
from agent_audit.manifest import ChainState, FileChecksum, Manifest
from agent_audit.sinks.base import DiskFullError, SinkError

_F_FULLFSYNC = 51  # macOS-specific fcntl constant


def _fsync_fd(fd: int) -> None:
    """Best-effort F_FULLFSYNC on macOS, regular fsync elsewhere.

    Default fsync on Darwin only flushes to disk write cache, not the actual
    platter — F_FULLFSYNC blocks until the data is durably on disk.
    """
    if platform.system() == "Darwin":
        try:
            import fcntl

            fcntl.fcntl(fd, _F_FULLFSYNC)
            return
        except (OSError, AttributeError):
            pass
    os.fsync(fd)


class _DailyFileState:
    """In-memory rolling SHA-256 for one daily JSONL file.

    On init, if the file already exists (e.g. previous process wrote to it
    today), seed the hash context from existing contents. After that, the
    hash is updated incrementally on each append.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._hash_ctx = hashlib.sha256()
        if path.exists():
            with open(path, "rb") as f:
                self._hash_ctx.update(f.read())

    def append_line(self, line_bytes: bytes) -> None:
        """Append + fsync. Raises DiskFullError on ENOSPC."""
        try:
            with open(self.path, "ab") as f:
                f.write(line_bytes)
                f.flush()
                _fsync_fd(f.fileno())
        except OSError as e:
            if e.errno == errno.ENOSPC:
                raise DiskFullError(
                    f"out of disk space writing to {self.path}"
                ) from e
            raise SinkError(f"failed to write to {self.path}: {e}") from e
        self._hash_ctx.update(line_bytes)

    def sha256(self) -> str:
        return self._hash_ctx.copy().hexdigest()


class LocalFileSink:
    """Daily-rotated JSONL audit sink.

    Args:
        dir: Output directory. Created if absent. Holds the JSONL files +
            `manifest.json`.
        pubkey_pem: Public key PEM bytes recorded in the manifest so an
            offline verifier can run `agent-audit verify` with no other
            inputs. Optional but strongly recommended.
        redaction_disabled: Record in the manifest that the recorder is
            using `RedactionConfig(disable=True)`. Forced visible by the
            self-audit checklist: redaction MUST NEVER silently be off.
        clock: Callable returning the current UTC datetime. Injected for
            tests that need to span daily rotation. Defaults to real time.
    """

    def __init__(
        self,
        dir: str | Path,
        pubkey_pem: bytes | str | None = None,
        redaction_disabled: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.dir = Path(dir).expanduser()
        self.dir.mkdir(parents=True, exist_ok=True)

        self._manifest_path = self.dir / "manifest.json"
        self._manifest = Manifest.load_or_create(self._manifest_path)
        self._manifest_dirty = False

        if pubkey_pem is not None:
            pem_str = (
                pubkey_pem.decode("ascii")
                if isinstance(pubkey_pem, bytes)
                else pubkey_pem
            )
            self._manifest.pubkey_pem = pem_str
            self._manifest_dirty = True

        if redaction_disabled and not self._manifest.redaction_disabled:
            self._manifest.redaction_disabled = True
            self._manifest_dirty = True

        if self._manifest_dirty:
            self._manifest.save_atomic(self._manifest_path)
            self._manifest_dirty = False

        self._daily_files: dict[str, _DailyFileState] = {}
        self._clock = clock or (lambda: datetime.now(tz=timezone.utc))
        self._closed = False

    @property
    def manifest(self) -> Manifest:
        """Read-only access to the in-memory manifest (tests + introspection)."""
        return self._manifest

    def _current_filename(self) -> str:
        return f"audit-{self._clock().strftime('%Y-%m-%d')}.jsonl"

    def _get_daily(self, filename: str) -> _DailyFileState:
        state = self._daily_files.get(filename)
        if state is None:
            state = _DailyFileState(self.dir / filename)
            self._daily_files[filename] = state
        return state

    async def write(self, record: dict[str, Any]) -> None:
        if self._closed:
            raise SinkError("LocalFileSink is closed — cannot write")

        filename = self._current_filename()
        daily = self._get_daily(filename)

        line = json.dumps(record, sort_keys=False, ensure_ascii=False) + "\n"
        daily.append_line(line.encode("utf-8"))

        self._update_manifest_in_memory(record, filename, daily.sha256())

        try:
            self._manifest.save_atomic(self._manifest_path)
        except OSError as e:
            if e.errno == errno.ENOSPC:
                raise DiskFullError(
                    "out of disk space writing manifest"
                ) from e
            raise SinkError(f"failed to flush manifest: {e}") from e

    def _update_manifest_in_memory(
        self, record: dict[str, Any], filename: str, file_sha256: str
    ) -> None:
        env = record["envelope"]
        chain_id = env["chain_id"]
        record_id = env["record_id"]

        # Per-chain head
        chain = self._manifest.chains.get(chain_id)
        if chain is None:
            chain = ChainState(chain_id=chain_id)
            self._manifest.chains[chain_id] = chain

        link = compute_chain_link(record)
        if chain.record_count == 0:
            chain.genesis_hash = link
            chain.first_record_id = record_id
        chain.head_hash = link
        chain.last_record_id = record_id
        chain.record_count += 1

        # Per-file
        file_csum = self._manifest.files.get(filename)
        if file_csum is None:
            file_csum = FileChecksum(
                sha256=file_sha256,
                record_count=1,
                first_record_id=record_id,
                last_record_id=record_id,
            )
            self._manifest.files[filename] = file_csum
        else:
            file_csum.sha256 = file_sha256
            file_csum.record_count += 1
            file_csum.last_record_id = record_id

        # Pubkey id (cheap to set; overwritten if subsequent records use a
        # different key — that's a v0.2 multi-key story).
        if self._manifest.pubkey_id is None:
            self._manifest.pubkey_id = env["key_id"]

    async def flush(self) -> None:
        # Per-write fsync already gives us "all records are durable on disk
        # by the time write() returns" — flush is a no-op for v0.1.
        return

    async def close(self) -> None:
        self._closed = True


__all__ = ["LocalFileSink"]
