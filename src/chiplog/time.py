"""Time primitives for audit records.

The signed time block in every record has three fields:

- ts_utc: RFC 3339 with nanosecond precision (wall clock)
- ts_monotonic_ns: process-monotonic nanoseconds (re-ordering detection)
- ts_source: declared trust level for ts_utc

ts_utc and ts_monotonic_ns are both signed. Tampering with either is detectable.
ts_source is advisory — declares to the verifier whether the wall clock came
from the system, an NTP-disciplined clock, or a trusted timestamp authority.
RFC 3161 TSA support is a v0.2 addition.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

# Re-export from schema so callers have one ClockSource, not two.
from chiplog.schema.v1 import ClockSource

__all__ = ["ClockSource", "monotonic_ns", "now_utc_rfc3339_ns"]


def now_utc_rfc3339_ns() -> str:
    """Current UTC time as RFC 3339 with nanosecond precision.

    Format: 2026-06-19T20:00:00.123456789Z
    """
    ns = time.time_ns()
    sec, ns_remainder = divmod(ns, 1_000_000_000)
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{ns_remainder:09d}Z"


def monotonic_ns() -> int:
    """Process-monotonic nanoseconds since an arbitrary epoch.

    Useful for detecting record re-ordering within a process even when the
    wall clock jumps (NTP correction, manual adjustment, leap seconds).
    """
    return time.monotonic_ns()
