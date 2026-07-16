"""Make a value representable in the JCS canonical form — and announce every
substitution.

Structurally a sibling of `redact.py`: a recursive walk over dict / list / tuple
that replaces each JCS-hostile SCALAR with a faithful, self-describing marker and
returns the list of substitutions so the recorder can attest them in
`payload.unrepresentable`.

Why this exists — the failure it closes:

  A tool arg or output can carry a value that RFC 8785 (JCS) cannot canonicalize.
  Two things then happen today, both bad, and both SILENT:

    - An int >= 2**53, a nan/inf: `rfc8785.dumps` RAISES. `sign_record` only
      guarded RecursionError, and every adapter swallows the recorder exception
      — so the tool RAN, no record was written, and the chain did NOT break.
      Silent evidence loss.
    - bytes / set / a non-string dict key: pydantic's `model_dump(mode="json")`
      LAUNDERS them before canonicalization — bytes -> a decoded str (a secret
      now looks like an ordinary value), a set -> a list, nan -> null, and
      {None: 'a', 'None': 'b'} -> {'None': 'b'} with one value silently
      DESTROYED. Canonicalization then succeeds over a value the runtime never
      produced, and signs it.

  Running this pass on the raw Python value BEFORE it enters the model turns both
  classes into an honest, representable, ANNOUNCED marker.

What a marker is — and what it deliberately is NOT:

  {"__agent_audit__": "unrepresentable", "reason": <r>, "py_type": <type>,
   "sha256": <hex of sha256(repr(value))>}

  It records TYPE + HASH only, never a reconstructed value. The original
  magnitude of an out-of-domain int, or the bytes behind a `bytes`, is not
  recoverable in a JCS-signable form and the marker does not pretend it is. It
  proves the value existed and distinguishes two different values by hash.

What this pass does NOT promise — it can itself raise, and that is fine:

  This pass is NOT exception-free, and does not pretend to be. It calls `repr()`
  to digest an unsupported value and `str()` to stringify a non-string dict key,
  and a hostile object can make EITHER raise (a `__repr__` / `__str__` that
  throws). It also does NOT make canonicalization incapable of raising: it
  handles the four enumerated scalar kinds and non-string keys, but other
  JCS-hostile inputs remain possible (a str containing an unpaired UTF-16
  surrogate cannot be encoded to UTF-8, and `model_dump` does not launder it).

  The honest guarantee is NOT "never raises". It is that the recorder runs this
  pass INSIDE its construction guard (see emit.py / RecordBuildError): any
  exception from here poisons the chain head and raises a typed error, so a
  failure is caught, made visible as a chain break, and reported — never silent.
"""

from __future__ import annotations

import hashlib
from typing import Any

from agent_audit.schema.v1 import UnrepresentableEntry, UnrepresentableReason

# Marker shape. Kept as module constants so tests and readers share one source.
MARKER_KEY = "__agent_audit__"
MARKER_TAG = "unrepresentable"

# JCS canonicalizes numbers as IEEE-754 doubles. Integers with abs value >= 2**53
# lose precision as doubles, so rfc8785 refuses them outright (IntegerDomainError).
JCS_SAFE_INT_BOUND = 2**53

__all__ = [
    "JCS_SAFE_INT_BOUND",
    "MARKER_KEY",
    "MARKER_TAG",
    "UnrepresentableEntry",
    "UnrepresentableReason",
    "normalize_for_canonical",
]


def _digest(value: object) -> str:
    return hashlib.sha256(repr(value).encode("utf-8")).hexdigest()


def _marker(reason: UnrepresentableReason, py_type: str, digest: str) -> dict[str, str]:
    return {
        MARKER_KEY: MARKER_TAG,
        "reason": reason.value,
        "py_type": py_type,
        "sha256": digest,
    }


def _substitute(
    value: object, reason: UnrepresentableReason, path: str
) -> tuple[dict[str, str], list[UnrepresentableEntry]]:
    py_type = type(value).__name__
    digest = _digest(value)
    entry = UnrepresentableEntry(
        path=path, reason=reason, py_type=py_type, sha256=digest
    )
    return _marker(reason, py_type, digest), [entry]


def normalize_for_canonical(
    value: Any, path: str = "$"
) -> tuple[Any, list[UnrepresentableEntry]]:
    """Return (representable_value, announced_substitutions).

    Walks dict / list / tuple. Replaces each JCS-hostile scalar with a marker and
    records it. JSON-native values pass through unchanged with no entries.

    Path uses the same JSONPath-shaped notation as redact.py:
    `$.input.args.count`, `$.output.body[3]`.
    """
    # None, bool, and str are JSON-native. bool is checked implicitly here BEFORE
    # int below — `isinstance(True, int)` is True, and a boolean is not an
    # out-of-domain integer. (A str with an unpaired surrogate is still
    # JCS-hostile; that rare case is left to the recorder's loud defense-in-depth
    # path rather than guessed at here — see the module docstring.)
    if value is None or isinstance(value, bool) or isinstance(value, str):
        return value, []

    if isinstance(value, int):
        if abs(value) >= JCS_SAFE_INT_BOUND:
            return _substitute(
                value, UnrepresentableReason.INTEGER_OUT_OF_JCS_DOMAIN, path
            )
        return value, []

    if isinstance(value, float):
        # nan, +inf, -inf are all not-finite and not representable in JCS.
        if value != value or value in (float("inf"), float("-inf")):
            return _substitute(value, UnrepresentableReason.FLOAT_NOT_FINITE, path)
        return value, []

    if isinstance(value, dict):
        return _normalize_dict(value, path)

    if isinstance(value, (list, tuple)):
        # tuple becomes list — JSON has no tuple — but only AFTER its items are
        # walked, so a hostile scalar nested in a tuple is still caught. (redact
        # never recursed into tuples; that is the hole this closes.)
        out_list: list[Any] = []
        entries: list[UnrepresentableEntry] = []
        for i, item in enumerate(value):
            norm_item, item_entries = normalize_for_canonical(item, f"{path}[{i}]")
            out_list.append(norm_item)
            entries.extend(item_entries)
        return out_list, entries

    # Everything else — bytes, bytearray, set, frozenset, complex, a custom
    # object — is an unsupported scalar. model_dump would launder some of these
    # into innocuous-looking JSON (bytes -> str, set -> list); the marker states
    # what it actually was.
    return _substitute(value, UnrepresentableReason.UNSUPPORTED_TYPE, path)


def _normalize_dict(
    value: dict[Any, Any], path: str
) -> tuple[dict[str, Any], list[UnrepresentableEntry]]:
    """Normalize a dict, closing the non-string-key hole without silent merges.

    JCS object keys MUST be strings. A non-string key is stringified and the
    substitution announced. The trap is COLLISION: `str(None) == "None"`, so
    `{None: 'a', 'None': 'b'}` would collapse to one entry and destroy a value
    (which is exactly what model_dump does today). To prevent that:

      1. String keys are assigned first and keep their natural slot — a
         legitimate string key is never disturbed.
      2. Non-string keys are stringified afterwards; if a stringified key would
         land on an already-taken slot it is disambiguated to a fresh unique key,
         so no value is ever overwritten, and the substitution is announced.
    """
    result: dict[str, Any] = {}
    entries: list[UnrepresentableEntry] = []

    str_items = [(k, v) for k, v in value.items() if isinstance(k, str)]
    nonstr_items = [(k, v) for k, v in value.items() if not isinstance(k, str)]

    for k, v in str_items:
        norm_v, v_entries = normalize_for_canonical(v, f"{path}.{k}")
        result[k] = norm_v
        entries.extend(v_entries)

    for k, v in nonstr_items:
        base = str(k)
        skey = base
        dup = 1
        while skey in result:
            # Deterministic, JCS-safe, and visibly synthetic so a reader can tell
            # this key was disambiguated from a collision rather than authored.
            skey = f"{base}::__agent_audit_dupkey_{dup}__"
            dup += 1

        entries.append(
            UnrepresentableEntry(
                path=f"{path}.{skey}",
                reason=UnrepresentableReason.NON_STRING_DICT_KEY,
                py_type=type(k).__name__,
                sha256=_digest(k),
            )
        )
        norm_v, v_entries = normalize_for_canonical(v, f"{path}.{skey}")
        result[skey] = norm_v
        entries.extend(v_entries)

    return result, entries
