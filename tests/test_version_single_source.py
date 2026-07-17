"""Structural: `__version__` is the packaged version, not a second copy of it.

`__version__` is in `__all__` — it is public API, and anything branching on it
is entitled to a true answer. Through 0.2.1 it said "0.1.2" while the
distribution said 0.2.1: two releases stale, because it was a hand-maintained
literal that every release had to remember to touch, and two releases in a row
did not.

The repo already learned this shape. 0.2.1 fixed a report block that named
releases it should not have, and the lesson recorded there was that "keep the
version numbers accurate" is not a rule that holds — the enforceable rule is
the one that removes the chance to get it wrong. Here that means one copy of
the number, in the packaging config, with the attribute derived from it.

So this test does not check that two literals agree. It checks that what the
package exports is what the package *is*.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import chiplog


def _packaged_version() -> str:
    root = Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version: str = pyproject["project"]["version"]
    return version


def test_version_attr_is_the_packaged_version() -> None:
    assert chiplog.__version__ == _packaged_version(), (
        f"chiplog.__version__ is {chiplog.__version__!r} but the distribution "
        f"is {_packaged_version()!r}. __version__ is public API; derive it from "
        f"the packaging config rather than keeping a second copy of the number."
    )
