"""The control-flow predicate is public API — hosts need it to stay honest.

chiplog forbids asserting an outcome by silence, so a host instrumenting
LangGraph nodes itself must separate a node that *parked* on a control-flow
signal from one that *crashed*. Park a node at a human gate and record it as a
failure, and you have signed a false failure — which this library treats as
exactly as dishonest as a false success. The predicate is therefore
load-bearing for record honesty, not a convenience.

It shipped underscore-prefixed and out of `__all__`, which left a host two
options: import a private name, or hand-roll the check. bosun took the private
import and was right to. A hand-rolled `isinstance(exc, (GraphInterrupt,
ParentCommand))` diverges *silently* the moment the runtime widens its
control-flow boundary — it already misses `GraphDrained` today. The delegating
predicate cannot drift, because it asks the runtime for the boundary instead of
restating it.

So the tests below pin two things: the name is public, and it recognises every
`GraphBubbleUp` subclass the installed runtime actually defines — enumerated
from the class tree rather than listed here, because a list here would be the
same brittle restatement the predicate exists to avoid.
"""

from __future__ import annotations

import pytest
from langgraph.errors import GraphBubbleUp

from chiplog.adapters import langgraph


def _all_signal_types() -> list[type[BaseException]]:
    """Every GraphBubbleUp subclass the installed runtime defines, transitively."""
    seen: list[type[BaseException]] = []

    def walk(cls: type[BaseException]) -> None:
        seen.append(cls)
        for sub in cls.__subclasses__():
            walk(sub)

    walk(GraphBubbleUp)
    return seen


def test_predicate_is_public_api() -> None:
    assert "is_control_flow_signal" in langgraph.__all__, (
        "the predicate is what a host needs to avoid signing false failures; "
        "leaving it private forces a private import or a silently-drifting copy"
    )


def test_predicate_recognises_every_runtime_control_flow_signal() -> None:
    pred = langgraph.is_control_flow_signal
    types = _all_signal_types()
    assert len(types) > 1, "expected the runtime to define GraphBubbleUp subclasses"
    for cls in types:
        # __new__, not __init__: isinstance is the whole question, and these
        # exceptions take runtime-specific constructor arguments.
        assert pred(cls.__new__(cls)), f"{cls.__name__} is a control-flow signal"


@pytest.mark.parametrize("exc", [ValueError("boom"), RuntimeError(), KeyError("k")])
def test_ordinary_exception_is_not_a_control_flow_signal(exc: BaseException) -> None:
    assert not langgraph.is_control_flow_signal(exc)


def test_private_name_still_resolves_for_hosts_already_importing_it() -> None:
    # bosun imports the underscore name today and pins chiplog >=0.2,<0.3.
    # Removing it inside that range would break a resolve, so it stays until 0.3.
    assert langgraph._is_control_flow_signal is langgraph.is_control_flow_signal
