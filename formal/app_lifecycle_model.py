#!/usr/bin/env python3
"""Bounded exhaustive model of src/app_state.rs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum, auto


class Phase(Enum):
    LOADING = auto()
    SETUP = auto()
    CREATING = auto()
    LOCKED = auto()
    UNLOCKING = auto()
    UNLOCKED = auto()
    DISPOSED = auto()


class Operation(Enum):
    CREATE = auto()
    UNLOCK = auto()


class Signal(Enum):
    INITIALIZED_EMPTY = auto()
    INITIALIZED_VAULT = auto()
    BEGIN_CREATE = auto()
    BEGIN_UNLOCK = auto()
    SUCCEEDED = auto()
    FAILED = auto()
    LOCK = auto()
    DISPOSE = auto()


Token = tuple[int, Operation]
MAX_GENERATION = 3  # Finite abstraction of Rust's u64::MAX exhaustion guard.


@dataclass(frozen=True)
class State:
    phase: Phase = Phase.LOADING
    generation: int = 0
    active: Token | None = None


def step(state: State, signal: Signal, token: Token | None = None) -> tuple[State, bool, Token | None]:
    if signal is Signal.INITIALIZED_EMPTY:
        return (State(Phase.SETUP, state.generation), True, None) if state.phase is Phase.LOADING else (state, False, None)
    if signal is Signal.INITIALIZED_VAULT:
        return (State(Phase.LOCKED, state.generation), True, None) if state.phase is Phase.LOADING else (state, False, None)
    if signal is Signal.BEGIN_CREATE:
        if state.phase is not Phase.SETUP or state.generation == MAX_GENERATION:
            return state, False, None
        issued = (state.generation + 1, Operation.CREATE)
        return State(Phase.CREATING, state.generation + 1, issued), True, issued
    if signal is Signal.BEGIN_UNLOCK:
        if state.phase is not Phase.LOCKED or state.generation == MAX_GENERATION:
            return state, False, None
        issued = (state.generation + 1, Operation.UNLOCK)
        return State(Phase.UNLOCKING, state.generation + 1, issued), True, issued
    if signal in (Signal.SUCCEEDED, Signal.FAILED):
        if token is None or token != state.active:
            return state, False, None
        expected = Phase.CREATING if token[1] is Operation.CREATE else Phase.UNLOCKING
        if state.phase is not expected:
            return state, False, None
        if signal is Signal.SUCCEEDED:
            return State(Phase.UNLOCKED, state.generation), True, None
        fallback = Phase.SETUP if token[1] is Operation.CREATE else Phase.LOCKED
        return State(fallback, state.generation), True, None
    if signal is Signal.LOCK:
        if state.phase is Phase.DISPOSED:
            return state, False, None
        target = {
            Phase.LOADING: Phase.LOADING,
            Phase.SETUP: Phase.SETUP,
            Phase.CREATING: Phase.LOCKED,
            Phase.LOCKED: Phase.LOCKED,
            Phase.UNLOCKING: Phase.LOCKED,
            Phase.UNLOCKED: Phase.LOCKED,
        }[state.phase]
        return State(target, min(state.generation + 1, MAX_GENERATION)), True, None
    if signal is Signal.DISPOSE:
        if state.phase is Phase.DISPOSED:
            return state, False, None
        return State(Phase.DISPOSED, min(state.generation + 1, MAX_GENERATION)), True, None
    raise AssertionError(f"unmodeled signal: {signal}")


def invariant(previous: State, current: State, signal: Signal, token: Token | None, accepted: bool) -> None:
    assert MAX_GENERATION >= current.generation >= previous.generation >= 0
    assert (current.active is not None) == (current.phase in (Phase.CREATING, Phase.UNLOCKING))
    if current.active is not None:
        assert current.active[0] == current.generation
        assert (current.phase, current.active[1]) in {
            (Phase.CREATING, Operation.CREATE),
            (Phase.UNLOCKING, Operation.UNLOCK),
        }
    if previous.phase is Phase.DISPOSED:
        assert current == previous and not accepted
    if signal is Signal.LOCK and accepted:
        assert current.active is None
        assert current.phase not in (Phase.CREATING, Phase.UNLOCKING, Phase.UNLOCKED)
    if signal in (Signal.SUCCEEDED, Signal.FAILED) and token != previous.active:
        assert not accepted
        if previous.phase is not Phase.UNLOCKED:
            assert current.phase is not Phase.UNLOCKED


def verify(max_depth: int = 10) -> tuple[int, int]:
    queue = deque([(State(), tuple(), 0)])
    seen: set[tuple[State, tuple[Token, ...], int]] = set()
    states: set[State] = set()
    transitions = 0
    while queue:
        state, known, depth = queue.popleft()
        key = (state, known, depth)
        if key in seen:
            continue
        seen.add(key)
        states.add(state)
        if depth == max_depth:
            continue
        stale = (max(0, state.generation - 1), Operation.UNLOCK)
        candidates: tuple[Token | None, ...] = (None, stale, *known[-3:], state.active)
        actions = [(signal, None) for signal in Signal if signal not in (Signal.SUCCEEDED, Signal.FAILED)]
        actions += [(signal, token) for signal in (Signal.SUCCEEDED, Signal.FAILED) for token in candidates]
        for signal, token in actions:
            current, accepted, issued = step(state, signal, token)
            invariant(state, current, signal, token, accepted)
            transitions += 1
            next_known = known if issued is None or issued in known else (*known, issued)
            queue.append((current, next_known, depth + 1))
    return len(states), transitions


if __name__ == "__main__":
    state_count, transition_count = verify()
    print(f"desktop vault lifecycle model passed: {state_count} states, {transition_count} bounded transitions")
