#!/usr/bin/env python3
"""Boundary model for the 3FA desktop vault auto-lock state machine."""

from __future__ import annotations

import argparse
import json
import sys
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 and older in the macOS system runtime.
    import tomli as tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

IDLE_TIMEOUT = 90
MAX_SESSION = 300
USER_ACTIVITY = frozenset({"keypad", "add_account", "scan_qr", "copy_code", "navigate", "sync"})
NON_ACTIVITY = frozenset({"timer_tick", "extend_request", "lock_now"})


@dataclass(frozen=True)
class State:
    now: int = 0
    locked: bool = True
    opened_at: int | None = None
    last_activity: int | None = None


def assert_state(state: State) -> int:
    assert state.now >= 0
    if state.locked:
        assert state.opened_at is None and state.last_activity is None
    else:
        assert state.opened_at is not None and state.last_activity is not None
        assert 0 <= state.opened_at <= state.last_activity <= state.now
    return 3


def lock(state: State) -> State:
    return State(now=state.now, locked=True)


def apply(state: State, event: dict[str, Any]) -> State:
    op = str(event["op"])
    if op == "advance":
        seconds = int(event["seconds"])
        if seconds < 0:
            raise ValueError("time must be monotonic")
        return State(state.now + seconds, state.locked, state.opened_at, state.last_activity)
    if op == "unlock":
        return State(state.now, False, state.now, state.now)
    if op == "lock":
        return lock(state)
    if op == "interaction":
        kind = str(event["kind"])
        if not state.locked and kind in USER_ACTIVITY:
            return State(state.now, False, state.opened_at, state.now)
        if kind not in USER_ACTIVITY and kind not in NON_ACTIVITY:
            raise ValueError(f"unknown interaction kind: {kind}")
        return state
    if op == "poll":
        if state.locked:
            return state
        assert state.opened_at is not None and state.last_activity is not None
        if state.now - state.last_activity >= IDLE_TIMEOUT:
            return lock(state)
        if state.now - state.opened_at >= MAX_SESSION:
            return lock(state)
        return state
    if op == "extend":
        if state.locked:
            return state
        assert state.opened_at is not None
        if state.now - state.opened_at >= MAX_SESSION:
            return lock(state)
        if bool(event.get("factor_satisfied", False)):
            return State(state.now, False, state.opened_at, state.now)
        return state
    raise ValueError(f"unsupported op: {op}")


def replay_events(events: list[dict[str, Any]]) -> tuple[State, list[dict[str, Any]]]:
    state = State()
    trace = [asdict(state)]
    for event in events:
        state = apply(state, event)
        assert_state(state)
        trace.append(asdict(state))
    return state, trace


def load_manifest() -> dict[str, Any]:
    with Path(__file__).with_name("fm.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    assert manifest["schema_version"] == 1
    assert manifest["adapter_protocol"] == "json-stdin/v1"
    assert manifest["constants"]["idle_timeout_seconds"] == IDLE_TIMEOUT
    assert manifest["constants"]["max_session_seconds"] == MAX_SESSION
    assert {item["id"] for item in manifest["invariants"]} == {
        "locked-clears-timers", "poll-enforces-idle", "poll-enforces-hard-cap",
        "non-activity-does-not-extend", "extension-preserves-hard-cap",
    }
    return manifest


def verify() -> dict[str, Any]:
    manifest = load_manifest()
    checks = 0
    boundaries = (0, 1, 88, 89, 90, 91, 179, 299, 300, 301, 360)

    for now in boundaries:
        polled = apply(State(now, False, 0, 0), {"op": "poll"})
        assert polled.locked == (now >= IDLE_TIMEOUT or now >= MAX_SESSION)
        checks += assert_state(polled) + 1

    for activity_at in (0, 1, 30, 80, 89):
        active = apply(State(activity_at, False, 0, 0), {"op": "interaction", "kind": "copy_code"})
        assert active.last_activity == activity_at
        checks += 1
        for elapsed in (0, 1, 89, 90, 91):
            candidate = State(activity_at + elapsed, False, 0, activity_at)
            polled = apply(candidate, {"op": "poll"})
            assert polled.locked == (elapsed >= IDLE_TIMEOUT or candidate.now >= MAX_SESSION)
            checks += assert_state(polled) + 1

    state = State(80, False, 0, 80)
    for kind in sorted(NON_ACTIVITY):
        assert apply(state, {"op": "interaction", "kind": kind}).last_activity == 80
        checks += 1

    for now in (0, 1, 89, 90, 299):
        state = State(now, False, 0, 0)
        assert apply(state, {"op": "extend", "factor_satisfied": False}).last_activity == 0
        granted = apply(state, {"op": "extend", "factor_satisfied": True})
        assert not granted.locked and granted.opened_at == 0 and granted.last_activity == now
        checks += 4

    for now in (300, 301, 360):
        for factor in (False, True):
            after = apply(State(now, False, 0, min(now, 299)), {"op": "extend", "factor_satisfied": factor})
            assert after.locked
            checks += assert_state(after) + 1

    events: list[dict[str, Any]] = [{"op": "unlock"}]
    for _ in range(29):
        events.extend(({"op": "advance", "seconds": 10}, {"op": "interaction", "kind": "sync"}))
    events.extend(({"op": "advance", "seconds": 10}, {"op": "poll"}))
    final, trace = replay_events(events)
    assert final.locked and final.now == MAX_SESSION
    assert final == replay_events(events)[0]
    checks += len(trace) + 2

    return {"status": "ok", "model": manifest["id"], "claim": manifest["claim"], "checks": checks, "boundary_times": len(boundaries), "hard_cap_witness_events": len(events)}


def emit(records: Iterable[dict[str, Any]]) -> None:
    for record in records:
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))


def replay() -> None:
    load_manifest()
    outputs = []
    for line_number, raw in enumerate(sys.stdin, start=1):
        raw = raw.strip()
        if not raw:
            continue
        request = json.loads(raw)
        if request.get("op") != "replay":
            raise ValueError("supported op is replay")
        final, trace = replay_events(list(request.get("events", [])))
        outputs.append({"schema_version": 1, "line": line_number, "final": asdict(final), "trace": trace})
    emit(outputs)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-stdin", action="store_true")
    args = parser.parse_args()
    if args.json_stdin:
        replay()
    else:
        print(json.dumps(verify(), sort_keys=True))


if __name__ == "__main__":
    main()
