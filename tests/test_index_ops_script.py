"""Long-running Ops indexer loop tests."""

from __future__ import annotations

import asyncio

import pytest

from scripts import index_ops


def test_indexer_defaults_to_one_shot_and_bounds_loop_configuration() -> None:
    args = index_ops.parse_args([])
    assert args.interval_seconds == 0
    assert args.max_retries == 3
    assert index_ops.parse_args(["--interval-seconds", "1800"]).interval_seconds == 1800
    with pytest.raises(SystemExit):
        index_ops.parse_args(["--interval-seconds", "299"])
    with pytest.raises(SystemExit):
        index_ops.parse_args(["--max-retries", "11"])


def test_retry_schedule_is_bounded() -> None:
    assert index_ops.retry_delays(0) == ()
    assert index_ops.retry_delays(5) == (5, 10, 20, 40, 60)


def test_one_shot_propagates_failure_and_returns_published_count() -> None:
    stop = asyncio.Event()

    async def success() -> int:
        return 7

    assert asyncio.run(index_ops.run_loop(interval_seconds=0, max_retries=3, stop=stop, run_once=success)) == 7

    async def failure() -> int:
        raise RuntimeError("failed")

    with pytest.raises(RuntimeError, match="failed"):
        asyncio.run(index_ops.run_loop(interval_seconds=0, max_retries=3, stop=asyncio.Event(), run_once=failure))


def test_continuous_loop_retries_then_stops_signal_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    stop = asyncio.Event()
    attempts = 0

    async def flaky() -> int:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError("transient")
        stop.set()
        return 4

    async def immediate_wait(event: asyncio.Event, _seconds: float) -> bool:
        return event.is_set()

    monkeypatch.setattr(index_ops, "_wait_or_stop", immediate_wait)
    count = asyncio.run(
        index_ops.run_loop(
            interval_seconds=300,
            max_retries=3,
            stop=stop,
            run_once=flaky,
        )
    )

    assert attempts == 3
    assert count == 4
