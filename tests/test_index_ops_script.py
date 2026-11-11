"""Long-running Ops indexer loop tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx
import pytest
from openai import AsyncOpenAI

from dash import ops_indexer
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


@pytest.mark.parametrize(
    ("status", "error_type", "interval"),
    [
        (401, "invalid_request_error", 300),
        (403, None, 300),
        (429, "insufficient_quota", 300),
        (429, "insufficient_quota", 1800),
    ],
)
def test_quota_failure_is_not_retried_within_cycle(
    monkeypatch: pytest.MonkeyPatch, status: int, error_type: str | None, interval: int
) -> None:
    now = 0.0
    attempts: list[float] = []
    waits: list[float] = []

    def provider(request: httpx.Request) -> httpx.Response:
        attempts.append(now)
        return httpx.Response(status, json={"error": {"type": error_type, "code": "provider_code"}})

    async def wait(event: asyncio.Event, seconds: float) -> bool:
        nonlocal now
        waits.append(seconds)
        now += seconds
        return len(waits) == 2

    document = ops_indexer.build_learning_document(
        {"id": "learning_1", "kind": "test", "lifecycle_status": "verified", "updated_at": datetime.now(UTC)}
    )

    async def scenario() -> int:
        async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as http_client:

            def client(**kwargs: object) -> AsyncOpenAI:
                return AsyncOpenAI(http_client=http_client, **kwargs)  # type: ignore[arg-type]

            monkeypatch.setattr(ops_indexer, "AsyncOpenAI", client)

            async def run_once() -> int:
                return len(await ops_indexer.embed_documents([document]))

            return await index_ops.run_loop(
                interval_seconds=interval, max_retries=3, stop=asyncio.Event(), run_once=run_once
            )

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(index_ops, "monotonic", lambda: now)
    monkeypatch.setattr(index_ops, "_wait_or_stop", wait)

    assert asyncio.run(scenario()) == 0
    cooldown = max(900, interval)
    assert attempts == [0, cooldown]
    assert waits == [cooldown, cooldown]


@pytest.mark.parametrize("status", [429, 500])
def test_transient_failure_keeps_retries(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    now = 0.0
    attempts: list[float] = []
    waits: list[float] = []

    def provider(request: httpx.Request) -> httpx.Response:
        attempts.append(now)
        return httpx.Response(status, json={"error": {"type": "rate_limit_exceeded"}})

    async def wait(event: asyncio.Event, seconds: float) -> bool:
        nonlocal now
        waits.append(seconds)
        now += seconds
        return seconds > 20

    document = ops_indexer.build_learning_document(
        {"id": "learning_1", "kind": "test", "lifecycle_status": "verified", "updated_at": datetime.now(UTC)}
    )

    async def scenario() -> int:
        async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as http_client:

            def client(**kwargs: object) -> AsyncOpenAI:
                return AsyncOpenAI(http_client=http_client, **kwargs)  # type: ignore[arg-type]

            monkeypatch.setattr(ops_indexer, "AsyncOpenAI", client)

            async def run_once() -> int:
                return len(await ops_indexer.embed_documents([document]))

            return await index_ops.run_loop(
                interval_seconds=300, max_retries=3, stop=asyncio.Event(), run_once=run_once
            )

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(index_ops, "monotonic", lambda: now)
    monkeypatch.setattr(index_ops, "_wait_or_stop", wait)

    assert asyncio.run(scenario()) == 0
    assert attempts == [0, 5, 15, 35]
    assert waits == [5, 10, 20, 265]
