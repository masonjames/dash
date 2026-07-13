"""Run the narrowly privileged canonical Ops hybrid indexer."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
from collections.abc import Awaitable, Callable, Sequence
from time import monotonic

from dash.ops_indexer import run_indexer


logger = logging.getLogger(__name__)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=0,
        help="Run continuously at this cadence (minimum 300); zero is one-shot.",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Bounded retries inside each interval (0-10).",
    )
    args = parser.parse_args(argv)
    if args.interval_seconds != 0 and not 300 <= args.interval_seconds <= 86_400:
        parser.error("--interval-seconds must be 0 or between 300 and 86400")
    if not 0 <= args.max_retries <= 10:
        parser.error("--max-retries must be between 0 and 10")
    return args


def retry_delays(max_retries: int) -> tuple[int, ...]:
    """Bound exponential retries so a failed index never spins or stampedes."""

    return tuple(min(60, 5 * 2**attempt) for attempt in range(max_retries))


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> bool:
    try:
        await asyncio.wait_for(stop.wait(), timeout=max(0.0, seconds))
    except TimeoutError:
        return False
    return True


async def run_loop(
    *,
    interval_seconds: int,
    max_retries: int,
    stop: asyncio.Event,
    run_once: Callable[[], Awaitable[int]] = run_indexer,
) -> int:
    """Run one index pass or a signal-stoppable, bounded-retry loop."""

    if interval_seconds == 0:
        return await run_once()

    last_count = 0
    while not stop.is_set():
        cycle_started = monotonic()
        for attempt, delay in enumerate((0, *retry_delays(max_retries))):
            if delay and await _wait_or_stop(stop, delay):
                return last_count
            try:
                last_count = await run_once()
                break
            except Exception as exc:
                # run_indexer has already persisted a redacted failed heartbeat.
                # Keep the process alive for the bounded retry/cadence without
                # claiming readiness through a lexical-only or partial index.
                logger.error(
                    "Ops index cycle attempt %s/%s failed: %s",
                    attempt + 1,
                    max_retries + 1,
                    type(exc).__name__,
                )
        remaining = interval_seconds - (monotonic() - cycle_started)
        if await _wait_or_stop(stop, max(0.0, remaining)):
            break
    return last_count


async def async_main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop.set)
        except NotImplementedError:  # pragma: no cover - Windows event loops
            pass
    count = await run_loop(
        interval_seconds=args.interval_seconds,
        max_retries=args.max_retries,
        stop=stop,
    )
    print(f"Published {count} canonical hybrid retrieval documents")
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
