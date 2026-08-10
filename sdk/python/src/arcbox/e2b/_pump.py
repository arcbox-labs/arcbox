"""Background output pumps, one per flavor.

``e2b`` pushes a command's output into callbacks while it runs, so the
handle needs something running in the background. The two flavors need
genuinely different machinery for that — a task on the event loop, a
daemon thread — which no token transform can produce from the other, so
both live here and ``scripts/gen_sync.py`` swaps ``AsyncPump`` for
``Pump`` alongside the other ``Async``-prefixed names.

Both take a *factory*, not a started job: in the sync flavor calling the
work eagerly would run it on the caller's thread, which is exactly the
blocking this exists to avoid.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from arcbox import AsyncFileWatch, FileWatch


class AsyncPump:
    """Runs a coroutine as a task until it finishes."""

    def __init__(self, factory: Callable[[], Coroutine[Any, Any, None]]) -> None:
        self._task = asyncio.ensure_future(factory())

    async def join(self) -> None:
        """Wait for the pump to finish, ignoring a cancellation."""
        with contextlib.suppress(asyncio.CancelledError):
            await self._task

    def cancel(self) -> None:
        """Stop pumping."""
        self._task.cancel()


class Pump:
    """Runs a callable on a daemon thread until it finishes."""

    def __init__(self, factory: Callable[[], None]) -> None:
        # unasync rewrites the async factory's coroutine into a plain
        # call, so in this flavor the "factory" *is* the work — running
        # it on the caller's thread is exactly what must not happen.
        self._thread = threading.Thread(target=factory, daemon=True)
        self._thread.start()

    def join(self) -> None:
        """Wait for the pump to finish."""
        self._thread.join()

    def cancel(self) -> None:
        """No-op: a thread cannot be interrupted.

        The pump ends when its output stream does, which happens when
        the command exits or the handle's stream is closed."""


async def async_stop_watch(pump: AsyncPump, watch: AsyncFileWatch) -> None:
    """Stop a watch pump: cancel the task, wait it out, then close the
    event generator — safe only once nothing is driving it."""
    pump.cancel()
    await pump.join()
    await watch.aclose()


def stop_watch(pump: Pump, watch: FileWatch) -> None:
    """Best-effort stop for the thread flavor.

    A pumping thread cannot be interrupted mid-read: closing the
    generator succeeds only between events (the ``RuntimeError`` from a
    running generator is suppressed). Otherwise the daemon thread ends
    when the watch stream does — sandbox stop or process exit — the
    same contract as :meth:`Pump.cancel`."""
    del pump
    with contextlib.suppress(RuntimeError):
        watch.close()


async def async_call(sink: Callable[[Any], object], value: Any) -> None:
    """Invoke a sink that may or may not be a coroutine function.

    The sync counterpart cannot be derived by the transform: dropping
    the `await` would leave a coroutine unawaited rather than calling
    the sink, so each flavor spells its own.
    """
    outcome = sink(value)
    if inspect.isawaitable(outcome):
        await outcome


def call(sink: Callable[[Any], object], value: Any) -> None:
    """Invoke a sink. A sync caller cannot await, so any awaitable a
    sink returns is the caller's own mistake and is left alone."""
    sink(value)
