"""The single transport→exception boundary.

Call sites wrap every RPC in :func:`wrap_errors` and never inspect
Connect or httpx errors themselves. Shared by the async and sync trees
(a non-suspending ``with`` block is valid in both).
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

import httpx

from arcbox.errors import (
    DAEMON_START_SUGGESTION,
    ArcBoxError,
    ConnectionFailedError,
    RequestTimeoutError,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@contextmanager
def wrap_errors(operation: str) -> Generator[None]:
    """Map transport failures to the typed hierarchy, stamping ``operation``.

    Precedence mirrors the TypeScript SDK: an already-typed
    :class:`ArcBoxError` passes through (gaining the operation name);
    connection-level failures become :class:`ConnectionFailedError` with
    a start-the-daemon suggestion; client-side deadline expiry becomes
    :class:`RequestTimeoutError`; any other httpx transport failure is
    preserved as the cause of a base :class:`ArcBoxError`.
    """
    try:
        yield
    except ArcBoxError as exc:
        if exc.operation is None:
            exc.operation = operation
        raise
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        raise ConnectionFailedError(
            "the ArcBox daemon is not reachable",
            suggestion=DAEMON_START_SUGGESTION,
            operation=operation,
        ) from exc
    except httpx.TimeoutException as exc:
        raise RequestTimeoutError(
            "the request deadline elapsed before the daemon answered",
            suggestion="increase Connection.request_timeout",
            operation=operation,
        ) from exc
    except httpx.HTTPError as exc:
        raise ArcBoxError(f"transport failure: {exc}", operation=operation) from exc
