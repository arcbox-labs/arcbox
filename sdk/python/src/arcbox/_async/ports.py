"""The ``sandbox.ports`` namespace: network readiness of one sandbox."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

import httpx
from google.protobuf import empty_pb2

from arcbox._boundary import wrap_errors
from arcbox._gen import process_pb2
from arcbox.errors import RequestTimeoutError, TimeoutError

if TYPE_CHECKING:
    from ._client import AsyncConnectClient

_PROCESS = "/arcbox.sandbox.v1.SandboxProcessService/"

#: Daemon default wait budget when no timeout is given (`process.proto`).
_DEFAULT_WAIT_FOR_PORT_SECONDS = 30

#: Daemon cap on the wait budget — longer requests are clamped
#: server-side (each wait pins a guest exec-channel slot).
_MAX_WAIT_FOR_PORT_SECONDS = 600


class AsyncPorts:
    """Network readiness of one sandbox."""

    def __init__(self, client: AsyncConnectClient, sandbox_id: str) -> None:
        self._client = client
        self._sandbox_id = sandbox_id

    async def wait_for_port(self, port: int, timeout: float | None = None) -> None:
        """Wait until something inside the sandbox listens on the given
        TCP port. The guest agent watches its own listen table — no
        client-side polling, no shelled-out probes. Returns as soon as a
        listener is up; raises :class:`arcbox.errors.TimeoutError`
        naming this knob when the budget elapses first.

        ``timeout`` defaults to the daemon's 30 s; values past the
        daemon's 600 s cap are clamped to it."""
        # 0 on the wire = the daemon default; the daemon clamps anything
        # past its cap, so the effective budget is known client-side too.
        requested = 0 if timeout is None else math.ceil(timeout)
        effective = (
            _DEFAULT_WAIT_FOR_PORT_SECONDS
            if requested == 0
            else min(requested, _MAX_WAIT_FOR_PORT_SECONDS)
        )
        with wrap_errors("ports.wait_for_port"):
            try:
                await self._client.unary(
                    _PROCESS + "WaitForPort",
                    process_pb2.WaitForPortRequest(
                        sandbox_id=self._sandbox_id, port=port, timeout_seconds=requested
                    ),
                    empty_pb2.Empty,
                    # Exempt from request_timeout: this unary deliberately
                    # parks server-side for the whole budget; grant it
                    # that long plus grace, so the daemon's own deadline
                    # answers first.
                    timeout=float(effective + 5),
                )
            # A deadline expiry here is THIS wait's budget (the daemon's
            # DEADLINE_EXCEEDED, or the grace bound above), not the
            # per-RPC knob — name the right one, mirroring connect()'s
            # discipline.
            except (RequestTimeoutError, httpx.TimeoutException) as exc:
                raise TimeoutError(
                    f"wait_for_port(timeout) elapsed before port {port} was listening",
                    suggestion=(
                        "increase the wait_for_port timeout argument, or check "
                        "that the workload actually binds this port"
                    ),
                    context={"port": str(port), "timeout_seconds": str(effective)},
                ) from exc
