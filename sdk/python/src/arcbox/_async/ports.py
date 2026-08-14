"""The ``sandbox.ports`` namespace: network reachability and readiness
of one sandbox — publish guest ports on host loopback, and wait for the
workload to listen."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

import httpx
from google.protobuf import empty_pb2

from arcbox._boundary import wrap_errors
from arcbox._gen import process_pb2, sandbox_pb2
from arcbox._types import (
    ExposedPort,
    PortProtocol,
    exposed_port_from_proto,
    port_protocol_to_proto,
)
from arcbox.errors import InvalidArgumentError, RequestTimeoutError, TimeoutError

if TYPE_CHECKING:
    from ._client import AsyncConnectClient

_PROCESS = "/arcbox.sandbox.v1.SandboxProcessService/"
_SANDBOX = "/arcbox.sandbox.v1.SandboxService/"

#: Daemon default wait budget when no timeout is given (`process.proto`).
_DEFAULT_WAIT_FOR_PORT_SECONDS = 30

#: Daemon cap on the wait budget — longer requests are clamped
#: server-side (each wait pins a guest exec-channel slot).
_MAX_WAIT_FOR_PORT_SECONDS = 600


class AsyncPorts:
    """Network reachability and readiness of one sandbox."""

    def __init__(self, client: AsyncConnectClient, sandbox_id: str) -> None:
        self._client = client
        self._sandbox_id = sandbox_id

    async def expose(
        self,
        port: int,
        *,
        host_port: int | None = None,
        protocol: PortProtocol = "tcp",
    ) -> ExposedPort:
        """Publish a sandbox port on host loopback and return the
        mapping. Idempotent for an existing identical mapping. The
        daemon owns the host listener; it disappears with the sandbox
        (and on :meth:`unexpose`).

        ``host_port`` binds a specific host port; ``None`` (the
        default) has the daemon allocate one — the allocated port is in
        the returned mapping. Ports below 1024 fail under the
        unprivileged daemon."""
        with wrap_errors("ports.expose"):
            response = await self._client.unary(
                _SANDBOX + "ExposePort",
                sandbox_pb2.ExposePortRequest(
                    id=self._sandbox_id,
                    sandbox_port=port,
                    host_port=host_port or 0,
                    protocol=port_protocol_to_proto(protocol),
                ),
                sandbox_pb2.ExposePortResponse,
            )
            return ExposedPort(sandbox_port=port, host_port=response.host_port, protocol=protocol)

    async def unexpose(self, port: int, *, protocol: PortProtocol = "tcp") -> None:
        """Remove a previously exposed mapping and close its host
        listener."""
        with wrap_errors("ports.unexpose"):
            await self._client.unary(
                _SANDBOX + "UnexposePort",
                sandbox_pb2.UnexposePortRequest(
                    id=self._sandbox_id,
                    sandbox_port=port,
                    protocol=port_protocol_to_proto(protocol),
                ),
                empty_pb2.Empty,
            )

    async def list(self) -> list[ExposedPort]:
        """The sandbox's current exposed-port mappings, from the
        daemon's authoritative live listener table — never a
        session-local cache."""
        with wrap_errors("ports.list"):
            response = await self._client.unary(
                _SANDBOX + "ListExposedPorts",
                sandbox_pb2.ListExposedPortsRequest(id=self._sandbox_id),
                sandbox_pb2.ListExposedPortsResponse,
            )
            return [exposed_port_from_proto(port) for port in response.ports]

    async def wait_for_port(self, port: int, timeout: float | None = None) -> None:
        """Wait until something inside the sandbox listens on the given
        TCP port. The guest agent watches its own listen table — no
        client-side polling, no shelled-out probes. Returns as soon as a
        listener is up; raises :class:`arcbox.errors.TimeoutError`
        naming this knob when the budget elapses first.

        ``timeout`` must be positive and finite; ``None`` (the default)
        means the daemon's 30 s (the wire reserves 0 for that default,
        so a literal zero budget is not expressible). The wire's
        granularity is whole seconds, so a fractional budget rounds UP
        to the next second — never down toward the reserved 0. Values
        past the daemon's 600 s cap are clamped to it."""
        with wrap_errors("ports.wait_for_port"):
            # Validate at the boundary: 0 would silently collide with
            # the wire's use-the-default sentinel (a 30 s wait, not an
            # immediate check), and negative/NaN/inf would reach the
            # timer and protobuf layers as raw invalid values.
            if timeout is not None and not (timeout > 0 and math.isfinite(timeout)):
                raise InvalidArgumentError(
                    "wait_for_port timeout must be a positive finite number of "
                    "seconds (omit it for the daemon's 30 s default)",
                    context={"timeout": str(timeout)},
                )
            # 0 on the wire = the daemon default; the daemon clamps
            # anything past its cap, so the effective budget is known
            # client-side too.
            requested = 0 if timeout is None else math.ceil(timeout)
            effective = (
                _DEFAULT_WAIT_FOR_PORT_SECONDS
                if requested == 0
                else min(requested, _MAX_WAIT_FOR_PORT_SECONDS)
            )
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
