"""Sandbox handles and the client entry point.

A handle holds only the sandbox id and the connection — state is never
cached; ``info()`` always fetches fresh.
"""

from __future__ import annotations

import asyncio
import math
import uuid
from contextlib import suppress
from typing import TYPE_CHECKING

from google.protobuf import empty_pb2

from arcbox._boundary import wrap_errors
from arcbox._gen import sandbox_pb2
from arcbox._types import (
    SandboxInfo,
    SandboxSummary,
    sandbox_info_from_proto,
    sandbox_state_from_proto,
    sandbox_state_to_proto,
    sandbox_summary_from_proto,
)
from arcbox.errors import ArcBoxError, NotFoundError, SandboxStateError

from ._client import AsyncConnectClient
from .commands import AsyncCommands
from .files import AsyncFiles

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence
    from types import TracebackType

    from arcbox._connection import Connection
    from arcbox._types import IdlePolicy, SandboxState

    from ._client import AsyncServerStream

_SANDBOX = "/arcbox.sandbox.v1.SandboxService/"

_READY_STATES = (sandbox_pb2.SANDBOX_STATE_READY, sandbox_pb2.SANDBOX_STATE_RUNNING)
_GONE_STATES = (sandbox_pb2.SANDBOX_STATE_STOPPING, sandbox_pb2.SANDBOX_STATE_STOPPED)
_READY_EVENTS = (
    sandbox_pb2.SANDBOX_EVENT_KIND_READY,
    sandbox_pb2.SANDBOX_EVENT_KIND_RUNNING,
    sandbox_pb2.SANDBOX_EVENT_KIND_IDLE,
)
_GONE_EVENTS = (
    sandbox_pb2.SANDBOX_EVENT_KIND_STOPPING,
    sandbox_pb2.SANDBOX_EVENT_KIND_STOPPED,
    sandbox_pb2.SANDBOX_EVENT_KIND_REMOVED,
)

#: How often ``connect`` re-inspects a PAUSING sandbox. No lifecycle
#: event marks the PAUSING→PAUSED edge, so it is polled out.
_PAUSE_SETTLE_POLL_SECONDS = 0.5


def _seconds_to_wire(seconds: float | None) -> int:
    return 0 if seconds is None else math.ceil(seconds)


class AsyncArcBox:
    """Client entry point. Holds one resolved connection; every handle it
    creates shares it. The :class:`AsyncSandbox` classmethods are sugar
    over a throwaway instance resolved from options/environment.

    Usable as a context manager: exiting the scope closes the SDK-owned
    HTTP client (handles created from this instance stop working); an
    injected ``Connection.http_client`` is left to its owner."""

    def __init__(self, connection: Connection | None = None) -> None:
        self._client = AsyncConnectClient(connection)

    async def aclose(self) -> None:
        """Close the SDK-owned HTTP client (no-op for an injected one)."""
        await self._client.aclose()

    async def __aenter__(self) -> AsyncArcBox:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def create(
        self,
        template: str = "",
        *,
        ttl: float | None = None,
        idle_timeout: float | None = None,
        on_idle: IdlePolicy | None = None,
        vcpus: int | None = None,
        memory_mib: int | None = None,
        cmd: Sequence[str] | None = None,
        env: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
        network: bool | None = None,
        wait_until_ready: bool = True,
    ) -> AsyncSandbox:
        """Create a sandbox and (by default) wait until it is READY.

        ``ttl`` is the hard maximum lifetime — on expiry the daemon
        always destroys the sandbox. ``idle_timeout`` + ``on_idle`` is
        the independent idle-reaping knob; never conflate the two.

        The sandbox id is minted client-side so the readiness
        subscription can be armed BEFORE the create call —
        subscribe-then-act, so no transition is missed (the CORE-67
        rule) — and so retries stay idempotent.
        """
        with wrap_errors("sandbox.create"):
            sandbox_id = str(uuid.uuid4())
            try:
                if wait_until_ready:
                    async with self._client.stream(
                        _SANDBOX + "Events",
                        sandbox_pb2.SandboxEventsRequest(sandbox_id=sandbox_id),
                        sandbox_pb2.WatchEventsResponse,
                    ) as events:
                        await self._create(
                            sandbox_id,
                            template,
                            ttl=ttl,
                            idle_timeout=idle_timeout,
                            on_idle=on_idle,
                            vcpus=vcpus,
                            memory_mib=memory_mib,
                            cmd=cmd,
                            env=env,
                            labels=labels,
                            network=network,
                        )
                        await self._wait_ready(sandbox_id, events)
                else:
                    await self._create(
                        sandbox_id,
                        template,
                        ttl=ttl,
                        idle_timeout=idle_timeout,
                        on_idle=on_idle,
                        vcpus=vcpus,
                        memory_mib=memory_mib,
                        cmd=cmd,
                        env=env,
                        labels=labels,
                        network=network,
                    )
                return AsyncSandbox(self._client, sandbox_id)
            except BaseException:
                # The sandbox may exist even though create() failed
                # (readiness failed, response lost) and ttl is optional,
                # so a leaked VM could run forever. Best-effort removal; a
                # failure here (e.g. nothing was created) must not mask
                # the original error.
                with suppress(Exception):
                    await self._client.unary(
                        _SANDBOX + "Remove",
                        sandbox_pb2.RemoveSandboxRequest(id=sandbox_id, force=True),
                        empty_pb2.Empty,
                    )
                raise

    async def connect(self, sandbox_id: str) -> AsyncSandbox:
        """Attach to an existing sandbox. A PAUSED sandbox is resumed
        (resume completes once it is READY again); a PAUSING one settles
        to PAUSED first, then resumes; a STARTING one is waited for. A
        terminal state is a typed error carrying the observed state.
        Connecting never touches the sandbox's lifecycle deadlines."""
        with wrap_errors("sandbox.connect"):
            info = await self._inspect(sandbox_id)
            # A pausing sandbox's next stop is PAUSED — never READY — so
            # waiting on readiness events would park forever. Poll the
            # checkpoint out, then route on whatever state it settled in.
            while info.state == sandbox_pb2.SANDBOX_STATE_PAUSING:
                await asyncio.sleep(_PAUSE_SETTLE_POLL_SECONDS)
                info = await self._inspect(sandbox_id)
            if info.state in _READY_STATES:
                return AsyncSandbox(self._client, sandbox_id)
            if info.state == sandbox_pb2.SANDBOX_STATE_PAUSED:
                # Deliberately no per-request deadline: restoring a
                # checkpoint takes as long as it takes, and the RPC
                # returns once READY.
                await self._client.unary(
                    _SANDBOX + "Resume",
                    sandbox_pb2.ResumeSandboxRequest(id=sandbox_id),
                    empty_pb2.Empty,
                    timeout=None,
                )
                return AsyncSandbox(self._client, sandbox_id)
            if info.state == sandbox_pb2.SANDBOX_STATE_STARTING:
                async with self._client.stream(
                    _SANDBOX + "Events",
                    sandbox_pb2.SandboxEventsRequest(sandbox_id=sandbox_id),
                    sandbox_pb2.WatchEventsResponse,
                ) as events:
                    await self._wait_ready(sandbox_id, events)
                return AsyncSandbox(self._client, sandbox_id)
            state = sandbox_state_from_proto(info.state)
            raise SandboxStateError(
                f"sandbox {sandbox_id} is {state} and cannot be connected to",
                context={"id": sandbox_id, "state": state, "error": info.error},
            )

    async def list(
        self,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> AsyncIterator[SandboxSummary]:
        """List sandboxes, auto-paginating server-side pages."""
        with wrap_errors("sandbox.list"):
            page_token = ""
            while True:
                page = await self._client.unary(
                    _SANDBOX + "List",
                    sandbox_pb2.ListSandboxesRequest(
                        state=(
                            sandbox_pb2.SANDBOX_STATE_UNSPECIFIED
                            if state is None
                            else sandbox_state_to_proto(state)
                        ),
                        labels=dict(labels) if labels else {},
                        page_token=page_token,
                    ),
                    sandbox_pb2.ListSandboxesResponse,
                )
                for row in page.sandboxes:
                    yield sandbox_summary_from_proto(row)
                page_token = page.next_page_token
                if page_token == "":
                    return

    async def _inspect(self, sandbox_id: str) -> sandbox_pb2.SandboxInfo:
        return await self._client.unary(
            _SANDBOX + "Inspect",
            sandbox_pb2.InspectSandboxRequest(id=sandbox_id),
            sandbox_pb2.SandboxInfo,
        )

    async def _create(
        self,
        sandbox_id: str,
        template: str,
        *,
        ttl: float | None,
        idle_timeout: float | None,
        on_idle: IdlePolicy | None,
        vcpus: int | None,
        memory_mib: int | None,
        cmd: Sequence[str] | None,
        env: Mapping[str, str] | None,
        labels: Mapping[str, str] | None,
        network: bool | None,
    ) -> None:
        request = sandbox_pb2.CreateSandboxRequest(
            id=sandbox_id,
            template=template,
            labels=dict(labels) if labels else {},
            cmd=list(cmd) if cmd else [],
            env=dict(env) if env else {},
            ttl_seconds=_seconds_to_wire(ttl),
            idle_timeout_seconds=_seconds_to_wire(idle_timeout),
            on_idle=(
                sandbox_pb2.IDLE_ACTION_UNSPECIFIED
                if on_idle is None
                else sandbox_pb2.IDLE_ACTION_KILL
                if on_idle == "kill"
                else sandbox_pb2.IDLE_ACTION_PAUSE
            ),
        )
        if vcpus is not None or memory_mib is not None:
            # Setting either sends `limits`, replacing template defaults
            # WHOLESALE (a zero subfield means the daemon default).
            request.limits.vcpus = vcpus or 0
            request.limits.memory_mib = memory_mib or 0
        if network is not None:
            request.network.mode = (
                sandbox_pb2.NETWORK_MODE_ENABLED if network else sandbox_pb2.NETWORK_MODE_NONE
            )
        await self._client.unary(_SANDBOX + "Create", request, sandbox_pb2.CreateSandboxResponse)

    async def _wait_ready(
        self,
        sandbox_id: str,
        events: AsyncServerStream[sandbox_pb2.WatchEventsResponse],
    ) -> None:
        """Consume lifecycle events until READY/RUNNING, or fail on a
        terminal transition. The subscription was armed before Create, so
        nothing can be missed; the one residual window — Create processed
        before the subscription registered server-side — is covered by an
        immediate Inspect and by re-inspecting on every keepalive frame."""

        def check(state: int, error: str) -> bool:
            if state in _READY_STATES:
                return True
            if state == sandbox_pb2.SANDBOX_STATE_FAILED:
                raise SandboxStateError(
                    f"sandbox {sandbox_id} failed to start: {error}",
                    context={"id": sandbox_id, "state": "failed", "error": error},
                )
            if state in _GONE_STATES:
                raise SandboxStateError(
                    f"sandbox {sandbox_id} stopped before becoming ready",
                    context={"id": sandbox_id, "state": "stopped"},
                )
            return False

        info = await self._inspect(sandbox_id)
        if check(info.state, info.error):
            return
        async for frame in events:
            payload = frame.WhichOneof("payload")
            if payload == "event":
                event = frame.event
                if event.kind in _READY_EVENTS:
                    return
                if event.kind == sandbox_pb2.SANDBOX_EVENT_KIND_FAILED:
                    error = event.attributes.get("error", "")
                    raise SandboxStateError(
                        f"sandbox {sandbox_id} failed to start: {error}",
                        context={"id": sandbox_id, "state": "failed", "error": error},
                    )
                if event.kind in _GONE_EVENTS:
                    raise SandboxStateError(
                        f"sandbox {sandbox_id} stopped before becoming ready",
                        context={"id": sandbox_id, "state": "stopped"},
                    )
            elif payload == "keep_alive":
                fresh = await self._inspect(sandbox_id)
                if check(fresh.state, fresh.error):
                    return
        raise ArcBoxError(
            f"the event stream ended before sandbox {sandbox_id} became ready",
            context={"id": sandbox_id},
        )


class AsyncSandbox:
    """A handle to one sandbox."""

    def __init__(self, client: AsyncConnectClient, sandbox_id: str) -> None:
        self._client = client
        # Flipped by the classmethod sugar, whose hidden entry point has
        # no other referent: the handle then closes the client on
        # context exit. Handles minted by a caller-held entry point
        # share its client and never close it.
        self._owns_client = False
        #: Sandbox id.
        self.id = sandbox_id
        #: Run processes inside the sandbox.
        self.commands = AsyncCommands(client, sandbox_id)
        #: Move bytes in and out of the sandbox.
        self.files = AsyncFiles(client, sandbox_id)

    @classmethod
    async def create(
        cls,
        template: str = "",
        *,
        ttl: float | None = None,
        idle_timeout: float | None = None,
        on_idle: IdlePolicy | None = None,
        vcpus: int | None = None,
        memory_mib: int | None = None,
        cmd: Sequence[str] | None = None,
        env: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
        network: bool | None = None,
        wait_until_ready: bool = True,
        connection: Connection | None = None,
    ) -> AsyncSandbox:
        """Create a sandbox against the default (or given) connection.
        The handle owns the hidden entry point's HTTP client and closes
        it on context exit; without the context manager, hold an
        :class:`AsyncArcBox` instead for deterministic cleanup."""
        box = AsyncArcBox(connection)
        try:
            sandbox = await box.create(
                template,
                ttl=ttl,
                idle_timeout=idle_timeout,
                on_idle=on_idle,
                vcpus=vcpus,
                memory_mib=memory_mib,
                cmd=cmd,
                env=env,
                labels=labels,
                network=network,
                wait_until_ready=wait_until_ready,
            )
        except BaseException:
            await box.aclose()
            raise
        sandbox._owns_client = True
        return sandbox

    @classmethod
    async def connect(
        cls, sandbox_id: str, *, connection: Connection | None = None
    ) -> AsyncSandbox:
        """Attach to an existing sandbox by id. Client ownership works as
        in :meth:`create`."""
        box = AsyncArcBox(connection)
        try:
            sandbox = await box.connect(sandbox_id)
        except BaseException:
            await box.aclose()
            raise
        sandbox._owns_client = True
        return sandbox

    @classmethod
    async def list(
        cls,
        *,
        state: SandboxState | None = None,
        labels: Mapping[str, str] | None = None,
        connection: Connection | None = None,
    ) -> AsyncIterator[SandboxSummary]:
        """List sandboxes (auto-paginating). The hidden entry point's
        HTTP client closes when iteration completes or the iterator is
        closed; abandoning it mid-iteration defers that to generator
        finalization, so callers that may stop early should hold an
        ArcBox entry point instead (or close the iterator explicitly,
        e.g. ``contextlib.aclosing`` in the async flavor)."""
        async with AsyncArcBox(connection) as box:
            async for summary in box.list(state=state, labels=labels):
                yield summary

    async def info(self) -> SandboxInfo:
        """Fetch the sandbox's current state — always fresh, never cached."""
        with wrap_errors("sandbox.info"):
            return sandbox_info_from_proto(
                await self._client.unary(
                    _SANDBOX + "Inspect",
                    sandbox_pb2.InspectSandboxRequest(id=self.id),
                    sandbox_pb2.SandboxInfo,
                )
            )

    async def kill(self) -> None:
        """Destroy the sandbox and release all its resources immediately."""
        with wrap_errors("sandbox.kill"):
            await self._client.unary(
                _SANDBOX + "Remove",
                sandbox_pb2.RemoveSandboxRequest(id=self.id, force=True),
                empty_pb2.Empty,
            )

    async def pause(self) -> None:
        """Checkpoint the sandbox to disk under the same id and release
        its runtime resources. Resume happens on the next ``connect``
        (or transparently, daemon-side, on the next data-plane call).
        Trades RAM for disk: a paused sandbox keeps paying
        ``storage_bytes``.

        Requires daemon-side CORE-21: the current local daemon serves
        Pause/Resume as contract-only stubs, so this raises an
        unimplemented :class:`ArcBoxError` until that lands."""
        with wrap_errors("sandbox.pause"):
            # No per-request deadline: checkpointing takes as long as it
            # takes.
            await self._client.unary(
                _SANDBOX + "Pause",
                sandbox_pb2.PauseSandboxRequest(id=self.id),
                empty_pb2.Empty,
                timeout=None,
            )

    async def __aenter__(self) -> AsyncSandbox:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        # Scope-exit disposal kills the sandbox so a leaked handle never
        # leaks a VM. Swallows only "already gone" — the whole
        # NotFoundError family, because the daemon does not attach
        # ErrorInfo details yet and a coarse NotFound on this id can only
        # mean the sandbox.
        try:
            with suppress(NotFoundError):
                await self.kill()
        finally:
            if self._owns_client:
                await self._client.aclose()
