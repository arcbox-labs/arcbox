"""Sandbox handles and the client entry point.

A handle holds only the sandbox id and the connection — state is never
cached; ``info()`` always fetches fresh.
"""

from __future__ import annotations

import asyncio
import math
import time
import uuid
from contextlib import suppress
from typing import TYPE_CHECKING

import httpx
from google.protobuf import empty_pb2

from arcbox._boundary import wrap_errors
from arcbox._gen import sandbox_pb2
from arcbox._types import (
    UNCHANGED,
    Capabilities,
    SandboxEvent,
    SandboxInfo,
    SandboxSummary,
    Unchanged,
    capabilities_from_proto,
    sandbox_event_from_proto,
    sandbox_info_from_proto,
    sandbox_state_from_proto,
    sandbox_state_to_proto,
    sandbox_summary_from_proto,
)
from arcbox.errors import (
    ArcBoxError,
    ConnectionFailedError,
    ConnectionLostError,
    InvalidArgumentError,
    NotFoundError,
    RequestTimeoutError,
    SandboxStateError,
    TimeoutError,
)

from ._client import AsyncConnectClient
from .commands import AsyncCommands
from .files import AsyncFiles
from .ports import AsyncPorts

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator, Mapping, Sequence
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

#: How often ``connect`` re-inspects a PAUSING sandbox. The daemon
#: emits ``SANDBOX_EVENT_KIND_PAUSED`` on this edge (CORE-21), but the
#: settle poll predates it and remains the simple, robust route — a
#: poll-to-event-wait conversion is a candidate cleanup, not a bug.
_PAUSE_SETTLE_POLL_SECONDS = 0.5

#: Default overall deadline for ``connect`` in seconds — generous
#: because a checkpoint restore or cold boot legitimately takes a
#: while. ``timeout=None`` disables the bound.
_CONNECT_TIMEOUT_SECONDS = 60.0


def _seconds_to_wire(seconds: float | None) -> int:
    return 0 if seconds is None else math.ceil(seconds)


def _connect_deadline_error(sandbox_id: str) -> TimeoutError:
    return TimeoutError(
        f"connect(timeout) elapsed before sandbox {sandbox_id} was ready",
        suggestion="increase the connect timeout argument",
        context={"id": sandbox_id},
    )


def _budget(deadline: float | None, sandbox_id: str) -> float | None:
    """Seconds left before ``deadline`` (``None`` = unbounded), raising
    the connect timeout once it has passed."""
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _connect_deadline_error(sandbox_id)
    return remaining


class AsyncArcBox:
    """Client entry point. Holds one resolved connection; every handle it
    creates shares it. The :class:`AsyncSandbox` classmethods are sugar
    over a throwaway instance resolved from options/environment.

    Usable as a context manager: exiting the scope closes the SDK-owned
    HTTP client (handles created from this instance stop working); an
    injected ``Connection.http_client`` is left to its owner."""

    def __init__(self, connection: Connection | None = None) -> None:
        self._client = AsyncConnectClient(connection)
        self._capabilities: Capabilities | None = None

    async def aclose(self) -> None:
        """Close the SDK-owned HTTP client (no-op for an injected one)."""
        await self._client.aclose()

    async def capabilities(self) -> Capabilities:
        """What the daemon can do: version, sandbox protocol level,
        feature flags, and whether nested virtualization is available.
        Answered host-side (works before any sandbox exists) and cached
        for the life of this client — a failed fetch is not cached, so
        the next call retries. The SDK does not gate on it: the daemon
        fails fast on its own (a ``CapabilityError`` from ``create``);
        this is the inspectable version of the same answer."""
        if self._capabilities is None:
            with wrap_errors("arcbox.capabilities"):
                self._capabilities = capabilities_from_proto(
                    await self._client.unary(
                        _SANDBOX + "GetCapabilities",
                        sandbox_pb2.GetCapabilitiesRequest(),
                        sandbox_pb2.GetCapabilitiesResponse,
                    )
                )
        return self._capabilities

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

    async def connect(
        self, sandbox_id: str, *, timeout: float | None = _CONNECT_TIMEOUT_SECONDS
    ) -> AsyncSandbox:
        """Attach to an existing sandbox. A PAUSED sandbox is resumed
        (resume completes once it is READY again); a PAUSING one settles
        to PAUSED first, then resumes; a STARTING one is waited for. A
        terminal state is a typed error carrying the observed state.
        Connecting never touches the sandbox's lifecycle deadlines.

        ``timeout`` bounds the WHOLE call — the settle poll, a resume,
        and the readiness wait share one deadline (default 60s;
        ``None`` or ``math.inf`` disables it). On expiry
        :class:`TimeoutError` is raised and the sandbox is left as it
        was."""
        with wrap_errors("sandbox.connect"):
            # Validate at the boundary: NaN and non-positive values
            # would otherwise corrupt or silently pre-expire the budget
            # arithmetic below.
            if timeout is not None and not timeout > 0:
                raise InvalidArgumentError(
                    "connect timeout must be a positive number of seconds "
                    "(None disables the bound)",
                    context={"timeout": str(timeout)},
                )
            # One deadline over every wait below — the settle poll,
            # resume, and the readiness wait; bounding only one of them
            # would be arbitrary while the neighbouring waits stayed
            # unbounded.
            deadline = (
                None if timeout is None or math.isinf(timeout) else time.monotonic() + timeout
            )
            try:
                return await self._connect(sandbox_id, deadline)
            except (RequestTimeoutError, httpx.TimeoutException) as exc:
                # A per-RPC expiry observed after the overall deadline
                # passed is the connect budget surfacing, not the
                # per-request knob.
                if deadline is not None and time.monotonic() >= deadline:
                    raise _connect_deadline_error(sandbox_id) from exc
                raise

    async def _connect(self, sandbox_id: str, deadline: float | None) -> AsyncSandbox:
        info = await self._inspect(sandbox_id, deadline=deadline)
        # A pausing sandbox's next stop is PAUSED — never READY — so
        # waiting on readiness events would park forever. Poll the
        # checkpoint out, then route on whatever state it settled in.
        while info.state == sandbox_pb2.SANDBOX_STATE_PAUSING:
            remaining = _budget(deadline, sandbox_id)
            await asyncio.sleep(
                _PAUSE_SETTLE_POLL_SECONDS
                if remaining is None
                else min(_PAUSE_SETTLE_POLL_SECONDS, remaining)
            )
            info = await self._inspect(sandbox_id, deadline=deadline)
        if info.state in _READY_STATES:
            return AsyncSandbox(self._client, sandbox_id)
        if info.state == sandbox_pb2.SANDBOX_STATE_PAUSED:
            # No per-request deadline of its own: restoring a checkpoint
            # takes as long as it takes, and the RPC returns once READY —
            # the overall connect deadline is the only bound.
            await self._client.unary(
                _SANDBOX + "Resume",
                sandbox_pb2.ResumeSandboxRequest(id=sandbox_id),
                empty_pb2.Empty,
                timeout=_budget(deadline, sandbox_id),
            )
            return AsyncSandbox(self._client, sandbox_id)
        if info.state == sandbox_pb2.SANDBOX_STATE_STARTING:
            async with self._client.stream(
                _SANDBOX + "Events",
                sandbox_pb2.SandboxEventsRequest(sandbox_id=sandbox_id),
                sandbox_pb2.WatchEventsResponse,
                timeout=_budget(deadline, sandbox_id),
            ) as events:
                await self._wait_ready(sandbox_id, events, deadline=deadline)
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

    async def _inspect(
        self, sandbox_id: str, deadline: float | None = None
    ) -> sandbox_pb2.SandboxInfo:
        """Inspect, with the configured per-RPC deadline capped by the
        remaining connect budget when one is running."""
        remaining = _budget(deadline, sandbox_id)
        request = sandbox_pb2.InspectSandboxRequest(id=sandbox_id)
        if remaining is None:
            return await self._client.unary(_SANDBOX + "Inspect", request, sandbox_pb2.SandboxInfo)
        base = self._client.request_timeout
        return await self._client.unary(
            _SANDBOX + "Inspect",
            request,
            sandbox_pb2.SandboxInfo,
            timeout=remaining if base is None else min(base, remaining),
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
        deadline: float | None = None,
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

        info = await self._inspect(sandbox_id, deadline=deadline)
        if check(info.state, info.error):
            return
        async for frame in events:
            # The stream's read timeout only bounds silence; frames may
            # keep arriving (keepalives) without ever tripping it, so the
            # overall budget is re-checked on every frame.
            _budget(deadline, sandbox_id)
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
                fresh = await self._inspect(sandbox_id, deadline=deadline)
                if check(fresh.state, fresh.error):
                    return
        raise ArcBoxError(
            f"the event stream ended before sandbox {sandbox_id} became ready",
            context={"id": sandbox_id},
        )


class AsyncEventStream:
    """A sandbox's lifecycle events, iterable one typed event at a time.

    The iterator ends when the daemon ends the stream. When exiting
    early (``break``), iterate inside the context-manager form —
    ``async with sandbox.events() as stream`` in the async flavor,
    ``with`` in the sync one — so the subscription closes at the break
    instead of whenever the generator finalizer runs."""

    def __init__(self, events: AsyncGenerator[SandboxEvent]) -> None:
        self._events = events

    def __aiter__(self) -> AsyncIterator[SandboxEvent]:
        return self._events

    async def aclose(self) -> None:
        """Cancel the subscription without consuming the rest."""
        await self._events.aclose()

    async def __aenter__(self) -> AsyncEventStream:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


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
        #: Network readiness of the sandbox.
        self.ports = AsyncPorts(client, sandbox_id)

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
        cls,
        sandbox_id: str,
        *,
        timeout: float | None = _CONNECT_TIMEOUT_SECONDS,
        connection: Connection | None = None,
    ) -> AsyncSandbox:
        """Attach to an existing sandbox by id. ``timeout`` bounds the
        whole call as in :meth:`AsyncArcBox.connect` (default 60s;
        ``None`` disables it; expiry raises :class:`TimeoutError`).
        Client ownership works as in :meth:`create`."""
        box = AsyncArcBox(connection)
        try:
            sandbox = await box.connect(sandbox_id, timeout=timeout)
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

    async def set_lifecycle(
        self,
        *,
        ttl: float | Unchanged | None = UNCHANGED,
        idle_timeout: float | Unchanged | None = UNCHANGED,
        on_idle: IdlePolicy | Unchanged | None = UNCHANGED,
    ) -> None:
        """Replace lifecycle deadlines. Each knob is tri-state: omitted
        (the :data:`arcbox.UNCHANGED` default) leaves it as it is;
        ``None`` restores the daemon default (no TTL / no idle detection
        / the default idle action) — the same meaning ``None`` has on
        ``create``; a value replaces it. ``ttl`` re-arms the hard cap
        this many seconds from NOW — calling repeatedly keeps a busy
        sandbox alive; ``idle_timeout`` re-arms a live idle timer. Works
        in any non-terminal state, including paused."""
        with wrap_errors("sandbox.set_lifecycle"):
            request = sandbox_pb2.SetLifecycleRequest(id=self.id)
            if not isinstance(ttl, Unchanged):
                request.ttl_seconds = _seconds_to_wire(ttl)
            if not isinstance(idle_timeout, Unchanged):
                request.idle_timeout_seconds = _seconds_to_wire(idle_timeout)
            if not isinstance(on_idle, Unchanged):
                request.on_idle = (
                    sandbox_pb2.IDLE_ACTION_UNSPECIFIED
                    if on_idle is None
                    else sandbox_pb2.IDLE_ACTION_KILL
                    if on_idle == "kill"
                    else sandbox_pb2.IDLE_ACTION_PAUSE
                )
            await self._client.unary(_SANDBOX + "SetLifecycle", request, empty_pb2.Empty)

    def events(self) -> AsyncEventStream:
        """Subscribe to this sandbox's lifecycle events, yielded as
        typed :class:`SandboxEvent` values (keepalive frames are
        filtered out). The iterator ends when the daemon ends the
        stream; closing the stream (or its context) cancels the
        subscription. A transport drop mid-stream is surfaced as
        :class:`arcbox.errors.ConnectionLostError` — re-subscribing is
        the caller's decision, since missed events cannot be replayed."""
        return AsyncEventStream(self._stream_events())

    async def _stream_events(self) -> AsyncGenerator[SandboxEvent]:
        with wrap_errors("sandbox.events"):
            entered = False
            try:
                async with self._client.stream(
                    _SANDBOX + "Events",
                    sandbox_pb2.SandboxEventsRequest(sandbox_id=self.id),
                    sandbox_pb2.WatchEventsResponse,
                ) as stream:
                    entered = True
                    async for frame in stream:
                        if frame.WhichOneof("payload") == "event":
                            yield sandbox_event_from_proto(frame.event)
            # ConnectionFailedError covers the drop's OTHER wire shape:
            # the daemon losing its upstream event source ends the HTTP
            # stream cleanly with a Connect `unavailable` error frame,
            # decoded into ConnectionFailedError. Daemon-typed errors map
            # to other classes and keep them.
            except (httpx.HTTPError, ConnectionFailedError) as exc:
                if not entered or isinstance(exc, ConnectionLostError):
                    # Before entry: a dial failure — the daemon was never
                    # reached; wrap_errors maps it to
                    # ConnectionFailedError. ConnectionLostError is
                    # already the stream-death error.
                    raise
                raise ConnectionLostError(
                    "the event stream died",
                    context={"id": self.id},
                    operation="sandbox.events",
                ) from exc

    async def pause(self) -> None:
        """Checkpoint the sandbox to disk under the same id and release
        its runtime resources. Resume happens on the next ``connect``
        (or transparently, daemon-side, on the next data-plane call).
        Trades RAM for disk: a paused sandbox keeps paying
        ``storage_bytes``. Requires a quiescent sandbox (READY — no
        running command)."""
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
