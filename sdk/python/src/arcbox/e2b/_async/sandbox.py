"""``e2b``'s ``Sandbox``, backed by the arcbox SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING

from arcbox import AsyncArcBox
from arcbox.e2b._types import (
    DEFAULT_SANDBOX_TIMEOUT_MS,
    SandboxInfo,
    normalize_template,
    seconds,
)
from arcbox.e2b.errors import unsupported
from arcbox.errors import NotFoundError

from .commands import AsyncCommands, AsyncPty
from .filesystem import AsyncFilesystem
from .git import AsyncGit

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

    from arcbox import AsyncSandbox as ArcBoxSandbox
    from arcbox import Connection


class AsyncSandbox:
    """``e2b``'s cloud sandbox, served by the local ArcBox daemon.

    The shape follows ``e2b`` deliberately, including the parts that
    read oddly here: ``sandbox_id`` rather than ``id``, milliseconds
    everywhere, ``metadata`` rather than ``labels``, and ``run()``
    raising on a non-zero exit. Divergences are documented on the
    members that carry them — :meth:`get_host` most of all.

    The E2B cloud arguments (``api_key``, ``domain``, ...) are accepted
    and ignored: a local daemon authenticates by socket permissions, so
    an app that reads ``E2B_API_KEY`` from its environment keeps
    working. ``connection`` is the arcbox escape hatch."""

    def __init__(self, sandbox: ArcBoxSandbox) -> None:
        self._sandbox = sandbox
        #: Unique identifier of the sandbox.
        self.sandbox_id = sandbox.id
        #: Interact with the sandbox filesystem.
        self.files = AsyncFilesystem(sandbox.files)
        #: Run commands in the sandbox.
        self.commands = AsyncCommands(sandbox.commands)
        #: Drive pseudo-terminals in the sandbox.
        self.pty = AsyncPty(sandbox.commands)
        #: Run git operations in the sandbox.
        self.git = AsyncGit(self.commands)
        # Host ports resolved by expose_port, keyed by sandbox port.
        self._hosts: dict[int, str] = {}

    @classmethod
    async def create(
        cls,
        template: str | None = None,
        *,
        metadata: Mapping[str, str] | None = None,
        envs: Mapping[str, str] | None = None,
        timeout_ms: float = DEFAULT_SANDBOX_TIMEOUT_MS,
        allow_internet_access: bool | None = None,
        connection: Connection | None = None,
        **_cloud: object,
    ) -> AsyncSandbox:
        """Create a sandbox from a template."""
        sandbox = await AsyncArcBox(connection).create(
            normalize_template(template),
            ttl=seconds(timeout_ms),
            labels=metadata,
            env=envs,
            network=allow_internet_access,
        )
        return cls(sandbox)

    @classmethod
    async def connect(
        cls,
        sandbox_id: str,
        *,
        timeout_ms: float | None = None,
        connection: Connection | None = None,
        **_cloud: object,
    ) -> AsyncSandbox:
        """Attach to an existing sandbox, resuming it when paused."""
        handle = cls(await AsyncArcBox(connection).connect(sandbox_id))
        if timeout_ms is not None:
            await handle.set_timeout(timeout_ms)
        return handle

    @classmethod
    async def list(
        cls,
        *,
        metadata: Mapping[str, str] | None = None,
        state: list[str] | None = None,
        connection: Connection | None = None,
        **_cloud: object,
    ) -> list[SandboxInfo]:
        """List sandboxes.

        ``e2b`` returns a paginator; the arcbox SDK streams every page
        already, so this returns the whole listing."""
        rows: list[SandboxInfo] = []
        async with AsyncArcBox(connection) as client:
            async for summary in client.list(labels=metadata):
                if state is not None and summary.state not in state:
                    continue
                rows.append(
                    SandboxInfo(
                        sandbox_id=summary.id,
                        template_id="",
                        metadata=summary.labels,
                        state=summary.state,
                        started_at=summary.created_at,
                    )
                )
        return rows

    async def is_running(self) -> bool:
        """Whether the sandbox is running.

        ``False`` covers a missing sandbox too, matching ``e2b``, where
        a killed sandbox reports not-running rather than raising."""
        try:
            info = await self._sandbox.info()
        except NotFoundError:
            return False
        return info.state in {"ready", "running"}

    async def set_timeout(self, timeout_ms: float) -> None:
        """Re-arm the sandbox's lifetime, measured from now.

        ``e2b`` only ever extends; arcbox replaces, so a shorter value
        here genuinely shortens the sandbox's life."""
        await self._sandbox.set_lifecycle(ttl=seconds(timeout_ms))

    async def kill(self) -> bool:
        """Kill the sandbox. ``False`` when it was already gone.

        ``e2b`` also exposes a ``Sandbox.kill(sandbox_id)`` class form;
        Python cannot carry both under one name, so reach a sandbox you
        do not hold through ``Sandbox.connect(sandbox_id)`` first."""
        try:
            await self._sandbox.kill()
        except NotFoundError:
            return False
        return True

    async def pause(self) -> bool:
        """Pause the sandbox, checkpointing it under the same id."""
        await self._sandbox.pause()
        return True

    async def beta_pause(self) -> bool:
        """Deprecated ``e2b`` alias for :meth:`pause`."""
        return await self.pause()

    async def get_info(self) -> SandboxInfo:
        """Current state of the sandbox, in ``e2b``'s shape."""
        info = await self._sandbox.info()
        return SandboxInfo(
            sandbox_id=info.id,
            template_id=info.template,
            metadata=info.labels,
            state=info.state,
            started_at=info.created_at,
            end_at=info.ttl_deadline,
        )

    async def expose_port(self, port: int) -> str:
        """Publish a sandbox port onto the host and return ``host:port``.

        The one real divergence from ``e2b``, which serves every sandbox
        port through an edge proxy at ``{port}-{id}.e2b.app`` and so can
        answer synchronously without being told. ArcBox forwards a port
        only once it is asked to, which is what this awaits."""
        exposed = await self._sandbox.ports.expose(port)
        host = f"127.0.0.1:{exposed.host_port}"
        self._hosts[port] = host
        return host

    async def unexpose_port(self, port: int) -> None:
        """Withdraw a port published by :meth:`expose_port`."""
        await self._sandbox.ports.unexpose(port)
        self._hosts.pop(port, None)

    def get_host(self, port: int) -> str:
        """``host:port`` for a port already published by :meth:`expose_port`.

        Synchronous, like ``e2b``'s — but a port this handle has not
        exposed raises instead of returning a plausible address that
        nothing is listening on."""
        host = self._hosts.get(port)
        if host is None:
            unsupported(
                "get_host",
                f"port {port} is not published — await sandbox.expose_port({port}) "
                "first, since ArcBox forwards ports on request rather than through "
                "an edge proxy",
            )
        return host

    def create_snapshot(self, *args: object, **kwargs: object) -> None:
        """Unsupported: cloud snapshots that outlive their sandbox."""
        del args, kwargs
        unsupported(
            "create_snapshot",
            "ArcBox snapshots are local; use arcbox's checkpoint()/restore() directly",
        )

    def fork(self, *args: object, **kwargs: object) -> None:
        """Unsupported: forking needs the cloud's copy-on-write pool."""
        del args, kwargs
        unsupported("fork", "no local equivalent")

    def get_metrics(self, *args: object, **kwargs: object) -> None:
        """Unsupported: per-sandbox metrics are a cloud service."""
        del args, kwargs
        unsupported("get_metrics", "no local equivalent")

    def upload_url(self, *args: object, **kwargs: object) -> None:
        """Unsupported: signed URLs are served by the E2B edge."""
        del args, kwargs
        unsupported("upload_url", "use files.write instead")

    def download_url(self, *args: object, **kwargs: object) -> None:
        """Unsupported: signed URLs are served by the E2B edge."""
        del args, kwargs
        unsupported("download_url", "use files.read instead")

    def get_mcp_url(self, *args: object, **kwargs: object) -> None:
        """Unsupported: the MCP gateway is a cloud service."""
        del args, kwargs
        unsupported("get_mcp_url", "no local equivalent")

    async def __aenter__(self) -> AsyncSandbox:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self._sandbox.__aexit__(exc_type, exc, tb)
