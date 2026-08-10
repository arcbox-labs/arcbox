"""The ``sandbox.files`` namespace in ``e2b``'s shape."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from arcbox.e2b._pump import AsyncPump, async_call, async_stop_watch
from arcbox.e2b._types import FileType, WriteInfo, to_entry_info, to_filesystem_event
from arcbox.errors import FileNotFoundError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from arcbox import AsyncFiles, AsyncFileWatch
    from arcbox.e2b._types import EntryInfo, FilesystemEvent


class AsyncWatchHandle:
    """A running directory watch, from :meth:`AsyncFilesystem.watch_dir`.

    :meth:`stop` cancels it; the sandbox stopping ends it cleanly on
    its own."""

    def __init__(self, watch: AsyncFileWatch, pump: AsyncPump, stopped: list[bool]) -> None:
        self._watch = watch
        self._pump = pump
        # Shared with the pump (a one-cell list, set before teardown): a
        # stream error after stop() is the clean end that was asked for,
        # not a watch failure.
        self._stopped = stopped

    async def stop(self) -> None:
        """Cancel the watch. Idempotent."""
        self._stopped[0] = True
        await async_stop_watch(self._pump, self._watch)


class AsyncFilesystem:
    """``e2b``'s ``Filesystem``, backed by arcbox's ``files``.

    The ``user`` argument is accepted and ignored: the daemon's file
    channel acts as the sandbox's own root, and silently succeeding
    under the wrong identity is better than failing on an argument most
    callers pass out of habit."""

    def __init__(self, files: AsyncFiles) -> None:
        self._files = files

    async def read(
        self,
        path: str,
        format: Literal["text", "bytes"] = "text",
        user: str | None = None,
    ) -> str | bytes:
        """Read a file. ``format='bytes'`` yields ``bytes``, else UTF-8 text."""
        del user
        if format == "bytes":
            return await self._files.read_bytes(path)
        return await self._files.read_text(path)

    async def write(self, path: str, data: str | bytes, user: str | None = None) -> WriteInfo:
        """Write one file."""
        del user
        if isinstance(data, str):
            await self._files.write_text(path, data)
        else:
            await self._files.write_bytes(path, data)
        return _write_info(path)

    async def write_files(self, entries: Sequence[tuple[str, str | bytes]]) -> list[WriteInfo]:
        """Write several files. Sequential — the wire has no batch write."""
        written: list[WriteInfo] = []
        for path, data in entries:
            written.append(await self.write(path, data))
        return written

    async def list(self, path: str) -> list[EntryInfo]:
        """List a directory's entries, non-recursively."""
        return [to_entry_info(entry, path) for entry in await self._files.list(path)]

    async def get_info(self, path: str) -> EntryInfo:
        """Metadata of one path."""
        return to_entry_info(await self._files.stat(path), _parent_of(path))

    async def exists(self, path: str) -> bool:
        """Whether the path exists."""
        try:
            await self._files.stat(path)
        except FileNotFoundError:
            return False
        return True

    async def make_dir(self, path: str) -> bool:
        """Create a directory and any missing parents.

        Returns ``False`` when it already existed, matching ``e2b``."""
        existed = await self.exists(path)
        await self._files.mkdir(path)
        return not existed

    async def rename(self, old_path: str, new_path: str) -> EntryInfo:
        """Rename or move an entry."""
        await self._files.move(old_path, new_path)
        return await self.get_info(new_path)

    async def remove(self, path: str) -> None:
        """Remove a file, symlink, or directory (recursively)."""
        # e2b's remove takes no recursive flag and deletes directories,
        # so the shim always asks for the recursive form.
        await self._files.remove(path, recursive=True)

    async def watch_dir(
        self,
        path: str,
        on_event: Callable[[FilesystemEvent], object],
        *,
        recursive: bool = False,
        on_exit: Callable[[BaseException | None], object] | None = None,
    ) -> AsyncWatchHandle:
        """Watch a directory and push each change into ``on_event`` —
        ``e2b``'s callback shape over arcbox's event iterable. Event
        paths are made relative to ``path``, matching ``e2b``'s ``name``
        field. ``on_exit`` fires once when the watch ends on its own
        (sandbox stop, or the error that killed it) — not on
        :meth:`AsyncWatchHandle.stop`."""
        watch = self._files.watch(path, recursive=recursive)
        prefix = path if path.endswith("/") else path + "/"
        stopped = [False]

        async def pump() -> None:
            error: BaseException | None = None
            try:
                async for event in watch:
                    shaped = to_filesystem_event(event, prefix)
                    if shaped is not None:
                        await async_call(on_event, shaped)
            except Exception as exc:
                if stopped[0]:
                    return
                error = exc
            if on_exit is not None:
                await async_call(on_exit, error)

        return AsyncWatchHandle(watch, AsyncPump(pump), stopped)


def _write_info(path: str) -> WriteInfo:
    return WriteInfo(name=_basename_of(path), path=path, type=FileType.FILE)


def _basename_of(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _parent_of(path: str) -> str:
    cut = path.rfind("/")
    return "/" if cut <= 0 else path[:cut]
