"""The ``sandbox.files`` namespace: move bytes in and out of one sandbox.

Bytes-first — text variants are explicit UTF-8 conveniences, never a
silent default.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from google.protobuf import empty_pb2

from arcbox._boundary import wrap_errors
from arcbox._gen import filesystem_pb2
from arcbox._types import MAX_FILE_BYTES, file_stat_from_proto, fs_event_from_proto
from arcbox.errors import ConnectionFailedError, ConnectionLostError, FileTooLargeError

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator
    from pathlib import PurePosixPath
    from types import TracebackType

    from arcbox._types import FileStat, FsEvent

    from ._client import AsyncConnectClient

_FILESYSTEM = "/arcbox.sandbox.v1.SandboxFilesystemService/"

#: Chunk size for streamed writes.
_WRITE_CHUNK_BYTES = 256 * 1024

#: Default permission bits for created files (mirrors the daemon's default).
_DEFAULT_WRITE_MODE = 0o644


class AsyncFileWatch:
    """A directory watch, iterable one typed filesystem event at a time.

    The iterator ends when the daemon ends the stream (the sandbox
    stopped). When exiting early (``break``), iterate inside the
    context-manager form — ``async with files.watch(...) as watch`` in
    the async flavor, ``with`` in the sync one — so the watch closes at
    the break instead of whenever the generator finalizer runs."""

    def __init__(self, events: AsyncGenerator[FsEvent]) -> None:
        self._events = events

    def __aiter__(self) -> AsyncIterator[FsEvent]:
        return self._events

    async def aclose(self) -> None:
        """Cancel the watch without consuming the rest."""
        await self._events.aclose()

    async def __aenter__(self) -> AsyncFileWatch:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


class AsyncFiles:
    """Move bytes in and out of one sandbox, and operate on its paths.

    Paths are absolute POSIX paths inside the sandbox rootfs — ``str``
    or :class:`pathlib.PurePosixPath` (a host ``Path`` qualifies on
    POSIX systems).
    """

    def __init__(self, client: AsyncConnectClient, sandbox_id: str) -> None:
        self._client = client
        self._sandbox_id = sandbox_id

    async def read_bytes(self, path: str | PurePosixPath) -> bytes:
        """Read a file as raw bytes."""
        with wrap_errors("files.read_bytes"):
            chunks: list[bytes] = []
            async with self._client.stream(
                _FILESYSTEM + "ReadFile",
                filesystem_pb2.ReadFileRequest(id=self._sandbox_id, path=str(path)),
                filesystem_pb2.FileChunk,
            ) as stream:
                async for chunk in stream:
                    if chunk.data:
                        chunks.append(chunk.data)
                    if chunk.done:
                        break
            return b"".join(chunks)

    async def read_text(self, path: str | PurePosixPath, encoding: str = "utf-8") -> str:
        """Read a file and decode it (UTF-8 by default)."""
        return (await self.read_bytes(path)).decode(encoding)

    async def write_bytes(
        self, path: str | PurePosixPath, data: bytes, mode: int | None = None
    ) -> None:
        """Write raw bytes to a file, creating or truncating it.

        ``mode`` is the Unix permission bits for the created file
        (default 0o644). The wire protocol reserves 0 as "use the
        default" (`filesystem.proto`), so a literal mode of 0 is not
        expressible — it also yields 0o644.
        """
        if len(data) > MAX_FILE_BYTES:
            raise FileTooLargeError(
                f"file of {len(data)} bytes exceeds the {MAX_FILE_BYTES}-byte per-file cap",
                operation="files.write_bytes",
                context={
                    "path": str(path),
                    "limit": str(MAX_FILE_BYTES),
                    "size": str(len(data)),
                },
            )
        requests = [
            filesystem_pb2.WriteFileRequest(
                open=filesystem_pb2.WriteFileOpen(
                    id=self._sandbox_id,
                    path=str(path),
                    mode=_DEFAULT_WRITE_MODE if mode is None else mode,
                )
            )
        ]
        # Always send at least one chunk so `done` is observed, even for
        # an empty file.
        offset = 0
        while True:
            end = min(offset + _WRITE_CHUNK_BYTES, len(data))
            done = end == len(data)
            requests.append(
                filesystem_pb2.WriteFileRequest(
                    chunk=filesystem_pb2.FileChunk(data=data[offset:end], done=done)
                )
            )
            if done:
                break
            offset = end
        with wrap_errors("files.write_bytes"):
            await self._client.client_stream(_FILESYSTEM + "WriteFile", requests, empty_pb2.Empty)

    async def write_text(
        self,
        path: str | PurePosixPath,
        text: str,
        encoding: str = "utf-8",
        mode: int | None = None,
    ) -> None:
        """Write text to a file (UTF-8 by default)."""
        await self.write_bytes(path, text.encode(encoding), mode)

    async def stat(self, path: str | PurePosixPath) -> FileStat:
        """Metadata for one path. Symlinks are reported (kind
        ``"symlink"`` with ``symlink_target``), not followed. A missing
        path raises :class:`arcbox.errors.FileNotFoundError` carrying
        the path in its context."""
        with wrap_errors("files.stat"):
            return file_stat_from_proto(
                await self._client.unary(
                    _FILESYSTEM + "Stat",
                    filesystem_pb2.StatFileRequest(id=self._sandbox_id, path=str(path)),
                    filesystem_pb2.FileStat,
                )
            )

    async def list(self, path: str | PurePosixPath) -> list[FileStat]:
        """A directory's entries, non-recursively. Every entry carries
        full :class:`FileStat` metadata — no per-entry stat
        round-trips needed."""
        with wrap_errors("files.list"):
            listing = await self._client.unary(
                _FILESYSTEM + "ListDir",
                filesystem_pb2.ListDirRequest(id=self._sandbox_id, path=str(path)),
                filesystem_pb2.ListDirResponse,
            )
            return [file_stat_from_proto(entry) for entry in listing.entries]

    async def mkdir(self, path: str | PurePosixPath, mode: int | None = None) -> None:
        """Create a directory. Always ``mkdir -p``: missing parents are
        created and an existing directory succeeds — the daemon exposes
        no non-recursive variant (`filesystem.proto`).

        ``mode`` is the Unix permission bits for created directories
        (default 0o755). The wire protocol reserves 0 as "use the
        default", so a literal mode of 0 is not expressible — it also
        yields 0o755."""
        with wrap_errors("files.mkdir"):
            await self._client.unary(
                _FILESYSTEM + "MakeDir",
                filesystem_pb2.MakeDirRequest(
                    id=self._sandbox_id, path=str(path), mode=0 if mode is None else mode
                ),
                empty_pb2.Empty,
            )

    async def remove(self, path: str | PurePosixPath, recursive: bool = False) -> None:
        """Remove a file, symlink, or directory. A non-empty directory
        requires ``recursive=True`` — without it the daemon refuses
        with a precondition error."""
        with wrap_errors("files.remove"):
            await self._client.unary(
                _FILESYSTEM + "Remove",
                filesystem_pb2.RemoveEntryRequest(
                    id=self._sandbox_id, path=str(path), recursive=recursive
                ),
                empty_pb2.Empty,
            )

    async def move(self, src: str | PurePosixPath, dst: str | PurePosixPath) -> None:
        """Rename / move a file or directory within the sandbox."""
        with wrap_errors("files.move"):
            await self._client.unary(
                _FILESYSTEM + "Move",
                filesystem_pb2.MoveEntryRequest(
                    id=self._sandbox_id, from_path=str(src), to_path=str(dst)
                ),
                empty_pb2.Empty,
            )

    def watch(self, path: str | PurePosixPath, recursive: bool = False) -> AsyncFileWatch:
        """Watch a directory for filesystem events, yielded as typed
        :class:`FsEvent` values (keepalive frames are filtered out).
        Push-based — the guest watches inotify directly, never a
        polling fallback; a rename within the watched tree arrives as
        one ``"renamed"`` event pairing ``path`` (old) with
        ``renamed_to`` (new).

        The iterator ends when the daemon ends the stream (the sandbox
        stopped); closing the watch (or its context) cancels it. A
        transport drop mid-stream is surfaced as
        :class:`arcbox.errors.ConnectionLostError` — re-watching is the
        caller's decision, since missed events cannot be replayed (the
        same rule as ``sandbox.events()``). When the kernel's event
        queue overflows, the daemon fails the stream with its
        re-list-and-re-watch guidance rather than silently streaming a
        wrong view."""
        return AsyncFileWatch(self._stream_watch(str(path), recursive))

    async def _stream_watch(self, path: str, recursive: bool) -> AsyncGenerator[FsEvent]:
        with wrap_errors("files.watch"):
            entered = False
            try:
                async with self._client.stream(
                    _FILESYSTEM + "WatchDir",
                    filesystem_pb2.WatchDirRequest(
                        id=self._sandbox_id, path=path, recursive=recursive
                    ),
                    filesystem_pb2.WatchDirResponse,
                ) as stream:
                    entered = True
                    async for frame in stream:
                        if frame.WhichOneof("payload") == "event":
                            yield fs_event_from_proto(frame.event)
            # ConnectionFailedError covers the drop's OTHER wire shape:
            # the daemon losing its upstream watch ends the HTTP stream
            # cleanly with a Connect `unavailable` error frame.
            # Daemon-typed errors (including the overflow's
            # re-list-and-re-watch guidance) map to other classes and
            # keep them.
            except (httpx.HTTPError, ConnectionFailedError) as exc:
                if not entered or isinstance(exc, ConnectionLostError):
                    # Before entry: a dial failure — the daemon was
                    # never reached. ConnectionLostError is already the
                    # stream-death error.
                    raise
                raise ConnectionLostError(
                    "the watch stream died",
                    context={"path": path},
                    operation="files.watch",
                ) from exc
