"""The ``sandbox.files`` namespace: move bytes in and out of one sandbox.

Bytes-first — text variants are explicit UTF-8 conveniences, never a
silent default.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from google.protobuf import empty_pb2

from arcbox._boundary import wrap_errors
from arcbox._gen import filesystem_pb2
from arcbox._types import MAX_FILE_BYTES
from arcbox.errors import FileTooLargeError

if TYPE_CHECKING:
    from ._client import AsyncConnectClient

_FILESYSTEM = "/arcbox.sandbox.v1.SandboxFilesystemService/"

#: Chunk size for streamed writes.
_WRITE_CHUNK_BYTES = 256 * 1024

#: Default permission bits for created files (mirrors the daemon's default).
_DEFAULT_WRITE_MODE = 0o644


class AsyncFiles:
    """Move bytes in and out of one sandbox."""

    def __init__(self, client: AsyncConnectClient, sandbox_id: str) -> None:
        self._client = client
        self._sandbox_id = sandbox_id

    async def read_bytes(self, path: str) -> bytes:
        """Read a file as raw bytes."""
        with wrap_errors("files.read_bytes"):
            chunks: list[bytes] = []
            async with self._client.stream(
                _FILESYSTEM + "ReadFile",
                filesystem_pb2.ReadFileRequest(id=self._sandbox_id, path=path),
                filesystem_pb2.FileChunk,
            ) as stream:
                async for chunk in stream:
                    if chunk.data:
                        chunks.append(chunk.data)
                    if chunk.done:
                        break
            return b"".join(chunks)

    async def read_text(self, path: str, encoding: str = "utf-8") -> str:
        """Read a file and decode it (UTF-8 by default)."""
        return (await self.read_bytes(path)).decode(encoding)

    async def write_bytes(self, path: str, data: bytes, mode: int | None = None) -> None:
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
                    "path": path,
                    "limit": str(MAX_FILE_BYTES),
                    "size": str(len(data)),
                },
            )
        requests = [
            filesystem_pb2.WriteFileRequest(
                open=filesystem_pb2.WriteFileOpen(
                    id=self._sandbox_id,
                    path=path,
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
        self, path: str, text: str, encoding: str = "utf-8", mode: int | None = None
    ) -> None:
        """Write text to a file (UTF-8 by default)."""
        await self.write_bytes(path, text.encode(encoding), mode)
