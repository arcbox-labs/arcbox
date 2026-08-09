"""files.watch() against a mock daemon.

The contracts under test: typed FsEvent mapping with rename pairing,
keepalive filtering, the clean server-side end (the daemon's
SandboxFileWatchEnd) terminating the iterator, early exit via the
context manager, the overflow error surfacing with its
re-list-and-re-watch guidance (never reshaped into a connection error),
and a mid-stream transport drop becoming ConnectionLostError -- watch
events cannot be replayed, so the SDK never auto-reconnects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest

from arcbox import Connection, Sandbox
from arcbox._envelope import FLAG_END_STREAM, encode_envelope
from arcbox._gen import filesystem_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import ArcBoxError, ConnectionFailedError, ConnectionLostError

if TYPE_CHECKING:
    from collections.abc import Callable


def event_frame(kind: filesystem_pb2.FsEventKind, path: str, renamed_to: str = "") -> bytes:
    frame = filesystem_pb2.WatchDirResponse(
        event=filesystem_pb2.FsEvent(kind=kind, path=path, renamed_to=renamed_to)
    )
    return encode_envelope(0, frame.SerializeToString())


def keepalive_frame() -> bytes:
    frame = filesystem_pb2.WatchDirResponse()
    frame.keep_alive.SetInParent()
    return encode_envelope(0, frame.SerializeToString())


def watch_response(frames: list[bytes], truncated: bool = False) -> httpx.Response:
    body = b"".join(frames)
    if not truncated:
        body += encode_envelope(FLAG_END_STREAM, b"{}")
    return httpx.Response(200, content=body, headers={"content-type": "application/connect+proto"})


def sync_sandbox(handler: Callable[[httpx.Request], httpx.Response]) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


def test_yields_typed_events_pairs_renames_and_filters_keepalives() -> None:
    requests: list[filesystem_pb2.WatchDirRequest] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/WatchDir")
        # The request body is one enveloped WatchDirRequest.
        requests.append(filesystem_pb2.WatchDirRequest.FromString(request.content[5:]))
        return watch_response(
            [
                keepalive_frame(),  # the establishment confirmation
                event_frame(filesystem_pb2.FS_EVENT_KIND_CREATED, "/tmp/w/a.bin"),
                event_frame(filesystem_pb2.FS_EVENT_KIND_MODIFIED, "/tmp/w/a.bin"),
                keepalive_frame(),
                event_frame(filesystem_pb2.FS_EVENT_KIND_RENAMED, "/tmp/w/a.bin", "/tmp/w/b.bin"),
                event_frame(filesystem_pb2.FS_EVENT_KIND_REMOVED, "/tmp/w/b.bin"),
            ]
        )

    sandbox = sync_sandbox(handler)
    events = list(sandbox.files.watch("/tmp/w", recursive=True))
    assert requests[0].id == "sb-1"
    assert requests[0].path == "/tmp/w"
    assert requests[0].recursive is True
    assert [(e.kind, e.path, e.renamed_to) for e in events] == [
        ("created", "/tmp/w/a.bin", None),
        ("modified", "/tmp/w/a.bin", None),
        ("renamed", "/tmp/w/a.bin", "/tmp/w/b.bin"),
        ("removed", "/tmp/w/b.bin", None),
    ]


def test_early_exit_via_the_context_closes_the_watch() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return watch_response([event_frame(filesystem_pb2.FS_EVENT_KIND_CREATED, "/tmp/w/x")] * 5)

    sandbox = sync_sandbox(handler)
    with sandbox.files.watch("/tmp/w") as watch:
        for event in watch:
            assert event.kind == "created"
            break
    with pytest.raises(StopIteration):
        next(iter(watch))


def test_the_overflow_error_surfaces_with_its_rescan_guidance() -> None:
    # The daemon's documented overflow shape: the guest fails the stream
    # (a Connect `internal` error frame) rather than silently streaming
    # a wrong view.
    def handler(_request: httpx.Request) -> httpx.Response:
        end = (
            b'{"error": {"code": "internal", "message": '
            b'"watch overflowed: the kernel dropped events; re-list and re-watch"}}'
        )
        body = event_frame(filesystem_pb2.FS_EVENT_KIND_CREATED, "/tmp/w/a") + encode_envelope(
            FLAG_END_STREAM, end
        )
        return httpx.Response(
            200, content=body, headers={"content-type": "application/connect+proto"}
        )

    sandbox = sync_sandbox(handler)
    with pytest.raises(ArcBoxError, match="re-list and re-watch") as exc_info:
        for _event in sandbox.files.watch("/tmp/w"):
            pass
    assert not isinstance(exc_info.value, ConnectionFailedError)


def test_a_mid_stream_drop_is_the_stream_death_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return watch_response(
            [event_frame(filesystem_pb2.FS_EVENT_KIND_CREATED, "/tmp/w/a")], truncated=True
        )

    sandbox = sync_sandbox(handler)
    with pytest.raises(ConnectionLostError):
        for _event in sandbox.files.watch("/tmp/w"):
            pass


def test_a_server_signaled_unavailable_end_frame_is_also_stream_death() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        end = b'{"error": {"code": "unavailable", "message": "watch source lost"}}'
        body = keepalive_frame() + encode_envelope(FLAG_END_STREAM, end)
        return httpx.Response(
            200, content=body, headers={"content-type": "application/connect+proto"}
        )

    sandbox = sync_sandbox(handler)
    with pytest.raises(ConnectionLostError):
        for _event in sandbox.files.watch("/tmp/w"):
            pass
