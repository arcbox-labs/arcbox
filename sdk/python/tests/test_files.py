"""files read/write against a mock daemon, incl. the mode-handling contract."""

from __future__ import annotations

import httpx
import pytest
from google.protobuf import empty_pb2

from arcbox import Connection, Sandbox
from arcbox._envelope import FLAG_END_STREAM, EnvelopeDecoder, encode_envelope
from arcbox._gen import filesystem_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import FileTooLargeError


class MockFilesystem:
    def __init__(self) -> None:
        self.writes: list[list[filesystem_pb2.WriteFileRequest]] = []
        #: chunks replayed by ReadFile.
        self.read_chunks: list[tuple[bytes, bool]] = [(b"hello ", False), (b"world", True)]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/WriteFile"):
            decoded = [
                filesystem_pb2.WriteFileRequest.FromString(payload)
                for _flags, payload in EnvelopeDecoder().feed(request.content)
            ]
            self.writes.append(decoded)
            body = encode_envelope(0, empty_pb2.Empty().SerializeToString()) + encode_envelope(
                FLAG_END_STREAM, b"{}"
            )
            return httpx.Response(
                200, content=body, headers={"content-type": "application/connect+proto"}
            )
        if path.endswith("/ReadFile"):
            frames = b""
            for data, done in self.read_chunks:
                chunk = filesystem_pb2.FileChunk(data=data, done=done)
                frames += encode_envelope(0, chunk.SerializeToString())
            frames += encode_envelope(FLAG_END_STREAM, b"{}")
            return httpx.Response(
                200, content=frames, headers={"content-type": "application/connect+proto"}
            )
        return httpx.Response(404, content=b"unhandled: " + path.encode())


def sandbox_for(daemon: MockFilesystem) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


def test_write_text_defaults_mode_to_0o644() -> None:
    daemon = MockFilesystem()
    sandbox_for(daemon).files.write_text("/tmp/hello.txt", "hi\n")
    frames = daemon.writes[0]
    assert frames[0].WhichOneof("payload") == "open"
    assert frames[0].open.path == "/tmp/hello.txt"
    assert frames[0].open.mode == 0o644
    assert frames[1].chunk.data == b"hi\n"
    assert frames[1].chunk.done


def test_write_bytes_honors_an_explicit_mode() -> None:
    daemon = MockFilesystem()
    sandbox_for(daemon).files.write_bytes("/x", b"data", mode=0o755)
    assert daemon.writes[0][0].open.mode == 0o755


def test_empty_file_still_sends_one_done_chunk() -> None:
    daemon = MockFilesystem()
    sandbox_for(daemon).files.write_bytes("/empty", b"")
    frames = daemon.writes[0]
    assert len(frames) == 2
    assert frames[1].chunk.data == b""
    assert frames[1].chunk.done


def test_large_writes_are_chunked_with_done_only_on_the_last() -> None:
    daemon = MockFilesystem()
    payload = bytes(300 * 1024)  # > one 256 KiB chunk
    sandbox_for(daemon).files.write_bytes("/big", payload)
    chunks = [f.chunk for f in daemon.writes[0][1:]]
    assert [len(c.data) for c in chunks] == [256 * 1024, 300 * 1024 - 256 * 1024]
    assert [c.done for c in chunks] == [False, True]


def test_oversized_writes_fail_before_any_request() -> None:
    daemon = MockFilesystem()
    sandbox = sandbox_for(daemon)
    with pytest.raises(FileTooLargeError) as exc_info:
        sandbox.files.write_bytes("/huge", bytes(256 * 1024 * 1024 + 1))
    assert exc_info.value.context["limit"] == str(256 * 1024 * 1024)
    assert daemon.writes == []


def test_read_bytes_assembles_chunks_until_done() -> None:
    daemon = MockFilesystem()
    sandbox = sandbox_for(daemon)
    assert sandbox.files.read_bytes("/f") == b"hello world"
    assert sandbox.files.read_text("/f") == "hello world"
