"""Offset-resume across stream death against a mock daemon.

The contract under test: when an attach stream drops mid-flow, the
handle re-attaches from the last DELIVERED per-channel offsets and the
consumer sees one seamless, gapless stream — the SDK's whole reason for
offset-addressed output. A truncated streaming body (no terminal
EndStreamResponse frame) IS the drop: the connection died mid-body.
Retries are bounded by consecutive dead dials; delivered output resets
the budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import pytest

from arcbox import AsyncSandbox, Connection, Sandbox
from arcbox._async._client import AsyncConnectClient
from arcbox._envelope import FLAG_END_STREAM, EnvelopeDecoder, encode_envelope
from arcbox._gen import process_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import ConnectionLostError, NotFoundError

if TYPE_CHECKING:
    from google.protobuf.message import Message


def proto_response(message: Message) -> httpx.Response:
    return httpx.Response(
        200,
        content=message.SerializeToString(),
        headers={"content-type": "application/proto"},
    )


def stream_response(frames: list[bytes], truncated: bool) -> httpx.Response:
    body = b"".join(frames)
    if not truncated:
        body += encode_envelope(FLAG_END_STREAM, b"{}")
    return httpx.Response(200, content=body, headers={"content-type": "application/connect+proto"})


def exited_execution() -> process_pb2.Execution:
    execution = process_pb2.Execution(id="cmd", state=process_pb2.EXECUTION_STATE_EXITED)
    execution.exit_status.code = 0
    return execution


@dataclass
class Chunk:
    channel: process_pb2.StdioChannel
    offset: int
    text: bytes


@dataclass
class FlakyDaemon:
    """Serves AttachExecution from a chunk script, truncating the body
    after ``die_after[n]`` chunks on the n-th attach (die forever once
    the script runs out). Replays only chunks at or past the requested
    offset, like the daemon."""

    chunks: list[Chunk]
    die_after: list[int]
    attaches: list[process_pb2.AttachExecutionRequest] = field(
        default_factory=list[process_pb2.AttachExecutionRequest]
    )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/StartExecution"):
            req = process_pb2.StartExecutionRequest.FromString(request.content)
            running = process_pb2.EXECUTION_STATE_RUNNING
            return proto_response(process_pb2.Execution(id=req.execution_id, state=running))
        if path.endswith("/WaitExecution"):
            return proto_response(exited_execution())
        if path.endswith("/AttachExecution"):
            _flags, payload = EnvelopeDecoder().feed(request.content)[0]
            attach = process_pb2.AttachExecutionRequest.FromString(payload)
            call = len(self.attaches)
            self.attaches.append(attach)
            budget = self.die_after[call] if call < len(self.die_after) else None
            frames: list[bytes] = []
            sent = 0
            for chunk in self.chunks:
                is_stderr = chunk.channel == process_pb2.STDIO_CHANNEL_STDERR
                from_offset = attach.stderr_offset if is_stderr else attach.stdout_offset
                if chunk.offset < from_offset:
                    continue
                if budget is not None and sent >= budget:
                    return stream_response(frames, truncated=True)
                event = process_pb2.ExecutionEvent()
                event.output.channel = chunk.channel
                event.output.offset = chunk.offset
                event.output.data = chunk.text
                frames.append(encode_envelope(0, event.SerializeToString()))
                sent += 1
            if budget is not None:
                return stream_response(frames, truncated=True)
            exited = process_pb2.ExecutionEvent()
            exited.exited.execution.CopyFrom(exited_execution())
            frames.append(encode_envelope(0, exited.SerializeToString()))
            return stream_response(frames, truncated=False)
        return httpx.Response(404, content=b"unhandled: " + path.encode())


def script() -> list[Chunk]:
    return [
        Chunk(process_pb2.STDIO_CHANNEL_STDOUT, 0, b"hel"),
        Chunk(process_pb2.STDIO_CHANNEL_STDERR, 0, b"warn"),
        Chunk(process_pb2.STDIO_CHANNEL_STDOUT, 3, b"lo "),
        Chunk(process_pb2.STDIO_CHANNEL_STDOUT, 6, b"world"),
    ]


def sync_sandbox(daemon: FlakyDaemon) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


def test_the_output_iterator_reattaches_from_the_delivered_offsets() -> None:
    # First attach dies after two chunks (stdout "hel" + stderr "warn").
    daemon = FlakyDaemon(script(), [2])
    handle = sync_sandbox(daemon).commands.run("emit", background=True)
    stdout = b""
    stderr = b""
    for chunk in handle.output:
        if chunk.channel == "stderr":
            stderr += chunk.data
        else:
            stdout += chunk.data
    # Seamless and gapless despite the mid-stream death.
    assert stdout == b"hello world"
    assert stderr == b"warn"
    assert len(daemon.attaches) == 2
    # The re-attach resumed exactly at the delivered high-water marks.
    assert daemon.attaches[1].stdout_offset == 3
    assert daemon.attaches[1].stderr_offset == 4


def test_repeated_drops_survive_while_each_dial_delivers_output() -> None:
    # Every attach dies after one delivered chunk; progress resets the
    # retry budget each time.
    daemon = FlakyDaemon(script(), [1, 1, 1, 1])
    handle = sync_sandbox(daemon).commands.run("emit", background=True)
    stdout = b"".join(c.data for c in handle.output if c.channel != "stderr")
    assert stdout == b"hello world"
    assert len(daemon.attaches) == 5


def test_wait_for_exit_result_collection_resumes_through_the_same_loop() -> None:
    daemon = FlakyDaemon(script(), [3])
    handle = sync_sandbox(daemon).commands.run("emit", background=True)
    result = handle.wait_for_exit(5)
    assert result.stdout == "hello world"
    assert result.stderr == "warn"
    # The resumed chunks were contiguous — no false truncation flag.
    assert result.truncated is False


def test_bounded_retries_exhaust_into_the_stream_death_error() -> None:
    # Every dial dies before delivering anything.
    daemon = FlakyDaemon(script(), [0] * 8)
    handle = sync_sandbox(daemon).commands.run("emit", background=True)
    with pytest.raises(ConnectionLostError) as exc_info:
        for _chunk in handle.output:
            pass
    assert exc_info.value.context["retries"] == "3"
    # The initial dial plus three re-dials.
    assert len(daemon.attaches) == 4


def test_a_server_signaled_unavailable_end_frame_is_retried() -> None:
    # The drop's other wire shape: the daemon loses its upstream agent
    # stream and ends the HTTP stream CLEANLY with a Connect
    # `unavailable` error frame. That must resume like raw truncation.
    attaches: list[process_pb2.AttachExecutionRequest] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/StartExecution"):
            req = process_pb2.StartExecutionRequest.FromString(request.content)
            running = process_pb2.EXECUTION_STATE_RUNNING
            return proto_response(process_pb2.Execution(id=req.execution_id, state=running))
        if path.endswith("/AttachExecution"):
            _flags, payload = EnvelopeDecoder().feed(request.content)[0]
            attach = process_pb2.AttachExecutionRequest.FromString(payload)
            attaches.append(attach)
            if len(attaches) == 1:
                event = process_pb2.ExecutionEvent()
                event.output.channel = process_pb2.STDIO_CHANNEL_STDOUT
                event.output.offset = 0
                event.output.data = b"hel"
                end = b'{"error": {"code": "unavailable", "message": "agent stream lost"}}'
                body = encode_envelope(0, event.SerializeToString()) + encode_envelope(
                    FLAG_END_STREAM, end
                )
                return httpx.Response(
                    200, content=body, headers={"content-type": "application/connect+proto"}
                )
            event = process_pb2.ExecutionEvent()
            event.output.channel = process_pb2.STDIO_CHANNEL_STDOUT
            event.output.offset = 3
            event.output.data = b"lo"
            exited = process_pb2.ExecutionEvent()
            exited.exited.execution.CopyFrom(exited_execution())
            frames = [
                encode_envelope(0, event.SerializeToString()),
                encode_envelope(0, exited.SerializeToString()),
            ]
            return stream_response(frames, truncated=False)
        return httpx.Response(404)

    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    sandbox = Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")
    handle = sandbox.commands.run("emit", background=True)
    stdout = b"".join(chunk.data for chunk in handle.output)
    assert stdout == b"hello"
    assert attaches[1].stdout_offset == 3


def test_a_daemon_typed_stream_error_is_surfaced_never_retried() -> None:
    attaches = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attaches
        path = request.url.path
        if path.endswith("/WaitExecution"):
            return proto_response(exited_execution())
        if path.endswith("/AttachExecution"):
            attaches += 1
            end = b'{"error": {"code": "not_found", "message": "no such execution"}}'
            body = encode_envelope(FLAG_END_STREAM, end)
            return httpx.Response(
                200, content=body, headers={"content-type": "application/connect+proto"}
            )
        return httpx.Response(404)

    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    sandbox = Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")
    handle = sandbox.commands.get("cmd")
    with pytest.raises(NotFoundError):
        for _chunk in handle.output:
            pass
    assert attaches == 1


@pytest.mark.anyio
async def test_async_tree_resumes_the_same_way() -> None:
    daemon = FlakyDaemon(script(), [2])
    http = httpx.AsyncClient(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    sandbox = AsyncSandbox(AsyncConnectClient(Connection(http_client=http)), "sb-1")
    handle = await sandbox.commands.run("emit", background=True)
    stdout = b""
    async for chunk in handle.output:
        if chunk.channel != "stderr":
            stdout += chunk.data
    assert stdout == b"hello world"
    assert daemon.attaches[1].stdout_offset == 3
