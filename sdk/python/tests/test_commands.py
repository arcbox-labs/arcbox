"""commands.run against a mock daemon: exit-as-data, streaming, kill."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import httpx
import pytest
from google.protobuf import empty_pb2

from arcbox import AsyncSandbox, Connection, Sandbox
from arcbox._async._client import AsyncConnectClient
from arcbox._envelope import FLAG_END_STREAM, encode_envelope
from arcbox._gen import process_pb2
from arcbox._sync._client import ConnectClient
from arcbox._types import command_result_from_execution
from arcbox.errors import (
    ArcBoxError,
    CommandFailedError,
    InvalidArgumentError,
    SandboxDiedError,
    TimeoutError,
)

if TYPE_CHECKING:
    from google.protobuf.message import Message


def execution(
    state: process_pb2.ExecutionState,
    exit_code: int | None = None,
    signal: int | None = None,
) -> process_pb2.Execution:
    e = process_pb2.Execution(id="exec-1", sandbox_id="sb-1", state=state)
    if exit_code is not None:
        e.exit_status.code = exit_code
    if signal is not None:
        e.exit_status.signal = signal
    return e


class TestResultMapping:
    def test_exit_code_is_data(self) -> None:
        result = command_result_from_execution(
            execution(process_pb2.EXECUTION_STATE_EXITED, exit_code=3), "out", "err"
        )
        assert result.exit_code == 3
        assert result.signal is None
        with pytest.raises(CommandFailedError) as exc_info:
            result.expect()
        assert exc_info.value.result is result

    def test_signal_death_is_shell_convention(self) -> None:
        result = command_result_from_execution(
            execution(process_pb2.EXECUTION_STATE_EXITED, signal=9), "", ""
        )
        assert result.exit_code == 137
        assert result.signal == "SIGKILL"

    def test_session_break_is_sandbox_died_not_an_exit(self) -> None:
        broken = execution(process_pb2.EXECUTION_STATE_EXITED)
        broken.error = "vsock session lost"
        with pytest.raises(SandboxDiedError):
            command_result_from_execution(broken, "", "")

    def test_missing_exit_status_is_a_typed_error(self) -> None:
        with pytest.raises(ArcBoxError, match="without an exit status"):
            command_result_from_execution(execution(process_pb2.EXECUTION_STATE_EXITED), "", "")


def proto_response(message: Message) -> httpx.Response:
    return httpx.Response(
        200,
        content=message.SerializeToString(),
        headers={"content-type": "application/proto"},
    )


def stream_response(*frames: bytes) -> httpx.Response:
    body = b"".join(frames) + encode_envelope(FLAG_END_STREAM, b"{}")
    return httpx.Response(200, content=body, headers={"content-type": "application/connect+proto"})


class MockDaemon:
    """Handles the process-service RPCs the run loop issues."""

    def __init__(self, exit_code: int = 0) -> None:
        self.exit_code = exit_code
        self.started: list[process_pb2.StartExecutionRequest] = []
        self.signals: list[process_pb2.SignalExecutionRequest] = []
        self.waits: list[process_pb2.WaitExecutionRequest] = []
        #: states served by successive WaitExecution calls before EXITED.
        self.wait_states: list[process_pb2.ExecutionState] = []
        #: (channel, offset, data) triples replayed by AttachExecution.
        self.chunks: list[tuple[process_pb2.StdioChannel, int, bytes]] = [
            (process_pb2.STDIO_CHANNEL_STDOUT, 0, b"hello "),
            (process_pb2.STDIO_CHANNEL_STDOUT, 6, b"world\n"),
            (process_pb2.STDIO_CHANNEL_STDERR, 0, b"warn\n"),
        ]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/StartExecution"):
            self.started.append(process_pb2.StartExecutionRequest.FromString(request.content))
            return proto_response(execution(process_pb2.EXECUTION_STATE_RUNNING))
        if path.endswith("/WaitExecution"):
            self.waits.append(process_pb2.WaitExecutionRequest.FromString(request.content))
            if self.wait_states:
                return proto_response(execution(self.wait_states.pop(0)))
            return proto_response(
                execution(process_pb2.EXECUTION_STATE_EXITED, exit_code=self.exit_code)
            )
        if path.endswith("/SignalExecution"):
            self.signals.append(process_pb2.SignalExecutionRequest.FromString(request.content))
            return proto_response(empty_pb2.Empty())
        if path.endswith("/AttachExecution"):
            frames: list[bytes] = []
            for channel, offset, data in self.chunks:
                event = process_pb2.ExecutionEvent()
                event.output.channel = channel
                event.output.offset = offset
                event.output.data = data
                frames.append(encode_envelope(0, event.SerializeToString()))
            exited = process_pb2.ExecutionEvent()
            exited.exited.execution.CopyFrom(
                execution(process_pb2.EXECUTION_STATE_EXITED, exit_code=self.exit_code)
            )
            frames.append(encode_envelope(0, exited.SerializeToString()))
            return stream_response(*frames)
        if path.endswith("/Remove"):
            return proto_response(empty_pb2.Empty())
        return httpx.Response(404, content=b"unhandled: " + path.encode())


def sync_sandbox(daemon: MockDaemon) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


def test_foreground_run_collects_output_and_exit() -> None:
    daemon = MockDaemon(exit_code=0)
    result = sync_sandbox(daemon).commands.run(["/bin/echo", "hello world"])
    assert result.exit_code == 0
    assert result.stdout == "hello world\n"
    assert result.stderr == "warn\n"
    assert not result.truncated
    assert daemon.started[0].cmd[:1] == ["/bin/echo"]
    assert daemon.started[0].execution_id != ""


def test_shell_string_form_wraps_in_sh_lc() -> None:
    daemon = MockDaemon()
    sync_sandbox(daemon).commands.run("exit 0")
    assert list(daemon.started[0].cmd) == ["/bin/sh", "-lc", "exit 0"]


def test_non_zero_exit_is_data_and_check_raises() -> None:
    daemon = MockDaemon(exit_code=3)
    sandbox = sync_sandbox(daemon)
    assert sandbox.commands.run("exit 3").exit_code == 3
    with pytest.raises(CommandFailedError):
        sandbox.commands.run("exit 3", check=True)


def test_check_with_background_is_rejected() -> None:
    daemon = MockDaemon()
    with pytest.raises(InvalidArgumentError):
        # type ignore: the overloads already forbid this statically; the
        # runtime guard for untyped callers is what is under test.
        sync_sandbox(daemon).commands.run("x", check=True, background=True)  # type: ignore
    assert daemon.started == []


def test_background_streams_output_then_waits() -> None:
    daemon = MockDaemon(exit_code=0)
    handle = sync_sandbox(daemon).commands.run("emit", background=True)
    streamed = [(chunk.channel, chunk.data) for chunk in handle.output]
    assert streamed == [
        ("stdout", b"hello "),
        ("stdout", b"world\n"),
        ("stderr", b"warn\n"),
    ]
    result = handle.wait_for_exit(30)
    assert result.exit_code == 0
    handle.kill("SIGKILL")
    assert daemon.signals[0].signal == process_pb2.SIGNAL_SIGKILL


def test_wait_slices_are_capped_and_floored_to_the_wire_granularity() -> None:
    daemon = MockDaemon(exit_code=0)
    handle = sync_sandbox(daemon).commands.run("spin", background=True)
    handle.wait_for_exit(45)
    assert daemon.waits[-1].timeout_seconds == 30


def test_sub_second_wait_honors_its_deadline() -> None:
    daemon = MockDaemon(exit_code=0)
    daemon.wait_states = [process_pb2.EXECUTION_STATE_RUNNING]
    handle = sync_sandbox(daemon).commands.run("spin", background=True)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        handle.wait_for_exit(0.2)
    elapsed = time.monotonic() - started
    # One immediate poll (timeout_seconds=0) after sleeping out the
    # remainder — not the old 1 s minimum server slice.
    assert [w.timeout_seconds for w in daemon.waits] == [0]
    assert 0.2 <= elapsed < 1.0


def test_retention_gap_reports_truncation() -> None:
    daemon = MockDaemon(exit_code=0)
    # First retained stdout byte starts at offset 100: the head was dropped.
    daemon.chunks = [(process_pb2.STDIO_CHANNEL_STDOUT, 100, b"tail")]
    result = sync_sandbox(daemon).commands.run("big output")
    assert result.truncated
    assert result.stdout == "tail"


def test_output_context_closes_the_stream_on_early_exit() -> None:
    daemon = MockDaemon(exit_code=0)
    handle = sync_sandbox(daemon).commands.run("emit", background=True)
    with handle.output as stream:
        for _chunk in stream:
            break
    # The underlying generator was closed at scope exit, releasing the
    # HTTP stream; resuming it yields nothing.
    with pytest.raises(StopIteration):
        next(iter(stream))


@pytest.mark.anyio
async def test_async_output_context_closes_the_stream_on_early_exit() -> None:
    daemon = MockDaemon(exit_code=0)
    http = httpx.AsyncClient(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    sandbox = AsyncSandbox(AsyncConnectClient(Connection(http_client=http)), "sb-1")
    handle = await sandbox.commands.run("emit", background=True)
    async with handle.output as stream:
        async for _chunk in stream:
            break
    with pytest.raises(StopAsyncIteration):
        await anext(aiter(stream))


@pytest.mark.anyio
async def test_async_tree_runs_the_same_loop() -> None:
    daemon = MockDaemon(exit_code=0)
    http = httpx.AsyncClient(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    sandbox = AsyncSandbox(AsyncConnectClient(Connection(http_client=http)), "sb-1")
    handle = await sandbox.commands.run("emit", background=True)
    streamed = b""
    async for chunk in handle.output:
        if chunk.channel != "stderr":
            streamed += chunk.data
    assert streamed == b"hello world\n"
    result = await handle.wait_for_exit(30)
    assert result.exit_code == 0
