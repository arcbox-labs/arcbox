"""PTY and stdin against a mock daemon.

The invariant that matters: stdin writes are offset-idempotent. The
handle advances its cursor only on a successful response, so a retry of
a lost write lands at the SAME offset and the daemon's deduplication
swallows the duplicate — never a double feed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest
from google.protobuf import empty_pb2

from arcbox import AsyncSandbox, Connection, PtySize, Sandbox
from arcbox._async._client import AsyncConnectClient
from arcbox._envelope import FLAG_END_STREAM, encode_envelope
from arcbox._gen import process_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import ConnectionFailedError, InvalidArgumentError, SandboxStateError

if TYPE_CHECKING:
    from google.protobuf.message import Message


def proto_response(message: Message) -> httpx.Response:
    return httpx.Response(
        200,
        content=message.SerializeToString(),
        headers={"content-type": "application/proto"},
    )


class MockDaemon:
    """A process-service double tracking stdin acceptance like the guest."""

    def __init__(self) -> None:
        self.starts: list[process_pb2.StartExecutionRequest] = []
        self.writes: list[process_pb2.WriteStdinRequest] = []
        self.resizes: list[process_pb2.TerminalSize] = []
        self.accepted = 0
        self.closed = False
        #: Accept the next write, then fail its response (a lost response).
        self.fail_next_write_response = False
        #: Execution state served by WaitExecution polls.
        self.wait_state: process_pb2.ExecutionState = process_pb2.EXECUTION_STATE_EXITED
        #: Reject writes with this status code without accepting anything.
        self.reject_writes: int | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/StartExecution"):
            req = process_pb2.StartExecutionRequest.FromString(request.content)
            self.starts.append(req)
            running = process_pb2.EXECUTION_STATE_RUNNING
            return proto_response(process_pb2.Execution(id=req.execution_id, state=running))
        if path.endswith("/WriteStdin"):
            write = process_pb2.WriteStdinRequest.FromString(request.content)
            self.writes.append(write)
            if self.reject_writes is not None:
                body = b'{"code": "failed_precondition", "message": "execution has exited"}'
                return httpx.Response(self.reject_writes, content=body)
            if write.offset > self.accepted:
                return httpx.Response(416, content=b'{"message": "stdin gap"}')
            # Deduplicate bytes below the accepted count (the guest contract).
            fresh = write.offset + len(write.data) - self.accepted
            if fresh > 0:
                self.accepted += fresh
            if write.eof:
                self.closed = True
            if self.fail_next_write_response:
                self.fail_next_write_response = False
                raise httpx.ConnectError("connection reset", request=request)
            return proto_response(
                process_pb2.StdinStatus(bytes_written=self.accepted, closed=self.closed)
            )
        if path.endswith("/GetStdinStatus"):
            return proto_response(
                process_pb2.StdinStatus(bytes_written=self.accepted, closed=self.closed)
            )
        if path.endswith("/ResizeExecutionTty"):
            resize = process_pb2.ResizeExecutionTtyRequest.FromString(request.content)
            self.resizes.append(resize.size)
            return proto_response(empty_pb2.Empty())
        if path.endswith("/WaitExecution"):
            req = process_pb2.WaitExecutionRequest.FromString(request.content)
            execution = process_pb2.Execution(id=req.execution_id, state=self.wait_state)
            if self.wait_state == process_pb2.EXECUTION_STATE_EXITED:
                execution.exit_status.code = 0
            execution.stdin.bytes_written = self.accepted
            execution.stdin.closed = self.closed
            return proto_response(execution)
        if path.endswith("/AttachExecution"):
            exited = process_pb2.ExecutionEvent()
            exited.exited.execution.state = process_pb2.EXECUTION_STATE_EXITED
            exited.exited.execution.exit_status.code = 0
            body = encode_envelope(0, exited.SerializeToString()) + encode_envelope(
                FLAG_END_STREAM, b"{}"
            )
            return httpx.Response(
                200, content=body, headers={"content-type": "application/connect+proto"}
            )
        return httpx.Response(404, content=b"unhandled: " + path.encode())


def sync_sandbox(daemon: MockDaemon) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


class TestPty:
    def test_pty_starts_a_tty_execution_with_stdin_open(self) -> None:
        daemon = MockDaemon()
        sync_sandbox(daemon).commands.run("stty size", pty=PtySize(cols=120, rows=40))
        start = daemon.starts[0]
        assert start.tty is True
        assert (start.tty_size.width, start.tty_size.height) == (120, 40)
        assert start.stdin is True

    def test_a_plain_run_keeps_stdin_at_eof_without_a_tty(self) -> None:
        daemon = MockDaemon()
        sync_sandbox(daemon).commands.run("true")
        start = daemon.starts[0]
        assert start.tty is False
        assert start.stdin is False

    def test_resize_sends_the_new_geometry(self) -> None:
        daemon = MockDaemon()
        handle = sync_sandbox(daemon).commands.run(
            "sh", pty=PtySize(cols=80, rows=24), background=True
        )
        handle.resize(200, 50)
        assert (daemon.resizes[0].width, daemon.resizes[0].height) == (200, 50)

    def test_pty_with_one_shot_stdin_is_rejected_before_any_rpc(self) -> None:
        daemon = MockDaemon()
        with pytest.raises(InvalidArgumentError):
            sync_sandbox(daemon).commands.run("cat", pty=PtySize(cols=80, rows=24), stdin="x")
        assert daemon.starts == []


class TestStdin:
    def test_cursor_tracks_across_writes_and_close_lands_at_it(self) -> None:
        daemon = MockDaemon()
        handle = sync_sandbox(daemon).commands.run("cat", background=True, stdin=True)
        handle.write_stdin("hello ")
        handle.write_stdin("world\n")
        handle.close_stdin()
        assert [w.offset for w in daemon.writes] == [0, 6, 12]
        assert daemon.writes[2].eof is True
        assert daemon.accepted == 12
        assert daemon.closed is True

    def test_a_retried_lost_write_never_double_feeds(self) -> None:
        daemon = MockDaemon()
        handle = sync_sandbox(daemon).commands.run("cat", background=True, stdin=True)
        handle.write_stdin("hello ")
        # The daemon accepts the write but the response is lost.
        daemon.fail_next_write_response = True
        with pytest.raises(ConnectionFailedError):
            handle.write_stdin("world")
        assert daemon.accepted == 11
        # The cursor did not advance, so the retry lands at the same
        # offset and the daemon deduplicates it — the process saw the
        # bytes once.
        handle.write_stdin("world")
        assert daemon.writes[-1].offset == 6
        assert daemon.accepted == 11

    def test_stdin_status_reports_acceptance_and_resyncs(self) -> None:
        daemon = MockDaemon()
        handle = sync_sandbox(daemon).commands.run("cat", background=True, stdin=True)
        handle.write_stdin("abc")
        status = handle.stdin_status()
        assert status.bytes_written == 3
        assert status.closed is False

    def test_foreground_stdin_is_written_then_closed_before_the_wait(self) -> None:
        daemon = MockDaemon()
        result = sync_sandbox(daemon).commands.run("cat", stdin="fed\n")
        assert result.exit_code == 0
        assert daemon.starts[0].stdin is True
        assert [w.eof for w in daemon.writes] == [False, True]
        assert daemon.closed is True

    def test_a_feed_racing_an_early_exit_is_noise_not_a_failure(self) -> None:
        daemon = MockDaemon()
        daemon.reject_writes = 412
        daemon.wait_state = process_pb2.EXECUTION_STATE_EXITED
        result = sync_sandbox(daemon).commands.run("true", stdin="unread")
        assert result.exit_code == 0

    def test_a_feed_failure_with_the_process_still_running_is_real(self) -> None:
        daemon = MockDaemon()
        daemon.reject_writes = 412
        daemon.wait_state = process_pb2.EXECUTION_STATE_RUNNING
        with pytest.raises(SandboxStateError):
            sync_sandbox(daemon).commands.run("cat", stdin="data")

    def test_foreground_stdin_true_is_rejected_before_any_rpc(self) -> None:
        daemon = MockDaemon()
        with pytest.raises(InvalidArgumentError):
            sync_sandbox(daemon).commands.run("cat", stdin=True)
        assert daemon.starts == []


class TestGet:
    def test_get_reattaches_and_seeds_the_stdin_cursor(self) -> None:
        daemon = MockDaemon()
        daemon.accepted = 7
        daemon.wait_state = process_pb2.EXECUTION_STATE_RUNNING
        handle = sync_sandbox(daemon).commands.get("exec-9")
        assert handle.command_id == "exec-9"
        handle.write_stdin("more")
        assert daemon.writes[0].offset == 7


@pytest.mark.anyio
async def test_async_tree_runs_the_same_stdin_loop() -> None:
    daemon = MockDaemon()
    http = httpx.AsyncClient(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    sandbox = AsyncSandbox(AsyncConnectClient(Connection(http_client=http)), "sb-1")
    handle = await sandbox.commands.run("cat", background=True, stdin=True)
    await handle.write_stdin("ab")
    await handle.close_stdin()
    assert [w.offset for w in daemon.writes] == [0, 2]
    assert daemon.closed is True
    again = await sandbox.commands.get(handle.command_id)
    assert again.command_id == handle.command_id
