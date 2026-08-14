"""The places where e2b's contract and arcbox's disagree.

Everything else is a rename. These cover the behavioural inversions —
raise-on-nonzero, push-callback output, milliseconds, the port model —
plus the honest refusals.
"""

from __future__ import annotations

import threading

import httpx
import pytest
from google.protobuf import empty_pb2
from google.protobuf.message import Message

from arcbox import Connection
from arcbox import Sandbox as ArcBoxSandbox
from arcbox._envelope import FLAG_END_STREAM, encode_envelope
from arcbox._gen import filesystem_pb2, process_pb2, sandbox_pb2
from arcbox._sync._client import ConnectClient
from arcbox.e2b import (
    CommandExitException,
    NotFoundException,
    Sandbox,
    SandboxException,
    UnsupportedException,
    permission_string,
)
from arcbox.errors import ArcBoxError
from arcbox.errors import NotFoundError as ArcBoxNotFoundError


class MockDaemon:
    """Answers just enough of the wire to exercise the shim."""

    def __init__(self) -> None:
        self.exit_code = 0
        #: (channel, text) pairs the one mock command replays.
        self.chunks: list[tuple[process_pb2.StdioChannel, str]] = []
        self.host_port = 49152
        #: (kind, path) pairs the mock WatchDir stream replays.
        self.watch_events: list[tuple[filesystem_pb2.FsEventKind, str]] = []
        self.creates: list[sandbox_pb2.CreateSandboxRequest] = []
        self.lifecycles: list[sandbox_pb2.SetLifecycleRequest] = []

    def _execution(self, exited: bool) -> process_pb2.Execution:
        execution = process_pb2.Execution(id="cmd", sandbox_id="sb-1")
        if exited:
            execution.state = process_pb2.EXECUTION_STATE_EXITED
            execution.exit_status.code = self.exit_code
        else:
            execution.state = process_pb2.EXECUTION_STATE_RUNNING
        return execution

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/Create"):
            self.creates.append(sandbox_pb2.CreateSandboxRequest.FromString(request.content))
            return _proto(sandbox_pb2.CreateSandboxResponse())
        if path.endswith("/Inspect"):
            return _proto(
                sandbox_pb2.SandboxInfo(
                    id="sb-1", state=sandbox_pb2.SANDBOX_STATE_READY, template="base"
                )
            )
        if path.endswith("/SetLifecycle"):
            self.lifecycles.append(sandbox_pb2.SetLifecycleRequest.FromString(request.content))
            return _proto(empty_pb2.Empty())
        if path.endswith("/Events"):
            # create() arms the readiness subscription before Create;
            # Inspect already answers READY, so nothing needs to arrive
            # on it.
            return _stream([])
        if path.endswith("/Remove"):
            return _proto(empty_pb2.Empty())
        if path.endswith("/ExposePort"):
            return _proto(sandbox_pb2.ExposePortResponse(host_port=self.host_port))
        if path.endswith("/StartExecution"):
            return _proto(self._execution(exited=False))
        if path.endswith("/WaitExecution"):
            return _proto(self._execution(exited=True))
        if path.endswith("/AttachExecution"):
            return _stream(self._attach_frames())
        if path.endswith("/ListExecutions"):
            running = self._execution(exited=False)
            done = process_pb2.Execution(
                id="done-cmd", sandbox_id="sb-1", state=process_pb2.EXECUTION_STATE_EXITED
            )
            return _proto(process_pb2.ListExecutionsResponse(executions=[running, done]))
        if path.endswith("/WatchDir"):
            frames: list[bytes] = []
            for kind, event_path in self.watch_events:
                frame = filesystem_pb2.WatchDirResponse()
                frame.event.kind = kind
                frame.event.path = event_path
                frames.append(encode_envelope(0, frame.SerializeToString()))
            return _stream(frames)
        if path.endswith("/ListDir"):
            return _proto(
                filesystem_pb2.ListDirResponse(
                    entries=[
                        filesystem_pb2.FileStat(
                            name="a.txt",
                            kind=filesystem_pb2.FILE_KIND_FILE,
                            size=3,
                            mode=0o644,
                            uid=1000,
                            gid=1000,
                        ),
                        filesystem_pb2.FileStat(
                            name="sub", kind=filesystem_pb2.FILE_KIND_DIRECTORY, mode=0o755
                        ),
                    ]
                )
            )
        return httpx.Response(404, content=b"unhandled: " + path.encode())

    def _attach_frames(self) -> list[bytes]:
        frames: list[bytes] = []
        offsets: dict[int, int] = {}
        for channel, text in self.chunks:
            data = text.encode()
            event = process_pb2.ExecutionEvent()
            event.output.channel = channel
            event.output.offset = offsets.get(channel, 0)
            event.output.data = data
            offsets[channel] = offsets.get(channel, 0) + len(data)
            frames.append(encode_envelope(0, event.SerializeToString()))
        exited = process_pb2.ExecutionEvent()
        exited.exited.execution.CopyFrom(self._execution(exited=True))
        frames.append(encode_envelope(0, exited.SerializeToString()))
        return frames


def _proto(message: Message) -> httpx.Response:
    return httpx.Response(
        200,
        content=message.SerializeToString(),
        headers={"content-type": "application/proto"},
    )


def _stream(frames: list[bytes]) -> httpx.Response:
    body = b"".join(frames) + encode_envelope(FLAG_END_STREAM, b"{}")
    return httpx.Response(200, content=body, headers={"content-type": "application/connect+proto"})


def sandbox_for(daemon: MockDaemon) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    return Sandbox(ArcBoxSandbox(ConnectClient(Connection(http_client=http)), "sb-1"))


def connection_for(daemon: MockDaemon) -> Connection:
    return Connection(
        http_client=httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    )


def test_run_raises_on_a_non_zero_exit_unlike_arcbox() -> None:
    daemon = MockDaemon()
    daemon.exit_code = 3

    with pytest.raises(CommandExitException) as exc_info:
        sandbox_for(daemon).commands.run("false")

    assert exc_info.value.exit_code == 3


def test_run_returns_the_result_on_a_zero_exit() -> None:
    daemon = MockDaemon()
    daemon.chunks = [(process_pb2.STDIO_CHANNEL_STDOUT, "hi\n")]

    result = sandbox_for(daemon).commands.run("echo hi")

    assert result.exit_code == 0
    assert result.stdout == "hi\n"


def test_output_is_pushed_into_callbacks_rather_than_iterated() -> None:
    daemon = MockDaemon()
    daemon.chunks = [
        (process_pb2.STDIO_CHANNEL_STDOUT, "out"),
        (process_pb2.STDIO_CHANNEL_STDERR, "err"),
    ]
    out: list[str] = []
    err: list[str] = []

    sandbox_for(daemon).commands.run("echo", on_stdout=out.append, on_stderr=err.append)

    assert "".join(out) == "out"
    assert "".join(err) == "err"


def test_get_host_resolves_only_after_the_port_is_exposed() -> None:
    daemon = MockDaemon()
    sandbox = sandbox_for(daemon)

    # e2b answers get_host synchronously for any port because its edge
    # proxy fronts them all; ArcBox forwards on request, so an
    # un-exposed port must fail loudly rather than return a dead host.
    with pytest.raises(UnsupportedException):
        sandbox.get_host(8080)

    host = sandbox.expose_port(8080)

    assert host == "127.0.0.1:49152"
    assert sandbox.get_host(8080) == host


def test_create_translates_e2bs_names_and_units() -> None:
    daemon = MockDaemon()

    Sandbox.create(
        "base",
        timeout_ms=60_000,
        metadata={"app": "demo"},
        envs={"KEY": "value"},
        connection=connection_for(daemon),
    )

    request = daemon.creates[-1]
    # 'base' is e2b's default template name; arcbox spells its built-in
    # minimal template ''.
    assert request.template == ""
    # e2b counts milliseconds, arcbox seconds.
    assert request.ttl_seconds == 60
    assert dict(request.labels) == {"app": "demo"}
    assert dict(request.env) == {"KEY": "value"}


def test_create_applies_e2bs_default_timeout() -> None:
    daemon = MockDaemon()

    Sandbox.create(connection=connection_for(daemon))

    assert daemon.creates[-1].ttl_seconds == 300


def test_set_timeout_re_arms_only_the_ttl() -> None:
    daemon = MockDaemon()

    sandbox_for(daemon).set_timeout(120_000)

    request = daemon.lifecycles[-1]
    assert request.ttl_seconds == 120
    assert not request.HasField("idle_timeout_seconds")


def test_files_list_reports_e2bs_entry_shape() -> None:
    daemon = MockDaemon()

    entries = sandbox_for(daemon).files.list("/tmp")

    assert entries[0].name == "a.txt"
    assert entries[0].path == "/tmp/a.txt"
    assert entries[0].type == "file"
    assert entries[0].permissions == "-rw-r--r--"
    assert entries[0].owner == "1000"
    assert entries[1].type == "dir"
    assert entries[1].permissions == "drwxr-xr-x"


def test_commands_list_maps_running_executions_to_process_info() -> None:
    daemon = MockDaemon()

    infos = sandbox_for(daemon).commands.list()

    assert [info.pid for info in infos] == ["cmd"]


def test_watch_dir_pushes_e2b_shaped_events_with_relative_names() -> None:
    daemon = MockDaemon()
    daemon.watch_events = [
        (filesystem_pb2.FS_EVENT_KIND_CREATED, "/tmp/w/a.bin"),
        (filesystem_pb2.FS_EVENT_KIND_MODIFIED, "/tmp/w/a.bin"),
        (filesystem_pb2.FS_EVENT_KIND_RENAMED, "/tmp/w/a.bin"),
        (filesystem_pb2.FS_EVENT_KIND_REMOVED, "/tmp/w/a.bin"),
    ]
    seen: list[tuple[str, str]] = []
    ended = threading.Event()

    handle = sandbox_for(daemon).files.watch_dir(
        "/tmp/w",
        lambda event: seen.append((event.type.value, event.name)),
        on_exit=lambda _error: ended.set(),
    )
    assert ended.wait(timeout=5), "the watch pump never reached its clean end"
    handle.stop()

    assert seen == [
        ("create", "a.bin"),
        ("write", "a.bin"),
        ("rename", "a.bin"),
        ("remove", "a.bin"),
    ]


def test_permission_string_renders_the_usual_bit_patterns() -> None:
    assert permission_string(0o644, is_directory=False) == "-rw-r--r--"
    assert permission_string(0o755, is_directory=True) == "drwxr-xr-x"
    assert permission_string(0o000, is_directory=False) == "----------"
    assert permission_string(0o777, is_directory=False) == "-rwxrwxrwx"


def test_exceptions_are_aliases_so_an_arcbox_error_matches_an_e2b_except() -> None:
    # A fresh `class NotFoundException(ArcBoxError)` would sit beside
    # what the SDK raises and never match it.
    raised = ArcBoxNotFoundError("gone")

    assert isinstance(raised, NotFoundException)
    assert isinstance(raised, SandboxException)
    assert SandboxException is ArcBoxError


def test_the_unsupported_surface_is_named_rather_than_failing_quietly() -> None:
    daemon = MockDaemon()
    sandbox = sandbox_for(daemon)

    for call in (
        sandbox.fork,
        sandbox.get_metrics,
        sandbox.upload_url,
        sandbox.download_url,
        sandbox.get_mcp_url,
        sandbox.create_snapshot,
        sandbox.git.dangerously_authenticate,
    ):
        with pytest.raises(UnsupportedException):
            call()
