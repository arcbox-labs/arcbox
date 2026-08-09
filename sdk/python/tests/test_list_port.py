"""commands.list() and ports.wait_for_port() against a mock daemon.

The contracts under test: the Execution -> CommandInfo summary mapping
(running rows without exit fields, code exits, signal deaths as
128+signal, error-terminated executions), and wait_for_port's deadline
discipline -- the daemon's DEADLINE_EXCEEDED becomes a TimeoutError
naming the wait_for_port timeout knob, never the per-RPC one.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx
import pytest
from google.protobuf import empty_pb2

from arcbox import Connection, Sandbox
from arcbox._gen import process_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import NotFoundError, RequestTimeoutError, TimeoutError

if TYPE_CHECKING:
    from collections.abc import Callable

STARTED = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
EXITED = datetime(2026, 8, 1, 12, 0, 5, tzinfo=timezone.utc)


def proto_response(message: empty_pb2.Empty | process_pb2.ListExecutionsResponse) -> httpx.Response:
    return httpx.Response(
        200,
        content=message.SerializeToString(),
        headers={"content-type": "application/proto"},
    )


def sync_sandbox(handler: Callable[[httpx.Request], httpx.Response]) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


def listing_response() -> process_pb2.ListExecutionsResponse:
    running = process_pb2.Execution(
        id="running-cmd", state=process_pb2.EXECUTION_STATE_RUNNING, tty=True
    )
    running.started_at.FromDatetime(STARTED)
    done = process_pb2.Execution(id="done-cmd", state=process_pb2.EXECUTION_STATE_EXITED)
    done.started_at.FromDatetime(STARTED)
    done.exited_at.FromDatetime(EXITED)
    done.exit_status.code = 3
    killed = process_pb2.Execution(id="killed-cmd", state=process_pb2.EXECUTION_STATE_EXITED)
    killed.exit_status.signal = 9
    broken = process_pb2.Execution(
        id="broken-cmd", state=process_pb2.EXECUTION_STATE_EXITED, error="sandbox stopped"
    )
    return process_pb2.ListExecutionsResponse(executions=[running, done, killed, broken])


class TestList:
    def test_maps_running_and_exited_executions_to_summaries(self) -> None:
        requests: list[process_pb2.ListExecutionsRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/ListExecutions")
            requests.append(process_pb2.ListExecutionsRequest.FromString(request.content))
            return proto_response(listing_response())

        rows = sync_sandbox(handler).commands.list()
        assert requests[0].sandbox_id == "sb-1"
        running, done, killed, broken = rows
        assert (running.command_id, running.tty, running.state) == ("running-cmd", True, "running")
        assert running.started_at == STARTED
        assert (running.exit_code, running.signal, running.exited_at) == (None, None, None)
        assert (done.state, done.exit_code, done.signal) == ("exited", 3, None)
        assert (done.started_at, done.exited_at) == (STARTED, EXITED)
        assert (killed.exit_code, killed.signal) == (137, "SIGKILL")
        assert (broken.exit_code, broken.error) == (None, "sandbox stopped")


class TestWaitForPort:
    def test_resolves_when_a_listener_comes_up_sending_the_requested_budget(self) -> None:
        requests: list[process_pb2.WaitForPortRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/WaitForPort")
            requests.append(process_pb2.WaitForPortRequest.FromString(request.content))
            return proto_response(empty_pb2.Empty())

        sync_sandbox(handler).ports.wait_for_port(8080, timeout=10)
        assert requests[0].sandbox_id == "sb-1"
        assert requests[0].port == 8080
        assert requests[0].timeout_seconds == 10

    def test_no_timeout_sends_zero_the_daemon_default(self) -> None:
        requests: list[process_pb2.WaitForPortRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(process_pb2.WaitForPortRequest.FromString(request.content))
            return proto_response(empty_pb2.Empty())

        sync_sandbox(handler).ports.wait_for_port(80)
        assert requests[0].timeout_seconds == 0

    def test_the_daemon_deadline_becomes_a_timeout_error_naming_the_knob(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            body = json.dumps(
                {"code": "deadline_exceeded", "message": "no listener on port 8080 within 10s"}
            ).encode()
            return httpx.Response(504, content=body)

        with pytest.raises(TimeoutError) as exc_info:
            sync_sandbox(handler).ports.wait_for_port(8080, timeout=10)
        assert not isinstance(exc_info.value, RequestTimeoutError)
        assert exc_info.value.operation == "ports.wait_for_port"
        assert exc_info.value.suggestion is not None
        assert "wait_for_port timeout" in exc_info.value.suggestion
        assert exc_info.value.context == {"port": "8080", "timeout_seconds": "10"}
        assert isinstance(exc_info.value.__cause__, RequestTimeoutError)

    def test_a_non_deadline_daemon_error_keeps_its_own_class(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            body = json.dumps({"code": "not_found", "message": "sandbox gone"}).encode()
            return httpx.Response(404, content=body)

        with pytest.raises(NotFoundError):
            sync_sandbox(handler).ports.wait_for_port(80)
