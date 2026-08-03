"""connect() lifecycle routing against a mock daemon.

The PAUSING case is the regression that matters: a pausing sandbox's
next stop is PAUSED — never READY — so connect must poll the checkpoint
out and then resume, not wait on readiness events that cannot arrive.
"""

from __future__ import annotations

import httpx
from google.protobuf import empty_pb2

from arcbox import ArcBox, Connection
from arcbox._gen import sandbox_pb2


class MockLifecycle:
    """Serves Inspect from a state script and records Resume calls."""

    def __init__(self, states: list[sandbox_pb2.SandboxState]) -> None:
        #: Consumed one per Inspect; the last entry repeats.
        self.states = states
        self.resumes = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/Inspect"):
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            body = sandbox_pb2.SandboxInfo(id="sb-1", state=state).SerializeToString()
        elif path.endswith("/Resume"):
            self.resumes += 1
            self.states = [sandbox_pb2.SANDBOX_STATE_READY]
            body = empty_pb2.Empty().SerializeToString()
        else:
            return httpx.Response(404, content=b"unhandled: " + path.encode())
        return httpx.Response(200, content=body, headers={"content-type": "application/proto"})


def connect_against(daemon: MockLifecycle) -> ArcBox:
    http = httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    return ArcBox(Connection(http_client=http))


def test_connect_resumes_a_paused_sandbox() -> None:
    daemon = MockLifecycle([sandbox_pb2.SANDBOX_STATE_PAUSED])
    sandbox = connect_against(daemon).connect("sb-1")
    assert sandbox.id == "sb-1"
    assert daemon.resumes == 1


def test_connect_settles_a_pausing_sandbox_then_resumes() -> None:
    daemon = MockLifecycle([sandbox_pb2.SANDBOX_STATE_PAUSING, sandbox_pb2.SANDBOX_STATE_PAUSED])
    sandbox = connect_against(daemon).connect("sb-1")
    assert sandbox.id == "sb-1"
    # The checkpoint was polled out (a second Inspect ran) and exactly
    # one Resume followed — not a readiness-event wait that never ends.
    assert daemon.states == [sandbox_pb2.SANDBOX_STATE_READY]
    assert daemon.resumes == 1
