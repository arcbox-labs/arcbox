"""connect() lifecycle routing against a mock daemon.

The PAUSING case is the regression that matters: a pausing sandbox's
next stop is PAUSED — never READY — so connect must poll the checkpoint
out and then resume, not wait on readiness events that cannot arrive.
"""

from __future__ import annotations

import httpx
from google.protobuf import empty_pb2

from arcbox import ArcBox, Connection
from arcbox._envelope import FLAG_END_STREAM, encode_envelope
from arcbox._gen import sandbox_pb2


def _events_body() -> bytes:
    """What the daemon serves a pausing sandbox: a keepalive and no
    state change, because READY is not where it is headed. The real
    stream never ends; ending it here makes a connect that wrongly
    waits on readiness fail fast, and say why, instead of hanging."""
    keepalive = sandbox_pb2.WatchEventsResponse(keep_alive=sandbox_pb2.KeepAlive())
    return encode_envelope(0, keepalive.SerializeToString()) + encode_envelope(
        FLAG_END_STREAM, b"{}"
    )


class MockLifecycle:
    """Serves Inspect from a state script, counting every call it answers."""

    def __init__(self, states: list[sandbox_pb2.SandboxState]) -> None:
        #: Consumed one per Inspect; the last entry repeats.
        self.states = states
        self.resumes = 0
        #: The settle poll is witnessed by this count: ``resume``
        #: rewrites ``states`` unconditionally, so the post-state is
        #: ``[READY]`` whether or not a second Inspect ever ran.
        self.inspects = 0
        #: Readiness subscriptions opened. A PAUSING connect must open none.
        self.event_streams = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/Inspect"):
            self.inspects += 1
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            body = sandbox_pb2.SandboxInfo(id="sb-1", state=state).SerializeToString()
        elif path.endswith("/Resume"):
            self.resumes += 1
            self.states = [sandbox_pb2.SANDBOX_STATE_READY]
            body = empty_pb2.Empty().SerializeToString()
        elif path.endswith("/Events"):
            self.event_streams += 1
            return httpx.Response(
                200,
                content=_events_body(),
                headers={"content-type": "application/connect+proto"},
            )
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
    # The negative that gives the PAUSING count below its meaning: an
    # already-settled state routes off the first Inspect.
    assert daemon.inspects == 1
    assert daemon.resumes == 1


def test_connect_settles_a_pausing_sandbox_then_resumes() -> None:
    daemon = MockLifecycle([sandbox_pb2.SANDBOX_STATE_PAUSING, sandbox_pb2.SANDBOX_STATE_PAUSED])
    sandbox = connect_against(daemon).connect("sb-1")
    assert sandbox.id == "sb-1"
    # The checkpoint was polled out — a second Inspect ran — and exactly
    # one Resume followed. No readiness subscription was ever opened:
    # that is the regression, since READY is not where a pausing sandbox
    # is headed.
    assert daemon.inspects == 2
    assert daemon.event_streams == 0
    assert daemon.resumes == 1
