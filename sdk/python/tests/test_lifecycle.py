"""events(), set_lifecycle(), and the capabilities handshake against a
mock daemon.

set_lifecycle's tri-state is the contract that matters: an omitted knob
must be ABSENT on the wire (unchanged), None must be an explicit
zero/UNSPECIFIED (restore the default — the same meaning None has on
create), and a value must replace. Getting presence wrong silently
rewrites deadlines the caller never touched.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest
from google.protobuf import empty_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

from arcbox import UNCHANGED, ArcBox, AsyncArcBox, AsyncSandbox, Connection, Sandbox
from arcbox._async._client import AsyncConnectClient
from arcbox._envelope import FLAG_END_STREAM, encode_envelope
from arcbox._gen import sandbox_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import ConnectionFailedError, ConnectionLostError

if TYPE_CHECKING:
    from google.protobuf.message import Message


def proto_response(message: Message) -> httpx.Response:
    return httpx.Response(
        200,
        content=message.SerializeToString(),
        headers={"content-type": "application/proto"},
    )


def event_frame(kind: sandbox_pb2.SandboxEventKind, **attributes: str) -> bytes:
    frame = sandbox_pb2.WatchEventsResponse()
    frame.event.sandbox_id = "sb-1"
    frame.event.kind = kind
    for key, value in attributes.items():
        frame.event.attributes[key] = value
    return encode_envelope(0, frame.SerializeToString())


def keepalive_frame() -> bytes:
    frame = sandbox_pb2.WatchEventsResponse()
    frame.keep_alive.SetInParent()
    return encode_envelope(0, frame.SerializeToString())


def events_response(frames: list[bytes], truncated: bool = False) -> httpx.Response:
    body = b"".join(frames)
    if not truncated:
        body += encode_envelope(FLAG_END_STREAM, b"{}")
    return httpx.Response(200, content=body, headers={"content-type": "application/connect+proto"})


def sync_sandbox(handler: Callable[[httpx.Request], httpx.Response]) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


class TestEvents:
    def test_yields_typed_events_and_filters_keepalives(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/Events")
            return events_response(
                [
                    keepalive_frame(),
                    event_frame(sandbox_pb2.SANDBOX_EVENT_KIND_CREATED),
                    event_frame(sandbox_pb2.SANDBOX_EVENT_KIND_READY),
                    keepalive_frame(),
                    event_frame(sandbox_pb2.SANDBOX_EVENT_KIND_PAUSING, reason="idle_timeout"),
                    event_frame(sandbox_pb2.SANDBOX_EVENT_KIND_PAUSED),
                ]
            )

        sandbox = sync_sandbox(handler)
        kinds: list[str] = []
        reasons: list[str | None] = []
        with sandbox.events() as stream:
            for event in stream:
                kinds.append(event.kind)
                if event.kind == "pausing":
                    reasons.append(event.attributes.get("reason"))
        assert kinds == ["created", "ready", "pausing", "paused"]
        assert reasons == ["idle_timeout"]

    def test_early_exit_via_the_context_closes_the_subscription(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return events_response([event_frame(sandbox_pb2.SANDBOX_EVENT_KIND_READY)] * 5)

        sandbox = sync_sandbox(handler)
        with sandbox.events() as stream:
            for event in stream:
                assert event.kind == "ready"
                break
        with pytest.raises(StopIteration):
            next(iter(stream))

    def test_a_mid_stream_drop_is_the_stream_death_error(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return events_response(
                [event_frame(sandbox_pb2.SANDBOX_EVENT_KIND_READY)], truncated=True
            )

        sandbox = sync_sandbox(handler)
        with pytest.raises(ConnectionLostError):
            for _event in sandbox.events():
                pass

    def test_a_server_signaled_unavailable_end_frame_is_also_stream_death(self) -> None:
        # The drop's other wire shape: the daemon loses its upstream
        # event source and ends the HTTP stream CLEANLY with a Connect
        # `unavailable` error frame.
        def handler(_request: httpx.Request) -> httpx.Response:
            end = b'{"error": {"code": "unavailable", "message": "event source lost"}}'
            body = event_frame(sandbox_pb2.SANDBOX_EVENT_KIND_READY) + encode_envelope(
                FLAG_END_STREAM, end
            )
            return httpx.Response(
                200, content=body, headers={"content-type": "application/connect+proto"}
            )

        sandbox = sync_sandbox(handler)
        with pytest.raises(ConnectionLostError):
            for _event in sandbox.events():
                pass

    def test_an_unavailable_end_with_zero_frames_stays_an_unreachable_daemon_error(self) -> None:
        # No frame was ever delivered, so nothing can have been missed:
        # the daemon is unreachable, not a stream that died (the TS SDK
        # classifies this identically).
        def handler(_request: httpx.Request) -> httpx.Response:
            end = b'{"error": {"code": "unavailable", "message": "daemon gone"}}'
            return httpx.Response(
                200,
                content=encode_envelope(FLAG_END_STREAM, end),
                headers={"content-type": "application/connect+proto"},
            )

        sandbox = sync_sandbox(handler)
        with pytest.raises(ConnectionFailedError) as exc_info:
            for _event in sandbox.events():
                pass
        assert not isinstance(exc_info.value, ConnectionLostError)


class LifecycleProbe:
    def __init__(self) -> None:
        self.requests: list[sandbox_pb2.SetLifecycleRequest] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/SetLifecycle")
        self.requests.append(sandbox_pb2.SetLifecycleRequest.FromString(request.content))
        return proto_response(empty_pb2.Empty())


class TestSetLifecycleTriState:
    def test_omitted_knobs_are_absent_on_the_wire(self) -> None:
        probe = LifecycleProbe()
        sync_sandbox(probe).set_lifecycle()
        req = probe.requests[0]
        assert not req.HasField("ttl_seconds")
        assert not req.HasField("idle_timeout_seconds")
        assert not req.HasField("on_idle")

    def test_values_replace(self) -> None:
        probe = LifecycleProbe()
        sync_sandbox(probe).set_lifecycle(ttl=5, idle_timeout=30)
        req = probe.requests[0]
        assert req.ttl_seconds == 5
        assert req.idle_timeout_seconds == 30
        assert not req.HasField("on_idle")

    def test_none_restores_the_default_as_explicit_zero(self) -> None:
        probe = LifecycleProbe()
        sync_sandbox(probe).set_lifecycle(ttl=None, on_idle=None)
        req = probe.requests[0]
        assert req.HasField("ttl_seconds")
        assert req.ttl_seconds == 0
        assert not req.HasField("idle_timeout_seconds")
        assert req.HasField("on_idle")
        assert req.on_idle == sandbox_pb2.IDLE_ACTION_UNSPECIFIED

    def test_explicit_unchanged_equals_omission(self) -> None:
        probe = LifecycleProbe()
        sync_sandbox(probe).set_lifecycle(ttl=UNCHANGED, on_idle="pause")
        req = probe.requests[0]
        assert not req.HasField("ttl_seconds")
        assert req.on_idle == sandbox_pb2.IDLE_ACTION_PAUSE


class CapsDaemon:
    def __init__(self, fail_first: bool = False) -> None:
        self.calls = 0
        self.fail_first = fail_first

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/GetCapabilities")
        self.calls += 1
        if self.fail_first and self.calls == 1:
            return httpx.Response(503, content=b'{"code": "unavailable", "message": "starting up"}')
        response = sandbox_pb2.GetCapabilitiesResponse(
            daemon_version="0.9.0",
            protocol=1,
            features=["pause_resume", "auto_resume"],
        )
        response.nested_virt.supported = False
        response.nested_virt.reason = "requires M3 or newer"
        return proto_response(response)


class TestCapabilities:
    def test_maps_the_handshake_and_caches_it_per_client(self) -> None:
        daemon = CapsDaemon()
        http = httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
        box = ArcBox(Connection(http_client=http))
        caps = box.capabilities()
        assert caps.daemon_version == "0.9.0"
        assert caps.protocol == 1
        assert caps.features == ["pause_resume", "auto_resume"]
        assert caps.nested_virt.supported is False
        assert caps.nested_virt.reason == "requires M3 or newer"
        assert box.capabilities() is caps
        assert daemon.calls == 1

    def test_a_failed_fetch_is_not_cached(self) -> None:
        daemon = CapsDaemon(fail_first=True)
        http = httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
        box = ArcBox(Connection(http_client=http))
        with pytest.raises(Exception, match="starting up"):
            box.capabilities()
        assert box.capabilities().protocol == 1
        assert daemon.calls == 2


@pytest.mark.anyio
async def test_async_tree_runs_the_same_surface() -> None:
    probe = LifecycleProbe()
    http = httpx.AsyncClient(transport=httpx.MockTransport(probe), base_url="http://arcbox")
    sandbox = AsyncSandbox(AsyncConnectClient(Connection(http_client=http)), "sb-1")
    await sandbox.set_lifecycle(ttl=None)
    assert probe.requests[0].HasField("ttl_seconds")

    daemon = CapsDaemon()
    http2 = httpx.AsyncClient(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    box = AsyncArcBox(Connection(http_client=http2))
    assert (await box.capabilities()).protocol == 1

    def events_handler(_request: httpx.Request) -> httpx.Response:
        return events_response([event_frame(sandbox_pb2.SANDBOX_EVENT_KIND_READY)])

    http3 = httpx.AsyncClient(
        transport=httpx.MockTransport(events_handler), base_url="http://arcbox"
    )
    watching = AsyncSandbox(AsyncConnectClient(Connection(http_client=http3)), "sb-1")
    kinds: list[str] = []
    async with watching.events() as stream:
        async for event in stream:
            kinds.append(event.kind)
    assert kinds == ["ready"]
