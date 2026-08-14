"""HTTP-client ownership: SDK-owned clients close deterministically,
injected ones belong to the caller and are never touched.

The ownership flags under test are deliberately private, so this file
asserts them directly instead of replaying full daemon flows.
"""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import httpx
import pytest
from google.protobuf import empty_pb2

from arcbox import ArcBox, ConnectClient, Connection, Sandbox
from arcbox._gen import sandbox_pb2


class MockSandboxService:
    """Answers the two RPCs the disposal paths issue."""

    def __init__(self) -> None:
        self.removed: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/Create"):
            body = sandbox_pb2.CreateSandboxResponse().SerializeToString()
        elif path.endswith("/Remove"):
            self.removed.append(sandbox_pb2.RemoveSandboxRequest.FromString(request.content).id)
            body = empty_pb2.Empty().SerializeToString()
        else:
            return httpx.Response(404, content=b"unhandled: " + path.encode())
        return httpx.Response(200, content=body, headers={"content-type": "application/proto"})


def injected_client(daemon: MockSandboxService) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")


def test_arcbox_context_exit_closes_the_sdk_owned_client() -> None:
    with ArcBox(Connection(socket_path="/tmp/never-dialed.sock")) as box:
        pass
    # httpx refuses requests on a closed client — the pool is gone.
    with pytest.raises(RuntimeError, match="closed"):
        box.connect("sb-1")


def test_an_injected_client_belongs_to_the_caller_and_stays_open() -> None:
    http = injected_client(MockSandboxService())
    with ArcBox(Connection(http_client=http)):
        pass
    assert not http.is_closed


def test_classmethod_sugar_handles_own_their_hidden_client() -> None:
    conn = Connection(http_client=injected_client(MockSandboxService()))
    sugar = Sandbox.create("", wait_until_ready=False, connection=conn)
    shared = ArcBox(conn).create("", wait_until_ready=False)
    assert sugar._owns_client
    assert not shared._owns_client


def test_sandbox_context_exit_closes_an_owned_client_after_kill() -> None:
    daemon = MockSandboxService()
    http = injected_client(daemon)
    client = ConnectClient(Connection(http_client=http))
    client._owns_http = True  # what the SDK-owned construction sets
    sandbox = Sandbox(client, "sb-1")
    sandbox._owns_client = True  # what the classmethod sugar sets
    with sandbox:
        pass
    assert daemon.removed == ["sb-1"]
    assert http.is_closed
