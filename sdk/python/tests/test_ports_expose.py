"""ports.expose()/unexpose()/list() against a mock daemon.

The contracts under test: the request shapes (0 = allocate a host port,
explicit protocol -- never UNSPECIFIED on the wire), the returned
mapping echoing the daemon's allocation, the ListExposedPorts row
mapping (UNSPECIFIED decodes as tcp), and error wrapping naming the
ports.* operation.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx
import pytest
from google.protobuf import empty_pb2, message

from arcbox import Connection, ExposedPort, Sandbox
from arcbox._gen import sandbox_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import NotFoundError

if TYPE_CHECKING:
    from collections.abc import Callable


def proto_response(body: message.Message) -> httpx.Response:
    return httpx.Response(
        200,
        content=body.SerializeToString(),
        headers={"content-type": "application/proto"},
    )


def sync_sandbox(handler: Callable[[httpx.Request], httpx.Response]) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


class TestExpose:
    def test_asks_for_an_allocated_host_port_by_default(self) -> None:
        requests: list[sandbox_pb2.ExposePortRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/ExposePort")
            requests.append(sandbox_pb2.ExposePortRequest.FromString(request.content))
            return proto_response(sandbox_pb2.ExposePortResponse(host_port=49152, guest_port=61000))

        mapping = sync_sandbox(handler).ports.expose(8080)
        assert requests[0].id == "sb-1"
        assert requests[0].sandbox_port == 8080
        assert requests[0].host_port == 0
        assert requests[0].protocol == sandbox_pb2.PORT_PROTOCOL_TCP
        assert mapping == ExposedPort(sandbox_port=8080, host_port=49152, protocol="tcp")

    def test_passes_a_specific_host_port_and_udp_through(self) -> None:
        requests: list[sandbox_pb2.ExposePortRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(sandbox_pb2.ExposePortRequest.FromString(request.content))
            return proto_response(sandbox_pb2.ExposePortResponse(host_port=5353))

        mapping = sync_sandbox(handler).ports.expose(53, host_port=5353, protocol="udp")
        assert requests[0].host_port == 5353
        assert requests[0].protocol == sandbox_pb2.PORT_PROTOCOL_UDP
        assert mapping.protocol == "udp"

    def test_wraps_daemon_errors_naming_the_operation(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            body = json.dumps({"code": "not_found", "message": "sandbox sb-1 not found"}).encode()
            return httpx.Response(404, content=body)

        with pytest.raises(NotFoundError) as exc_info:
            sync_sandbox(handler).ports.expose(8080)
        assert exc_info.value.operation == "ports.expose"


class TestUnexpose:
    def test_names_the_mapping_by_sandbox_port_and_protocol(self) -> None:
        requests: list[sandbox_pb2.UnexposePortRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/UnexposePort")
            requests.append(sandbox_pb2.UnexposePortRequest.FromString(request.content))
            return proto_response(empty_pb2.Empty())

        sync_sandbox(handler).ports.unexpose(8080)
        assert requests[0].id == "sb-1"
        assert requests[0].sandbox_port == 8080
        assert requests[0].protocol == sandbox_pb2.PORT_PROTOCOL_TCP


class TestListExposed:
    def test_maps_rows_decoding_unspecified_as_tcp(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/ListExposedPorts")
            req = sandbox_pb2.ListExposedPortsRequest.FromString(request.content)
            assert req.id == "sb-1"
            return proto_response(
                sandbox_pb2.ListExposedPortsResponse(
                    ports=[
                        sandbox_pb2.ExposedPort(
                            sandbox_port=8080,
                            host_port=49152,
                            protocol=sandbox_pb2.PORT_PROTOCOL_TCP,
                        ),
                        sandbox_pb2.ExposedPort(
                            sandbox_port=53,
                            host_port=5353,
                            protocol=sandbox_pb2.PORT_PROTOCOL_UDP,
                        ),
                        sandbox_pb2.ExposedPort(sandbox_port=9000, host_port=49153),
                    ]
                )
            )

        assert sync_sandbox(handler).ports.list() == [
            ExposedPort(sandbox_port=8080, host_port=49152, protocol="tcp"),
            ExposedPort(sandbox_port=53, host_port=5353, protocol="udp"),
            ExposedPort(sandbox_port=9000, host_port=49153, protocol="tcp"),
        ]

    def test_wraps_a_vanished_sandbox_naming_the_operation(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            body = json.dumps({"code": "not_found", "message": "sandbox sb-1 not found"}).encode()
            return httpx.Response(404, content=body)

        with pytest.raises(NotFoundError) as exc_info:
            sync_sandbox(handler).ports.list()
        assert exc_info.value.operation == "ports.list"
