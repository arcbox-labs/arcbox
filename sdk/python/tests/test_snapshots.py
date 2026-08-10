"""Snapshot catalog against a mock daemon: sandbox.checkpoint(),
ArcBox.restore()/list_snapshots()/delete_snapshot().

The contracts under test: the checkpoint result is the catalog row
(response id + creation time, request-echoed name and labels), restore
mints the new sandbox id client-side and hands back a handle on it,
list_snapshots auto-paginates, and errors carry the snapshots.*
operation names.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx
import pytest
from google.protobuf import empty_pb2, message

from arcbox import ArcBox, Connection, Sandbox, Snapshot
from arcbox._gen import sandbox_pb2, snapshot_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import NotFoundError, SandboxStateError

if TYPE_CHECKING:
    from collections.abc import Callable

CREATED = datetime(2026, 8, 10, 8, 0, 0, tzinfo=timezone.utc)


def proto_response(body: message.Message) -> httpx.Response:
    return httpx.Response(
        200,
        content=body.SerializeToString(),
        headers={"content-type": "application/proto"},
    )


def sync_box(handler: Callable[[httpx.Request], httpx.Response]) -> ArcBox:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    return ArcBox(Connection(http_client=http))


def sync_sandbox(handler: Callable[[httpx.Request], httpx.Response]) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


class TestCheckpoint:
    def test_returns_the_catalog_row_the_daemon_recorded(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/Checkpoint")
            req = snapshot_pb2.CheckpointRequest.FromString(request.content)
            assert req.sandbox_id == "sb-1"
            assert req.name == "warm-base"
            assert dict(req.labels) == {"tier": "warm"}
            response = snapshot_pb2.CheckpointResponse(snapshot_id="snap-1")
            response.created_at.FromDatetime(CREATED)
            return proto_response(response)

        row = sync_sandbox(handler).checkpoint(name="warm-base", labels={"tier": "warm"})
        assert row == Snapshot(
            id="snap-1",
            sandbox_id="sb-1",
            name="warm-base",
            labels={"tier": "warm"},
            created_at=CREATED,
        )

    def test_wraps_daemon_errors_naming_the_operation(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            body = json.dumps(
                {"code": "failed_precondition", "message": "sandbox is not READY"}
            ).encode()
            return httpx.Response(412, content=body)

        with pytest.raises(SandboxStateError) as exc_info:
            sync_sandbox(handler).checkpoint()
        assert exc_info.value.operation == "sandbox.checkpoint"


class TestRestore:
    def test_mints_the_new_sandbox_id_client_side(self) -> None:
        requests: list[snapshot_pb2.RestoreRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/Restore")
            req = snapshot_pb2.RestoreRequest.FromString(request.content)
            requests.append(req)
            # A deliberately different id: an implementation that took
            # its identity from the response instead of the client-minted
            # id must fail the assertions below.
            return proto_response(
                snapshot_pb2.RestoreResponse(id="server-side-id", ip_address="192.168.64.7")
            )

        sandbox = sync_box(handler).restore(
            "snap-1", ttl=90.5, labels={"origin": "snap-1"}, fresh_network=True
        )
        req = requests[0]
        assert req.snapshot_id == "snap-1"
        assert dict(req.labels) == {"origin": "snap-1"}
        assert req.network_override is True
        # Seconds round UP to whole wire seconds.
        assert req.ttl_seconds == 91
        # The id is minted client-side (idempotent retries) and is the
        # handle's identity — never the response's.
        assert sandbox.id == req.id
        assert sandbox.id != "server-side-id"
        uuid.UUID(sandbox.id)

    def test_wraps_a_missing_snapshot_naming_the_operation(self) -> None:
        removed: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/Remove"):
                req = sandbox_pb2.RemoveSandboxRequest.FromString(request.content)
                removed.append(req.id)
                return proto_response(empty_pb2.Empty())
            body = json.dumps(
                {"code": "not_found", "message": "snapshot snap-9 not found"}
            ).encode()
            return httpx.Response(404, content=body)

        with pytest.raises(NotFoundError) as exc_info:
            sync_box(handler).restore("snap-9")
        assert exc_info.value.operation == "snapshots.restore"
        # A failed restore may still have created the sandbox (response
        # lost), so the minted id gets a best-effort forced removal —
        # the create() rule.
        assert len(removed) == 1
        uuid.UUID(removed[0])


class TestListSnapshots:
    def test_auto_paginates_and_maps_rows(self) -> None:
        requests: list[snapshot_pb2.ListSnapshotsRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/ListSnapshots")
            req = snapshot_pb2.ListSnapshotsRequest.FromString(request.content)
            requests.append(req)
            if req.page_token == "":
                first = snapshot_pb2.SnapshotSummary(
                    id="snap-1",
                    sandbox_id="sb-1",
                    name="warm-base",
                    labels={"tier": "warm"},
                )
                first.created_at.FromDatetime(CREATED)
                return proto_response(
                    snapshot_pb2.ListSnapshotsResponse(snapshots=[first], next_page_token="page-2")
                )
            return proto_response(
                snapshot_pb2.ListSnapshotsResponse(
                    snapshots=[snapshot_pb2.SnapshotSummary(id="snap-2", sandbox_id="sb-2")]
                )
            )

        rows = list(sync_box(handler).list_snapshots(sandbox_id="sb-1", labels={"tier": "warm"}))
        assert rows == [
            Snapshot(
                id="snap-1",
                sandbox_id="sb-1",
                name="warm-base",
                labels={"tier": "warm"},
                created_at=CREATED,
            ),
            Snapshot(id="snap-2", sandbox_id="sb-2"),
        ]
        assert [req.page_token for req in requests] == ["", "page-2"]
        assert requests[0].sandbox_id == "sb-1"
        assert dict(requests[0].labels) == {"tier": "warm"}


class TestDeleteSnapshot:
    def test_names_the_snapshot_to_delete(self) -> None:
        requests: list[snapshot_pb2.DeleteSnapshotRequest] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/DeleteSnapshot")
            requests.append(snapshot_pb2.DeleteSnapshotRequest.FromString(request.content))
            return proto_response(empty_pb2.Empty())

        sync_box(handler).delete_snapshot("snap-1")
        assert requests[0].snapshot_id == "snap-1"

    def test_wraps_daemon_errors_naming_the_operation(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            body = json.dumps(
                {"code": "not_found", "message": "snapshot snap-1 not found"}
            ).encode()
            return httpx.Response(404, content=body)

        with pytest.raises(NotFoundError) as exc_info:
            sync_box(handler).delete_snapshot("snap-1")
        assert exc_info.value.operation == "snapshots.delete"
