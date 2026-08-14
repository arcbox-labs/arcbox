"""The filesystem path verbs against a mock daemon.

The contracts under test: DTO mapping (wire FileStat -> int/datetime,
kind names, absent-field elision), the exact request fields each verb
sends (mode 0 = daemon default, the recursive flag, from/to, PurePath
acceptance), and the registry-typed errors the daemon documents --
FILE_NOT_FOUND with the path in context, FAILED_PRECONDITION for a
non-recursive remove of a non-empty directory.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import PurePosixPath

import httpx
import pytest
from google.protobuf import empty_pb2

from arcbox import Connection, Sandbox
from arcbox._gen import errors_pb2, filesystem_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import FileNotFoundError, SandboxStateError

MODIFIED = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def wire_stat() -> filesystem_pb2.FileStat:
    stat = filesystem_pb2.FileStat(
        name="a.bin",
        kind=filesystem_pb2.FILE_KIND_FILE,
        size=18,
        mode=0o644,
        uid=1000,
        gid=1000,
    )
    stat.modified_at.FromDatetime(MODIFIED)
    return stat


def proto_response(message: object) -> httpx.Response:
    assert hasattr(message, "SerializeToString")
    return httpx.Response(
        200,
        content=message.SerializeToString(),  # type: ignore[attr-defined]
        headers={"content-type": "application/proto"},
    )


class MockVerbs:
    """Records every path-verb request; scripted responses per verb."""

    def __init__(self) -> None:
        self.stats: list[filesystem_pb2.StatFileRequest] = []
        self.lists: list[filesystem_pb2.ListDirRequest] = []
        self.mkdirs: list[filesystem_pb2.MakeDirRequest] = []
        self.removes: list[filesystem_pb2.RemoveEntryRequest] = []
        self.moves: list[filesystem_pb2.MoveEntryRequest] = []
        self.stat_response: httpx.Response = proto_response(wire_stat())
        self.remove_response: httpx.Response = proto_response(empty_pb2.Empty())

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/Stat"):
            self.stats.append(filesystem_pb2.StatFileRequest.FromString(request.content))
            return self.stat_response
        if path.endswith("/ListDir"):
            self.lists.append(filesystem_pb2.ListDirRequest.FromString(request.content))
            listing = filesystem_pb2.ListDirResponse(
                entries=[
                    wire_stat(),
                    filesystem_pb2.FileStat(
                        name="sub", kind=filesystem_pb2.FILE_KIND_DIRECTORY, mode=0o755
                    ),
                ]
            )
            return proto_response(listing)
        if path.endswith("/MakeDir"):
            self.mkdirs.append(filesystem_pb2.MakeDirRequest.FromString(request.content))
            return proto_response(empty_pb2.Empty())
        if path.endswith("/Remove"):
            self.removes.append(filesystem_pb2.RemoveEntryRequest.FromString(request.content))
            return self.remove_response
        if path.endswith("/Move"):
            self.moves.append(filesystem_pb2.MoveEntryRequest.FromString(request.content))
            return proto_response(empty_pb2.Empty())
        return httpx.Response(404, content=b"unhandled: " + path.encode())


def sandbox_for(daemon: MockVerbs) -> Sandbox:
    http = httpx.Client(transport=httpx.MockTransport(daemon), base_url="http://arcbox")
    return Sandbox(ConnectClient(Connection(http_client=http)), "sb-1")


def file_not_found_response() -> httpx.Response:
    # The daemon's documented shape: NOT_FOUND + the FILE_NOT_FOUND
    # registry detail carrying the path (app/arcbox-api error.rs).
    info = errors_pb2.ErrorInfo(
        code=errors_pb2.ERROR_CODE_FILE_NOT_FOUND,
        suggestion="check the path with `Stat` or `ListDir` on its parent directory",
        context={"path": "/gone"},
    )
    body = json.dumps(
        {
            "code": "not_found",
            "message": "path not found: /gone",
            "details": [
                {
                    "type": "arcbox.sandbox.v1.ErrorInfo",
                    "value": base64.b64encode(info.SerializeToString()).decode(),
                }
            ],
        }
    ).encode()
    return httpx.Response(404, content=body)


class TestStat:
    def test_maps_the_wire_stat_to_int_and_datetime(self) -> None:
        daemon = MockVerbs()
        stat = sandbox_for(daemon).files.stat("/tmp/a.bin")
        assert daemon.stats[0].id == "sb-1"
        assert daemon.stats[0].path == "/tmp/a.bin"
        assert stat.name == "a.bin"
        assert stat.kind == "file"
        assert stat.size == 18
        assert stat.mode == 0o644
        assert stat.modified_at == MODIFIED
        assert stat.uid == 1000
        assert stat.gid == 1000
        assert stat.symlink_target is None

    def test_accepts_a_pure_posix_path(self) -> None:
        daemon = MockVerbs()
        sandbox_for(daemon).files.stat(PurePosixPath("/tmp/a.bin"))
        assert daemon.stats[0].path == "/tmp/a.bin"

    def test_reports_a_symlink_with_its_target_and_elides_absent_fields(self) -> None:
        daemon = MockVerbs()
        daemon.stat_response = proto_response(
            filesystem_pb2.FileStat(
                name="link",
                kind=filesystem_pb2.FILE_KIND_SYMLINK,
                symlink_target="/etc/hosts",
            )
        )
        stat = sandbox_for(daemon).files.stat("/tmp/link")
        assert stat.kind == "symlink"
        assert stat.symlink_target == "/etc/hosts"
        assert stat.modified_at is None
        assert stat.size == 0

    def test_a_kind_this_sdk_predates_maps_to_unknown(self) -> None:
        daemon = MockVerbs()
        stat = filesystem_pb2.FileStat(name="x")
        # Open proto3 enum: an unknown wire value survives the parse.
        stat_bytes = stat.SerializeToString() + bytes([0x10, 99])
        daemon.stat_response = httpx.Response(
            200, content=stat_bytes, headers={"content-type": "application/proto"}
        )
        assert sandbox_for(daemon).files.stat("/x").kind == "unknown"

    def test_a_missing_path_is_file_not_found_with_the_path_in_context(self) -> None:
        daemon = MockVerbs()
        daemon.stat_response = file_not_found_response()
        with pytest.raises(FileNotFoundError) as exc_info:
            sandbox_for(daemon).files.stat("/gone")
        assert exc_info.value.code == "FILE_NOT_FOUND"
        assert exc_info.value.context == {"path": "/gone"}
        assert exc_info.value.operation == "files.stat"


class TestList:
    def test_maps_every_entry_preserving_the_daemon_order(self) -> None:
        daemon = MockVerbs()
        entries = sandbox_for(daemon).files.list("/tmp")
        assert daemon.lists[0].path == "/tmp"
        assert [(e.name, e.kind) for e in entries] == [("a.bin", "file"), ("sub", "directory")]


class TestMkdir:
    def test_defaults_mode_to_zero_on_the_wire(self) -> None:
        daemon = MockVerbs()
        files = sandbox_for(daemon).files
        files.mkdir("/tmp/a/b")
        files.mkdir("/tmp/c", mode=0o700)
        assert [(r.path, r.mode) for r in daemon.mkdirs] == [("/tmp/a/b", 0), ("/tmp/c", 0o700)]


class TestRemove:
    def test_sends_the_recursive_flag_exactly_as_requested(self) -> None:
        daemon = MockVerbs()
        files = sandbox_for(daemon).files
        files.remove("/tmp/file")
        files.remove("/tmp/tree", recursive=True)
        assert [(r.path, r.recursive) for r in daemon.removes] == [
            ("/tmp/file", False),
            ("/tmp/tree", True),
        ]

    def test_non_recursive_remove_of_a_non_empty_directory_is_the_precondition_error(
        self,
    ) -> None:
        daemon = MockVerbs()
        # The daemon's documented shape: DirectoryNotEmpty -> 412 ->
        # FAILED_PRECONDITION, no ErrorInfo detail.
        daemon.remove_response = httpx.Response(
            412,
            content=json.dumps(
                {"code": "failed_precondition", "message": "directory not empty: /full"}
            ).encode(),
        )
        with pytest.raises(SandboxStateError) as exc_info:
            sandbox_for(daemon).files.remove("/full")
        assert exc_info.value.operation == "files.remove"


class TestMove:
    def test_sends_src_dst_as_from_path_to_path(self) -> None:
        daemon = MockVerbs()
        sandbox_for(daemon).files.move("/tmp/a", PurePosixPath("/tmp/b"))
        assert daemon.moves[0].from_path == "/tmp/a"
        assert daemon.moves[0].to_path == "/tmp/b"
