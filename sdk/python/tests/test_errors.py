"""The single transport→exception boundary, mirrored from the TS tests."""

from __future__ import annotations

import base64
import json
from typing import cast

import httpx
import pytest

from arcbox._boundary import wrap_errors
from arcbox._envelope import unary_error
from arcbox._gen import errors_pb2
from arcbox.errors import (
    ArcBoxError,
    CapabilityError,
    CommandTimeoutError,
    ConnectionFailedError,
    FileNotFoundError,
    NotFoundError,
    RequestTimeoutError,
    SandboxNotFoundError,
    SandboxStateError,
)


def daemon_error_body(
    code: int,
    suggestion: str = "",
    context: dict[str, str] | None = None,
    connect_code: str = "failed_precondition",
    pad_base64: bool = True,
) -> bytes:
    # cast: proto3 enums are open — the unknown-code test sends 999.
    info = errors_pb2.ErrorInfo(
        code=cast("errors_pb2.ErrorCode", code), suggestion=suggestion, context=context or {}
    )
    value = base64.b64encode(info.SerializeToString()).decode()
    if not pad_base64:
        value = value.rstrip("=")
    return json.dumps(
        {
            "code": connect_code,
            "message": "boom",
            "details": [{"type": "arcbox.sandbox.v1.ErrorInfo", "value": value}],
        }
    ).encode()


def test_maps_error_info_details_to_the_registry_class() -> None:
    err = unary_error(
        400,
        daemon_error_body(
            errors_pb2.ERROR_CODE_SANDBOX_NOT_FOUND,
            suggestion="list sandboxes with `abctl sandbox list`",
            context={"id": "sb-1"},
        ),
        operation="sandbox.info",
    )
    assert isinstance(err, SandboxNotFoundError)
    assert err.code == "SANDBOX_NOT_FOUND"
    assert err.suggestion == "list sandboxes with `abctl sandbox list`"
    assert err.context == {"id": "sb-1"}
    assert err.operation == "sandbox.info"


@pytest.mark.parametrize(
    ("code", "cls"),
    [
        (errors_pb2.ERROR_CODE_SANDBOX_PAUSED, SandboxStateError),
        (errors_pb2.ERROR_CODE_NESTED_VIRT_UNSUPPORTED, CapabilityError),
        (errors_pb2.ERROR_CODE_COMMAND_TIMEOUT, CommandTimeoutError),
        (errors_pb2.ERROR_CODE_FILE_NOT_FOUND, FileNotFoundError),
    ],
)
def test_maps_state_capability_and_timeout_registry_codes(
    code: int, cls: type[ArcBoxError]
) -> None:
    assert isinstance(unary_error(400, daemon_error_body(code)), cls)


def test_accepts_unpadded_base64_details() -> None:
    err = unary_error(
        400,
        daemon_error_body(errors_pb2.ERROR_CODE_SANDBOX_NOT_FOUND, pad_base64=False),
    )
    assert isinstance(err, SandboxNotFoundError)


def test_keeps_unknown_registry_codes_on_the_base_class() -> None:
    err = unary_error(400, daemon_error_body(999))
    assert type(err) is ArcBoxError
    assert err.code == "ERROR_CODE_999"


def test_routes_on_the_connect_code_without_an_error_info_detail() -> None:
    body = json.dumps({"code": "not_found", "message": "gone"}).encode()
    err = unary_error(404, body, operation="op")
    assert isinstance(err, NotFoundError)
    assert err.code == "not_found"
    assert err.operation == "op"

    deadline = unary_error(408, json.dumps({"code": "deadline_exceeded"}).encode())
    assert isinstance(deadline, RequestTimeoutError)
    assert deadline.suggestion == "increase Connection.request_timeout"

    unavailable = unary_error(503, json.dumps({"code": "unavailable"}).encode())
    assert isinstance(unavailable, ConnectionFailedError)


def test_non_json_bodies_fall_back_to_the_http_status_table() -> None:
    err = unary_error(503, b"<html>bad gateway</html>")
    assert isinstance(err, ConnectionFailedError)
    assert err.code == "unavailable"
    unknown = unary_error(500, b"?")
    assert type(unknown) is ArcBoxError
    assert unknown.code == "unknown"


def test_wrap_errors_maps_connection_failures_with_a_suggestion() -> None:
    with pytest.raises(ConnectionFailedError) as exc_info, wrap_errors("sandbox.create"):
        raise httpx.ConnectError("[Errno 2] No such file or directory")
    err = exc_info.value
    assert err.operation == "sandbox.create"
    assert err.suggestion is not None and "abctl daemon start" in err.suggestion
    assert isinstance(err.__cause__, httpx.ConnectError)


def test_wrap_errors_maps_client_side_deadline_expiry() -> None:
    with pytest.raises(RequestTimeoutError), wrap_errors("op"):
        raise httpx.ReadTimeout("slow daemon")


def test_wrap_errors_stamps_the_operation_on_passthrough() -> None:
    original = SandboxNotFoundError("gone")
    with pytest.raises(SandboxNotFoundError) as exc_info, wrap_errors("sandbox.kill"):
        raise original
    assert exc_info.value is original
    assert original.operation == "sandbox.kill"

    stamped = SandboxNotFoundError("gone", operation="files.read_bytes")
    with pytest.raises(SandboxNotFoundError), wrap_errors("sandbox.kill"):
        raise stamped
    assert stamped.operation == "files.read_bytes"
