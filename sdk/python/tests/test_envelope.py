"""Connect streaming envelope framing."""

from __future__ import annotations

import json
import struct

import pytest

from arcbox._envelope import (
    FLAG_END_STREAM,
    MAX_ENVELOPE_BYTES,
    EnvelopeDecoder,
    encode_envelope,
    end_stream_error,
)
from arcbox.errors import ArcBoxError, SandboxNotFoundError


def test_roundtrips_one_envelope() -> None:
    encoded = encode_envelope(0, b"abc")
    assert encoded == b"\x00\x00\x00\x00\x03abc"
    assert EnvelopeDecoder().feed(encoded) == [(0, b"abc")]


def test_decodes_frames_fed_byte_by_byte() -> None:
    encoded = encode_envelope(0, b"hello") + encode_envelope(FLAG_END_STREAM, b"{}")
    decoder = EnvelopeDecoder()
    frames: list[tuple[int, bytes]] = []
    for i in range(len(encoded)):
        frames.extend(decoder.feed(encoded[i : i + 1]))
    assert frames == [(0, b"hello"), (FLAG_END_STREAM, b"{}")]


def test_decodes_multiple_frames_from_one_feed() -> None:
    encoded = encode_envelope(0, b"a") + encode_envelope(0, b"b") + encode_envelope(2, b"{}")
    assert EnvelopeDecoder().feed(encoded) == [(0, b"a"), (0, b"b"), (2, b"{}")]


def test_rejects_an_envelope_past_the_sanity_cap() -> None:
    header = struct.pack(">BI", 0, MAX_ENVELOPE_BYTES + 1)
    with pytest.raises(ArcBoxError, match="sanity cap"):
        EnvelopeDecoder().feed(header)


def test_end_stream_success_is_none() -> None:
    assert end_stream_error(b"{}") is None
    assert end_stream_error(json.dumps({"metadata": {}}).encode()) is None


def test_end_stream_error_maps_through_the_registry() -> None:
    payload = json.dumps({"error": {"code": "not_found", "message": "gone"}}).encode()
    err = end_stream_error(payload, operation="files.read_bytes")
    assert err is not None
    assert err.operation == "files.read_bytes"


def test_end_stream_garbage_is_a_typed_error_not_a_crash() -> None:
    err = end_stream_error(b"\xff\xfe")
    assert isinstance(err, ArcBoxError)


def test_end_stream_error_carries_error_info_details() -> None:
    import base64

    from arcbox._gen import errors_pb2

    info = errors_pb2.ErrorInfo(code=errors_pb2.ERROR_CODE_SANDBOX_NOT_FOUND)
    payload = json.dumps(
        {
            "error": {
                "code": "not_found",
                "message": "gone",
                "details": [
                    {
                        "type": "arcbox.sandbox.v1.ErrorInfo",
                        "value": base64.b64encode(info.SerializeToString()).decode(),
                    }
                ],
            }
        }
    ).encode()
    assert isinstance(end_stream_error(payload), SandboxNotFoundError)
