"""Connect protocol framing and error-body shapes.

The Connect protocol (https://connectrpc.com/docs/protocol) frames
streaming payloads in envelopes — 1 flags byte + 4-byte big-endian
length + payload — and reports errors as JSON: unary errors as the
non-200 response body, streaming errors inside the terminal
EndStreamResponse envelope. This module owns both encodings; it is pure
and shared by the async and sync trees.

Error bodies are decoded with msgspec Structs — typed validation at the
single untrusted-input boundary instead of hand-walked dicts.
"""

from __future__ import annotations

import base64
import struct

import msgspec
from google.protobuf.message import DecodeError

from arcbox._gen import errors_pb2
from arcbox.errors import ArcBoxError, error_from_wire

#: Envelope flag bits (Connect streaming RPCs).
FLAG_COMPRESSED = 0b01
FLAG_END_STREAM = 0b10

#: Ceiling on a single received envelope. The daemon streams file bytes
#: in small chunks and the per-file cap is 256 MiB, so anything past
#: this is a corrupt frame, not data.
MAX_ENVELOPE_BYTES = 32 * 1024 * 1024

_HEADER = struct.Struct(">BI")

#: Fully-qualified type of the daemon's error detail (`errors.proto`).
_ERROR_INFO_TYPE = "arcbox.sandbox.v1.ErrorInfo"

# HTTP status -> Connect code, used only when a unary error body is not
# valid Connect error JSON (the spec's fallback table).
_HTTP_FALLBACK_CODES = {
    400: "internal",
    401: "unauthenticated",
    403: "permission_denied",
    404: "unimplemented",
    429: "unavailable",
    502: "unavailable",
    503: "unavailable",
    504: "unavailable",
}


def encode_envelope(flags: int, payload: bytes) -> bytes:
    """Encode one Connect streaming envelope."""
    return _HEADER.pack(flags, len(payload)) + payload


class EnvelopeDecoder:
    """Incremental envelope decoder: feed bytes, collect (flags, payload) frames."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        self._buffer += data
        frames: list[tuple[int, bytes]] = []
        while len(self._buffer) >= _HEADER.size:
            flags, length = _HEADER.unpack_from(self._buffer)
            if length > MAX_ENVELOPE_BYTES:
                raise ArcBoxError(
                    f"stream envelope of {length} bytes exceeds the "
                    f"{MAX_ENVELOPE_BYTES}-byte sanity cap"
                )
            end = _HEADER.size + length
            if len(self._buffer) < end:
                break
            frames.append((flags, bytes(self._buffer[_HEADER.size : end])))
            del self._buffer[:end]
        return frames


class ConnectErrorDetail(msgspec.Struct):
    """One error detail: a type name plus base64-encoded protobuf bytes."""

    type: str = ""
    value: str = ""


class ConnectWireError(msgspec.Struct):
    """The JSON `error` object of the Connect protocol.

    ``code`` is deliberately required (the spec always sends it): its
    presence is what distinguishes Connect error JSON from an arbitrary
    JSON body something in front of the daemon may return — a reverse
    proxy's ``{"error": "Bad Gateway"}`` must route to the HTTP-status
    fallback, not decode as an empty Connect error.
    """

    code: str
    message: str = ""
    details: list[ConnectErrorDetail] = msgspec.field(default_factory=list[ConnectErrorDetail])


class EndStreamPayload(msgspec.Struct):
    """The terminal EndStreamResponse envelope of a streaming RPC."""

    error: ConnectWireError | None = None


_WIRE_ERROR_DECODER = msgspec.json.Decoder(ConnectWireError)
_END_STREAM_DECODER = msgspec.json.Decoder(EndStreamPayload)


def _error_info(wire: ConnectWireError) -> errors_pb2.ErrorInfo | None:
    """Extract and decode the daemon's `ErrorInfo` detail, if attached."""
    for detail in wire.details:
        if detail.type != _ERROR_INFO_TYPE:
            continue
        # The spec allows both padded and unpadded base64.
        padded = detail.value + "=" * (-len(detail.value) % 4)
        try:
            raw = base64.b64decode(padded)
            return errors_pb2.ErrorInfo.FromString(raw)
        except (ValueError, DecodeError):
            # Already on the error path: a malformed optional detail
            # degrades to the coarse Connect code instead of masking the
            # daemon's error with a decode exception.
            return None
    return None


def wire_error_to_exception(wire: ConnectWireError, operation: str | None = None) -> ArcBoxError:
    """Map a decoded Connect error to the typed hierarchy."""
    return error_from_wire(wire.code, wire.message, _error_info(wire), operation)


def unary_error(status_code: int, body: bytes, operation: str | None = None) -> ArcBoxError:
    """Map a non-200 unary response to the typed hierarchy."""
    try:
        wire = _WIRE_ERROR_DECODER.decode(body)
    except msgspec.DecodeError:
        wire = ConnectWireError(
            code=_HTTP_FALLBACK_CODES.get(status_code, "unknown"),
            message=f"HTTP {status_code}",
        )
    return wire_error_to_exception(wire, operation)


def end_stream_error(payload: bytes, operation: str | None = None) -> ArcBoxError | None:
    """Decode an EndStreamResponse; return its error, or None on success."""
    try:
        end = _END_STREAM_DECODER.decode(payload)
    except msgspec.DecodeError as exc:
        return ArcBoxError(f"malformed EndStreamResponse: {exc}", operation=operation)
    if end.error is None:
        return None
    return wire_error_to_exception(end.error, operation)
