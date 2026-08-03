"""Connect-over-httpx transport.

Unary RPCs are plain POSTs with binary-protobuf bodies
(``application/proto``); streaming RPCs speak the Connect streaming
envelope (``application/connect+proto``, framing in ``_envelope``).
The local tier dials the daemon's Unix socket through httpx's ``uds``
transport; the same code path serves a future remote tier over HTTPS.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Generic, TypeVar

import httpx

from arcbox._connection import Connection, resolve_connection
from arcbox._envelope import (
    FLAG_COMPRESSED,
    FLAG_END_STREAM,
    EnvelopeDecoder,
    encode_envelope,
    end_stream_error,
    unary_error,
)
from arcbox.errors import ArcBoxError, InvalidArgumentError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable, Mapping
    from contextlib import AbstractAsyncContextManager
    from types import TracebackType

    from google.protobuf.message import Message

M = TypeVar("M", bound="Message")

_UNARY_HEADERS = {
    "content-type": "application/proto",
    "connect-protocol-version": "1",
}
_STREAM_HEADERS = {
    "content-type": "application/connect+proto",
    "connect-protocol-version": "1",
}


class _UseDefault:
    """Sentinel: apply the connection's ``request_timeout``."""

    def __repr__(self) -> str:
        # Stable across the async and sync trees so signatures compare
        # equal in the parity test (and read cleanly in help()).
        return "USE_DEFAULT"


_USE_DEFAULT = _UseDefault()


class AsyncConnectClient:
    """One resolved connection to a daemon; every handle shares it."""

    def __init__(
        self,
        connection: Connection | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        resolved = resolve_connection(connection, os.environ if env is None else env)
        #: Per-unary-RPC deadline in seconds, when configured. Streams
        #: and long-polls never receive it.
        self.request_timeout = resolved.request_timeout
        injected = connection.http_client if connection is not None else None
        if injected is not None:
            required = httpx.AsyncClient
            if not isinstance(injected, required):
                raise InvalidArgumentError(
                    f"Connection.http_client must be an httpx.{required.__name__} for this surface"
                )
            self._http = injected
            return
        headers = {"authorization": f"Bearer {resolved.api_key}"} if resolved.api_key else None
        transport = (
            httpx.AsyncHTTPTransport(uds=resolved.socket_path)
            if resolved.socket_path is not None
            else None
        )
        self._http = httpx.AsyncClient(
            base_url=resolved.base_url,
            transport=transport,
            headers=headers,
            timeout=None,
        )

    async def unary(
        self,
        path: str,
        request: Message,
        response_type: type[M],
        timeout: float | _UseDefault | None = _USE_DEFAULT,
    ) -> M:
        """One unary RPC. ``timeout`` overrides the configured deadline;
        an explicit ``None`` means no deadline (checkpoint restores take
        as long as they take)."""
        effective = self.request_timeout if isinstance(timeout, _UseDefault) else timeout
        headers = dict(_UNARY_HEADERS)
        if effective is not None:
            headers["connect-timeout-ms"] = str(int(effective * 1000))
        response = await self._http.post(
            path,
            content=request.SerializeToString(),
            headers=headers,
            timeout=None if effective is None else httpx.Timeout(effective),
        )
        if response.status_code != 200:
            raise unary_error(response.status_code, response.content)
        content_type = response.headers.get("content-type", "")
        if not content_type.startswith("application/proto"):
            raise ArcBoxError(f"unexpected unary response content-type {content_type!r}")
        message = response_type()
        message.ParseFromString(response.content)
        return message

    def stream(self, path: str, request: Message, response_type: type[M]) -> AsyncServerStream[M]:
        """One server-streaming RPC. Entering the returned context sends
        the request (that is what registers a subscription server-side);
        iterate it for messages."""
        return AsyncServerStream(self._http, path, request, response_type)

    async def client_stream(
        self, path: str, requests: Iterable[Message], response_type: type[M]
    ) -> M:
        """One client-streaming RPC with the full request sequence known
        up front: the envelopes are sent as one body and the single
        response message is returned."""
        body = b"".join(encode_envelope(0, m.SerializeToString()) for m in requests)
        response = await self._http.post(path, content=body, headers=_STREAM_HEADERS, timeout=None)
        if response.status_code != 200:
            raise unary_error(response.status_code, response.content)
        decoder = EnvelopeDecoder()
        message: M | None = None
        for flags, payload in decoder.feed(response.content):
            if flags & FLAG_COMPRESSED:
                raise ArcBoxError("received a compressed frame without negotiating compression")
            if flags & FLAG_END_STREAM:
                error = end_stream_error(payload)
                if error is not None:
                    raise error
            else:
                decoded = response_type()
                decoded.ParseFromString(payload)
                message = decoded
        if message is None:
            raise ArcBoxError("the stream ended without a response message")
        return message


class AsyncServerStream(Generic[M]):
    """One server-streaming call: a context manager yielding an iterator.

    The stream ends deterministically — with the terminal
    EndStreamResponse frame or a typed error, never silence.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        path: str,
        request: Message,
        response_type: type[M],
    ) -> None:
        self._http = http
        self._path = path
        self._body = encode_envelope(0, request.SerializeToString())
        self._response_type = response_type
        self._cm: AbstractAsyncContextManager[httpx.Response] | None = None
        self._response: httpx.Response | None = None

    async def __aenter__(self) -> AsyncServerStream[M]:
        cm = self._http.stream(
            "POST", self._path, content=self._body, headers=_STREAM_HEADERS, timeout=None
        )
        response = await cm.__aenter__()
        if response.status_code != 200:
            body = await response.aread()
            await cm.__aexit__(None, None, None)
            raise unary_error(response.status_code, body)
        self._cm = cm
        self._response = response
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._cm is not None:
            await self._cm.__aexit__(exc_type, exc, tb)

    def __aiter__(self) -> AsyncIterator[M]:
        return self._messages()

    async def _messages(self) -> AsyncIterator[M]:
        response = self._response
        if response is None:
            raise ArcBoxError("stream iterated before it was entered")
        decoder = EnvelopeDecoder()
        async for data in response.aiter_bytes():
            for flags, payload in decoder.feed(data):
                if flags & FLAG_COMPRESSED:
                    raise ArcBoxError("received a compressed frame without negotiating compression")
                if flags & FLAG_END_STREAM:
                    error = end_stream_error(payload)
                    if error is not None:
                        raise error
                    return
                message = self._response_type()
                message.ParseFromString(payload)
                yield message
        raise ArcBoxError("the stream ended without an EndStreamResponse")
