"""wait_for_log() against a mock daemon.

The contracts under test: line-oriented matching over the replayed,
offset-addressed output (a line split across chunks still matches; a
line printed before the call matches immediately), regex and substring
forms, resume through the shared re-attach loop, the typed
exit-without-match error, and the deadline surfacing as a TimeoutError
naming the wait_for_log knob.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import httpx
import pytest

from arcbox import CommandHandle, Connection
from arcbox._envelope import FLAG_END_STREAM, encode_envelope
from arcbox._gen import process_pb2
from arcbox._sync._client import ConnectClient
from arcbox.errors import ArcBoxError, ConnectionLostError, TimeoutError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

STDOUT = process_pb2.STDIO_CHANNEL_STDOUT
STDERR = process_pb2.STDIO_CHANNEL_STDERR


def output_frame(channel: int, offset: int, text: str) -> bytes:
    event = process_pb2.ExecutionEvent()
    event.output.channel = channel  # type: ignore[assignment]
    event.output.offset = offset
    event.output.data = text.encode()
    return encode_envelope(0, event.SerializeToString())


def exited_frame() -> bytes:
    event = process_pb2.ExecutionEvent()
    event.exited.execution.id = "cmd"
    event.exited.execution.state = process_pb2.EXECUTION_STATE_EXITED
    event.exited.execution.exit_status.code = 0
    return encode_envelope(0, event.SerializeToString())


def stream_response(body: bytes, truncated: bool = False) -> httpx.Response:
    if not truncated:
        body += encode_envelope(FLAG_END_STREAM, b"{}")
    return httpx.Response(200, content=body, headers={"content-type": "application/connect+proto"})


class FlakyAttach:
    """Serves AttachExecution from a chunk script (replaying from the
    requested offsets like the daemon), optionally cutting the n-th
    stream after ``die_after[n]`` chunks (a raw truncation)."""

    def __init__(
        self,
        chunks: list[tuple[int, int, str]],
        die_after: list[int] | None = None,
    ) -> None:
        self.chunks = chunks
        self.die_after = die_after or []
        self.attaches: list[process_pb2.AttachExecutionRequest] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/AttachExecution"):
            req = process_pb2.AttachExecutionRequest.FromString(request.content[5:])
            call = len(self.attaches)
            self.attaches.append(req)
            budget = self.die_after[call] if call < len(self.die_after) else None
            body = b""
            sent = 0
            for channel, offset, text in self.chunks:
                resume = req.stderr_offset if channel == STDERR else req.stdout_offset
                if offset < resume:
                    continue
                if budget is not None and sent >= budget:
                    return stream_response(body, truncated=True)
                body += output_frame(channel, offset, text)
                sent += 1
            if budget is not None:
                return stream_response(body, truncated=True)
            return stream_response(body + exited_frame())
        return httpx.Response(404, content=b"unhandled: " + path.encode())


def handle_for(handler: Callable[[httpx.Request], httpx.Response]) -> CommandHandle:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://arcbox")
    return CommandHandle(ConnectClient(Connection(http_client=http)), "sb-1", "cmd")


def test_matches_a_line_split_across_chunks_and_channels() -> None:
    daemon = FlakyAttach(
        [
            (STDOUT, 0, "boot...\nser"),
            (STDERR, 0, "warn: noise\n"),
            (STDOUT, 11, "ver ready\ntail"),
        ]
    )
    assert handle_for(daemon).wait_for_log("server ready") == "server ready"


def test_matches_with_a_regex_and_returns_the_whole_line() -> None:
    daemon = FlakyAttach([(STDOUT, 0, "listening on port 8080\n")])
    line = handle_for(daemon).wait_for_log(re.compile(r"port \d+"))
    assert line == "listening on port 8080"


def test_matches_on_stderr_and_replayed_output_matches_immediately() -> None:
    daemon = FlakyAttach([(STDERR, 0, "level=info started\n")])
    assert handle_for(daemon).wait_for_log("started") == "level=info started"


def test_a_trailing_unterminated_line_still_matches_at_exit() -> None:
    daemon = FlakyAttach([(STDOUT, 0, "done without newline")])
    assert handle_for(daemon).wait_for_log("without newline") == "done without newline"


def test_resumes_through_the_reattach_loop_when_the_stream_drops_mid_scan() -> None:
    daemon = FlakyAttach(
        [
            (STDOUT, 0, "part one\nsecond "),
            (STDOUT, 16, "half matches\n"),
        ],
        die_after=[1],
    )
    assert handle_for(daemon).wait_for_log("half matches") == "second half matches"
    assert len(daemon.attaches) == 2
    # The re-attach resumed at the delivered high-water mark: the whole
    # first chunk (16 bytes), including the partial "second " tail.
    assert daemon.attaches[1].stdout_offset == 16


def test_exit_without_a_match_is_a_typed_error_not_a_timeout() -> None:
    daemon = FlakyAttach([(STDOUT, 0, "nothing here\n")])
    with pytest.raises(ArcBoxError, match="exited before the log pattern") as exc_info:
        handle_for(daemon).wait_for_log("absent-marker", timeout=5)
    assert not isinstance(exc_info.value, TimeoutError)
    assert exc_info.value.operation == "commands.wait_for_log"


def test_the_deadline_surfaces_as_a_timeout_error_naming_the_knob() -> None:
    # An endless stream of keepalive frames without the pattern: the
    # per-frame deadline check must fire.
    def keepalives() -> Iterator[bytes]:
        event = process_pb2.ExecutionEvent()
        event.keep_alive.SetInParent()
        frame = encode_envelope(0, event.SerializeToString())
        while True:
            yield frame

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=keepalives(),
            headers={"content-type": "application/connect+proto"},
        )

    with pytest.raises(TimeoutError) as exc_info:
        handle_for(handler).wait_for_log("never-appears", timeout=0.05)
    assert exc_info.value.operation == "commands.wait_for_log"
    assert exc_info.value.suggestion == "increase the wait_for_log timeout argument"


def test_a_match_arriving_past_the_deadline_is_still_a_timeout() -> None:
    # Deadline-first ordering: a frame landing after expiry must not
    # flip the timeout into a late success (or a late exit error).
    daemon = FlakyAttach([(STDOUT, 0, "the-marker\n")])
    with pytest.raises(TimeoutError):
        handle_for(daemon).wait_for_log("the-marker", timeout=0.0)


def test_a_dead_attach_past_the_deadline_is_the_timeout_not_stream_death() -> None:
    # Every dial dies immediately; with the deadline already passed the
    # exhausted retry budget surfaces as the wait_for_log timeout.
    daemon = FlakyAttach([(STDOUT, 0, "x\n")], die_after=[0, 0, 0, 0, 0])
    with pytest.raises(TimeoutError):
        handle_for(daemon).wait_for_log("never", timeout=0.0)


def test_a_dead_attach_without_a_deadline_stays_stream_death() -> None:
    daemon = FlakyAttach([(STDOUT, 0, "x\n")], die_after=[0, 0, 0, 0, 0])
    with pytest.raises(ConnectionLostError):
        handle_for(daemon).wait_for_log("never")


def test_the_attach_read_gap_is_bounded_by_the_remaining_budget() -> None:
    # A wedged stream that stops producing frames entirely must not
    # outlive the wait_for_log budget: each attach dial carries a read
    # timeout equal to the remaining time (visible to the transport via
    # the request's timeout extension).
    read_timeouts: list[float | None] = []

    class Recorder(FlakyAttach):
        def __call__(self, request: httpx.Request) -> httpx.Response:
            timeout = request.extensions.get("timeout")
            read_timeouts.append(None if timeout is None else timeout.get("read"))
            return super().__call__(request)

    bounded = Recorder([(STDOUT, 0, "the-marker\n")])
    assert handle_for(bounded).wait_for_log("the-marker", timeout=30) == "the-marker"
    assert read_timeouts[0] is not None
    assert 0 < read_timeouts[0] <= 30

    # Without a deadline (and for plain output streaming) the attach
    # stays unbounded — long-lived streams must not time out on idle.
    unbounded = Recorder([(STDOUT, 0, "the-marker\n")])
    assert handle_for(unbounded).wait_for_log("the-marker") == "the-marker"
    assert read_timeouts[-1] is None


def test_a_daemon_typed_stream_error_keeps_its_own_class() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        end = json.dumps({"error": {"code": "not_found", "message": "no such execution"}}).encode()
        return httpx.Response(
            200,
            content=output_frame(STDOUT, 0, "x\n") + encode_envelope(FLAG_END_STREAM, end),
            headers={"content-type": "application/connect+proto"},
        )

    with pytest.raises(ArcBoxError) as exc_info:
        handle_for(handler).wait_for_log("never", timeout=30)
    assert not isinstance(exc_info.value, TimeoutError)
