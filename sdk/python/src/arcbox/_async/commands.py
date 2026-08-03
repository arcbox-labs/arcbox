"""The ``sandbox.commands`` namespace: run processes inside one sandbox."""

from __future__ import annotations

import math
import time
import uuid
from typing import TYPE_CHECKING, Literal, overload

from google.protobuf import empty_pb2

from arcbox._boundary import wrap_errors
from arcbox._gen import process_pb2
from arcbox._types import (
    SIGNAL_VALUES,
    CommandResult,
    OutputChunk,
    command_result_from_execution,
)
from arcbox.errors import InvalidArgumentError, TimeoutError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence

    from arcbox._types import OutputChannel, SignalName

    from ._client import AsyncConnectClient, AsyncServerStream

_PROCESS = "/arcbox.sandbox.v1.SandboxProcessService/"

#: Longest single WaitExecution long-poll slice, so a dropped daemon
#: surfaces as an error instead of an infinite silent wait.
_WAIT_SLICE_SECONDS = 30


def _normalize_cmd(cmd: str | Sequence[str]) -> list[str]:
    """``str`` is sugar for a shell command; a sequence is argv, executed
    directly with no shell involved."""
    return ["/bin/sh", "-lc", cmd] if isinstance(cmd, str) else list(cmd)


def _channel_name(channel: int) -> OutputChannel:
    if channel == process_pb2.STDIO_CHANNEL_STDERR:
        return "stderr"
    if channel == process_pb2.STDIO_CHANNEL_PTY:
        return "pty"
    return "stdout"


def _decode_output(chunks: list[bytes]) -> str:
    return b"".join(chunks).decode("utf-8", errors="replace")


class AsyncCommandHandle:
    """A handle to a running (or finished) command. The process is
    decoupled from this object: dropping the handle never kills the
    process."""

    def __init__(self, client: AsyncConnectClient, sandbox_id: str, command_id: str) -> None:
        self._client = client
        self._sandbox_id = sandbox_id
        #: Execution id, unique within the sandbox; addressable across clients.
        self.command_id = command_id

    @property
    def output(self) -> AsyncIterator[OutputChunk]:
        """Stream the command's output from the beginning — or from the
        earliest byte the daemon still retains (8 MiB per channel);
        replayed buffered output comes first, then live output follows;
        the stream ends when the process exits (deterministic
        termination — never silence)."""
        return self._stream_output()

    async def _stream_output(self) -> AsyncIterator[OutputChunk]:
        with wrap_errors("commands.output"):
            async with self._attach() as stream:
                async for event in stream:
                    kind = event.WhichOneof("event")
                    if kind == "output":
                        chunk = event.output
                        yield OutputChunk(_channel_name(chunk.channel), chunk.data)
                    elif kind == "exited":
                        return

    async def wait_for_exit(self, timeout: float | None = None) -> CommandResult:
        """Wait until the command exits and return its result (server-side
        long-poll; no client-side spinning). ``timeout`` bounds the WAIT,
        not the process: on expiry a :class:`TimeoutError` is raised and
        the process keeps running."""
        deadline = None if timeout is None else time.monotonic() + timeout
        with wrap_errors("commands.wait_for_exit"):
            while True:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError(
                        "wait_for_exit(timeout) elapsed before the command exited",
                        suggestion=(
                            "increase the wait_for_exit timeout argument, or kill() the command"
                        ),
                        context={"command_id": self.command_id},
                    )
                slice_seconds = (
                    _WAIT_SLICE_SECONDS
                    if remaining is None
                    else min(_WAIT_SLICE_SECONDS, max(1, math.ceil(remaining)))
                )
                execution = await self._client.unary(
                    _PROCESS + "WaitExecution",
                    process_pb2.WaitExecutionRequest(
                        sandbox_id=self._sandbox_id,
                        execution_id=self.command_id,
                        timeout_seconds=slice_seconds,
                    ),
                    process_pb2.Execution,
                    # Exempt from request_timeout: this unary deliberately
                    # parks server-side for the slice; grant it that long
                    # plus grace.
                    timeout=float(slice_seconds + 5),
                )
                if execution.state == process_pb2.EXECUTION_STATE_EXITED:
                    break
            return await self._collect_result(execution)

    async def kill(self, signal: SignalName = "SIGTERM") -> None:
        """Deliver a signal to the whole process group (default SIGTERM)."""
        with wrap_errors("commands.kill"):
            await self._client.unary(
                _PROCESS + "SignalExecution",
                process_pb2.SignalExecutionRequest(
                    sandbox_id=self._sandbox_id,
                    execution_id=self.command_id,
                    signal=SIGNAL_VALUES[signal],
                ),
                empty_pb2.Empty,
            )

    def _attach(self) -> AsyncServerStream[process_pb2.ExecutionEvent]:
        return self._client.stream(
            _PROCESS + "AttachExecution",
            process_pb2.AttachExecutionRequest(
                sandbox_id=self._sandbox_id,
                execution_id=self.command_id,
                stdout_offset=0,
                stderr_offset=0,
            ),
            process_pb2.ExecutionEvent,
        )

    async def _collect_result(self, execution: process_pb2.Execution) -> CommandResult:
        """Assemble the result of an exited execution. Output is re-read
        from offset 0 — the daemon retains and replays it, so the result
        is complete even when nobody consumed the live stream, UNLESS the
        command outgrew the daemon's per-channel retention (8 MiB): chunk
        offsets expose the dropped head, reported as ``truncated``."""
        stdout: list[bytes] = []
        stderr: list[bytes] = []
        next_stdout = 0
        next_stderr = 0
        truncated = False
        async with self._attach() as stream:
            async for event in stream:
                kind = event.WhichOneof("event")
                if kind == "output":
                    chunk = event.output
                    is_stderr = chunk.channel == process_pb2.STDIO_CHANNEL_STDERR
                    # A chunk landing past the expected offset means
                    # retention already dropped bytes we asked for.
                    if chunk.offset > (next_stderr if is_stderr else next_stdout):
                        truncated = True
                    after = chunk.offset + len(chunk.data)
                    if is_stderr:
                        next_stderr = after
                        stderr.append(chunk.data)
                    else:
                        next_stdout = after
                        stdout.append(chunk.data)
                elif kind == "exited":
                    break
        return command_result_from_execution(
            execution, _decode_output(stdout), _decode_output(stderr), truncated
        )


class AsyncCommands:
    """Run processes inside one sandbox."""

    def __init__(self, client: AsyncConnectClient, sandbox_id: str) -> None:
        self._client = client
        self._sandbox_id = sandbox_id

    @overload
    async def run(
        self,
        cmd: str | Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        user: str | None = None,
        timeout: float | None = None,
        check: bool = False,
        background: Literal[False] = False,
    ) -> CommandResult: ...

    @overload
    async def run(
        self,
        cmd: str | Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        user: str | None = None,
        timeout: float | None = None,
        background: Literal[True],
    ) -> AsyncCommandHandle: ...

    async def run(
        self,
        cmd: str | Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        user: str | None = None,
        timeout: float | None = None,
        check: bool = False,
        background: bool = False,
    ) -> CommandResult | AsyncCommandHandle:
        """Run a command. Foreground (default): returns the complete
        :class:`CommandResult` once the process exits — non-zero exit is
        data unless ``check=True`` (`subprocess.run` semantics).
        Background (``background=True``): returns as soon as the process
        is started, with a handle for streaming and waiting.

        ``timeout`` kills the whole process group after that many
        seconds; expiry surfaces as signal death in the result
        (exit-as-data), not as a raised error."""
        if background and check:
            raise InvalidArgumentError(
                "check=True applies to foreground runs; call "
                ".wait_for_exit() and .expect() on the handle instead",
                operation="commands.run",
            )
        handle = await self._start(cmd, cwd=cwd, env=env, user=user, timeout=timeout)
        if background:
            return handle
        result = await handle.wait_for_exit()
        return result.expect() if check else result

    async def _start(
        self,
        cmd: str | Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str] | None,
        user: str | None,
        timeout: float | None,
    ) -> AsyncCommandHandle:
        with wrap_errors("commands.run"):
            # The execution id is minted client-side: a lost response
            # leaves an addressable execution, and retries are idempotent
            # by contract.
            execution_id = str(uuid.uuid4())
            execution = await self._client.unary(
                _PROCESS + "StartExecution",
                process_pb2.StartExecutionRequest(
                    sandbox_id=self._sandbox_id,
                    execution_id=execution_id,
                    cmd=_normalize_cmd(cmd),
                    env=dict(env) if env else {},
                    working_dir=cwd or "",
                    user=user or "",
                    timeout_seconds=0 if timeout is None else math.ceil(timeout),
                    stdin=False,
                ),
                process_pb2.Execution,
            )
            return AsyncCommandHandle(self._client, self._sandbox_id, execution.id)
