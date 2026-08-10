"""The ``sandbox.commands`` and ``sandbox.pty`` namespaces in ``e2b``'s shape."""

from __future__ import annotations

import codecs
from typing import TYPE_CHECKING, Literal, overload

from arcbox import PtySize as ArcBoxPtySize
from arcbox.e2b._pump import AsyncPump, async_call
from arcbox.e2b._types import CommandResult, ProcessInfo, PtySize, expect_zero_exit, seconds

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from arcbox import AsyncCommandHandle as ArcBoxCommandHandle
    from arcbox import AsyncCommands as ArcBoxCommands


class AsyncCommandHandle:
    """A running command, in ``e2b``'s shape.

    The output model is inverted from arcbox's on purpose: ``e2b``
    pushes chunks into ``on_stdout``/``on_stderr`` callbacks, so this
    handle pumps the underlying stream into them from the moment it is
    created. A handle with no callbacks starts no pump — the bytes are
    still retained daemon-side and arrive with the result."""

    def __init__(
        self,
        handle: ArcBoxCommandHandle,
        on_stdout: Callable[[str], object] | None = None,
        on_stderr: Callable[[str], object] | None = None,
        on_data: Callable[[bytes], object] | None = None,
    ) -> None:
        self._handle = handle
        #: Execution id. ``e2b`` names it ``pid``; arcbox ids are not OS pids.
        self.pid = handle.command_id
        self._failure: BaseException | None = None
        self._pump: AsyncPump | None = None
        # Set by disconnect(): the pump stops delivering and detaches.
        self._disconnected = False
        if on_stdout is not None or on_stderr is not None or on_data is not None:
            self._pump = AsyncPump(lambda: self._pump_output(on_stdout, on_stderr, on_data))

    async def _pump_output(
        self,
        on_stdout: Callable[[str], object] | None,
        on_stderr: Callable[[str], object] | None,
        on_data: Callable[[bytes], object] | None,
    ) -> None:
        # One incremental decoder per channel: stdout and stderr
        # interleave on the wire, and a multibyte character split across
        # frames must reassemble within its own channel.
        decoders = {
            "stdout": codecs.getincrementaldecoder("utf-8")("replace"),
            "stderr": codecs.getincrementaldecoder("utf-8")("replace"),
        }
        try:
            async for chunk in self._handle.output:
                if self._disconnected:
                    # Breaking out closes the underlying stream.
                    break
                # A terminal merges stdout and stderr and carries escape
                # sequences, so its bytes go to on_data undecoded —
                # decoding them as text would corrupt what a terminal
                # emulator needs.
                if on_data is not None:
                    await async_call(on_data, chunk.data)
                    continue
                channel = "stderr" if chunk.channel == "stderr" else "stdout"
                sink = on_stderr if channel == "stderr" else on_stdout
                if sink is not None:
                    await async_call(sink, decoders[channel].decode(chunk.data))
            if not self._disconnected:
                # Flush a partial multibyte character buffered at end of
                # stream.
                stdout_tail = decoders["stdout"].decode(b"", final=True)
                if stdout_tail and on_stdout is not None:
                    await async_call(on_stdout, stdout_tail)
                stderr_tail = decoders["stderr"].decode(b"", final=True)
                if stderr_tail and on_stderr is not None:
                    await async_call(on_stderr, stderr_tail)
        except Exception as error:
            # Surfaced by wait(): raising out of a detached pump would be
            # an unretrieved exception with no caller to receive it. A
            # failure after disconnect() is that teardown, not something
            # to report.
            if not self._disconnected:
                self._failure = error

    async def wait(self) -> CommandResult:
        """Wait for the command to finish.

        Raises ``CommandExitException`` on a non-zero exit, as ``e2b``
        does."""
        result = await self._handle.wait_for_exit()
        if self._pump is not None:
            await self._pump.join()
        failure = self._failure
        if failure is not None:
            # Re-raises exactly what the stream raised: the SDK's typed
            # exception classes must reach the caller intact.
            raise failure
        return expect_zero_exit(result)

    async def kill(self, signal: str = "SIGKILL") -> bool:
        """Kill the command's process group."""
        await self._handle.kill(signal)  # pyright: ignore[reportArgumentType]
        return True

    async def send_stdin(self, data: str | bytes) -> None:
        """Feed bytes to the command's stdin."""
        await self._handle.write_stdin(data)

    async def close_stdin(self) -> None:
        """Close the command's stdin."""
        await self._handle.close_stdin()

    async def resize(self, size: PtySize) -> None:
        """Resize the command's terminal."""
        await self._handle.resize(size.cols, size.rows)

    async def disconnect(self) -> None:
        """Stop receiving output without killing the command.

        The async flavor cancels the pump task outright; the sync one
        cannot interrupt its thread, so the flag makes the pump swallow
        the next chunk, break out, and detach. Output the daemon retains
        still arrives with the result via :meth:`wait`."""
        self._disconnected = True
        pump, self._pump = self._pump, None
        if pump is not None:
            pump.cancel()


class AsyncCommands:
    """``e2b``'s ``Commands``, backed by arcbox's ``commands``."""

    def __init__(self, commands: ArcBoxCommands) -> None:
        self._commands = commands

    @overload
    async def run(
        self,
        cmd: str,
        *,
        background: Literal[False] = False,
        cwd: str | None = None,
        user: str | None = None,
        envs: Mapping[str, str] | None = None,
        on_stdout: Callable[[str], object] | None = None,
        on_stderr: Callable[[str], object] | None = None,
        stdin: bool = False,
        timeout_ms: float | None = None,
    ) -> CommandResult: ...

    @overload
    async def run(
        self,
        cmd: str,
        *,
        background: Literal[True],
        cwd: str | None = None,
        user: str | None = None,
        envs: Mapping[str, str] | None = None,
        on_stdout: Callable[[str], object] | None = None,
        on_stderr: Callable[[str], object] | None = None,
        stdin: bool = False,
        timeout_ms: float | None = None,
    ) -> AsyncCommandHandle: ...

    async def run(
        self,
        cmd: str,
        *,
        background: bool = False,
        cwd: str | None = None,
        user: str | None = None,
        envs: Mapping[str, str] | None = None,
        on_stdout: Callable[[str], object] | None = None,
        on_stderr: Callable[[str], object] | None = None,
        stdin: bool = False,
        timeout_ms: float | None = None,
    ) -> CommandResult | AsyncCommandHandle:
        """Run a command.

        Foreground returns the result and raises
        ``CommandExitException`` on a non-zero exit; ``background=True``
        returns a handle."""
        handle = await self._commands.run(
            cmd,
            background=True,
            cwd=cwd,
            user=user,
            env=envs,
            timeout=seconds(timeout_ms),
            # stdin only makes sense on a handle the caller keeps, which
            # is the background path; a foreground run waits for an exit.
            stdin=stdin and background,
        )
        shim = AsyncCommandHandle(handle, on_stdout, on_stderr)
        return shim if background else await shim.wait()

    async def connect(
        self,
        pid: str,
        on_stdout: Callable[[str], object] | None = None,
        on_stderr: Callable[[str], object] | None = None,
    ) -> AsyncCommandHandle:
        """Take a handle on a command started elsewhere."""
        return AsyncCommandHandle(await self._commands.get(pid), on_stdout, on_stderr)

    async def kill(self, pid: str) -> bool:
        """Signal a command by id."""
        await (await self._commands.get(pid)).kill("SIGKILL")
        return True

    async def send_stdin(self, pid: str, data: str | bytes) -> None:
        """Feed bytes to a command's stdin by id."""
        await (await self._commands.get(pid)).write_stdin(data)

    async def close_stdin(self, pid: str) -> None:
        """Close a command's stdin by id."""
        await (await self._commands.get(pid)).close_stdin()

    async def list(self) -> list[ProcessInfo]:
        """List the sandbox's running commands."""
        infos = await self._commands.list()
        return [ProcessInfo(pid=info.command_id) for info in infos if info.state == "running"]


class AsyncPty:
    """``e2b``'s ``Pty``, backed by the ``tty`` argument on ``commands.run``.

    arcbox has no separate PTY service — a terminal is one flag on an
    execution — so this namespace is sugar that keeps ``e2b`` code
    working."""

    def __init__(self, commands: ArcBoxCommands) -> None:
        self._commands = commands

    async def create(
        self,
        size: PtySize,
        on_data: Callable[[bytes], object],
        *,
        cwd: str | None = None,
        user: str | None = None,
        envs: Mapping[str, str] | None = None,
        timeout_ms: float | None = None,
    ) -> AsyncCommandHandle:
        """Start a shell on a pseudo-terminal of the given size."""
        handle = await self._commands.run(
            ["/bin/sh", "-l"],
            background=True,
            pty=ArcBoxPtySize(cols=size.cols, rows=size.rows),
            cwd=cwd,
            user=user,
            env=envs,
            timeout=seconds(timeout_ms),
        )
        return AsyncCommandHandle(handle, on_data=on_data)

    async def connect(self, pid: str, on_data: Callable[[bytes], object]) -> AsyncCommandHandle:
        """Take a handle on a terminal started elsewhere."""
        return AsyncCommandHandle(await self._commands.get(pid), on_data=on_data)

    async def send_input(self, pid: str, data: bytes) -> None:
        """Feed bytes to the terminal."""
        await (await self._commands.get(pid)).write_stdin(data)

    async def resize(self, pid: str, size: PtySize) -> None:
        """Resize the terminal."""
        handle = await self._commands.get(pid)
        await handle.resize(size.cols, size.rows)

    async def kill(self, pid: str) -> bool:
        """Kill the terminal's process group."""
        await (await self._commands.get(pid)).kill("SIGKILL")
        return True
