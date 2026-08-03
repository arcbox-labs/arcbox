"""The hello-world closed loop against a LIVE daemon socket.

Opt-in: set ARCBOX_SDK_E2E=1 (and have `abctl daemon start` running,
with sandbox support on this host). Skipped cleanly otherwise.
Connection resolution applies, so ARCBOX_SOCKET / ARCBOX_DATA_DIR
point the loop at a dev daemon.

This is the design doc's 20-line hello world minus the parts outside
phase 1's surface: ports.expose and wait_for_port are deferred, so the
background command is observed through its output stream and
wait_for_exit instead of a port probe. Both surfaces run the same
scenario — the sync flavor exercises the generated tree end to end.
"""

from __future__ import annotations

import os

import pytest

from arcbox import AsyncSandbox, Sandbox

pytestmark = pytest.mark.skipif(
    os.environ.get("ARCBOX_SDK_E2E") != "1",
    reason="set ARCBOX_SDK_E2E=1 with a live daemon (sandbox support required)",
)


def test_sync_hello_world() -> None:
    # Built-in minimal template (busybox) — no image pull involved.
    sandbox = Sandbox.create("", ttl=300)
    try:
        # files: write then read back.
        sandbox.files.write_text("/tmp/hello.txt", "hello from arcbox\n")
        assert sandbox.files.read_text("/tmp/hello.txt") == "hello from arcbox\n"

        # foreground command: exit-as-data plus the expect() sugar.
        result = sandbox.commands.run(["/bin/cat", "/tmp/hello.txt"])
        assert result.expect().stdout == "hello from arcbox\n"

        # non-zero exit is data, not an exception (string form = shell sugar).
        failing = sandbox.commands.run("exit 3")
        assert failing.exit_code == 3

        # background command: iterable output, then wait_for_exit.
        bg = sandbox.commands.run("for i in 1 2 3; do echo line$i; done", background=True)
        streamed = b"".join(chunk.data for chunk in bg.output if chunk.channel != "stderr")
        assert b"line3" in streamed
        assert bg.wait_for_exit(30).exit_code == 0

        # kill() delivers a signal to the whole process group.
        sleeper = sandbox.commands.run(["/bin/sleep", "300"], background=True)
        sleeper.kill("SIGKILL")
        killed = sleeper.wait_for_exit(30)
        assert killed.signal == "SIGKILL"
        assert killed.exit_code == 137

        # info() is always fresh.
        assert sandbox.info().state in ("ready", "running")
    finally:
        sandbox.kill()


@pytest.mark.anyio
async def test_async_hello_world() -> None:
    sandbox = await AsyncSandbox.create("", ttl=300)
    async with sandbox:
        await sandbox.files.write_text("/tmp/hello.txt", "hello from arcbox\n")
        assert await sandbox.files.read_text("/tmp/hello.txt") == "hello from arcbox\n"

        result = await sandbox.commands.run(["/bin/cat", "/tmp/hello.txt"])
        assert result.expect().stdout == "hello from arcbox\n"

        bg = await sandbox.commands.run("for i in 1 2 3; do echo line$i; done", background=True)
        streamed = b""
        async for chunk in bg.output:
            if chunk.channel != "stderr":
                streamed += chunk.data
        assert b"line3" in streamed
        assert (await bg.wait_for_exit(30)).exit_code == 0
    # context exit: sandbox killed, nothing leaked
