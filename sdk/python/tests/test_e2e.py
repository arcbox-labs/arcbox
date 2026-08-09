"""The hello-world closed loop against a LIVE daemon socket.

Opt-in: set ARCBOX_SDK_E2E=1 (and have `abctl daemon start` running,
with sandbox support on this host). Skipped cleanly otherwise.
Connection resolution applies, so ARCBOX_SOCKET / ARCBOX_DATA_DIR
point the loop at a dev daemon.

This is the design doc's 20-line hello world plus the phase 2a surface:
PTY, stdin, re-attach, set_lifecycle, capabilities, and events. Still
outside scope: ports.expose and wait_for_port (2b). The sync flavor
exercises the generated tree end to end — including genuinely blocking
event-stream reads.
"""

from __future__ import annotations

import os

import pytest

from arcbox import ArcBox, AsyncSandbox, PtySize, Sandbox

pytestmark = pytest.mark.skipif(
    os.environ.get("ARCBOX_SDK_E2E") != "1",
    reason="set ARCBOX_SDK_E2E=1 with a live daemon (sandbox support required)",
)


def test_capabilities_handshake() -> None:
    # This suite only runs on sandbox-capable hosts, so nested_virt must
    # report supported — the same answer create() relies on.
    with ArcBox() as box:
        caps = box.capabilities()
    assert caps.protocol >= 1
    assert caps.daemon_version != ""
    assert "pause_resume" in caps.features
    assert caps.nested_virt.supported is True


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

        # stdin: foreground write-then-close (subprocess semantics).
        echoed = sandbox.commands.run(["/bin/cat"], stdin="hello stdin\n")
        assert echoed.expect().stdout == "hello stdin\n"

        # stdin: a background handle drives offset-idempotent writes.
        cat_bg = sandbox.commands.run(["/bin/cat"], background=True, stdin=True)
        cat_bg.write_stdin("first ")
        cat_bg.write_stdin("second\n")
        cat_bg.close_stdin()
        assert cat_bg.wait_for_exit(30).stdout == "first second\n"

        # commands.get: re-attach by id; the retained output replays.
        again = sandbox.commands.get(cat_bg.command_id)
        assert again.wait_for_exit(30).stdout == "first second\n"

        # PTY: stty reads the allocated terminal's geometry (rows cols),
        # and output arrives merged (a pty run's stdout carries it all).
        tty = sandbox.commands.run("stty size", pty=PtySize(cols=120, rows=40))
        assert "40 120" in tty.expect().stdout

        # PTY resize: the running terminal observes the new geometry.
        resized = sandbox.commands.run(
            "sleep 2; stty size", pty=PtySize(cols=80, rows=24), background=True
        )
        resized.resize(200, 50)
        assert "50 200" in resized.wait_for_exit(30).stdout

        # set_lifecycle tri-state: re-arm the TTL, then remove it (None),
        # then re-arm again so the sandbox cannot outlive a crash here.
        sandbox.set_lifecycle(ttl=600)
        assert sandbox.info().ttl_deadline is not None
        sandbox.set_lifecycle(ttl=None)
        assert sandbox.info().ttl_deadline is None
        sandbox.set_lifecycle(ttl=300)

        # info() is always fresh.
        assert sandbox.info().state in ("ready", "running")
    finally:
        sandbox.kill()


def test_events_observe_the_idle_auto_pause() -> None:
    # A short idle timeout with the PAUSE policy: the daemon must emit
    # PAUSING (reason idle_timeout) then PAUSED on the events stream.
    # The sync flavor genuinely blocks on each read — no polling.
    sandbox = Sandbox.create("", ttl=300, idle_timeout=4, on_idle="pause")
    try:
        kinds: list[str] = []
        reason = ""
        with sandbox.events() as stream:
            for event in stream:
                kinds.append(event.kind)
                if event.kind == "pausing":
                    reason = event.attributes.get("reason", "")
                if event.kind == "paused":
                    break
        assert "pausing" in kinds
        assert kinds[-1] == "paused"
        assert reason == "idle_timeout"
        assert sandbox.info().state == "paused"
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
