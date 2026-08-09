"""The hello-world closed loop against a LIVE daemon socket.

Opt-in: set ARCBOX_SDK_E2E=1 (and have `abctl daemon start` running,
with sandbox support on this host). Skipped cleanly otherwise.
Connection resolution applies, so ARCBOX_SOCKET / ARCBOX_DATA_DIR
point the loop at a dev daemon.

This is the design doc's 20-line hello world plus the phase 2a surface
(PTY, stdin, re-attach, set_lifecycle, capabilities, events) and the
phase 2b surface (filesystem path verbs, watch, wait_for_port,
commands.list, wait_for_log). Still outside scope: Template statics.
The sync flavor exercises the generated tree end to end — including
genuinely blocking event-stream reads.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from arcbox import ArcBox, AsyncSandbox, FsEvent, PtySize, Sandbox
from arcbox.errors import ArcBoxError
from arcbox.errors import FileNotFoundError as SandboxFileNotFoundError
from arcbox.errors import TimeoutError as SandboxTimeoutError

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


def test_sync_phase_2b_surface() -> None:
    # Path verbs, wait_for_port, commands.list, and wait_for_log on the
    # genuinely blocking sync tree (the watch flavor is exercised async
    # below, where a read can be raced against a timer).
    sandbox = Sandbox.create("", ttl=300)
    try:
        # The listener below needs busybox `nc`.
        assert sandbox.commands.run("command -v nc").exit_code == 0

        # Path verbs roundtrip: mkdir -p -> write -> stat -> list ->
        # move -> remove (with the non-recursive guard).
        sandbox.files.mkdir("/tmp/verbs/nested")
        sandbox.files.mkdir("/tmp/verbs/nested")  # mkdir -p: idempotent
        sandbox.files.write_text("/tmp/verbs/nested/a.txt", "payload\n")
        stat = sandbox.files.stat("/tmp/verbs/nested/a.txt")
        assert stat.kind == "file"
        assert stat.size == 8
        assert stat.mode == 0o644
        assert stat.name == "a.txt"
        assert stat.modified_at is not None
        assert [e.name for e in sandbox.files.list("/tmp/verbs/nested")] == ["a.txt"]
        sandbox.files.move("/tmp/verbs/nested/a.txt", "/tmp/verbs/nested/b.txt")
        assert sandbox.files.read_text("/tmp/verbs/nested/b.txt") == "payload\n"
        with pytest.raises(SandboxFileNotFoundError):
            sandbox.files.stat("/tmp/verbs/nested/a.txt")
        # A non-empty directory refuses a non-recursive remove...
        with pytest.raises(ArcBoxError):
            sandbox.files.remove("/tmp/verbs")
        # ...and a recursive one takes the tree out.
        sandbox.files.remove("/tmp/verbs", recursive=True)
        with pytest.raises(SandboxFileNotFoundError):
            sandbox.files.stat("/tmp/verbs")

        # wait_for_port: nothing listens yet — a 1 s budget times out
        # with the knob-naming error...
        with pytest.raises(SandboxTimeoutError):
            sandbox.ports.wait_for_port(23456, timeout=1)
        # ...then a background nc listener flips it.
        listener = sandbox.commands.run(
            ["/bin/sh", "-c", "exec nc -l -p 23456 >/dev/null"], background=True
        )
        sandbox.ports.wait_for_port(23456, timeout=30)

        # commands.list rediscovers the running listener by id.
        rows = sandbox.commands.list()
        assert any(r.command_id == listener.command_id and r.state == "running" for r in rows)
        listener.kill("SIGKILL")
        listener.wait_for_exit(30)

        # wait_for_log catches a delayed echo while the command keeps
        # running (the wait ends on the match, not the exit).
        delayed = sandbox.commands.run("sleep 2; echo the-marker-line; sleep 300", background=True)
        assert delayed.wait_for_log("the-marker-line", timeout=30) == "the-marker-line"
        delayed.kill("SIGKILL")
        delayed.wait_for_exit(30)
    finally:
        sandbox.kill()


@pytest.mark.anyio
async def test_async_watch_observes_a_write() -> None:
    sandbox = await AsyncSandbox.create("", ttl=300)
    async with sandbox:
        await sandbox.files.mkdir("/tmp/watched")

        async def first_event() -> FsEvent | None:
            async with sandbox.files.watch("/tmp/watched", recursive=True) as watch:
                async for event in watch:
                    return event
            return None

        # Registration is asynchronous, so write markers until the first
        # event lands (each write is itself a fresh candidate event).
        task = asyncio.ensure_future(first_event())
        event: FsEvent | None = None
        try:
            for i in range(20):
                await sandbox.files.write_text("/tmp/watched/marker.txt", f"ping {i}\n")
                done, _pending = await asyncio.wait([task], timeout=1.0)
                if done:
                    event = task.result()
                    break
        finally:
            task.cancel()
        assert event is not None
        assert event.path == "/tmp/watched/marker.txt"
        assert event.kind in ("created", "modified")


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
