// The hello-world closed loop against a LIVE daemon socket.
//
// Opt-in: set ARCBOX_SDK_E2E=1 (and have `abctl daemon start` running,
// with sandbox support on this host). Skipped cleanly otherwise.
// Connection resolution applies, so ARCBOX_SOCKET / ARCBOX_DATA_DIR
// point the loop at a dev daemon.
//
// This is the design doc's 20-line hello world plus the phase 2a
// surface (PTY, stdin, re-attach, setLifecycle, capabilities, events)
// and the phase 2b surface (filesystem path verbs, watch, waitForPort,
// commands.list, waitForLog). Still outside scope: Template statics.
import { describe, expect, it } from "vitest";

import type { FsEvent } from "../src/index";
import {
  ArcBox,
  ArcBoxError,
  FileNotFoundError,
  Sandbox,
  TimeoutError,
} from "../src/index";
import { wait } from "foxts/wait";

const enabled = process.env.ARCBOX_SDK_E2E === "1";

describe.skipIf(!enabled)("hello world against a live daemon", () => {
  it("answers the capabilities handshake", async () => {
    // This suite only runs on sandbox-capable hosts, so nested_virt
    // must report supported — the same answer create() relies on.
    const caps = await new ArcBox().capabilities();
    expect(caps.protocol).toBeGreaterThanOrEqual(1);
    expect(caps.daemonVersion).not.toBe("");
    expect(caps.features).toContain("pause_resume");
    expect(caps.nestedVirt.supported).toBe(true);
  }, 60000);

  it("creates a sandbox, moves files, runs commands, and cleans up", async () => {
    // Built-in minimal template (busybox) — no image pull involved.
    const sandbox = await Sandbox.create("", { ttlMs: 300000 });
    try {
      // files: write then read back.
      await sandbox.files.writeText("/tmp/hello.txt", "hello from arcbox\n");
      expect(await sandbox.files.readText("/tmp/hello.txt")).toBe(
        "hello from arcbox\n",
      );

      // foreground command: exit-as-data plus the expect() sugar.
      const result = await sandbox.commands.run(["/bin/cat", "/tmp/hello.txt"]);
      expect(result.expect().stdout).toBe("hello from arcbox\n");

      // non-zero exit is data, not an exception (string form = shell sugar).
      const failing = await sandbox.commands.run("exit 3");
      expect(failing.exitCode).toBe(3);

      // background command: async-iterable output, then waitForExit.
      const bg = await sandbox.commands.run(
        "for i in 1 2 3; do echo line$i; done",
        {
          background: true,
        },
      );
      let streamed = "";
      for await (const chunk of bg.output) {
        if (chunk.channel !== "stderr") {
          streamed += new TextDecoder().decode(chunk.data);
        }
      }
      expect(streamed).toContain("line3");
      const exited = await bg.waitForExit(30000);
      expect(exited.exitCode).toBe(0);

      // kill() delivers a signal to the whole process group.
      const sleeper = await sandbox.commands.run(["/bin/sleep", "300"], {
        background: true,
      });
      await sleeper.kill("SIGKILL");
      const killed = await sleeper.waitForExit(30000);
      expect(killed.signal).toBe("SIGKILL");
      expect(killed.exitCode).toBe(137);

      // stdin: foreground write-then-close (subprocess semantics).
      const echoed = await sandbox.commands.run(["/bin/cat"], {
        stdin: "hello stdin\n",
      });
      expect(echoed.expect().stdout).toBe("hello stdin\n");

      // stdin: a background handle drives offset-idempotent writes.
      const catBg = await sandbox.commands.run(["/bin/cat"], {
        background: true,
        stdin: true,
      });
      await catBg.writeStdin("first ");
      await catBg.writeStdin("second\n");
      await catBg.closeStdin();
      expect((await catBg.waitForExit(30000)).stdout).toBe("first second\n");

      // commands.get: re-attach by id; the retained output replays.
      const again = await sandbox.commands.get(catBg.commandId);
      expect((await again.waitForExit(30000)).stdout).toBe("first second\n");

      // PTY: stty reads the allocated terminal's geometry (rows cols),
      // and output arrives merged (a pty run's stdout carries it all).
      const tty = await sandbox.commands.run("stty size", {
        pty: { cols: 120, rows: 40 },
      });
      expect(tty.expect().stdout).toContain("40 120");

      // PTY resize: the running terminal observes the new geometry.
      const resized = await sandbox.commands.run("sleep 2; stty size", {
        pty: { cols: 80, rows: 24 },
        background: true,
      });
      await resized.resize(200, 50);
      expect((await resized.waitForExit(30000)).stdout).toContain("50 200");

      // setLifecycle tri-state: re-arm the TTL, then remove it (null),
      // then re-arm again so the sandbox cannot outlive a crash here.
      await sandbox.setLifecycle({ ttlMs: 600000 });
      expect((await sandbox.info()).ttlDeadline).toBeDefined();
      await sandbox.setLifecycle({ ttlMs: null });
      expect((await sandbox.info()).ttlDeadline).toBeUndefined();
      await sandbox.setLifecycle({ ttlMs: 300000 });

      // info() is always fresh.
      const info = await sandbox.info();
      expect(["ready", "running"]).toContain(info.state);
    } finally {
      await sandbox.kill();
    }
  }, 300000);

  it("drives the 2b surface: path verbs, watch, waitForPort, list, waitForLog", async () => {
    const sandbox = await Sandbox.create("", { ttlMs: 300000 });
    try {
      // The listener below needs busybox `nc`.
      expect((await sandbox.commands.run("command -v nc")).exitCode).toBe(0);

      // Path verbs roundtrip: mkdir -p → write → stat → list → move →
      // remove (with the non-recursive guard).
      await sandbox.files.mkdir("/tmp/verbs/nested");
      await sandbox.files.mkdir("/tmp/verbs/nested"); // mkdir -p: idempotent
      await sandbox.files.writeText("/tmp/verbs/nested/a.txt", "payload\n");
      const stat = await sandbox.files.stat("/tmp/verbs/nested/a.txt");
      expect(stat.kind).toBe("file");
      expect(stat.size).toBe(8);
      expect(stat.mode).toBe(0o644);
      expect(stat.name).toBe("a.txt");
      expect(stat.modifiedAt).toBeInstanceOf(Date);
      const entries = await sandbox.files.list("/tmp/verbs/nested");
      expect(entries.map((e) => e.name)).toEqual(["a.txt"]);
      await sandbox.files.move(
        "/tmp/verbs/nested/a.txt",
        "/tmp/verbs/nested/b.txt",
      );
      expect(await sandbox.files.readText("/tmp/verbs/nested/b.txt")).toBe(
        "payload\n",
      );
      await expect(
        sandbox.files.stat("/tmp/verbs/nested/a.txt"),
      ).rejects.toBeInstanceOf(FileNotFoundError);
      // A non-empty directory refuses a non-recursive remove...
      await expect(sandbox.files.remove("/tmp/verbs")).rejects.toBeInstanceOf(
        ArcBoxError,
      );
      // ...and a recursive one takes the tree out.
      await sandbox.files.remove("/tmp/verbs", { recursive: true });
      await expect(sandbox.files.stat("/tmp/verbs")).rejects.toBeInstanceOf(
        FileNotFoundError,
      );

      // watch: a write inside the watched tree arrives as an event.
      // Registration is asynchronous, so write markers until the first
      // event lands (each write is itself a fresh candidate event).
      await sandbox.files.mkdir("/tmp/watched");
      const iterator = sandbox.files
        .watch("/tmp/watched", { recursive: true })
        [Symbol.asyncIterator]();
      const first = iterator.next();
      let event: FsEvent | undefined;
      for (let i = 0; i < 20 && event === undefined; i++) {
        // eslint-disable-next-line no-await-in-loop -- sequential by design: each marker write precedes the next race
        await sandbox.files.writeText(
          "/tmp/watched/marker.txt",
          `ping ${String(i)}\n`,
        );
        // eslint-disable-next-line no-await-in-loop -- sequential by design: race the pending first event against a beat
        const winner = await Promise.race([first, wait(1000).then(() => {})]);
        if (winner !== undefined && winner.done !== true) {
          event = winner.value;
        }
      }
      expect(event?.path).toBe("/tmp/watched/marker.txt");
      expect(["created", "modified"]).toContain(event?.kind);
      await iterator.return?.(undefined); // breaking out cancels the watch

      // waitForPort: nothing listens yet — a 1 s budget times out with
      // the knob-naming error...
      await expect(
        sandbox.ports.waitForPort(23456, { timeoutMs: 1000 }),
      ).rejects.toBeInstanceOf(TimeoutError);
      // ...then a background nc listener flips it.
      const listener = await sandbox.commands.run(
        ["/bin/sh", "-c", "exec nc -l -p 23456 >/dev/null"],
        { background: true },
      );
      await sandbox.ports.waitForPort(23456, { timeoutMs: 30000 });

      // commands.list rediscovers the running listener by id.
      const rows = await sandbox.commands.list();
      expect(
        rows.some(
          (row) =>
            row.commandId === listener.commandId && row.state === "running",
        ),
      ).toBe(true);
      await listener.kill("SIGKILL");
      await listener.waitForExit(30000);

      // waitForLog catches a delayed echo while the command keeps
      // running (the wait ends on the match, not the exit).
      const delayed = await sandbox.commands.run(
        "sleep 2; echo the-marker-line; sleep 300",
        { background: true },
      );
      expect(
        await delayed.waitForLog("the-marker-line", { timeoutMs: 30000 }),
      ).toBe("the-marker-line");
      await delayed.kill("SIGKILL");
      await delayed.waitForExit(30000);
    } finally {
      await sandbox.kill();
    }
  }, 300000);

  it("events() observes the idle auto-pause", async () => {
    // A short idle timeout with the PAUSE policy: the daemon must emit
    // PAUSING (reason idle_timeout) then PAUSED on the events stream.
    const sandbox = await Sandbox.create("", {
      ttlMs: 300000,
      idleTimeoutMs: 4000,
      onIdle: "pause",
    });
    try {
      const kinds: string[] = [];
      let reason = "";
      for await (const event of sandbox.events()) {
        kinds.push(event.kind);
        if (event.kind === "pausing") {
          reason = event.attributes.reason ?? "";
        }
        if (event.kind === "paused") {
          break;
        }
      }
      expect(kinds).toContain("pausing");
      expect(kinds.at(-1)).toBe("paused");
      expect(reason).toBe("idle_timeout");
      expect((await sandbox.info()).state).toBe("paused");
    } finally {
      await sandbox.kill();
    }
  }, 300000);
});
