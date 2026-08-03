// The hello-world closed loop against a LIVE daemon socket.
//
// Opt-in: set ARCBOX_SDK_E2E=1 (and have `abctl daemon start` running,
// with sandbox support on this host). Skipped cleanly otherwise.
// Connection resolution applies, so ARCBOX_SOCKET / ARCBOX_DATA_DIR
// point the loop at a dev daemon.
//
// This is the design doc's 20-line hello world minus the parts outside
// phase 1's surface: ports.expose and waitForPort are deferred, so the
// background command is observed through its output stream and
// waitForExit instead of a port probe.
import { describe, expect, it } from "vitest";

import { Sandbox } from "../src/index";

const enabled = process.env.ARCBOX_SDK_E2E === "1";

describe.skipIf(!enabled)("hello world against a live daemon", () => {
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

      // info() is always fresh.
      const info = await sandbox.info();
      expect(["ready", "running"]).toContain(info.state);
    } finally {
      await sandbox.kill();
    }
  }, 300000);
});
