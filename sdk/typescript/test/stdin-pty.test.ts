// PTY and stdin against a mock daemon.
//
// The invariant that matters: stdin writes are offset-idempotent. The
// handle advances its cursor only on a successful response, so a retry
// of a lost write lands at the SAME offset and the daemon's
// deduplication swallows the duplicate — never a double feed.

import { create } from "@bufbuild/protobuf";
import { EmptySchema } from "@bufbuild/protobuf/wkt";
import type { Transport } from "@connectrpc/connect";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { Commands } from "../src/commands";
import { ConnectionFailedError, InvalidArgumentError } from "../src/errors";
import type {
  StartExecutionRequest,
  TerminalSize,
  WriteStdinRequest,
} from "../src/gen/arcbox/sandbox/v1/process_pb";
import {
  ExecutionSchema,
  ExecutionState,
  SandboxProcessService,
  StdinStatusSchema,
} from "../src/gen/arcbox/sandbox/v1/process_pb";
import type { ClientContext } from "../src/transport";

/** A process-service double tracking stdin acceptance like the guest. */
class MockDaemon {
  starts: StartExecutionRequest[] = [];
  writes: WriteStdinRequest[] = [];
  resizes: TerminalSize[] = [];
  accepted = 0n;
  closed = false;
  /** Accept the next write, then fail its response (a lost response). */
  failNextWriteResponse = false;
  /** Execution state served by WaitExecution polls. */
  waitState = ExecutionState.EXITED;
  /** Throw this from WriteStdin without accepting anything. */
  rejectWrites?: ConnectError;

  transport(): Transport {
    return createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        startExecution: (req) => {
          this.starts.push(req);
          return create(ExecutionSchema, {
            id: req.executionId,
            state: ExecutionState.RUNNING,
          });
        },
        writeStdin: (req) => {
          this.writes.push(req);
          if (this.rejectWrites !== undefined) {
            throw this.rejectWrites;
          }
          if (req.offset > this.accepted) {
            throw new ConnectError("stdin gap", Code.OutOfRange);
          }
          // Deduplicate bytes below the accepted count (the guest contract).
          const fresh =
            req.offset + BigInt(req.data.byteLength) - this.accepted;
          if (fresh > 0n) {
            this.accepted += fresh;
          }
          if (req.eof) {
            this.closed = true;
          }
          if (this.failNextWriteResponse) {
            this.failNextWriteResponse = false;
            throw new ConnectError("connection reset", Code.Unavailable);
          }
          return create(StdinStatusSchema, {
            bytesWritten: this.accepted,
            closed: this.closed,
          });
        },
        getStdinStatus: () =>
          create(StdinStatusSchema, {
            bytesWritten: this.accepted,
            closed: this.closed,
          }),
        resizeExecutionTty: (req) => {
          if (req.size !== undefined) {
            this.resizes.push(req.size);
          }
          return create(EmptySchema);
        },
        waitExecution: (req) =>
          create(ExecutionSchema, {
            id: req.executionId,
            state: this.waitState,
            ...(this.waitState === ExecutionState.EXITED && {
              exitStatus: { status: { case: "code" as const, value: 0 } },
            }),
          }),
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator; this double serves from memory
        async *attachExecution() {
          yield {
            event: {
              case: "exited" as const,
              value: {
                execution: create(ExecutionSchema, {
                  state: ExecutionState.EXITED,
                  exitStatus: { status: { case: "code" as const, value: 0 } },
                }),
              },
            },
          };
        },
      });
    });
  }

  commands(): Commands {
    const ctx: ClientContext = { transport: this.transport() };
    return new Commands(ctx, "sb-1");
  }
}

describe("PTY", () => {
  it("run(pty) starts a TTY execution of that geometry with stdin open", async () => {
    const daemon = new MockDaemon();
    await daemon.commands().run("stty size", { pty: { cols: 120, rows: 40 } });
    const start = daemon.starts[0];
    expect(start?.tty).toBe(true);
    expect(start?.ttySize).toMatchObject({ width: 120, height: 40 });
    expect(start?.stdin).toBe(true);
  });

  it("a plain run keeps stdin at EOF and allocates no TTY", async () => {
    const daemon = new MockDaemon();
    await daemon.commands().run("true");
    const start = daemon.starts[0];
    expect(start?.tty).toBe(false);
    expect(start?.stdin).toBe(false);
  });

  it("resize() sends the new geometry", async () => {
    const daemon = new MockDaemon();
    const handle = await daemon
      .commands()
      .run("sh", { pty: { cols: 80, rows: 24 }, background: true });
    await handle.resize(200, 50);
    expect(daemon.resizes[0]).toMatchObject({ width: 200, height: 50 });
  });

  it("rejects pty combined with one-shot stdin data before any RPC", async () => {
    const daemon = new MockDaemon();
    await expect(
      daemon.commands().run("cat", { pty: { cols: 80, rows: 24 }, stdin: "x" }),
    ).rejects.toBeInstanceOf(InvalidArgumentError);
    expect(daemon.starts).toHaveLength(0);
  });
});

describe("stdin", () => {
  it("tracks the write cursor across writes and closes at it", async () => {
    const daemon = new MockDaemon();
    const handle = await daemon
      .commands()
      .run("cat", { background: true, stdin: true });
    await handle.writeStdin("hello ");
    await handle.writeStdin("world\n");
    await handle.closeStdin();
    expect(daemon.writes.map((w) => w.offset)).toEqual([0n, 6n, 12n]);
    expect(daemon.writes[2]?.eof).toBe(true);
    expect(daemon.accepted).toBe(12n);
    expect(daemon.closed).toBe(true);
  });

  it("a retried lost write never double-feeds (offset idempotency)", async () => {
    const daemon = new MockDaemon();
    const handle = await daemon
      .commands()
      .run("cat", { background: true, stdin: true });
    await handle.writeStdin("hello ");
    // The daemon accepts the write but the response is lost.
    daemon.failNextWriteResponse = true;
    await expect(handle.writeStdin("world")).rejects.toBeInstanceOf(
      ConnectionFailedError,
    );
    expect(daemon.accepted).toBe(11n);
    // The cursor did not advance, so the retry lands at the same offset
    // and the daemon deduplicates it — the process saw the bytes once.
    await handle.writeStdin("world");
    expect(daemon.writes.at(-1)?.offset).toBe(6n);
    expect(daemon.accepted).toBe(11n);
  });

  it("stdinStatus() reports the daemon's acceptance state and resyncs", async () => {
    const daemon = new MockDaemon();
    const handle = await daemon
      .commands()
      .run("cat", { background: true, stdin: true });
    await handle.writeStdin("abc");
    const status = await handle.stdinStatus();
    expect(status).toEqual({ bytesWritten: 3, closed: false });
  });

  it("foreground stdin data is written then closed before the wait", async () => {
    const daemon = new MockDaemon();
    const result = await daemon.commands().run("cat", { stdin: "fed\n" });
    expect(result.exitCode).toBe(0);
    expect(daemon.starts[0]?.stdin).toBe(true);
    expect(daemon.writes).toHaveLength(2);
    expect(daemon.writes[0]?.eof).toBe(false);
    expect(daemon.writes[1]?.eof).toBe(true);
    expect(daemon.closed).toBe(true);
  });

  it("a feed racing the process's early exit is noise, not a failure", async () => {
    const daemon = new MockDaemon();
    daemon.rejectWrites = new ConnectError(
      "execution has exited",
      Code.FailedPrecondition,
    );
    daemon.waitState = ExecutionState.EXITED;
    const result = await daemon.commands().run("true", { stdin: "unread" });
    expect(result.exitCode).toBe(0);
  });

  it("a feed failure with the process still running is real", async () => {
    const daemon = new MockDaemon();
    daemon.rejectWrites = new ConnectError(
      "stdin is already closed",
      Code.FailedPrecondition,
    );
    daemon.waitState = ExecutionState.RUNNING;
    await expect(
      daemon.commands().run("cat", { stdin: "data" }),
    ).rejects.toThrow("stdin is already closed");
  });

  it("rejects stdin: true on a foreground run before any RPC", async () => {
    const daemon = new MockDaemon();
    await expect(
      daemon.commands().run("cat", { stdin: true }),
    ).rejects.toBeInstanceOf(InvalidArgumentError);
    expect(daemon.starts).toHaveLength(0);
  });
});

describe("commands.get", () => {
  it("re-attaches by id and seeds the stdin cursor from the daemon", async () => {
    const daemon = new MockDaemon();
    daemon.accepted = 7n;
    daemon.waitState = ExecutionState.RUNNING;
    const seeded = create(ExecutionSchema, {
      id: "exec-9",
      state: ExecutionState.RUNNING,
      stdin: { bytesWritten: 7n, closed: false },
    });
    const transport = createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        waitExecution: () => seeded,
        writeStdin(req) {
          daemon.writes.push(req);
          return create(StdinStatusSchema, {
            bytesWritten: req.offset + BigInt(req.data.byteLength),
          });
        },
      });
    });
    const commands = new Commands({ transport }, "sb-1");
    const handle = await commands.get("exec-9");
    expect(handle.commandId).toBe("exec-9");
    await handle.writeStdin("more");
    expect(daemon.writes[0]?.offset).toBe(7n);
  });
});
