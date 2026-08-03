import { create } from "@bufbuild/protobuf";
import { EmptySchema } from "@bufbuild/protobuf/wkt";
import { describe, expect, it } from "vitest";

import {
  CommandHandle,
  commandResultFromExecution,
  normalizeCmd,
} from "../src/commands";
import {
  ArcBoxError,
  CommandFailedError,
  SandboxDiedError,
} from "../src/errors";
import type { ExecutionEvent } from "../src/gen/arcbox/sandbox/v1/process_pb";
import {
  ExecutionEventSchema,
  ExecutionSchema,
  ExecutionState,
  StdioChannel,
} from "../src/gen/arcbox/sandbox/v1/process_pb";

describe("normalizeCmd", () => {
  it("passes argv through untouched", () => {
    expect(normalizeCmd(["node", "--version"])).toEqual(["node", "--version"]);
  });

  it("wraps a string in a login shell", () => {
    expect(normalizeCmd("echo hi")).toEqual(["/bin/sh", "-lc", "echo hi"]);
  });
});

describe("commandResultFromExecution", () => {
  it("surfaces a normal exit code as data, and expect() passes on zero", () => {
    const execution = create(ExecutionSchema, {
      id: "x",
      exitStatus: { status: { case: "code", value: 0 } },
    });
    const result = commandResultFromExecution(execution, "out", "err");
    expect(result.exitCode).toBe(0);
    expect(result.signal).toBeUndefined();
    expect(result.stdout).toBe("out");
    expect(result.stderr).toBe("err");
    expect(result.expect()).toBe(result);
  });

  it("expect() throws CommandFailedError on non-zero exit", () => {
    const execution = create(ExecutionSchema, {
      id: "x",
      exitStatus: { status: { case: "code", value: 3 } },
    });
    const result = commandResultFromExecution(execution, "", "boom");
    expect(() => result.expect()).toThrow(CommandFailedError);
  });

  it("maps signal death to 128+n with the signal name", () => {
    const execution = create(ExecutionSchema, {
      id: "x",
      exitStatus: { status: { case: "signal", value: 9 } },
    });
    const result = commandResultFromExecution(execution, "", "");
    expect(result.exitCode).toBe(137);
    expect(result.signal).toBe("SIGKILL");
  });

  it("names unregistered signals numerically", () => {
    const execution = create(ExecutionSchema, {
      id: "x",
      exitStatus: { status: { case: "signal", value: 31 } },
    });
    expect(commandResultFromExecution(execution, "", "").signal).toBe("SIG31");
  });

  it("throws SandboxDiedError when the execution ended without an observed exit", () => {
    const execution = create(ExecutionSchema, {
      id: "x",
      error: "session broke",
    });
    expect(() => commandResultFromExecution(execution, "", "")).toThrow(
      SandboxDiedError,
    );
  });

  it("throws on a terminal execution with no exit status and no error", () => {
    const execution = create(ExecutionSchema, { id: "x" });
    expect(() => commandResultFromExecution(execution, "", "")).toThrow(
      ArcBoxError,
    );
  });
});

describe("CommandHandle output collection", () => {
  type HandleCtx = ConstructorParameters<typeof CommandHandle>[0];
  type HandleClient = ConstructorParameters<typeof CommandHandle>[1];

  const exited = create(ExecutionSchema, {
    id: "cmd",
    state: ExecutionState.EXITED,
    exitStatus: { status: { case: "code", value: 0 } },
  });

  function output(channel: StdioChannel, offset: bigint, text: string) {
    return create(ExecutionEventSchema, {
      event: {
        case: "output",
        value: { channel, offset, data: new TextEncoder().encode(text) },
      },
    });
  }

  /** Only the methods the code under test calls are stubbed. */
  function stubClient(overrides: Partial<HandleClient>): HandleClient {
    return overrides as HandleClient;
  }

  function handleWith(events: ExecutionEvent[]): CommandHandle {
    const client = stubClient({
      waitExecution: () => Promise.resolve(exited),
      // eslint-disable-next-line @typescript-eslint/require-await -- mirrors the AsyncIterable contract of the generated client
      async *attachExecution() {
        yield* events;
        yield create(ExecutionEventSchema, {
          event: { case: "exited", value: { execution: exited } },
        });
      },
    });
    return new CommandHandle(
      { transport: {} } as HandleCtx,
      client,
      "sb",
      "cmd",
    );
  }

  it("assembles contiguous replayed chunks as complete, untruncated output", async () => {
    const result = await handleWith([
      output(StdioChannel.STDOUT, 0n, "hel"),
      output(StdioChannel.STDOUT, 3n, "lo"),
      output(StdioChannel.STDERR, 0n, "warn"),
    ]).waitForExit();
    expect(result.stdout).toBe("hello");
    expect(result.stderr).toBe("warn");
    expect(result.truncated).toBe(false);
  });

  it("flags truncation when retention dropped the head of a channel", async () => {
    const result = await handleWith([
      output(StdioChannel.STDOUT, 4096n, "tail"),
    ]).waitForExit();
    expect(result.stdout).toBe("tail");
    expect(result.truncated).toBe(true);
  });

  it("kill() applies the configured per-unary deadline", async () => {
    let seen: unknown;
    const client = stubClient({
      signalExecution(_req, opts) {
        seen = opts;
        return Promise.resolve(create(EmptySchema));
      },
    });
    const handle = new CommandHandle(
      { transport: {}, requestTimeoutMs: 1234 } as HandleCtx,
      client,
      "sb",
      "cmd",
    );
    await handle.kill();
    expect(seen).toEqual({ timeoutMs: 1234 });
  });
});
