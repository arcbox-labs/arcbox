// waitForLog() against a mock daemon.
//
// The contracts under test: line-oriented matching over the replayed,
// offset-addressed output (a line split across chunks still matches; a
// line printed before the call matches immediately), regex and
// substring forms, resume through the shared re-attach loop, the typed
// exit-without-match error, and the deadline surfacing as a
// TimeoutError naming the waitForLog knob.

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { Commands } from "../src/commands";
import { ArcBoxError, TimeoutError } from "../src/errors";
import {
  ExecutionEventSchema,
  ExecutionSchema,
  ExecutionState,
  SandboxProcessService,
  StdioChannel,
} from "../src/gen/arcbox/sandbox/v1/process_pb";

const exited = create(ExecutionSchema, {
  id: "cmd",
  state: ExecutionState.EXITED,
  exitStatus: { status: { case: "code", value: 0 } },
});

interface Chunk {
  channel: StdioChannel;
  offset: bigint;
  text: string;
}

function outputEvent(chunk: Chunk) {
  return create(ExecutionEventSchema, {
    event: {
      case: "output",
      value: {
        channel: chunk.channel,
        offset: chunk.offset,
        data: new TextEncoder().encode(chunk.text),
      },
    },
  });
}

const exitedEvent = create(ExecutionEventSchema, {
  event: { case: "exited", value: { execution: exited } },
});

const RE_PORT = /port \d+/;

/**
 * Serves AttachExecution from a chunk script (replaying from the
 * requested offsets like the daemon), optionally killing the n-th
 * stream after `dieAfter[n]` chunks. `exits` appends the exited frame.
 */
function daemonOf(
  chunks: Chunk[],
  opts: { dieAfter?: number[]; exits?: boolean } = {},
) {
  const attaches: number[] = [];
  const transport = createRouterTransport(({ service }) => {
    service(SandboxProcessService, {
      waitExecution: () => exited,
      // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator
      async *attachExecution(req) {
        const budget = opts.dieAfter?.[attaches.length];
        attaches.push(0);
        let sent = 0;
        for (let i = 0, len = chunks.length; i < len; i++) {
          const chunk = chunks[i];
          if (chunk === undefined) {
            continue;
          }
          const from =
            chunk.channel === StdioChannel.STDERR
              ? req.stderrOffset
              : req.stdoutOffset;
          if (chunk.offset < from) {
            continue;
          }
          if (budget !== undefined && sent >= budget) {
            throw new ConnectError("stream reset", Code.Unavailable);
          }
          yield outputEvent(chunk);
          sent += 1;
        }
        if (budget !== undefined) {
          throw new ConnectError("stream reset", Code.Unavailable);
        }
        if (opts.exits !== false) {
          yield exitedEvent;
        }
      },
    });
  });
  return { commands: new Commands({ transport }, "sb-1"), attaches };
}

async function handleOf(daemon: { commands: Commands }) {
  return daemon.commands.get("cmd");
}

describe("waitForLog", () => {
  it("matches a line split across chunks and channels", async () => {
    const daemon = daemonOf([
      { channel: StdioChannel.STDOUT, offset: 0n, text: "boot...\nser" },
      { channel: StdioChannel.STDERR, offset: 0n, text: "warn: noise\n" },
      { channel: StdioChannel.STDOUT, offset: 11n, text: "ver ready\ntail" },
    ]);
    const handle = await handleOf(daemon);
    await expect(handle.waitForLog("server ready")).resolves.toBe(
      "server ready",
    );
  });

  it("matches with a regex and returns the whole line", async () => {
    const daemon = daemonOf([
      {
        channel: StdioChannel.STDOUT,
        offset: 0n,
        text: "listening on port 8080\n",
      },
    ]);
    const handle = await handleOf(daemon);
    await expect(handle.waitForLog(RE_PORT)).resolves.toBe(
      "listening on port 8080",
    );
  });

  it("matches on stderr, and a replayed (pre-call) line matches immediately", async () => {
    const daemon = daemonOf([
      {
        channel: StdioChannel.STDERR,
        offset: 0n,
        text: "level=info started\n",
      },
    ]);
    const handle = await handleOf(daemon);
    await expect(handle.waitForLog("started")).resolves.toBe(
      "level=info started",
    );
  });

  it("a trailing unterminated line still matches at exit", async () => {
    const daemon = daemonOf([
      {
        channel: StdioChannel.STDOUT,
        offset: 0n,
        text: "done without newline",
      },
    ]);
    const handle = await handleOf(daemon);
    await expect(handle.waitForLog("without newline")).resolves.toBe(
      "done without newline",
    );
  });

  it("resumes through the re-attach loop when the stream drops mid-scan", async () => {
    const daemon = daemonOf(
      [
        { channel: StdioChannel.STDOUT, offset: 0n, text: "part one\nsecond " },
        { channel: StdioChannel.STDOUT, offset: 16n, text: "half matches\n" },
      ],
      { dieAfter: [1] },
    );
    const handle = await handleOf(daemon);
    await expect(handle.waitForLog("half matches")).resolves.toBe(
      "second half matches",
    );
    expect(daemon.attaches.length).toBe(2);
  });

  it("exit without a match is a typed error, not a timeout", async () => {
    const daemon = daemonOf([
      { channel: StdioChannel.STDOUT, offset: 0n, text: "nothing here\n" },
    ]);
    const handle = await handleOf(daemon);
    const failing = handle.waitForLog("absent-marker", { timeoutMs: 5000 });
    await expect(failing).rejects.toBeInstanceOf(ArcBoxError);
    await expect(failing).rejects.not.toBeInstanceOf(TimeoutError);
    await expect(failing).rejects.toThrow(
      "the command exited before the log pattern appeared",
    );
  });

  it("the deadline surfaces as a TimeoutError naming the knob", async () => {
    // A stream that stays open forever without the pattern: the abort
    // signal must cut it and surface the waitForLog timeout.
    const transport = createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        waitExecution: () => exited,
        async *attachExecution(_req, ctx) {
          yield outputEvent({
            channel: StdioChannel.STDOUT,
            offset: 0n,
            text: "still warming up\n",
          });
          await new Promise<never>((_resolve, reject) => {
            ctx.signal.addEventListener("abort", () => {
              reject(new ConnectError("canceled", Code.Canceled));
            });
          });
        },
      });
    });
    const commands = new Commands({ transport }, "sb-1");
    const handle = await commands.get("cmd");
    const failing = handle.waitForLog("never-appears", { timeoutMs: 100 });
    await expect(failing).rejects.toBeInstanceOf(TimeoutError);
    await expect(failing).rejects.toMatchObject({
      operation: "commands.waitForLog",
      suggestion: "increase the waitForLog timeoutMs option",
    });
  });

  it("rejects a nonsensical timeout at the boundary", async () => {
    const daemon = daemonOf([]);
    const handle = await handleOf(daemon);
    await expect(
      handle.waitForLog("x", { timeoutMs: -1 }),
    ).rejects.toMatchObject({ name: "InvalidArgumentError" });
  });
});
