// Offset-resume across stream death against a mock daemon.
//
// The contract under test: when an attach stream drops mid-flow, the
// handle re-attaches from the last DELIVERED per-channel offsets and the
// consumer sees one seamless, gapless stream — the SDK's whole reason
// for offset-addressed output. Retries are bounded by consecutive dead
// dials; delivered output resets the budget.

import { create } from "@bufbuild/protobuf";
import type { Transport } from "@connectrpc/connect";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { Commands } from "../src/commands";
import { ConnectionLostError, NotFoundError } from "../src/errors";
import type { AttachExecutionRequest } from "../src/gen/arcbox/sandbox/v1/process_pb";
import {
  ExecutionEventSchema,
  ExecutionSchema,
  ExecutionState,
  SandboxProcessService,
  StdioChannel,
} from "../src/gen/arcbox/sandbox/v1/process_pb";

interface Chunk {
  channel: StdioChannel;
  offset: bigint;
  text: string;
}

const exited = create(ExecutionSchema, {
  id: "cmd",
  state: ExecutionState.EXITED,
  exitStatus: { status: { case: "code", value: 0 } },
});

/**
 * Serves AttachExecution from a chunk script, killing the stream after
 * `dieAfter[n]` chunks on the n-th attach (die forever once the script
 * runs out). Replays only chunks at or past the requested offset, like
 * the daemon.
 */
class FlakyDaemon {
  attaches: AttachExecutionRequest[] = [];

  constructor(
    public chunks: Chunk[],
    public dieAfter: number[],
  ) {}

  transport(): Transport {
    // Locals captured by the handlers below; the arrays are shared refs.
    const { attaches, chunks, dieAfter } = this;
    return createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        startExecution: (req) =>
          create(ExecutionSchema, {
            id: req.executionId,
            state: ExecutionState.RUNNING,
          }),
        waitExecution: () => exited,
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator; this double serves from memory
        async *attachExecution(req) {
          const call = attaches.length;
          attaches.push(req);
          const budget = dieAfter[call];
          let sent = 0;
          for (let i = 0, len = chunks.length; i < len; i++) {
            const chunk = chunks[i];
            if (chunk === undefined) {
              continue;
            }
            const isStderr = chunk.channel === StdioChannel.STDERR;
            const from = isStderr ? req.stderrOffset : req.stdoutOffset;
            if (chunk.offset < from) {
              continue;
            }
            if (budget !== undefined && sent >= budget) {
              throw new ConnectError("stream reset", Code.Unavailable);
            }
            yield create(ExecutionEventSchema, {
              event: {
                case: "output",
                value: {
                  channel: chunk.channel,
                  offset: chunk.offset,
                  data: new TextEncoder().encode(chunk.text),
                },
              },
            });
            sent += 1;
          }
          if (budget !== undefined) {
            throw new ConnectError("stream reset", Code.Unavailable);
          }
          yield create(ExecutionEventSchema, {
            event: { case: "exited", value: { execution: exited } },
          });
        },
      });
    });
  }

  commands(): Commands {
    return new Commands({ transport: this.transport() }, "sb-1");
  }
}

const script: Chunk[] = [
  { channel: StdioChannel.STDOUT, offset: 0n, text: "hel" },
  { channel: StdioChannel.STDERR, offset: 0n, text: "warn" },
  { channel: StdioChannel.STDOUT, offset: 3n, text: "lo " },
  { channel: StdioChannel.STDOUT, offset: 6n, text: "world" },
];

describe("offset-resume", () => {
  it("the output iterator re-attaches from the delivered offsets", async () => {
    // First attach dies after two chunks (stdout "hel" + stderr "warn").
    const daemon = new FlakyDaemon(script, [2]);
    const handle = await daemon.commands().run("emit", { background: true });
    let stdout = "";
    let stderr = "";
    for await (const chunk of handle.output) {
      const text = new TextDecoder().decode(chunk.data);
      if (chunk.channel === "stderr") {
        stderr += text;
      } else {
        stdout += text;
      }
    }
    // Seamless and gapless despite the mid-stream death.
    expect(stdout).toBe("hello world");
    expect(stderr).toBe("warn");
    expect(daemon.attaches).toHaveLength(2);
    // The re-attach resumed exactly at the delivered high-water marks.
    expect(daemon.attaches[1]?.stdoutOffset).toBe(3n);
    expect(daemon.attaches[1]?.stderrOffset).toBe(4n);
  });

  it("survives repeated drops as long as each dial delivers output", async () => {
    // Every attach dies after one delivered chunk; four dials complete
    // the script. Progress resets the retry budget each time.
    const daemon = new FlakyDaemon(script, [1, 1, 1, 1]);
    const handle = await daemon.commands().run("emit", { background: true });
    let stdout = "";
    for await (const chunk of handle.output) {
      if (chunk.channel !== "stderr") {
        stdout += new TextDecoder().decode(chunk.data);
      }
    }
    expect(stdout).toBe("hello world");
    expect(daemon.attaches).toHaveLength(5);
  });

  it("waitForExit's result collection resumes through the same loop", async () => {
    const daemon = new FlakyDaemon(script, [3]);
    const handle = await daemon.commands().run("emit", { background: true });
    const result = await handle.waitForExit(1000);
    expect(result.stdout).toBe("hello world");
    expect(result.stderr).toBe("warn");
    // The resumed chunks were contiguous — no false truncation flag.
    expect(result.truncated).toBe(false);
  });

  it("bounded retries: dead dials exhaust into ConnectionLostError", async () => {
    // Every dial dies before delivering anything.
    const daemon = new FlakyDaemon(script, [0, 0, 0, 0, 0, 0, 0, 0]);
    const handle = await daemon.commands().run("emit", { background: true });
    const consume = async () => {
      for await (const chunk of handle.output) {
        void chunk;
      }
    };
    await expect(consume()).rejects.toBeInstanceOf(ConnectionLostError);
    // The initial dial plus MAX_ATTACH_RETRIES re-dials.
    expect(daemon.attaches).toHaveLength(4);
  });

  it("a daemon-typed stream error is surfaced, never retried", async () => {
    let attaches = 0;
    const transport = createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        waitExecution: () => exited,
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator
        async *attachExecution() {
          attaches += 1;
          yield create(ExecutionEventSchema, {
            event: {
              case: "output",
              value: {
                channel: StdioChannel.STDOUT,
                offset: 0n,
                data: new Uint8Array([120]),
              },
            },
          });
          throw new ConnectError("no such execution", Code.NotFound);
        },
      });
    });
    const commands = new Commands({ transport }, "sb-1");
    const handle = await commands.get("cmd");
    const consume = async () => {
      for await (const chunk of handle.output) {
        void chunk;
      }
    };
    await expect(consume()).rejects.toBeInstanceOf(NotFoundError);
    expect(attaches).toBe(1);
  });
});
