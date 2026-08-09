// commands.list() and ports.waitForPort() against a mock daemon.
//
// The contracts under test: the Execution → CommandInfo summary mapping
// (running rows without exit fields, code exits, signal deaths as
// 128+signal, error-terminated executions), and waitForPort's deadline
// discipline — the daemon's DEADLINE_EXCEEDED becomes a TimeoutError
// naming the waitForPort timeoutMs knob, never the per-RPC one.

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import type { Transport } from "@connectrpc/connect";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { RequestTimeoutError, TimeoutError } from "../src/errors";
import type { WaitForPortRequest } from "../src/gen/arcbox/sandbox/v1/process_pb";
import {
  ExecutionSchema,
  ExecutionState,
  ListExecutionsResponseSchema,
  SandboxProcessService,
} from "../src/gen/arcbox/sandbox/v1/process_pb";
import { Commands } from "../src/commands";
import { Ports } from "../src/ports";

const STARTED = new Date("2026-08-01T12:00:00Z");
const EXITED = new Date("2026-08-01T12:00:05Z");

describe("commands.list", () => {
  it("maps running and exited executions to summaries", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        listExecutions(req) {
          expect(req.sandboxId).toBe("sb-1");
          return create(ListExecutionsResponseSchema, {
            executions: [
              create(ExecutionSchema, {
                id: "running-cmd",
                state: ExecutionState.RUNNING,
                tty: true,
                startedAt: timestampFromDate(STARTED),
              }),
              create(ExecutionSchema, {
                id: "done-cmd",
                state: ExecutionState.EXITED,
                startedAt: timestampFromDate(STARTED),
                exitedAt: timestampFromDate(EXITED),
                exitStatus: { status: { case: "code", value: 3 } },
              }),
              create(ExecutionSchema, {
                id: "killed-cmd",
                state: ExecutionState.EXITED,
                exitStatus: { status: { case: "signal", value: 9 } },
              }),
              create(ExecutionSchema, {
                id: "broken-cmd",
                state: ExecutionState.EXITED,
                error: "sandbox stopped",
              }),
            ],
          });
        },
      });
    });
    const commands = new Commands({ transport: mock }, "sb-1");
    expect(await commands.list()).toEqual([
      {
        commandId: "running-cmd",
        tty: true,
        state: "running",
        startedAt: STARTED,
      },
      {
        commandId: "done-cmd",
        tty: false,
        state: "exited",
        startedAt: STARTED,
        exitedAt: EXITED,
        exitCode: 3,
      },
      {
        commandId: "killed-cmd",
        tty: false,
        state: "exited",
        exitCode: 137,
        signal: "SIGKILL",
      },
      {
        commandId: "broken-cmd",
        tty: false,
        state: "exited",
        error: "sandbox stopped",
      },
    ]);
  });
});

function portsOn(transport: Transport): Ports {
  return new Ports({ transport }, "sb-1");
}

describe("ports.waitForPort", () => {
  it("resolves when a listener comes up, sending the requested budget", async () => {
    let seen: WaitForPortRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        waitForPort(req) {
          seen = req;
          return {};
        },
      });
    });
    await portsOn(mock).waitForPort(8080, { timeoutMs: 10000 });
    expect(seen?.sandboxId).toBe("sb-1");
    expect(seen?.port).toBe(8080);
    expect(seen?.timeoutSeconds).toBe(10);
  });

  it("no timeout option sends 0 — the daemon's 30 s default", async () => {
    let seen: WaitForPortRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        waitForPort(req) {
          seen = req;
          return {};
        },
      });
    });
    await portsOn(mock).waitForPort(80);
    expect(seen?.timeoutSeconds).toBe(0);
  });

  it("the daemon's DEADLINE_EXCEEDED becomes a TimeoutError naming the knob", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        waitForPort() {
          throw new ConnectError(
            "no listener on port 8080 within 10s",
            Code.DeadlineExceeded,
          );
        },
      });
    });
    const failing = portsOn(mock).waitForPort(8080, { timeoutMs: 10000 });
    await expect(failing).rejects.toBeInstanceOf(TimeoutError);
    await expect(failing).rejects.not.toBeInstanceOf(RequestTimeoutError);
    await expect(failing).rejects.toMatchObject({
      operation: "ports.waitForPort",
      suggestion: expect.stringContaining("waitForPort timeoutMs") as string,
      context: { port: "8080", timeoutSeconds: "10" },
    });
  });

  it("a non-deadline daemon error keeps its own class", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxProcessService, {
        waitForPort() {
          throw new ConnectError("sandbox gone", Code.NotFound);
        },
      });
    });
    await expect(portsOn(mock).waitForPort(80)).rejects.not.toBeInstanceOf(
      TimeoutError,
    );
  });
});
