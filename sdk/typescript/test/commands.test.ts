import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import { commandResultFromExecution, normalizeCmd } from "../src/commands.js";
import {
  ArcBoxError,
  CommandFailedError,
  SandboxDiedError,
} from "../src/errors.js";
import { ExecutionSchema } from "../src/gen/arcbox/sandbox/v1/process_pb.js";

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
