import { Code, ConnectError } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import {
  ErrorCode,
  ErrorInfoSchema,
} from "../src/gen/arcbox/sandbox/v1/errors_pb.js";
import {
  ArcBoxError,
  CapabilityError,
  CommandFailedError,
  CommandTimeoutError,
  ConnectionFailedError,
  FileNotFoundError,
  InvalidArgumentError,
  NotFoundError,
  RequestTimeoutError,
  SandboxNotFoundError,
  SandboxStateError,
  toArcBoxError,
} from "../src/errors.js";

function daemonError(
  code: ErrorCode,
  suggestion = "",
  context: Record<string, string> = {},
) {
  return new ConnectError("boom", Code.FailedPrecondition, undefined, [
    { desc: ErrorInfoSchema, value: { code, suggestion, context } },
  ]);
}

describe("toArcBoxError", () => {
  it("maps ErrorInfo details to the registry class with code, suggestion, and context", () => {
    const err = toArcBoxError(
      daemonError(
        ErrorCode.SANDBOX_NOT_FOUND,
        "list sandboxes with `abctl sandbox list`",
        {
          id: "sb-1",
        },
      ),
      "sandbox.info",
    );
    expect(err).toBeInstanceOf(SandboxNotFoundError);
    expect(err.code).toBe("SANDBOX_NOT_FOUND");
    expect(err.suggestion).toBe("list sandboxes with `abctl sandbox list`");
    expect(err.context).toEqual({ id: "sb-1" });
    expect(err.operation).toBe("sandbox.info");
  });

  it("maps state and capability registry codes", () => {
    expect(
      toArcBoxError(daemonError(ErrorCode.SANDBOX_PAUSED), "op"),
    ).toBeInstanceOf(SandboxStateError);
    expect(
      toArcBoxError(daemonError(ErrorCode.NESTED_VIRT_UNSUPPORTED), "op"),
    ).toBeInstanceOf(CapabilityError);
    expect(
      toArcBoxError(daemonError(ErrorCode.COMMAND_TIMEOUT), "op"),
    ).toBeInstanceOf(CommandTimeoutError);
    expect(
      toArcBoxError(daemonError(ErrorCode.FILE_NOT_FOUND), "op"),
    ).toBeInstanceOf(FileNotFoundError);
  });

  it("keeps unknown registry codes on the base class with the code preserved", () => {
    const err = toArcBoxError(daemonError(999 as ErrorCode), "op");
    expect(err.constructor).toBe(ArcBoxError);
    expect(err.code).toBe("ERROR_CODE_999");
  });

  it("routes on the Connect code when no ErrorInfo detail rode along", () => {
    const notFound = toArcBoxError(
      new ConnectError("gone", Code.NotFound),
      "op",
    );
    expect(notFound).toBeInstanceOf(NotFoundError);
    expect(notFound.code).toBe("NotFound");

    const deadline = toArcBoxError(
      new ConnectError("late", Code.DeadlineExceeded),
      "op",
    );
    expect(deadline).toBeInstanceOf(RequestTimeoutError);
    expect(deadline.suggestion).toContain("requestTimeoutMs");

    expect(
      toArcBoxError(new ConnectError("bad", Code.InvalidArgument), "op"),
    ).toBeInstanceOf(InvalidArgumentError);
  });

  it("turns a missing socket (ENOENT) into ConnectionFailedError with a daemon-start suggestion", () => {
    const enoent = Object.assign(new Error("connect ENOENT /tmp/x.sock"), {
      code: "ENOENT",
    });
    const err = toArcBoxError(enoent, "sandbox.create");
    expect(err).toBeInstanceOf(ConnectionFailedError);
    expect(err.suggestion).toContain("abctl daemon start");
  });

  it("detects ECONNREFUSED through a ConnectError cause chain", () => {
    const refused = Object.assign(new Error("connect ECONNREFUSED"), {
      code: "ECONNREFUSED",
    });
    const wrapped = ConnectError.from(refused, Code.Unavailable);
    expect(toArcBoxError(wrapped, "op")).toBeInstanceOf(ConnectionFailedError);
  });

  it("passes ArcBoxError through, stamping the operation once", () => {
    const original = new SandboxNotFoundError("gone");
    const mapped = toArcBoxError(original, "sandbox.kill");
    expect(mapped).toBe(original);
    expect(mapped.operation).toBe("sandbox.kill");
    expect(toArcBoxError(original, "other.op").operation).toBe("sandbox.kill");
  });

  it("wraps arbitrary reasons on the base class", () => {
    const err = toArcBoxError(new Error("weird"), "op");
    expect(err.constructor).toBe(ArcBoxError);
    expect(err.message).toBe("weird");
  });
});

describe("CommandFailedError", () => {
  it("names the exit code and carries the result", () => {
    const err = new CommandFailedError({
      exitCode: 2,
      stdout: "",
      stderr: "oops",
    });
    expect(err.message).toContain("exit code 2");
    expect(err.result.stderr).toBe("oops");
  });

  it("names the signal when the process was signal-killed", () => {
    const err = new CommandFailedError({
      exitCode: 137,
      signal: "SIGKILL",
      stdout: "",
      stderr: "",
    });
    expect(err.message).toContain("SIGKILL");
  });
});
