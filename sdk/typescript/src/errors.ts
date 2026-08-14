import { Code, ConnectError } from "@connectrpc/connect";

import { ErrorCode, ErrorInfoSchema } from "./gen/arcbox/sandbox/v1/errors_pb";

/**
 * Options carried by every ArcBox error.
 */
export interface ArcBoxErrorOptions {
  /** Machine-readable cause from the daemon's error registry (`errors.proto`). */
  code?: string;
  /** Actionable fix, phrased for direct display ("run `abctl daemon start`"). */
  suggestion?: string;
  /** Structured facts about the failure (which limit, which state, ...). */
  context?: Record<string, string>;
  /** The SDK operation that failed (e.g. "commands.run"). */
  operation?: string;
  /** Underlying cause, preserved for debugging. */
  cause?: unknown;
}

/**
 * Base class of every error thrown by this SDK.
 *
 * Carries the machine-readable `code` from the daemon's error registry
 * (`arcbox.sandbox.v1.ErrorCode`) when one was attached, an actionable
 * `suggestion`, structured `context`, and the failed `operation`.
 */
export class ArcBoxError extends Error {
  readonly code?: string;
  readonly suggestion?: string;
  readonly context: Readonly<Record<string, string>>;
  /** Stamped by the call site that surfaced the error. */
  operation?: string;

  constructor(message: string, options: ArcBoxErrorOptions = {}) {
    // Error reads only `cause` from the options bag; the SDK keys ride along.
    super(message, options);
    this.name = "ArcBoxError";
    if (options.code !== undefined) {
      this.code = options.code;
    }
    if (options.suggestion !== undefined) {
      this.suggestion = options.suggestion;
    }
    this.context = options.context ?? {};
    if (options.operation !== undefined) {
      this.operation = options.operation;
    }
  }
}

/** A request was rejected at the boundary: unknown, contradictory, or malformed input. */
export class InvalidArgumentError extends ArcBoxError {
  name = "InvalidArgumentError";
}

/** The daemon is unreachable (socket missing, connection refused, ...). */
export class ConnectionFailedError extends ArcBoxError {
  name = "ConnectionFailedError";
}

/**
 * A live stream died mid-flow — and, where the SDK re-attaches
 * (command output), could not be re-established within the retry
 * budget. The `cause` chain carries the underlying transport failure.
 */
export class ConnectionLostError extends ConnectionFailedError {
  name = "ConnectionLostError";
}

/** Authentication is required or was rejected. Reserved for the remote tier (CORE-63). */
export class AuthenticationError extends ArcBoxError {
  name = "AuthenticationError";
}

/** SDK and daemon protocol levels are incompatible. */
export class ProtocolMismatchError extends ArcBoxError {
  name = "ProtocolMismatchError";
}

/** The addressed resource does not exist. */
export class NotFoundError extends ArcBoxError {
  name = "NotFoundError";
}
/** The addressed sandbox does not exist. */
export class SandboxNotFoundError extends NotFoundError {
  name = "SandboxNotFoundError";
}
/** The addressed template does not exist. */
export class TemplateNotFoundError extends NotFoundError {
  name = "TemplateNotFoundError";
}
/** The addressed command (execution) does not exist. */
export class CommandNotFoundError extends NotFoundError {
  name = "CommandNotFoundError";
}
/** The addressed path does not exist inside the sandbox. */
export class FileNotFoundError extends NotFoundError {
  name = "FileNotFoundError";
}

/** This host cannot run sandboxes (e.g. no nested virtualization; CORE-13). */
export class CapabilityError extends ArcBoxError {
  name = "CapabilityError";
}

/** The sandbox is in a state that does not permit the operation. */
export class SandboxStateError extends ArcBoxError {
  name = "SandboxStateError";
}
/** The sandbox died out from under the operation; context carries the terminal state. */
export class SandboxDiedError extends SandboxStateError {
  name = "SandboxDiedError";
}

/** A timeout fired. Subclasses name exactly which knob. */
export class TimeoutError extends ArcBoxError {
  name = "TimeoutError";
}
/** The sandbox's hard maximum lifetime (`ttlMs`) expired and the daemon destroyed it. */
export class SandboxTtlError extends TimeoutError {
  name = "SandboxTtlError";
}
/** A per-command timeout (`RunOptions.timeoutMs`) fired and the process group was killed. */
export class CommandTimeoutError extends TimeoutError {
  name = "CommandTimeoutError";
}
/** A per-RPC deadline (`connection.requestTimeoutMs`) fired. */
export class RequestTimeoutError extends TimeoutError {
  name = "RequestTimeoutError";
}

/** A file transfer exceeded the per-file size cap; context carries the limit. */
export class FileTooLargeError extends ArcBoxError {
  name = "FileTooLargeError";
}

/** Shape of a finished command, as carried by {@link CommandFailedError}. */
export interface CommandFailure {
  exitCode: number;
  signal?: string;
  stdout: string;
  stderr: string;
}

/**
 * Thrown ONLY by `CommandResult.expect()` — non-zero exit is data
 * everywhere else. Carries the full result.
 */
export class CommandFailedError extends ArcBoxError {
  name = "CommandFailedError";
  readonly result: CommandFailure;

  constructor(result: CommandFailure, options: ArcBoxErrorOptions = {}) {
    const what =
      result.signal === undefined
        ? `exit code ${String(result.exitCode)}`
        : `signal ${result.signal}`;
    super(`command failed with ${what}`, options);
    this.result = result;
  }
}

const DAEMON_START_SUGGESTION =
  "run `abctl daemon start` (or launch the ArcBox app)";

type ErrorClass = new (
  message: string,
  options?: ArcBoxErrorOptions,
) => ArcBoxError;

/** The registry-driven mapping (`errors.proto` → class), applied when the daemon attached `ErrorInfo`. */
const REGISTRY_CLASSES: ReadonlyMap<ErrorCode, ErrorClass> = new Map<
  ErrorCode,
  ErrorClass
>([
  [ErrorCode.SANDBOX_NOT_FOUND, SandboxNotFoundError],
  [ErrorCode.TEMPLATE_NOT_FOUND, TemplateNotFoundError],
  [ErrorCode.EXECUTION_NOT_FOUND, CommandNotFoundError],
  [ErrorCode.FILE_NOT_FOUND, FileNotFoundError],
  [ErrorCode.SANDBOX_PAUSED, SandboxStateError],
  [ErrorCode.SANDBOX_NOT_READY, SandboxStateError],
  [ErrorCode.SANDBOX_FAILED, SandboxStateError],
  [ErrorCode.TTL_EXPIRED, SandboxTtlError],
  [ErrorCode.COMMAND_TIMEOUT, CommandTimeoutError],
  [ErrorCode.NESTED_VIRT_UNSUPPORTED, CapabilityError],
  [ErrorCode.TEMPLATE_INVALID, InvalidArgumentError],
  [ErrorCode.FILE_TOO_LARGE, FileTooLargeError],
  [ErrorCode.TTY_REQUIRED, InvalidArgumentError],
  [ErrorCode.PORT_IN_USE, InvalidArgumentError],
  [ErrorCode.AUTH_REQUIRED, AuthenticationError],
  [ErrorCode.PROTOCOL_MISMATCH, ProtocolMismatchError],
  // STDIN_CLOSED and RESOURCE_EXHAUSTED_HOST stay on the base class:
  // the preserved `code` string is their precise identity.
]);

/**
 * Map one daemon/transport failure to the typed hierarchy. The single
 * transport→exception boundary: call sites wrap every RPC with it and
 * never inspect Connect errors themselves.
 *
 * Precedence: an `ErrorInfo` detail (the daemon's error registry) wins;
 * otherwise the coarse Connect code routes; connection-level syscall
 * failures (missing socket, refused connection) become
 * {@link ConnectionFailedError} with a start-the-daemon suggestion.
 */
export function toArcBoxError(reason: unknown, operation: string): ArcBoxError {
  if (reason instanceof ArcBoxError) {
    reason.operation ??= operation;
    return reason;
  }
  if (isConnectionRefused(reason)) {
    return new ConnectionFailedError("the ArcBox daemon is not reachable", {
      suggestion: DAEMON_START_SUGGESTION,
      operation,
      cause: reason,
    });
  }
  const cerr = ConnectError.from(reason);
  const info = cerr.findDetails(ErrorInfoSchema)[0];
  const options: ArcBoxErrorOptions = { operation, cause: reason };
  let Ctor: ErrorClass;
  if (info === undefined) {
    Ctor = classForConnectCode(cerr.code, options);
  } else {
    options.code = errorCodeName(info.code);
    if (info.suggestion !== "") {
      options.suggestion = info.suggestion;
    }
    options.context = info.context;
    Ctor = REGISTRY_CLASSES.get(info.code) ?? ArcBoxError;
  }
  return new Ctor(cerr.rawMessage, options);
}

/** `ErrorCode` numeric value → its registry name (e.g. "SANDBOX_NOT_FOUND"). */
function errorCodeName(code: ErrorCode): string {
  const name: unknown = ErrorCode[code];
  return typeof name === "string" ? name : `ERROR_CODE_${String(code)}`;
}

/** Fallback routing on the coarse Connect code when no `ErrorInfo` detail rode along. */
function classForConnectCode(
  code: Code,
  options: ArcBoxErrorOptions,
): ErrorClass {
  options.code ??= Code[code];
  switch (code) {
    case Code.NotFound:
      return NotFoundError;
    case Code.InvalidArgument:
      return InvalidArgumentError;
    case Code.FailedPrecondition:
      return SandboxStateError;
    case Code.DeadlineExceeded:
      options.suggestion ??= "increase connection.requestTimeoutMs";
      return RequestTimeoutError;
    case Code.Unavailable:
      options.suggestion ??= DAEMON_START_SUGGESTION;
      return ConnectionFailedError;
    case Code.Unauthenticated:
      return AuthenticationError;
    default:
      return ArcBoxError;
  }
}

/**
 * Whether the cause chain bottoms out in a connection-level syscall
 * failure. connect-node maps ECONNREFUSED to Code.Unavailable but leaves
 * ENOENT — the missing-socket shape of "daemon not running" — as
 * Unknown, so both are detected here directly. Mid-stream teardown
 * shapes (ECONNRESET, EPIPE, ECONNABORTED) are the same family: the
 * daemon stopped answering.
 */
function isConnectionRefused(reason: unknown): boolean {
  const codes = new Set([
    "ENOENT",
    "ECONNREFUSED",
    "ENOTSOCK",
    "ECONNRESET",
    "ECONNABORTED",
    "EPIPE",
  ]);
  for (let cursor = reason; typeof cursor === "object" && cursor !== null; ) {
    const code = (cursor as { code?: unknown }).code;
    if (typeof code === "string" && codes.has(code)) {
      return true;
    }
    cursor = (cursor as { cause?: unknown }).cause;
  }
  return false;
}
