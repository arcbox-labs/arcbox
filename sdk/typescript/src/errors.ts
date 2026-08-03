import { Code, ConnectError } from '@connectrpc/connect';

import { ErrorCode, ErrorInfoSchema } from './gen/arcbox/sandbox/v1/errors_pb.js';

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
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = new.target.name;
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
export class InvalidArgumentError extends ArcBoxError {}

/** The daemon is unreachable (socket missing, connection refused, ...). */
export class ConnectionFailedError extends ArcBoxError {}

/** Authentication is required or was rejected. Reserved for the remote tier (CORE-63). */
export class AuthenticationError extends ArcBoxError {}

/** SDK and daemon protocol levels are incompatible. */
export class ProtocolMismatchError extends ArcBoxError {}

/** The addressed resource does not exist. */
export class NotFoundError extends ArcBoxError {}
/** The addressed sandbox does not exist. */
export class SandboxNotFoundError extends NotFoundError {}
/** The addressed template does not exist. */
export class TemplateNotFoundError extends NotFoundError {}
/** The addressed command (execution) does not exist. */
export class CommandNotFoundError extends NotFoundError {}
/** The addressed path does not exist inside the sandbox. */
export class FileNotFoundError extends NotFoundError {}

/** This host cannot run sandboxes (e.g. no nested virtualization; CORE-13). */
export class CapabilityError extends ArcBoxError {}

/** The sandbox is in a state that does not permit the operation. */
export class SandboxStateError extends ArcBoxError {}
/** The sandbox died out from under the operation; context carries the terminal state. */
export class SandboxDiedError extends SandboxStateError {}

/** A timeout fired. Subclasses name exactly which knob. */
export class TimeoutError extends ArcBoxError {}
/** The sandbox's hard maximum lifetime (`ttlMs`) expired and the daemon destroyed it. */
export class SandboxTtlError extends TimeoutError {}
/** A per-command timeout (`RunOptions.timeoutMs`) fired and the process group was killed. */
export class CommandTimeoutError extends TimeoutError {}
/** A per-RPC deadline (`connection.requestTimeoutMs`) fired. */
export class RequestTimeoutError extends TimeoutError {}

/** A file transfer exceeded the per-file size cap; context carries the limit. */
export class FileTooLargeError extends ArcBoxError {}

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

const DAEMON_START_SUGGESTION = 'run `abctl daemon start` (or launch the ArcBox app)';

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
    return new ConnectionFailedError('the ArcBox daemon is not reachable', {
      suggestion: DAEMON_START_SUGGESTION,
      operation,
      cause: reason,
    });
  }
  const cerr = ConnectError.from(reason);
  const info = cerr.findDetails(ErrorInfoSchema)[0];
  const options: ArcBoxErrorOptions = { operation, cause: reason };
  let ctor: new (message: string, options?: ArcBoxErrorOptions) => ArcBoxError;
  if (info !== undefined) {
    options.code = errorCodeName(info.code);
    if (info.suggestion !== '') {
      options.suggestion = info.suggestion;
    }
    options.context = info.context;
    ctor = REGISTRY_CLASSES.get(info.code) ?? ArcBoxError;
  } else {
    ctor = classForConnectCode(cerr.code, options);
  }
  return new ctor(cerr.rawMessage, options);
}

/** `ErrorCode` numeric value → its registry name (e.g. "SANDBOX_NOT_FOUND"). */
function errorCodeName(code: ErrorCode): string {
  const name: unknown = ErrorCode[code];
  return typeof name === 'string' ? name : `ERROR_CODE_${String(code)}`;
}

type ErrorClass = new (message: string, options?: ArcBoxErrorOptions) => ArcBoxError;

/** The registry-driven mapping (`errors.proto` → class), applied when the daemon attached `ErrorInfo`. */
const REGISTRY_CLASSES: ReadonlyMap<ErrorCode, ErrorClass> = new Map<ErrorCode, ErrorClass>([
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

/** Fallback routing on the coarse Connect code when no `ErrorInfo` detail rode along. */
function classForConnectCode(code: Code, options: ArcBoxErrorOptions): ErrorClass {
  options.code ??= Code[code];
  switch (code) {
    case Code.NotFound:
      return NotFoundError;
    case Code.InvalidArgument:
      return InvalidArgumentError;
    case Code.FailedPrecondition:
      return SandboxStateError;
    case Code.DeadlineExceeded:
      options.suggestion ??= 'increase connection.requestTimeoutMs';
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
 * ENOENT — the missing-socket shape of "daemon not running" — as Unknown,
 * so both are detected here directly.
 */
function isConnectionRefused(reason: unknown): boolean {
  for (let cursor = reason; typeof cursor === 'object' && cursor !== null;) {
    const code = (cursor as { code?: unknown }).code;
    if (code === 'ENOENT' || code === 'ECONNREFUSED' || code === 'ENOTSOCK') {
      return true;
    }
    cursor = (cursor as { cause?: unknown }).cause;
  }
  return false;
}
