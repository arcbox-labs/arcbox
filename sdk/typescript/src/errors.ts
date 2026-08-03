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
