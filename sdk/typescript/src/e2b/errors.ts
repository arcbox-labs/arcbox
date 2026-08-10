/**
 * The error classes `e2b` exports.
 *
 * Most are **aliases** of the `@arcbox/sandbox` class that already means
 * the same thing, not new subclasses. That is the load-bearing choice:
 * the errors your code catches are thrown by the underlying SDK, so a
 * fresh `class SandboxError extends ArcBoxError` would sit beside them
 * and never match. Aliasing makes `catch (e) { if (e instanceof
 * SandboxError) }` behave exactly as it did against `e2b`.
 *
 * The rest fall into two groups, both documented per class: those this
 * shim raises itself ({@link CommandExitError}, {@link UnsupportedError}),
 * and those kept only so an `import { … } from 'e2b'` still resolves —
 * a local daemon has no rate limiter, no registry build, and no volumes,
 * so nothing can raise them.
 */

import { ArcBoxError, CommandFailedError } from "../index";

export {
  // Base of every failure.
  ArcBoxError as SandboxError,
  AuthenticationError,
  FileNotFoundError,
  InvalidArgumentError,
  NotFoundError,
  SandboxNotFoundError,
  // e2b's TemplateError is the broader "something about the template"
  // class; ArcBox only ever fails to resolve one.
  TemplateNotFoundError as TemplateError,
  TimeoutError,
} from "../index";

/**
 * A command exited non-zero.
 *
 * `e2b` throws this from `run()` and `wait()` rather than returning the
 * result, and reads the result's fields off the error. Extends
 * `CommandFailedError` so ArcBox-side handlers still catch it.
 */
export class CommandExitError extends CommandFailedError {
  override name = "CommandExitError";

  /** Process exit code — non-zero, or `128 + signal` for signal death. */
  get exitCode(): number {
    return this.result.exitCode;
  }

  /** Signal name when the process was killed by one. */
  get error(): string | undefined {
    return this.result.signal;
  }

  get stdout(): string {
    return this.result.stdout;
  }

  get stderr(): string {
    return this.result.stderr;
  }
}

/**
 * Part of the `e2b` surface this shim does not implement.
 *
 * Raised eagerly, never silently ignored: the operations behind it —
 * fork, volumes, signed upload/download URLs, sandbox metrics, the MCP
 * gateway, and the template build DSL — address E2B cloud services with
 * no local equivalent, so a no-op would corrupt whatever the caller does
 * next. The README lists them.
 */
export class UnsupportedError extends ArcBoxError {
  override name = "UnsupportedError";
}

/** Raise {@link UnsupportedError}, so call sites stay one line. */
export function unsupported(operation: string, reason: string): never {
  throw new UnsupportedError(
    `${operation} is not supported by @arcbox/sandbox/e2b: ${reason}`,
    {
      operation,
      suggestion:
        "this runs against a local ArcBox daemon rather than the E2B cloud — see the @arcbox/sandbox README",
    },
  );
}

/**
 * The sandbox ran out of disk.
 *
 * Never raised: the daemon does not distinguish a full disk from any
 * other write failure. Exported so `import { NotEnoughSpaceError }`
 * resolves.
 */
export class NotEnoughSpaceError extends ArcBoxError {
  override name = "NotEnoughSpaceError";
}

/**
 * The caller is being rate limited.
 *
 * Never raised: a local daemon has no quota. Exported so the import
 * resolves.
 */
export class RateLimitError extends ArcBoxError {
  override name = "RateLimitError";
}

/**
 * A git operation could not authenticate against its remote.
 *
 * Never raised: `git` runs as an ordinary command inside the sandbox, so
 * an auth failure arrives as a non-zero exit like any other.
 */
export class GitAuthError extends ArcBoxError {
  override name = "GitAuthError";
}

/**
 * A git operation failed against its upstream.
 *
 * Never raised, for the same reason as {@link GitAuthError}.
 */
export class GitUpstreamError extends ArcBoxError {
  override name = "GitUpstreamError";
}

/**
 * A template build failed.
 *
 * Never raised: the build DSL is unsupported ({@link UnsupportedError}).
 */
export class BuildError extends ArcBoxError {
  override name = "BuildError";
}

/**
 * A template build's file upload failed.
 *
 * Never raised, for the same reason as {@link BuildError}.
 */
export class FileUploadError extends ArcBoxError {
  override name = "FileUploadError";
}

/**
 * A volume operation failed.
 *
 * Never raised: volumes are unsupported ({@link UnsupportedError}).
 */
export class VolumeError extends ArcBoxError {
  override name = "VolumeError";
}
