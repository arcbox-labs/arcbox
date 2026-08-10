/**
 * `@arcbox/sandbox/e2b` — the `e2b` SDK's surface, served by a local ArcBox
 * daemon instead of the E2B cloud.
 *
 * Swap the import and keep the code:
 *
 * ```ts
 * import { Sandbox } from '@arcbox/sandbox/e2b'; // was: from 'e2b'
 * ```
 *
 * The default export is `Sandbox`, as in `e2b`, so `import Sandbox from
 * '@arcbox/sandbox/e2b'` works too. What is not covered — fork, volumes,
 * signed URLs, metrics, MCP, and the template build DSL — throws
 * {@link UnsupportedError} rather than failing quietly; the README
 * lists it.
 */

export {
  DEFAULT_SANDBOX_TIMEOUT_MS,
  Sandbox,
  type ConnectionOpts,
  type SandboxConnectOpts,
  type SandboxInfo,
  type SandboxListOpts,
  type SandboxOpts,
  Sandbox as default,
} from "./sandbox";

export {
  CommandHandle,
  Commands,
  Pty,
  type CommandConnectOpts,
  type CommandResult,
  type CommandStartOpts,
  type OutputSinks,
  type ProcessInfo,
  type PtyCreateOpts,
  type PtySize,
} from "./commands";

export {
  Filesystem,
  FileType,
  permissionString,
  WatchHandle,
  type EntryInfo,
  type FilesystemEvent,
  type FilesystemEventType,
  type FilesystemReadOpts,
  type FilesystemWriteOpts,
  type WatchOpts,
  type WriteEntry,
  type WriteInfo,
} from "./filesystem";

export {
  Git,
  type GitBranches,
  type GitCloneOpts,
  type GitCommitOpts,
  type GitRequestOpts,
} from "./git";

export {
  AuthenticationError,
  BuildError,
  CommandExitError,
  FileNotFoundError,
  FileUploadError,
  GitAuthError,
  GitUpstreamError,
  InvalidArgumentError,
  NotEnoughSpaceError,
  NotFoundError,
  RateLimitError,
  SandboxError,
  SandboxNotFoundError,
  TemplateError,
  TimeoutError,
  UnsupportedError,
  VolumeError,
} from "./errors";

export type { SandboxState } from "../index";
