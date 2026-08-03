/**
 * @arcbox/sandbox — run isolated microVM sandboxes on the local ArcBox
 * daemon (and, later, a remote tier) over the Connect protocol.
 *
 * Public surface only: everything under `src/gen/` is generated wire
 * code and is deliberately NOT exported — public shapes are hand-written
 * and mapped at the transport boundary.
 */

export { ArcBox, Sandbox } from './sandbox.js';
export type {
  ConnectSandboxOptions,
  CreateSandboxOptions,
  ListSandboxesOptions,
} from './sandbox.js';

export { CommandHandle, CommandResult, Commands } from './commands.js';
export type { CommandOutput, RunOptions, SignalName } from './commands.js';

export { Files, MAX_FILE_BYTES } from './files.js';
export type { WriteOptions } from './files.js';

export type { ConnectionOptions } from './connection.js';

export type { IdlePolicy, SandboxInfo, SandboxState, SandboxSummary } from './types.js';

export {
  ArcBoxError,
  AuthenticationError,
  CapabilityError,
  CommandFailedError,
  CommandNotFoundError,
  CommandTimeoutError,
  ConnectionFailedError,
  FileNotFoundError,
  FileTooLargeError,
  InvalidArgumentError,
  NotFoundError,
  ProtocolMismatchError,
  RequestTimeoutError,
  SandboxDiedError,
  SandboxNotFoundError,
  SandboxStateError,
  SandboxTtlError,
  TemplateNotFoundError,
  TimeoutError,
} from './errors.js';
export type { ArcBoxErrorOptions, CommandFailure } from './errors.js';
