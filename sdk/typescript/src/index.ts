/**
 * @arcbox/sandbox — run isolated microVM sandboxes on the local ArcBox
 * daemon (and, later, a remote tier) over the Connect protocol.
 *
 * Public surface only: everything under `src/gen/` is generated wire
 * code and is deliberately NOT exported — public shapes are hand-written
 * and mapped at the transport boundary.
 */

export { ArcBox, Sandbox } from "./sandbox";
export type {
  ConnectSandboxOptions,
  CreateSandboxOptions,
  ListSandboxesOptions,
} from "./sandbox";

export { CommandHandle, CommandResult, Commands } from "./commands";
export type {
  CommandOutput,
  PtySize,
  RunOptions,
  SignalName,
  StdinStatus,
} from "./commands";

export { Files, MAX_FILE_BYTES } from "./files";
export type { WriteOptions } from "./files";

export type { ConnectionOptions } from "./connection";

export type {
  IdlePolicy,
  SandboxInfo,
  SandboxState,
  SandboxSummary,
} from "./types";

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
} from "./errors";
export type { ArcBoxErrorOptions, CommandFailure } from "./errors";
