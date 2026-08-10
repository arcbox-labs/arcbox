/** The `sandbox.commands` and `sandbox.pty` namespaces in `e2b`'s shape. */

import type {
  CommandHandle as ArcBoxCommandHandle,
  Commands as ArcBoxCommands,
  CommandResult as ArcBoxCommandResult,
  SignalName,
} from "../index";

import { CommandExitError } from "./errors";

/** A finished command, as `e2b` reports it. */
export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  /** Signal name when the process was killed by one. */
  error?: string;
}

/** Options shared by the command entry points. */
export interface CommandStartOpts {
  background?: boolean;
  cwd?: string;
  user?: string;
  envs?: Record<string, string>;
  onStdout?: (data: string) => void | Promise<void>;
  onStderr?: (data: string) => void | Promise<void>;
  /** Keep stdin open for {@link CommandHandle.sendStdin}. */
  stdin?: boolean;
  /** Kill the process group after this long. */
  timeoutMs?: number;
}

/** Where a handle delivers a command's output while it runs. */
export interface OutputSinks {
  onStdout?: (data: string) => void | Promise<void>;
  onStderr?: (data: string) => void | Promise<void>;
  /** Raw, undecoded bytes — how a terminal's merged stream is delivered. */
  onData?: (data: Uint8Array) => void | Promise<void>;
}

/** Options for connecting to an already-running command. */
export type CommandConnectOpts = Pick<
  CommandStartOpts,
  "onStdout" | "onStderr" | "timeoutMs"
>;

/** Terminal size, as `e2b` names it. */
export interface PtySize {
  cols: number;
  rows: number;
}

/**
 * One running command, as `e2b` lists them.
 *
 * The daemon reports execution ids and states, not argv: `cmd`, `args`,
 * `envs`, and `cwd` are empty rather than invented.
 */
export interface ProcessInfo {
  /** Execution id. `e2b` names it `pid`; ArcBox ids are not OS pids. */
  pid: string;
  cmd: string;
  args: string[];
  envs: Record<string, string>;
  cwd?: string;
}

/** Options for {@link Pty.create}. */
export interface PtyCreateOpts extends PtySize {
  onData: (data: Uint8Array) => void | Promise<void>;
  cwd?: string;
  user?: string;
  envs?: Record<string, string>;
  timeoutMs?: number;
}

function toResult(result: ArcBoxCommandResult): CommandResult {
  const out: CommandResult = {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exitCode,
  };
  if (result.signal !== undefined) {
    out.error = result.signal;
  }
  return out;
}

/** Throw `e2b`'s error class on a non-zero exit; return the result otherwise. */
function expectZeroExit(result: ArcBoxCommandResult): CommandResult {
  if (result.exitCode !== 0) {
    throw new CommandExitError(result);
  }
  return toResult(result);
}

/**
 * A running command, in `e2b`'s shape.
 *
 * The output model is inverted from ArcBox's on purpose: `e2b` pushes
 * chunks into `onStdout`/`onStderr` callbacks, so this handle pumps the
 * underlying async iterable into them from the moment it is created. A
 * handle with no callbacks starts no pump — the bytes are still
 * retained daemon-side and arrive with the result.
 */
export class CommandHandle {
  /** Execution id. `e2b` names it `pid`; ArcBox ids are not OS pids. */
  readonly pid: string;

  readonly #handle: ArcBoxCommandHandle;
  #pump: Promise<void> | undefined;
  /** Set by {@link disconnect}: the pump stops delivering and detaches. */
  #disconnected = false;
  /**
   * Boxed so an `undefined` failure is still a failure, and so the
   * original error object survives — the SDK throws typed classes and
   * re-wrapping one would break the caller's `instanceof`.
   */
  #pumpFailure: { readonly error: unknown } | undefined;

  constructor(handle: ArcBoxCommandHandle, sinks: OutputSinks = {}) {
    this.#handle = handle;
    this.pid = handle.commandId;
    if (
      sinks.onData !== undefined ||
      sinks.onStdout !== undefined ||
      sinks.onStderr !== undefined
    ) {
      this.#pump = this.#pumpOutput(sinks);
    }
  }

  async #pumpOutput(sinks: OutputSinks): Promise<void> {
    // One streaming decoder per channel: stdout and stderr interleave
    // on the wire, and a multibyte character split across frames must
    // reassemble within its own channel, not against the other's bytes.
    const decoders = { stdout: new TextDecoder(), stderr: new TextDecoder() };
    try {
      for await (const chunk of this.#handle.output) {
        if (this.#disconnected) {
          // Breaking out of for-await closes the underlying stream.
          break;
        }
        // A terminal merges stdout and stderr and carries escape
        // sequences, so its bytes go to onData undecoded — decoding
        // them as text would corrupt what a terminal emulator needs.
        if (sinks.onData !== undefined) {
          await sinks.onData(chunk.data);
          continue;
        }
        const channel = chunk.channel === "stderr" ? "stderr" : "stdout";
        const sink = channel === "stderr" ? sinks.onStderr : sinks.onStdout;
        if (sink !== undefined) {
          await sink(decoders[channel].decode(chunk.data, { stream: true }));
        }
      }
      if (!this.#disconnected) {
        // Flush a partial multibyte character buffered at end of stream.
        const stdoutTail = decoders.stdout.decode();
        if (stdoutTail !== "" && sinks.onStdout !== undefined) {
          await sinks.onStdout(stdoutTail);
        }
        const stderrTail = decoders.stderr.decode();
        if (stderrTail !== "" && sinks.onStderr !== undefined) {
          await sinks.onStderr(stderrTail);
        }
      }
    } catch (error) {
      // Surfaced by wait(): throwing out of a detached pump would be an
      // unhandled rejection with no caller to receive it. A failure
      // after disconnect() is that teardown, not something to report.
      if (!this.#disconnected) {
        this.#pumpFailure = { error };
      }
    }
  }

  /**
   * Wait for the command to finish.
   *
   * Throws {@link CommandExitError} on a non-zero exit, as `e2b` does.
   */
  async wait(): Promise<CommandResult> {
    const result = await this.#handle.waitForExit();
    await this.#pump;
    if (this.#pumpFailure !== undefined) {
      // Re-raises exactly what the stream threw: the SDK's typed error
      // classes must reach the caller intact.
      throw this.#pumpFailure.error;
    }
    return expectZeroExit(result);
  }

  /** Kill the command's process group. */
  async kill(signal: SignalName = "SIGKILL"): Promise<boolean> {
    await this.#handle.kill(signal);
    return true;
  }

  /** Feed bytes to the command's stdin. */
  async sendStdin(data: string): Promise<void> {
    await this.#handle.writeStdin(data);
  }

  /** Close the command's stdin. */
  async closeStdin(): Promise<void> {
    await this.#handle.closeStdin();
  }

  /**
   * Stop receiving output without killing the command.
   *
   * Delivery stops at the next chunk boundary — the pump swallows it,
   * breaks out, and breaking closes the underlying stream. Output the
   * daemon retains still arrives with the result via {@link wait}.
   */
  async disconnect(): Promise<void> {
    this.#disconnected = true;
    this.#pump = undefined;
    await Promise.resolve();
  }
}

/** `e2b`'s `Commands`, backed by `@arcbox/sandbox`'s `commands`. */
export class Commands {
  readonly #commands: ArcBoxCommands;

  constructor(commands: ArcBoxCommands) {
    this.#commands = commands;
  }

  /**
   * Run a command. Foreground resolves with the result and throws
   * {@link CommandExitError} on a non-zero exit; `background: true`
   * resolves with a {@link CommandHandle}.
   */
  async run(
    cmd: string,
    opts?: CommandStartOpts & { background?: false },
  ): Promise<CommandResult>;
  async run(
    cmd: string,
    opts: CommandStartOpts & { background: true },
  ): Promise<CommandHandle>;
  async run(
    cmd: string,
    opts: CommandStartOpts = {},
  ): Promise<CommandResult | CommandHandle> {
    const handle = await this.#start(cmd, opts);
    return opts.background === true ? handle : handle.wait();
  }

  async #start(cmd: string, opts: CommandStartOpts): Promise<CommandHandle> {
    const handle = await this.#commands.run(cmd, {
      background: true,
      ...(opts.cwd !== undefined && { cwd: opts.cwd }),
      ...(opts.user !== undefined && { user: opts.user }),
      ...(opts.envs !== undefined && { env: opts.envs }),
      ...(opts.timeoutMs !== undefined && { timeoutMs: opts.timeoutMs }),
      // `stdin` only makes sense on a handle the caller keeps, which is
      // the background path; a foreground run waits for an exit.
      ...(opts.stdin === true && opts.background === true && { stdin: true }),
    });
    return new CommandHandle(handle, opts);
  }

  /** Take a handle on a command started elsewhere. */
  async connect(
    pid: string,
    opts: CommandConnectOpts = {},
  ): Promise<CommandHandle> {
    return new CommandHandle(await this.#commands.get(pid), opts);
  }

  /** Signal a command by id. */
  async kill(pid: string): Promise<boolean> {
    const handle = await this.#commands.get(pid);
    await handle.kill("SIGKILL");
    return true;
  }

  /** Feed bytes to a command's stdin by id. */
  async sendStdin(pid: string, data: string): Promise<void> {
    await (await this.#commands.get(pid)).writeStdin(data);
  }

  /** Close a command's stdin by id. */
  async closeStdin(pid: string): Promise<void> {
    await (await this.#commands.get(pid)).closeStdin();
  }

  /** List the sandbox's running commands. */
  async list(): Promise<ProcessInfo[]> {
    const infos = await this.#commands.list();
    const running: ProcessInfo[] = [];
    for (const info of infos) {
      if (info.state === "running") {
        running.push({ pid: info.commandId, cmd: "", args: [], envs: {} });
      }
    }
    return running;
  }
}

/**
 * `e2b`'s `Pty`, backed by the `tty` option on `commands.run`.
 *
 * ArcBox has no separate PTY service — a terminal is one flag on an
 * execution — so this namespace is sugar that keeps `e2b` code working.
 */
export class Pty {
  readonly #commands: ArcBoxCommands;

  constructor(commands: ArcBoxCommands) {
    this.#commands = commands;
  }

  /** Start a shell on a pseudo-terminal of the given size. */
  async create(opts: PtyCreateOpts): Promise<CommandHandle> {
    const handle = await this.#commands.run(["/bin/sh", "-l"], {
      background: true,
      pty: { cols: opts.cols, rows: opts.rows },
      ...(opts.cwd !== undefined && { cwd: opts.cwd }),
      ...(opts.user !== undefined && { user: opts.user }),
      ...(opts.envs !== undefined && { env: opts.envs }),
      ...(opts.timeoutMs !== undefined && { timeoutMs: opts.timeoutMs }),
    });
    return new CommandHandle(handle, { onData: opts.onData });
  }

  /** Take a handle on a terminal started elsewhere. */
  async connect(
    pid: string,
    opts: { onData: (data: Uint8Array) => void | Promise<void> },
  ): Promise<CommandHandle> {
    return new CommandHandle(await this.#commands.get(pid), {
      onData: opts.onData,
    });
  }

  /** Feed bytes to the terminal. */
  async sendInput(pid: string, data: Uint8Array): Promise<void> {
    await (await this.#commands.get(pid)).writeStdin(data);
  }

  /** Resize the terminal. */
  async resize(pid: string, size: PtySize): Promise<void> {
    await (await this.#commands.get(pid)).resize(size.cols, size.rows);
  }

  /** Kill the terminal's process group. */
  async kill(pid: string): Promise<boolean> {
    await (await this.#commands.get(pid)).kill("SIGKILL");
    return true;
  }
}
