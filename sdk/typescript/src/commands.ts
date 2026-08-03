import { Buffer } from "node:buffer";

import type { Client } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";

import {
  ArcBoxError,
  CommandFailedError,
  SandboxDiedError,
  TimeoutError,
  toArcBoxError,
} from "./errors.js";
import type { Execution } from "./gen/arcbox/sandbox/v1/process_pb.js";
import {
  ExecutionState,
  SandboxProcessService,
  Signal,
  StdioChannel,
} from "./gen/arcbox/sandbox/v1/process_pb.js";
import type { ClientContext } from "./transport.js";
import { unaryOptions } from "./transport.js";

/** Signals deliverable to a command's process group. */
export type SignalName =
  | "SIGTERM"
  | "SIGKILL"
  | "SIGINT"
  | "SIGHUP"
  | "SIGQUIT";

const SIGNAL_VALUES: Record<SignalName, Signal> = {
  SIGHUP: Signal.SIGHUP,
  SIGINT: Signal.SIGINT,
  SIGQUIT: Signal.SIGQUIT,
  SIGKILL: Signal.SIGKILL,
  SIGTERM: Signal.SIGTERM,
};

/** Options for {@link Commands.run}. */
export interface RunOptions {
  /** Working directory (default: rootfs default). */
  cwd?: string;
  /** Environment variable overrides. */
  env?: Record<string, string>;
  /** User to run as (default: rootfs default). */
  user?: string;
  /**
   * Kill the whole process group after this long. Expiry surfaces as
   * signal death in the result (exit-as-data), not as a thrown error.
   */
  timeoutMs?: number;
  /** Return a {@link CommandHandle} immediately instead of waiting for exit. */
  background?: boolean;
}

/** One chunk of command output. */
export interface CommandOutput {
  channel: "stdout" | "stderr" | "pty";
  data: Uint8Array;
}

/**
 * A finished command. Non-zero exit is data, not an exception —
 * {@link expect} is the opt-in throw.
 */
export class CommandResult {
  /** Signal name when killed by a signal (e.g. "SIGKILL"). */
  readonly signal?: string;

  constructor(
    /**
     * Process exit code. When the process was killed by a signal this is
     * `128 + signal` (shell convention) and {@link signal} is set.
     */
    readonly exitCode: number,
    signal: string | undefined,
    readonly stdout: string,
    /** Stderr content — warnings land here too; it is not "errors". */
    readonly stderr: string,
    /**
     * True when the daemon's output retention (8 MiB per channel)
     * dropped bytes before they were collected — {@link stdout} /
     * {@link stderr} then hold only the newest retained output.
     */
    readonly truncated = false,
  ) {
    if (signal !== undefined) {
      this.signal = signal;
    }
  }

  /** Throw {@link CommandFailedError} when the exit code is non-zero; otherwise return this. */
  expect(): this {
    if (this.exitCode !== 0) {
      throw new CommandFailedError(this);
    }
    return this;
  }
}

/**
 * `string` sugar for a shell command; `string[]` is argv, executed
 * directly with no shell involved.
 */
export function normalizeCmd(cmd: string | string[]): string[] {
  return typeof cmd === "string" ? ["/bin/sh", "-lc", cmd] : cmd;
}

/** Map a POSIX signal number to its conventional name. */
function signalName(value: number): string {
  const name: unknown = Signal[value];
  return typeof name === "string" && name !== "UNSPECIFIED"
    ? name
    : `SIG${String(value)}`;
}

/**
 * Build the exit-as-data result from a terminal execution. An execution
 * that ended without an observed exit (session broke, sandbox stopped)
 * throws {@link SandboxDiedError} instead — that is not an exit.
 */
export function commandResultFromExecution(
  execution: Execution,
  stdout: string,
  stderr: string,
  truncated = false,
): CommandResult {
  if (execution.error !== "") {
    throw new SandboxDiedError(
      `command ended without an exit: ${execution.error}`,
      {
        context: { executionId: execution.id, error: execution.error },
      },
    );
  }
  const status = execution.exitStatus?.status;
  switch (status?.case) {
    case "code":
      return new CommandResult(
        status.value,
        undefined,
        stdout,
        stderr,
        truncated,
      );
    case "signal":
      return new CommandResult(
        128 + status.value,
        signalName(status.value),
        stdout,
        stderr,
        truncated,
      );
    default:
      throw new ArcBoxError("execution exited without an exit status", {
        context: { executionId: execution.id },
      });
  }
}

type ProcessClient = Client<typeof SandboxProcessService>;

/**
 * A handle to a running (or finished) command. The process is decoupled
 * from this object: dropping the handle never kills the process.
 */
export class CommandHandle {
  readonly commandId: string;
  readonly #ctx: ClientContext;
  readonly #client: ProcessClient;
  readonly #sandboxId: string;

  constructor(
    ctx: ClientContext,
    client: ProcessClient,
    sandboxId: string,
    commandId: string,
  ) {
    this.#ctx = ctx;
    this.#client = client;
    this.#sandboxId = sandboxId;
    this.commandId = commandId;
  }

  /**
   * Stream the command's output from the beginning — or from the
   * earliest byte the daemon still retains (8 MiB per channel); replayed
   * buffered output comes first, then live output follows; the stream
   * ends when the process exits (deterministic termination — never
   * silence).
   */
  get output(): AsyncIterable<CommandOutput> {
    return this.#streamOutput();
  }

  async *#streamOutput(): AsyncGenerator<CommandOutput> {
    try {
      for await (const event of this.#attach()) {
        if (event.event.case === "output") {
          const chunk = event.event.value;
          yield {
            channel:
              chunk.channel === StdioChannel.STDERR
                ? "stderr"
                : channelName(chunk.channel),
            data: chunk.data,
          };
        } else if (event.event.case === "exited") {
          return;
        }
      }
    } catch (error) {
      throw toArcBoxError(error, "commands.output");
    }
  }

  /**
   * Wait until the command exits and return its result (long-poll; no
   * client-side spinning). `timeoutMs` bounds the WAIT, not the process:
   * on expiry a {@link TimeoutError} is thrown and the process keeps
   * running.
   */
  async waitForExit(timeoutMs?: number): Promise<CommandResult> {
    const deadline =
      timeoutMs === undefined ? undefined : Date.now() + timeoutMs;
    try {
      let execution: Execution;
      for (;;) {
        const remaining =
          deadline === undefined ? undefined : deadline - Date.now();
        if (remaining !== undefined && remaining <= 0) {
          throw new TimeoutError(
            "waitForExit(timeoutMs) elapsed before the command exited",
            {
              suggestion:
                "increase the waitForExit timeoutMs argument, or kill() the command",
              context: { commandId: this.commandId },
            },
          );
        }
        // Long-poll in bounded slices so a dropped daemon surfaces as an
        // error instead of an infinite silent wait.
        const sliceSeconds =
          remaining === undefined
            ? 30
            : Math.min(30, Math.max(1, Math.ceil(remaining / 1000)));
        // eslint-disable-next-line no-await-in-loop -- sequential by design: each long-poll slice must finish before the next
        execution = await this.#client.waitExecution(
          {
            sandboxId: this.#sandboxId,
            executionId: this.commandId,
            timeoutSeconds: sliceSeconds,
          },
          // Exempt from requestTimeoutMs: this unary deliberately parks
          // server-side for sliceSeconds; grant it that long plus grace.
          { timeoutMs: (sliceSeconds + 5) * 1000 },
        );
        if (execution.state === ExecutionState.EXITED) {
          break;
        }
      }
      return await this.#collectResult(execution);
    } catch (error) {
      throw toArcBoxError(error, "commands.waitForExit");
    }
  }

  /** Deliver a signal to the whole process group (default SIGTERM). */
  async kill(signal: SignalName = "SIGTERM"): Promise<void> {
    try {
      await this.#client.signalExecution(
        {
          sandboxId: this.#sandboxId,
          executionId: this.commandId,
          signal: SIGNAL_VALUES[signal],
        },
        unaryOptions(this.#ctx),
      );
    } catch (error) {
      throw toArcBoxError(error, "commands.kill");
    }
  }

  #attach() {
    return this.#client.attachExecution({
      sandboxId: this.#sandboxId,
      executionId: this.commandId,
      stdoutOffset: 0n,
      stderrOffset: 0n,
    });
  }

  /**
   * Assemble the result of an exited execution. Output is re-read from
   * offset 0 — the daemon retains and replays it, so the result is
   * complete even when nobody consumed the live stream, UNLESS the
   * command outgrew the daemon's per-channel retention (8 MiB): chunk
   * offsets expose the dropped head, reported as `truncated`.
   */
  async #collectResult(execution: Execution): Promise<CommandResult> {
    const stdout: Uint8Array[] = [];
    const stderr: Uint8Array[] = [];
    let nextStdout = 0n;
    let nextStderr = 0n;
    let truncated = false;
    for await (const event of this.#attach()) {
      if (event.event.case === "output") {
        const chunk = event.event.value;
        const isStderr = chunk.channel === StdioChannel.STDERR;
        // A chunk landing past the expected offset means retention
        // already dropped bytes we asked for.
        if (chunk.offset > (isStderr ? nextStderr : nextStdout)) {
          truncated = true;
        }
        const after = chunk.offset + BigInt(chunk.data.byteLength);
        if (isStderr) {
          nextStderr = after;
          stderr.push(chunk.data);
        } else {
          nextStdout = after;
          stdout.push(chunk.data);
        }
      } else if (event.event.case === "exited") {
        break;
      }
    }
    return commandResultFromExecution(
      execution,
      decode(stdout),
      decode(stderr),
      truncated,
    );
  }
}

/**
 * The `sandbox.commands` namespace: run processes inside one sandbox.
 */
export class Commands {
  readonly #client: ProcessClient;
  readonly #ctx: ClientContext;
  readonly #sandboxId: string;

  constructor(ctx: ClientContext, sandboxId: string) {
    this.#client = createClient(SandboxProcessService, ctx.transport);
    this.#ctx = ctx;
    this.#sandboxId = sandboxId;
  }

  /**
   * Run a command. Foreground (default): resolves with the complete
   * {@link CommandResult} once the process exits. Background
   * (`background: true`): resolves as soon as the process is started,
   * with a {@link CommandHandle} for streaming and waiting.
   */
  run(
    cmd: string | string[],
    opts?: RunOptions & { background?: false },
  ): Promise<CommandResult>;
  run(
    cmd: string | string[],
    opts: RunOptions & { background: true },
  ): Promise<CommandHandle>;
  async run(
    cmd: string | string[],
    opts: RunOptions = {},
  ): Promise<CommandResult | CommandHandle> {
    const handle = await this.#start(cmd, opts);
    return opts.background === true ? handle : handle.waitForExit();
  }

  async #start(
    cmd: string | string[],
    opts: RunOptions,
  ): Promise<CommandHandle> {
    try {
      // The execution id is minted client-side: a lost response leaves an
      // addressable execution, and retries are idempotent by contract.
      const executionId = crypto.randomUUID();
      const execution = await this.#client.startExecution(
        {
          sandboxId: this.#sandboxId,
          executionId,
          cmd: normalizeCmd(cmd),
          env: opts.env ?? {},
          workingDir: opts.cwd ?? "",
          user: opts.user ?? "",
          timeoutSeconds:
            opts.timeoutMs === undefined ? 0 : Math.ceil(opts.timeoutMs / 1000),
          stdin: false,
        },
        unaryOptions(this.#ctx),
      );
      return new CommandHandle(
        this.#ctx,
        this.#client,
        this.#sandboxId,
        execution.id,
      );
    } catch (error) {
      throw toArcBoxError(error, "commands.run");
    }
  }
}

function channelName(channel: StdioChannel): "stdout" | "pty" {
  return channel === StdioChannel.PTY ? "pty" : "stdout";
}

function decode(chunks: Uint8Array[]): string {
  return new TextDecoder().decode(Buffer.concat(chunks));
}
