import { Buffer } from "node:buffer";

import type { Client } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";
import { timestampDate } from "@bufbuild/protobuf/wkt";

import {
  ArcBoxError,
  CommandFailedError,
  ConnectionFailedError,
  ConnectionLostError,
  InvalidArgumentError,
  SandboxDiedError,
  TimeoutError,
  toArcBoxError,
} from "./errors";
import type {
  Execution,
  ExecutionEvent,
} from "./gen/arcbox/sandbox/v1/process_pb";
import {
  ExecutionState,
  SandboxProcessService,
  Signal,
  StdioChannel,
} from "./gen/arcbox/sandbox/v1/process_pb";
import type { ClientContext } from "./transport";
import { unaryOptions } from "./transport";

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

/**
 * Consecutive dead re-attach dials tolerated before an output stream
 * surfaces the stream-death error. Delivered output resets the budget,
 * so a long-lived stream survives any number of isolated drops.
 */
const MAX_ATTACH_RETRIES = 3;
const MAX_ATTACH_RETRIES_LABEL = String(MAX_ATTACH_RETRIES);

/** Node clamps timer delays past 2^31 - 1 to 1ms; reject rather than mislead. */
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

/** Terminal geometry for a PTY command. */
export interface PtySize {
  /** Terminal width in columns. */
  cols: number;
  /** Terminal height in rows. */
  rows: number;
}

/** Stdin acceptance state of a command, as reported by the daemon. */
export interface StdinStatus {
  /**
   * Bytes accepted and forwarded so far — the offset the next stdin
   * write starts at.
   */
  bytesWritten: number;
  /** Whether stdin has been closed. */
  closed: boolean;
}

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
  /**
   * Allocate a pseudo-terminal of this size. Output then arrives merged
   * on the `"pty"` channel — stdout and stderr are indistinguishable
   * once a terminal is allocated — and stdin stays open: end input by
   * writing Ctrl-D (`"\x04"`) via {@link CommandHandle.writeStdin};
   * {@link CommandHandle.closeStdin} is rejected for PTY commands.
   */
  pty?: PtySize;
  /**
   * Feed the command's stdin. A string (UTF-8) or bytes is written and
   * then closed before the run resolves (subprocess semantics). `true`
   * keeps stdin open for manual {@link CommandHandle.writeStdin} /
   * {@link CommandHandle.closeStdin} — background runs only, since a
   * foreground run cannot write while it waits. Unset: the process
   * starts with stdin already at EOF.
   */
  stdin?: string | Uint8Array | boolean;
}

/** One chunk of command output. */
export interface CommandOutput {
  channel: "stdout" | "stderr" | "pty";
  data: Uint8Array;
}

/** Options for {@link CommandHandle.waitForLog}. */
export interface WaitForLogOptions {
  /**
   * Give up after this long. Default: no deadline — the wait still ends
   * when the command exits. On expiry a {@link TimeoutError} naming
   * this knob is thrown; the command keeps running. Fractional values
   * round up; the valid range is 1..2^31 - 1, and
   * `Number.POSITIVE_INFINITY` disables the bound.
   */
  timeoutMs?: number;
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

/** Lifecycle state of a command (execution). */
export type CommandState = "running" | "exited";

/**
 * One row of a command listing — the summary {@link Commands.list}
 * returns. Exit is data, mirroring {@link CommandResult}: a signal death
 * reports `128 + signal` with {@link signal} set; an execution that
 * ended without an observed exit carries {@link error} instead.
 */
export interface CommandInfo {
  /** Execution id — feed it to `commands.get()` for a live handle. */
  commandId: string;
  /** Whether the process runs on a pseudo-TTY. */
  tty: boolean;
  state: CommandState;
  /** When the process was dispatched. */
  startedAt?: Date;
  /** When the process terminated (unset while running). */
  exitedAt?: Date;
  /** Exit code (`128 + signal` for signal deaths), set on an observed exit. */
  exitCode?: number;
  /** Signal name when killed by a signal (e.g. "SIGKILL"). */
  signal?: string;
  /** Set when the execution ended without an observed exit. */
  error?: string;
}

/** Map one Execution row to the public summary DTO. */
export function commandInfoFromExecution(execution: Execution): CommandInfo {
  const out: CommandInfo = {
    commandId: execution.id,
    tty: execution.tty,
    state: execution.state === ExecutionState.EXITED ? "exited" : "running",
  };
  if (execution.startedAt !== undefined) {
    out.startedAt = timestampDate(execution.startedAt);
  }
  if (execution.exitedAt !== undefined) {
    out.exitedAt = timestampDate(execution.exitedAt);
  }
  const status = execution.exitStatus?.status;
  if (status?.case === "code") {
    out.exitCode = status.value;
  } else if (status?.case === "signal") {
    out.exitCode = 128 + status.value;
    out.signal = signalName(status.value);
  }
  if (execution.error !== "") {
    out.error = execution.error;
  }
  return out;
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

/**
 * Line-oriented pattern scanner over per-channel byte streams. Each
 * channel gets its own streaming decoder and partial-line buffer, so
 * interleaved chunks and multi-byte UTF-8 sequences split across chunk
 * boundaries never corrupt a line. Memory is bounded by the longest
 * line, not the output length.
 */
class LogScanner {
  readonly #matches: (line: string) => boolean;
  readonly #channels = new Map<
    StdioChannel,
    { decoder: TextDecoder; partial: string }
  >();

  constructor(pattern: string | RegExp) {
    this.#matches =
      typeof pattern === "string"
        ? (line) => line.includes(pattern)
        : (line) => {
            // A global/sticky regex carries stateful lastIndex across
            // test() calls; reset it so every line is tested afresh.
            pattern.lastIndex = 0;
            return pattern.test(line);
          };
  }

  /** Feed one chunk; returns the first matching complete line, if any. */
  push(channel: StdioChannel, data: Uint8Array): string | undefined {
    let state = this.#channels.get(channel);
    if (state === undefined) {
      state = { decoder: new TextDecoder(), partial: "" };
      this.#channels.set(channel, state);
    }
    const lines = (
      state.partial + state.decoder.decode(data, { stream: true })
    ).split("\n");
    // The final element is the new unterminated tail.
    state.partial = lines.pop() ?? "";
    return lines.find(this.#matches);
  }

  /** End of output: test the unterminated tails too. */
  flush(): string | undefined {
    for (const state of this.#channels.values()) {
      const tail = state.partial + state.decoder.decode();
      if (tail !== "" && this.#matches(tail)) {
        return tail;
      }
    }
    return undefined;
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
  /**
   * The next stdin write offset — advanced only on a successful write,
   * so a retried write lands at the same offset and the daemon's
   * deduplication makes it idempotent. `undefined` = unknown (a
   * re-attached handle); resynced lazily via GetStdinStatus.
   */
  #stdinOffset: bigint | undefined;

  constructor(
    ctx: ClientContext,
    client: ProcessClient,
    sandboxId: string,
    commandId: string,
    stdinOffset: bigint | undefined = 0n,
  ) {
    this.#ctx = ctx;
    this.#client = client;
    this.#sandboxId = sandboxId;
    this.commandId = commandId;
    this.#stdinOffset = stdinOffset;
  }

  /**
   * Stream the command's output from the beginning — or from the
   * earliest byte the daemon still retains (8 MiB per channel); replayed
   * buffered output comes first, then live output follows; the stream
   * ends when the process exits (deterministic termination — never
   * silence). A transport drop mid-stream re-attaches transparently
   * from the last delivered offsets (see {@link ConnectionLostError}
   * for the exhausted-retries case).
   */
  get output(): AsyncIterable<CommandOutput> {
    return this.#streamOutput();
  }

  async *#streamOutput(): AsyncGenerator<CommandOutput> {
    try {
      for await (const event of this.#attachEvents("commands.output")) {
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

  /**
   * Wait until a log line matching `pattern` appears on any of the
   * command's output channels, and return that line. A `string` pattern
   * is substring containment; a `RegExp` is tested per line. Purely
   * SDK-side — no daemon RPC beyond the attach: the offset-addressed
   * output replays from the beginning (or the earliest retained byte),
   * so a line printed before the call matches immediately, and a
   * transport drop resumes through the same re-attach loop as
   * {@link output}.
   *
   * Matching is line-oriented: complete lines are tested as they
   * arrive, and a trailing unterminated line is tested once the command
   * exits. If the command exits (or the daemon closes the record)
   * before any match, an {@link ArcBoxError} is thrown — that is not a
   * timeout. `timeoutMs` bounds the WAIT, not the process.
   */
  async waitForLog(
    pattern: string | RegExp,
    opts: WaitForLogOptions = {},
  ): Promise<string> {
    let deadline: AbortSignal | undefined;
    if (opts.timeoutMs !== undefined) {
      // Same knob discipline as connect(): fractional values round up,
      // Infinity disables the bound, and the rest of the range is
      // validated here so a bad knob surfaces as the SDK's typed error.
      const timeoutMs = Math.ceil(opts.timeoutMs);
      if (
        Number.isNaN(timeoutMs) ||
        timeoutMs <= 0 ||
        (Number.isFinite(timeoutMs) && timeoutMs > MAX_TIMEOUT_MS)
      ) {
        throw new InvalidArgumentError(
          "waitForLog timeoutMs must be a positive number of milliseconds " +
            "at most 2**31 - 1 (Number.POSITIVE_INFINITY disables the bound)",
          {
            context: { timeoutMs: String(opts.timeoutMs) },
            operation: "commands.waitForLog",
          },
        );
      }
      if (Number.isFinite(timeoutMs)) {
        deadline = AbortSignal.timeout(timeoutMs);
      }
    }
    const patternLabel = String(pattern);
    const scanner = new LogScanner(pattern);
    try {
      for await (const event of this.#attachEvents(
        "commands.waitForLog",
        deadline,
      )) {
        if (event.event.case === "output") {
          const chunk = event.event.value;
          const line = scanner.push(chunk.channel, chunk.data);
          if (line !== undefined) {
            return line;
          }
        } else if (event.event.case === "exited") {
          break;
        }
      }
      // The command exited (or the daemon closed the record): a
      // trailing unterminated line still counts.
      const tail = scanner.flush();
      // eslint-disable-next-line sukka/prefer-nullthrow -- a miss must surface as the SDK's typed ArcBoxError with context, not a generic invariant error
      if (tail === undefined) {
        throw new ArcBoxError(
          "the command exited before the log pattern appeared",
          {
            operation: "commands.waitForLog",
            context: { commandId: this.commandId, pattern: patternLabel },
          },
        );
      }
      return tail;
    } catch (error) {
      // A failure observed after the deadline fired is the deadline
      // surfacing (the aborted attach stream) — the only aborter of
      // this signal is the timeout.
      if (deadline?.aborted === true && !(error instanceof TimeoutError)) {
        throw new TimeoutError(
          "waitForLog(timeoutMs) elapsed before the log pattern appeared",
          {
            suggestion: "increase the waitForLog timeoutMs option",
            operation: "commands.waitForLog",
            cause: error,
            context: { commandId: this.commandId, pattern: patternLabel },
          },
        );
      }
      throw toArcBoxError(error, "commands.waitForLog");
    }
  }

  /**
   * Write bytes (or a UTF-8 string) to the command's stdin. Requires a
   * run started with `stdin: true` or a PTY.
   *
   * Writes are offset-idempotent: the handle tracks the stdin cursor and
   * advances it only on success, so retrying a failed or lost write
   * *with the same data* is safe — the daemon deduplicates bytes below
   * its accepted count and never double-feeds the process. Issue writes
   * sequentially; the handle tracks a single cursor.
   */
  async writeStdin(data: string | Uint8Array): Promise<void> {
    const bytes =
      typeof data === "string" ? new TextEncoder().encode(data) : data;
    try {
      const offset = await this.#stdinCursor();
      const status = await this.#client.writeStdin(
        {
          sandboxId: this.#sandboxId,
          executionId: this.commandId,
          offset,
          data: bytes,
          eof: false,
        },
        unaryOptions(this.#ctx),
      );
      this.#stdinOffset = status.bytesWritten;
    } catch (error) {
      throw toArcBoxError(error, "commands.writeStdin");
    }
  }

  /**
   * Close the command's stdin (EOF). Rejected for PTY commands — write
   * Ctrl-D (`"\x04"`) instead.
   */
  async closeStdin(): Promise<void> {
    try {
      const offset = await this.#stdinCursor();
      await this.#client.writeStdin(
        {
          sandboxId: this.#sandboxId,
          executionId: this.commandId,
          offset,
          data: new Uint8Array(),
          eof: true,
        },
        unaryOptions(this.#ctx),
      );
    } catch (error) {
      throw toArcBoxError(error, "commands.closeStdin");
    }
  }

  /**
   * The daemon's stdin acceptance state — the recovery point after a
   * lost write response. Also resyncs the handle's write cursor.
   */
  async stdinStatus(): Promise<StdinStatus> {
    try {
      const status = await this.#client.getStdinStatus(
        { sandboxId: this.#sandboxId, executionId: this.commandId },
        unaryOptions(this.#ctx),
      );
      this.#stdinOffset = status.bytesWritten;
      return {
        bytesWritten: Number(status.bytesWritten),
        closed: status.closed,
      };
    } catch (error) {
      throw toArcBoxError(error, "commands.stdinStatus");
    }
  }

  /** Resize a PTY command's terminal. */
  async resize(cols: number, rows: number): Promise<void> {
    try {
      await this.#client.resizeExecutionTty(
        {
          sandboxId: this.#sandboxId,
          executionId: this.commandId,
          size: { width: cols, height: rows },
        },
        unaryOptions(this.#ctx),
      );
    } catch (error) {
      throw toArcBoxError(error, "commands.resize");
    }
  }

  /** The tracked stdin cursor, resynced from the daemon when unknown. */
  async #stdinCursor(): Promise<bigint> {
    if (this.#stdinOffset === undefined) {
      const status = await this.#client.getStdinStatus(
        { sandboxId: this.#sandboxId, executionId: this.commandId },
        unaryOptions(this.#ctx),
      );
      this.#stdinOffset = status.bytesWritten;
    }
    return this.#stdinOffset;
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

  /**
   * The resumable attach loop shared by {@link output} and the result
   * collection: streams execution events, tracking the byte offset each
   * channel has delivered. When the transport drops mid-stream, it
   * re-attaches from those offsets — the daemon replays nothing already
   * delivered — so the consumer sees one seamless, gapless stream. Only
   * consecutive dead dials count against the retry budget (delivered
   * output resets it); once exhausted, the stream-death
   * {@link ConnectionLostError} carries the last transport failure.
   */
  async *#attachEvents(
    operation: string,
    signal?: AbortSignal,
  ): AsyncGenerator<ExecutionEvent> {
    let stdoutOffset = 0n;
    let stderrOffset = 0n;
    let failures = 0;
    for (;;) {
      try {
        // eslint-disable-next-line no-await-in-loop -- sequential by design: each re-attach resumes where the last stream died
        for await (const event of this.#client.attachExecution(
          {
            sandboxId: this.#sandboxId,
            executionId: this.commandId,
            stdoutOffset,
            stderrOffset,
          },
          signal === undefined ? undefined : { signal },
        )) {
          if (event.event.case === "output") {
            const chunk = event.event.value;
            const after = chunk.offset + BigInt(chunk.data.byteLength);
            if (chunk.channel === StdioChannel.STDERR) {
              if (after > stderrOffset) {
                stderrOffset = after;
                failures = 0;
              }
            } else if (after > stdoutOffset) {
              stdoutOffset = after;
              failures = 0;
            }
          }
          yield event;
          if (event.event.case === "exited") {
            return;
          }
        }
        // A clean server-side end without an exited frame: nothing more
        // is coming (the daemon closed the record).
        return;
      } catch (error) {
        const mapped = toArcBoxError(error, operation);
        // An aborted caller deadline is never worth re-dialing for.
        if (signal?.aborted === true) {
          throw mapped;
        }
        if (!(mapped instanceof ConnectionFailedError)) {
          throw mapped;
        }
        failures += 1;
        if (failures > MAX_ATTACH_RETRIES) {
          throw new ConnectionLostError(
            "the output stream died and could not be re-attached within " +
              "the retry budget",
            {
              operation,
              cause: error,
              context: {
                commandId: this.commandId,
                retries: MAX_ATTACH_RETRIES_LABEL,
              },
            },
          );
        }
      }
    }
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
    for await (const event of this.#attachEvents("commands.waitForExit")) {
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
    const stdinData =
      typeof opts.stdin === "string"
        ? new TextEncoder().encode(opts.stdin)
        : opts.stdin instanceof Uint8Array
          ? opts.stdin
          : undefined;
    if (opts.stdin === true && opts.background !== true) {
      throw new InvalidArgumentError(
        "stdin: true keeps stdin open for the handle and requires " +
          "background: true; pass a string or bytes to feed a foreground run",
        { operation: "commands.run" },
      );
    }
    if (stdinData !== undefined && opts.pty !== undefined) {
      throw new InvalidArgumentError(
        "a PTY's stdin cannot be closed after a one-shot write; use " +
          "background: true with writeStdin, ending input with Ctrl-D (0x04)",
        { operation: "commands.run" },
      );
    }
    const handle = await this.#start(cmd, opts, stdinData !== undefined);
    if (stdinData !== undefined) {
      await this.#feedStdin(handle, stdinData);
    }
    return opts.background === true ? handle : handle.waitForExit();
  }

  /**
   * Re-attach to an execution by id — from another process, or after
   * losing the handle. Verifies the execution exists (an unknown id is a
   * typed not-found error) and seeds the handle's stdin cursor from the
   * daemon's accepted count so later writes resume without a gap.
   */
  async get(commandId: string): Promise<CommandHandle> {
    try {
      const execution = await this.#client.waitExecution(
        {
          sandboxId: this.#sandboxId,
          executionId: commandId,
          timeoutSeconds: 0,
        },
        unaryOptions(this.#ctx),
      );
      return new CommandHandle(
        this.#ctx,
        this.#client,
        this.#sandboxId,
        execution.id,
        execution.stdin?.bytesWritten,
      );
    } catch (error) {
      throw toArcBoxError(error, "commands.get");
    }
  }

  /**
   * List this sandbox's commands, running and exited — the rediscovery
   * path after losing handles (or a whole process): pick an id from a
   * summary and {@link get} a live handle for it. Executions are
   * retained for the life of their sandbox.
   */
  async list(): Promise<CommandInfo[]> {
    try {
      const listing = await this.#client.listExecutions(
        { sandboxId: this.#sandboxId },
        unaryOptions(this.#ctx),
      );
      return listing.executions.map(commandInfoFromExecution);
    } catch (error) {
      throw toArcBoxError(error, "commands.list");
    }
  }

  async #start(
    cmd: string | string[],
    opts: RunOptions,
    feedsStdin: boolean,
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
          // A PTY inherently keeps stdin open (EOF is not expressible on
          // a terminal); otherwise stdin stays open exactly when the
          // caller feeds or drives it.
          stdin: opts.pty !== undefined || opts.stdin === true || feedsStdin,
          tty: opts.pty !== undefined,
          ...(opts.pty !== undefined && {
            ttySize: { width: opts.pty.cols, height: opts.pty.rows },
          }),
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

  /**
   * Write-then-close the one-shot stdin payload. A process is free to
   * exit without consuming its stdin (`subprocess` semantics): when the
   * feed fails but the execution has already exited, the exit result is
   * the truth and the failed feed is noise — the write merely raced the
   * exit. Any other failure is real and surfaces.
   */
  async #feedStdin(handle: CommandHandle, data: Uint8Array): Promise<void> {
    try {
      await handle.writeStdin(data);
      await handle.closeStdin();
    } catch (error) {
      const mapped = toArcBoxError(error, "commands.run");
      let state: Execution | undefined;
      try {
        state = await this.#client.waitExecution(
          {
            sandboxId: this.#sandboxId,
            executionId: handle.commandId,
            timeoutSeconds: 0,
          },
          unaryOptions(this.#ctx),
        );
      } catch {
        // The poll itself failed; the original feed error stands.
      }
      if (state?.state !== ExecutionState.EXITED) {
        // The caller gets no handle out of a thrown run(), so a
        // still-running process (cat waiting on input) would keep the
        // sandbox RUNNING with no way to reach it. Best-effort kill;
        // the feed error is the one to surface.
        try {
          await handle.kill("SIGKILL");
        } catch {
          // Best-effort only.
        }
        throw mapped;
      }
    }
  }
}

function channelName(channel: StdioChannel): "stdout" | "pty" {
  return channel === StdioChannel.PTY ? "pty" : "stdout";
}

function decode(chunks: Uint8Array[]): string {
  return new TextDecoder().decode(Buffer.concat(chunks));
}
