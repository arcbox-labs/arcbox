import { setTimeout as sleep } from "node:timers/promises";

import type { CallOptions, Client } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";
import { noop } from "foxts/noop";

import { Commands } from "./commands";
import type { ConnectionOptions } from "./connection";
import {
  ArcBoxError,
  ConnectionFailedError,
  ConnectionLostError,
  InvalidArgumentError,
  NotFoundError,
  SandboxStateError,
  TimeoutError,
  toArcBoxError,
} from "./errors";
import { Files } from "./files";
import { Ports } from "./ports";
import type { WatchEventsResponse } from "./gen/arcbox/sandbox/v1/sandbox_pb";
import {
  IdleAction,
  NetworkMode,
  SandboxEventKind,
  SandboxService,
  SandboxState as SandboxStateProto,
} from "./gen/arcbox/sandbox/v1/sandbox_pb";
import type { ClientContext } from "./transport";
import { createClientContext, unaryOptions } from "./transport";
import type {
  Capabilities,
  IdlePolicy,
  SandboxEvent,
  SandboxInfo,
  SandboxState,
  SandboxSummary,
} from "./types";
import {
  capabilitiesFromProto,
  sandboxEventFromProto,
  sandboxInfoFromProto,
  sandboxStateToProto,
  sandboxSummaryFromProto,
} from "./types";

/** Options for {@link Sandbox.create}. */
export interface CreateSandboxOptions {
  /**
   * Hard maximum lifetime in milliseconds. On expiry the daemon always
   * destroys the sandbox — pausing does not apply. Distinct from
   * {@link idleTimeoutMs}; never conflate the two knobs.
   */
  ttlMs?: number;
  /**
   * Apply {@link onIdle} after this long without a running command
   * (re-armed on every idle transition). Unset = no idle detection.
   */
  idleTimeoutMs?: number;
  /** What the daemon does when the idle timeout expires (default: kill). */
  onIdle?: "kill" | "pause";
  /** vCPU count (default: template, else daemon default). */
  vcpus?: number;
  /** Memory in MiB (default: template, else daemon default). */
  memoryMib?: number;
  /** Initial command launched after boot; its exit returns the sandbox to READY. */
  cmd?: string[];
  /** Environment for the initial command, merged over the template's env. */
  env?: Record<string, string>;
  /** Labels for filtering in list/events. */
  labels?: Record<string, string>;
  /** `false` disables networking entirely (no network device). */
  network?: boolean;
  /** Resolve only once the sandbox is READY (default true). */
  waitUntilReady?: boolean;
  /** Connection override for this entry point. */
  connection?: ConnectionOptions;
}

/** Options for {@link Sandbox.connect}. */
export interface ConnectSandboxOptions {
  /**
   * Overall deadline in milliseconds for the whole connect() call: the
   * PAUSING settle poll, a checkpoint resume, and the STARTING
   * readiness wait all share it (default 60_000 — generous because a
   * checkpoint restore or cold boot legitimately takes a while). On
   * expiry a {@link TimeoutError} is thrown and the sandbox is left as
   * it was. Fractional values round up; the valid range is 1..2^31 - 1,
   * and `Number.POSITIVE_INFINITY` disables the bound.
   */
  timeoutMs?: number;
  /** Connection override for this entry point. */
  connection?: ConnectionOptions;
}

/** Options for {@link Sandbox.list}. */
export interface ListSandboxesOptions {
  /** Keep only sandboxes in this state. */
  state?: SandboxState;
  /** Keep only sandboxes carrying all of these labels. */
  labels?: Record<string, string>;
  connection?: ConnectionOptions;
}

/**
 * A lifecycle-deadline update for {@link Sandbox.setLifecycle}. Each
 * knob is tri-state: **omitted** (or `undefined`) leaves it unchanged;
 * **`null`** restores the daemon default (no TTL / no idle detection /
 * the default idle action); a **value** replaces it.
 */
export interface LifecycleUpdate {
  /**
   * Replace the hard maximum lifetime: expire this long from NOW —
   * calling repeatedly keeps a busy sandbox alive (E2B timeout
   * semantics). `null` removes the limit.
   */
  ttlMs?: number | null;
  /**
   * Replace the idle window, re-arming a live timer. `null` disables
   * idle detection.
   */
  idleTimeoutMs?: number | null;
  /**
   * Replace what the daemon does when the idle timeout expires.
   * `null` restores the daemon default (currently `"kill"`).
   */
  onIdle?: IdlePolicy | null;
}

type SandboxClient = Client<typeof SandboxService>;

/**
 * How often {@link ArcBox.connect} re-inspects a PAUSING sandbox. The
 * daemon emits `SANDBOX_EVENT_KIND_PAUSED` on this edge (CORE-21), but
 * the settle poll predates it and remains the simple, robust route — a
 * poll-to-event-wait conversion is a candidate cleanup, not a bug.
 */
const PAUSE_SETTLE_POLL_MS = 500;

/** Default overall deadline for {@link ArcBox.connect} — see {@link ConnectSandboxOptions.timeoutMs}. */
const CONNECT_TIMEOUT_MS = 60000;

/** Node clamps timer delays past 2^31 - 1 to 1ms; reject rather than mislead. */
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

/** Merge the connect deadline signal into a call's options, when one is set. */
function withSignal(
  options: CallOptions,
  signal: AbortSignal | undefined,
): CallOptions {
  return { ...options, ...(signal !== undefined && { signal }) };
}

/**
 * Client entry point. Holds one resolved connection; every handle it
 * creates shares it. The {@link Sandbox} statics are sugar over a
 * throwaway `ArcBox` resolved from options/environment.
 */
export class ArcBox {
  readonly #ctx: ClientContext;
  readonly #client: SandboxClient;
  #capabilities?: Promise<Capabilities>;

  constructor(options: ConnectionOptions = {}) {
    this.#ctx = createClientContext(options);
    this.#client = createClient(SandboxService, this.#ctx.transport);
  }

  /**
   * What the daemon can do: version, sandbox protocol level, feature
   * flags, and whether nested virtualization is available. Answered
   * host-side (works before any sandbox exists) and cached for the life
   * of this client — a failed fetch is not cached, so the next call
   * retries. The SDK does not gate on it: the daemon fails fast on its
   * own (a `CapabilityError` from `create`); this is the inspectable
   * version of the same answer.
   */
  capabilities(): Promise<Capabilities> {
    this.#capabilities ??= this.#fetchCapabilities().catch((error: unknown) => {
      this.#capabilities = undefined;
      throw toArcBoxError(error, "arcbox.capabilities");
    });
    return this.#capabilities;
  }

  async #fetchCapabilities(): Promise<Capabilities> {
    return capabilitiesFromProto(
      await this.#client.getCapabilities({}, unaryOptions(this.#ctx)),
    );
  }

  /**
   * Create a sandbox and (by default) wait until it is READY.
   *
   * The sandbox id is minted client-side so the readiness subscription
   * can be armed BEFORE the create call — subscribe-then-act, so no
   * transition is missed (the CORE-67 rule) — and so retries stay
   * idempotent.
   */
  async create(
    template = "",
    opts: CreateSandboxOptions = {},
  ): Promise<Sandbox> {
    const id = crypto.randomUUID();
    const abort = new AbortController();
    try {
      let firstEvent: Promise<IteratorResult<WatchEventsResponse>> | undefined;
      let events: AsyncIterator<WatchEventsResponse> | undefined;
      if (opts.waitUntilReady !== false) {
        const stream = this.#client.events(
          { sandboxId: id },
          { signal: abort.signal },
        );
        events = stream[Symbol.asyncIterator]();
        // Starting the first read is what sends the subscription request.
        firstEvent = events.next();
        firstEvent.catch(noop); // pre-handled: cancellation on the fast path is fine
      }
      await this.#client.create(
        {
          id,
          template,
          labels: opts.labels ?? {},
          cmd: opts.cmd ?? [],
          env: opts.env ?? {},
          ...((opts.vcpus !== undefined || opts.memoryMib !== undefined) && {
            limits: {
              vcpus: opts.vcpus ?? 0,
              memoryMib: BigInt(opts.memoryMib ?? 0),
            },
          }),
          ...(!(opts.network === undefined) && {
            network: {
              mode: opts.network ? NetworkMode.ENABLED : NetworkMode.NONE,
            },
          }),
          ttlSeconds: secondsFromMs(opts.ttlMs),
          idleTimeoutSeconds: secondsFromMs(opts.idleTimeoutMs),
          onIdle:
            opts.onIdle === undefined
              ? IdleAction.UNSPECIFIED
              : opts.onIdle === "kill"
                ? IdleAction.KILL
                : IdleAction.PAUSE,
        },
        unaryOptions(this.#ctx),
      );
      if (events !== undefined && firstEvent !== undefined) {
        await this.#waitReady(id, events, firstEvent);
      }
      return new Sandbox(this.#ctx, id);
    } catch (error) {
      // The sandbox may exist even though create() failed (readiness
      // failed, response lost) and ttlMs is optional, so a leaked VM
      // could run forever. Best-effort removal; a failure here (e.g.
      // nothing was created) must not mask the original error.
      await this.#client
        .remove({ id, force: true }, unaryOptions(this.#ctx))
        .catch(noop);
      throw toArcBoxError(error, "sandbox.create");
    } finally {
      abort.abort();
    }
  }

  /**
   * Attach to an existing sandbox. A PAUSED sandbox is resumed (resume
   * completes once it is READY again); a PAUSING one settles to PAUSED
   * first, then resumes; a STARTING one is waited for. A terminal state
   * is a typed error carrying the observed state. Connecting never
   * touches the sandbox's lifecycle deadlines.
   *
   * `timeoutMs` bounds the WHOLE call — the settle poll, a resume, and
   * the readiness wait share one deadline (default 60s). On expiry a
   * {@link TimeoutError} is thrown and the sandbox is left as it was.
   */
  async connect(
    id: string,
    opts: ConnectSandboxOptions = {},
  ): Promise<Sandbox> {
    // Fractional milliseconds round up; the rest of the range is
    // validated here so a bad knob surfaces as the SDK's typed error:
    // AbortSignal.timeout() throws a raw RangeError on non-integers and
    // negatives, NaN and NEGATIVE_INFINITY would silently disable the
    // bound, and Node clamps timer delays past 2^31 - 1 to 1ms.
    const timeoutMs = Math.ceil(opts.timeoutMs ?? CONNECT_TIMEOUT_MS);
    if (
      Number.isNaN(timeoutMs) ||
      timeoutMs <= 0 ||
      (Number.isFinite(timeoutMs) && timeoutMs > MAX_TIMEOUT_MS)
    ) {
      throw new InvalidArgumentError(
        "connect timeoutMs must be a positive number of milliseconds at " +
          "most 2**31 - 1 (Number.POSITIVE_INFINITY disables the bound)",
        {
          context: { timeoutMs: String(opts.timeoutMs) },
          operation: "sandbox.connect",
        },
      );
    }
    const timeoutLabel = String(timeoutMs);
    // One deadline over every wait below — the settle poll, resume, and
    // the readiness wait; bounding only one of them would be arbitrary
    // while the neighbouring waits stayed unbounded.
    const deadline = Number.isFinite(timeoutMs)
      ? AbortSignal.timeout(timeoutMs)
      : undefined;
    try {
      let info = await this.#client.inspect(
        { id },
        withSignal(unaryOptions(this.#ctx), deadline),
      );
      // A pausing sandbox's next stop is PAUSED — never READY — so
      // waiting on readiness events would park forever. Poll the
      // checkpoint out, then route on whatever state it settled in.
      while (info.state === SandboxStateProto.PAUSING) {
        // eslint-disable-next-line no-await-in-loop -- sequential by design: each re-inspect waits out the poll interval
        await sleep(PAUSE_SETTLE_POLL_MS, undefined, { signal: deadline });
        // eslint-disable-next-line no-await-in-loop -- sequential by design: the settled state decides the route
        info = await this.#client.inspect(
          { id },
          withSignal(unaryOptions(this.#ctx), deadline),
        );
      }
      switch (info.state) {
        case SandboxStateProto.READY:
        case SandboxStateProto.RUNNING:
          return new Sandbox(this.#ctx, id);
        case SandboxStateProto.PAUSED:
          // No per-request deadline of its own: restoring a checkpoint
          // takes as long as it takes, and the RPC returns once READY —
          // the overall connect deadline is the only bound.
          await this.#client.resume({ id }, withSignal({}, deadline));
          return new Sandbox(this.#ctx, id);
        case SandboxStateProto.STARTING: {
          const abort = new AbortController();
          try {
            const stream = this.#client.events(
              { sandboxId: id },
              {
                signal:
                  deadline === undefined
                    ? abort.signal
                    : AbortSignal.any([abort.signal, deadline]),
              },
            );
            const events = stream[Symbol.asyncIterator]();
            const first = events.next();
            first.catch(noop);
            await this.#waitReady(id, events, first, deadline);
          } finally {
            abort.abort();
          }
          return new Sandbox(this.#ctx, id);
        }
        default:
          throw new SandboxStateError(
            `sandbox ${id} is ${sandboxInfoFromProto(info).state} and cannot be connected to`,
            {
              context: {
                id,
                state: sandboxInfoFromProto(info).state,
                error: info.error,
              },
            },
          );
      }
    } catch (error) {
      // A failure observed after the deadline fired is the deadline
      // surfacing (an aborted RPC, wait, or event read) — unless the
      // SDK already typed it, in which case the state error stands.
      if (deadline?.aborted === true && !(error instanceof ArcBoxError)) {
        throw toArcBoxError(
          new TimeoutError(
            `connect(timeoutMs) elapsed before sandbox ${id} was ready`,
            {
              suggestion: "increase the connect timeoutMs option",
              context: { id, timeoutMs: timeoutLabel },
              cause: error,
            },
          ),
          "sandbox.connect",
        );
      }
      throw toArcBoxError(error, "sandbox.connect");
    }
  }

  /** List sandboxes, auto-paginating server-side pages. */
  async *list(opts: ListSandboxesOptions = {}): AsyncIterable<SandboxSummary> {
    try {
      let pageToken = "";
      do {
        // eslint-disable-next-line no-await-in-loop -- sequential by design: each request needs the previous page's token
        const page = await this.#client.list(
          {
            state:
              opts.state === undefined ? 0 : sandboxStateToProto(opts.state),
            labels: opts.labels ?? {},
            pageToken,
          },
          unaryOptions(this.#ctx),
        );
        yield* page.sandboxes.map(sandboxSummaryFromProto);
        pageToken = page.nextPageToken;
      } while (pageToken !== "");
    } catch (error) {
      throw toArcBoxError(error, "sandbox.list");
    }
  }

  /**
   * Consume lifecycle events until READY/RUNNING, or fail on a terminal
   * transition. The subscription was armed before Create, so nothing can
   * be missed; the one residual window — Create processed before the
   * subscription registered server-side — is covered by an immediate
   * Inspect and by re-inspecting on every keepalive frame.
   */
  async #waitReady(
    id: string,
    events: AsyncIterator<WatchEventsResponse>,
    firstEvent: Promise<IteratorResult<WatchEventsResponse>>,
    deadline?: AbortSignal,
  ): Promise<void> {
    const check = (state: SandboxStateProto, error: string): boolean => {
      switch (state) {
        case SandboxStateProto.READY:
        case SandboxStateProto.RUNNING:
          return true;
        case SandboxStateProto.FAILED:
          throw new SandboxStateError(
            `sandbox ${id} failed to start: ${error}`,
            {
              context: { id, state: "failed", error },
            },
          );
        case SandboxStateProto.STOPPING:
        case SandboxStateProto.STOPPED:
          throw new SandboxStateError(
            `sandbox ${id} stopped before becoming ready`,
            {
              context: { id, state: "stopped" },
            },
          );
        default:
          return false;
      }
    };
    const inspected = await this.#client.inspect(
      { id },
      withSignal(unaryOptions(this.#ctx), deadline),
    );
    if (check(inspected.state, inspected.error)) {
      return;
    }
    let next = firstEvent;
    for (;;) {
      // eslint-disable-next-line no-await-in-loop -- sequential by design: lifecycle events must be consumed in order
      const frame = await next;
      if (frame.done === true) {
        throw new ArcBoxError(
          `the event stream ended before sandbox ${id} became ready`,
          {
            context: { id },
          },
        );
      }
      const payload = frame.value.payload;
      if (payload.case === "event") {
        const event = payload.value;
        switch (event.kind) {
          case SandboxEventKind.READY:
          case SandboxEventKind.RUNNING:
          case SandboxEventKind.IDLE:
            return;
          case SandboxEventKind.FAILED:
            throw new SandboxStateError(
              `sandbox ${id} failed to start: ${event.attributes.error ?? ""}`,
              {
                context: {
                  id,
                  state: "failed",
                  error: event.attributes.error ?? "",
                },
              },
            );
          case SandboxEventKind.STOPPING:
          case SandboxEventKind.STOPPED:
          case SandboxEventKind.REMOVED:
            throw new SandboxStateError(
              `sandbox ${id} stopped before becoming ready`,
              {
                context: { id, state: "stopped" },
              },
            );
          default:
            break;
        }
      } else if (payload.case === "keepAlive") {
        // eslint-disable-next-line no-await-in-loop -- sequential by design: the re-inspect must resolve before reading further events
        const info = await this.#client.inspect(
          { id },
          withSignal(unaryOptions(this.#ctx), deadline),
        );
        if (check(info.state, info.error)) {
          return;
        }
      }
      next = events.next();
      next.catch(noop);
    }
  }
}

/**
 * A handle to one sandbox. Holds only the id and the connection — state
 * is never cached; {@link info} always fetches fresh.
 */
export class Sandbox {
  readonly id: string;
  /** Run processes inside the sandbox. */
  readonly commands: Commands;
  /** Move bytes in and out of the sandbox. */
  readonly files: Files;
  /** Network readiness of the sandbox. */
  readonly ports: Ports;

  readonly #ctx: ClientContext;
  readonly #client: SandboxClient;

  constructor(ctx: ClientContext, id: string) {
    this.#ctx = ctx;
    this.#client = createClient(SandboxService, ctx.transport);
    this.id = id;
    this.commands = new Commands(ctx, id);
    this.files = new Files(ctx, id);
    this.ports = new Ports(ctx, id);
  }

  /** Create a sandbox against the default (or given) connection. */
  static create(
    this: void,
    template = "",
    opts: CreateSandboxOptions = {},
  ): Promise<Sandbox> {
    return new ArcBox(opts.connection).create(template, opts);
  }

  /** Attach to an existing sandbox by id. */
  static connect(
    this: void,
    id: string,
    opts: ConnectSandboxOptions = {},
  ): Promise<Sandbox> {
    return new ArcBox(opts.connection).connect(id, opts);
  }

  /** List sandboxes (auto-paginating). */
  static list(
    this: void,
    opts: ListSandboxesOptions = {},
  ): AsyncIterable<SandboxSummary> {
    return new ArcBox(opts.connection).list(opts);
  }

  /** Fetch the sandbox's current state — always fresh, never cached. */
  async info(): Promise<SandboxInfo> {
    try {
      return sandboxInfoFromProto(
        await this.#client.inspect({ id: this.id }, unaryOptions(this.#ctx)),
      );
    } catch (error) {
      throw toArcBoxError(error, "sandbox.info");
    }
  }

  /** Destroy the sandbox and release all its resources immediately. */
  async kill(): Promise<void> {
    try {
      await this.#client.remove(
        { id: this.id, force: true },
        unaryOptions(this.#ctx),
      );
    } catch (error) {
      throw toArcBoxError(error, "sandbox.kill");
    }
  }

  /**
   * Checkpoint the sandbox to disk under the same id and release its
   * runtime resources. Resume happens on the next {@link Sandbox.connect}
   * (or transparently, daemon-side, on the next data-plane call). Trades
   * RAM for disk: a paused sandbox keeps paying `storageBytes`. Requires
   * a quiescent sandbox (READY — no running command).
   */
  async pause(): Promise<void> {
    try {
      // No per-request deadline: checkpointing takes as long as it takes.
      await this.#client.pause({ id: this.id });
    } catch (error) {
      throw toArcBoxError(error, "sandbox.pause");
    }
  }

  /**
   * Replace lifecycle deadlines. Each knob is tri-state (see
   * {@link LifecycleUpdate}): omitted = unchanged, `null` = restore the
   * daemon default, a value = replace. `ttlMs` re-arms the hard cap
   * from NOW; `idleTimeoutMs` re-arms a live idle timer. Works in any
   * non-terminal state, including paused.
   */
  async setLifecycle(update: LifecycleUpdate): Promise<void> {
    try {
      await this.#client.setLifecycle(
        {
          id: this.id,
          ...(update.ttlMs !== undefined && {
            ttlSeconds: update.ttlMs === null ? 0 : secondsFromMs(update.ttlMs),
          }),
          ...(update.idleTimeoutMs !== undefined && {
            idleTimeoutSeconds:
              update.idleTimeoutMs === null
                ? 0
                : secondsFromMs(update.idleTimeoutMs),
          }),
          ...(update.onIdle !== undefined && {
            onIdle:
              update.onIdle === null
                ? IdleAction.UNSPECIFIED
                : update.onIdle === "kill"
                  ? IdleAction.KILL
                  : IdleAction.PAUSE,
          }),
        },
        unaryOptions(this.#ctx),
      );
    } catch (error) {
      throw toArcBoxError(error, "sandbox.setLifecycle");
    }
  }

  /**
   * Subscribe to this sandbox's lifecycle events, yielded as typed
   * {@link SandboxEvent}s (keepalive frames are filtered out). The
   * iterator ends when the daemon ends the stream; breaking out of the
   * loop cancels the subscription. A transport drop mid-stream is
   * surfaced as {@link ConnectionLostError} — re-subscribing is the
   * caller's decision, since missed events cannot be replayed.
   */
  events(): AsyncIterable<SandboxEvent> {
    return this.#streamEvents();
  }

  async *#streamEvents(): AsyncGenerator<SandboxEvent> {
    let delivered = false;
    try {
      for await (const frame of this.#client.events({ sandboxId: this.id })) {
        delivered = true;
        if (frame.payload.case === "event") {
          yield sandboxEventFromProto(frame.payload.value);
        }
      }
    } catch (error) {
      const mapped = toArcBoxError(error, "sandbox.events");
      // A connection failure after frames flowed is a mid-stream drop
      // (the stream-death error); before any frame it is an unreachable
      // daemon, reported as such.
      if (
        delivered &&
        mapped instanceof ConnectionFailedError &&
        !(mapped instanceof ConnectionLostError)
      ) {
        throw new ConnectionLostError("the event stream died", {
          operation: "sandbox.events",
          cause: error,
          context: { id: this.id },
        });
      }
      throw mapped;
    }
  }

  /**
   * `await using` disposal: kill the sandbox, so a leaked handle never
   * leaks a VM. Swallows only "already gone" — the whole NotFoundError
   * family, because the daemon does not attach `ErrorInfo` details yet
   * and a coarse NotFound on this id can only mean the sandbox.
   */
  async [Symbol.asyncDispose](): Promise<void> {
    try {
      await this.kill();
    } catch (error) {
      if (!(error instanceof NotFoundError)) {
        throw error;
      }
    }
  }
}

function secondsFromMs(ms: number | undefined): number {
  return ms === undefined ? 0 : Math.ceil(ms / 1000);
}
