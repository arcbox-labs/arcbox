import type { Client } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";
import { noop } from "foxts/noop";

import { Commands } from "./commands.js";
import type { ConnectionOptions } from "./connection.js";
import {
  ArcBoxError,
  NotFoundError,
  SandboxStateError,
  toArcBoxError,
} from "./errors.js";
import { Files } from "./files.js";
import type { WatchEventsResponse } from "./gen/arcbox/sandbox/v1/sandbox_pb.js";
import {
  IdleAction,
  NetworkMode,
  SandboxEventKind,
  SandboxService,
  SandboxState as SandboxStateProto,
} from "./gen/arcbox/sandbox/v1/sandbox_pb.js";
import type { ClientContext } from "./transport.js";
import { createClientContext, unaryOptions } from "./transport.js";
import type { SandboxInfo, SandboxState, SandboxSummary } from "./types.js";
import {
  sandboxInfoFromProto,
  sandboxStateToProto,
  sandboxSummaryFromProto,
} from "./types.js";

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

type SandboxClient = Client<typeof SandboxService>;

/**
 * Client entry point. Holds one resolved connection; every handle it
 * creates shares it. The {@link Sandbox} statics are sugar over a
 * throwaway `ArcBox` resolved from options/environment.
 */
export class ArcBox {
  readonly #ctx: ClientContext;
  readonly #client: SandboxClient;

  constructor(options: ConnectionOptions = {}) {
    this.#ctx = createClientContext(options);
    this.#client = createClient(SandboxService, this.#ctx.transport);
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
   * completes once it is READY again); a STARTING one is waited for. A
   * terminal state is a typed error carrying the observed state.
   * Connecting never touches the sandbox's lifecycle deadlines.
   */
  async connect(id: string): Promise<Sandbox> {
    try {
      const info = await this.#client.inspect({ id }, unaryOptions(this.#ctx));
      switch (info.state) {
        case SandboxStateProto.READY:
        case SandboxStateProto.RUNNING:
          return new Sandbox(this.#ctx, id);
        case SandboxStateProto.PAUSED:
          // Deliberately no per-request deadline: restoring a checkpoint
          // takes as long as it takes, and the RPC returns once READY.
          await this.#client.resume({ id });
          return new Sandbox(this.#ctx, id);
        case SandboxStateProto.STARTING:
        case SandboxStateProto.PAUSING: {
          const abort = new AbortController();
          try {
            const stream = this.#client.events(
              { sandboxId: id },
              { signal: abort.signal },
            );
            const events = stream[Symbol.asyncIterator]();
            const first = events.next();
            first.catch(noop);
            await this.#waitReady(id, events, first);
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
      unaryOptions(this.#ctx),
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
          unaryOptions(this.#ctx),
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

  readonly #ctx: ClientContext;
  readonly #client: SandboxClient;

  constructor(ctx: ClientContext, id: string) {
    this.#ctx = ctx;
    this.#client = createClient(SandboxService, ctx.transport);
    this.id = id;
    this.commands = new Commands(ctx, id);
    this.files = new Files(ctx, id);
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
    return new ArcBox(opts.connection).connect(id);
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
   * RAM for disk: a paused sandbox keeps paying `storageBytes`.
   *
   * Requires daemon-side CORE-21: the current local daemon serves
   * Pause/Resume as contract-only stubs, so this rejects with an
   * Unimplemented {@link ArcBoxError} until that lands.
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
