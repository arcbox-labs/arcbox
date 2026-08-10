/** `e2b`'s `Sandbox`, backed by `@arcbox/sandbox`. */

import type {
  ConnectionOptions,
  Sandbox as ArcBoxSandbox,
  SandboxState,
} from "../index";
import { ArcBox, NotFoundError } from "../index";

import { Commands, Pty } from "./commands";
import { unsupported } from "./errors";
import { Filesystem } from "./filesystem";
import { Git } from "./git";

/** `e2b`'s default sandbox timeout. */
export const DEFAULT_SANDBOX_TIMEOUT_MS = 300000;

/**
 * Connection options.
 *
 * The E2B cloud knobs (`apiKey`, `domain`, `accessToken`, …) are
 * accepted and ignored — a local daemon authenticates by socket
 * permissions — so an app that reads `E2B_API_KEY` from its environment
 * keeps working unchanged. `connection` is the ArcBox escape hatch.
 */
export interface ConnectionOpts {
  apiKey?: string;
  accessToken?: string;
  domain?: string;
  apiUrl?: string;
  debug?: boolean;
  requestTimeoutMs?: number;
  headers?: Record<string, string>;
  /** ArcBox connection override; no `e2b` counterpart. */
  connection?: ConnectionOptions;
}

/** Options for {@link Sandbox.create}. */
export interface SandboxOpts extends ConnectionOpts {
  /** Template name; `''` and `'base'` both mean the built-in minimal one. */
  template?: string;
  /** Arbitrary metadata — ArcBox calls these labels. */
  metadata?: Record<string, string>;
  /** Environment for the sandbox's initial command. */
  envs?: Record<string, string>;
  /** Hard maximum lifetime. */
  timeoutMs?: number;
  /** `false` disables networking entirely. */
  allowInternetAccess?: boolean;
}

/** Options for {@link Sandbox.connect}. */
export type SandboxConnectOpts = ConnectionOpts & { timeoutMs?: number };

/** Options for {@link Sandbox.list}. */
export interface SandboxListOpts extends ConnectionOpts {
  query?: { metadata?: Record<string, string>; state?: SandboxState[] };
}

/** One row of a sandbox listing, in `e2b`'s shape. */
export interface SandboxInfo {
  sandboxId: string;
  templateId: string;
  name?: string;
  metadata: Record<string, string>;
  startedAt?: Date;
  endAt?: Date;
  state: SandboxState;
}

/**
 * What {@link Sandbox.list} returns: both of `e2b`'s listing shapes at
 * once. Awaiting it yields the whole listing (the daemon streams every
 * page already); calling {@link nextItems} pages e2b-style — one page,
 * carrying that same complete listing.
 */
export class SandboxPaginator implements PromiseLike<SandboxInfo[]> {
  readonly #all: Promise<SandboxInfo[]>;
  #consumed = false;

  constructor(all: Promise<SandboxInfo[]>) {
    this.#all = all;
  }

  /** Whether {@link nextItems} has a page left (exactly one, the whole listing). */
  get hasNext(): boolean {
    return !this.#consumed;
  }

  /** The next page: the complete listing first, `[]` from then on. */
  async nextItems(): Promise<SandboxInfo[]> {
    if (this.#consumed) {
      return [];
    }
    this.#consumed = true;
    return this.#all;
  }

  // eslint-disable-next-line sukka/unicorn/no-thenable -- deliberate: e2b v1 code awaits list() while v2 code holds the paginator; PromiseLike is the one shape that serves both
  then<TResult1 = SandboxInfo[], TResult2 = never>(
    onfulfilled?:
      | ((value: SandboxInfo[]) => TResult1 | PromiseLike<TResult1>)
      | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): PromiseLike<TResult1 | TResult2> {
    // eslint-disable-next-line promise/prefer-catch -- not a consumer call: this IS the PromiseLike implementation, forwarding both callbacks
    return this.#all.then(onfulfilled, onrejected);
  }
}

/**
 * `e2b`'s cloud sandbox, served by the local ArcBox daemon.
 *
 * The shape follows `e2b` deliberately, including the parts that read
 * oddly here: `sandboxId` rather than `id`, milliseconds everywhere,
 * `metadata` rather than `labels`, and `run()` throwing on a non-zero
 * exit. Divergences are documented on the members that carry them —
 * `getHost` most of all.
 */
export class Sandbox {
  /** Unique identifier of the sandbox. */
  readonly sandboxId: string;
  /** Interact with the sandbox filesystem. */
  readonly files: Filesystem;
  /** Run commands in the sandbox. */
  readonly commands: Commands;
  /** Drive pseudo-terminals in the sandbox. */
  readonly pty: Pty;
  /** Run git operations in the sandbox. */
  readonly git: Git;

  readonly #client: ArcBox;
  readonly #sandbox: ArcBoxSandbox;
  /** Host ports resolved by {@link exposePort}, keyed by sandbox port. */
  readonly #hosts = new Map<number, string>();

  constructor(client: ArcBox, sandbox: ArcBoxSandbox) {
    this.#client = client;
    this.#sandbox = sandbox;
    this.sandboxId = sandbox.id;
    this.files = new Filesystem(sandbox.files);
    this.commands = new Commands(sandbox.commands);
    this.pty = new Pty(sandbox.commands);
    this.git = new Git(this.commands);
  }

  /** Create a sandbox from a template. */
  static async create(this: void, opts?: SandboxOpts): Promise<Sandbox>;
  static async create(
    this: void,
    template: string,
    opts?: SandboxOpts,
  ): Promise<Sandbox>;
  static async create(
    this: void,
    templateOrOpts?: string | SandboxOpts,
    maybeOpts?: SandboxOpts,
  ): Promise<Sandbox> {
    const opts =
      (typeof templateOrOpts === "string" ? maybeOpts : templateOrOpts) ?? {};
    const template =
      typeof templateOrOpts === "string" ? templateOrOpts : opts.template;
    const client = new ArcBox(opts.connection);
    const sandbox = await client.create(normalizeTemplate(template), {
      ttlMs: opts.timeoutMs ?? DEFAULT_SANDBOX_TIMEOUT_MS,
      ...(opts.metadata !== undefined && { labels: opts.metadata }),
      ...(opts.envs !== undefined && { env: opts.envs }),
      ...(opts.allowInternetAccess !== undefined && {
        network: opts.allowInternetAccess,
      }),
    });
    return new Sandbox(client, sandbox);
  }

  /** Attach to an existing sandbox, resuming it when paused. */
  static async connect(
    this: void,
    sandboxId: string,
    opts: SandboxConnectOpts = {},
  ): Promise<Sandbox> {
    const client = new ArcBox(opts.connection);
    const sandbox = await client.connect(sandboxId);
    const handle = new Sandbox(client, sandbox);
    if (opts.timeoutMs !== undefined) {
      await handle.setTimeout(opts.timeoutMs);
    }
    return handle;
  }

  /**
   * List sandboxes, as a {@link SandboxPaginator} that is also
   * awaitable: `await Sandbox.list()` yields the whole listing, and
   * `Sandbox.list().nextItems()` pages e2b-style (one page carrying
   * that same complete listing — the daemon streams every page
   * already).
   */
  static list(this: void, opts: SandboxListOpts = {}): SandboxPaginator {
    const collect = async (): Promise<SandboxInfo[]> => {
      const client = new ArcBox(opts.connection);
      const wanted = opts.query?.state;
      const rows: SandboxInfo[] = [];
      for await (const summary of client.list({
        ...(opts.query?.metadata !== undefined && {
          labels: opts.query.metadata,
        }),
      })) {
        if (wanted !== undefined && !wanted.includes(summary.state)) {
          continue;
        }
        const row: SandboxInfo = {
          sandboxId: summary.id,
          templateId: "",
          metadata: summary.labels,
          state: summary.state,
        };
        if (summary.createdAt !== undefined) {
          row.startedAt = summary.createdAt;
        }
        rows.push(row);
      }
      return rows;
    };
    return new SandboxPaginator(collect());
  }

  /** Kill a sandbox by id. Resolves `false` when it was already gone. */
  static async kill(
    this: void,
    sandboxId: string,
    opts: ConnectionOpts = {},
  ): Promise<boolean> {
    try {
      await (await new ArcBox(opts.connection).connect(sandboxId)).kill();
      return true;
    } catch (error) {
      if (error instanceof NotFoundError) {
        return false;
      }
      throw error;
    }
  }

  /** Extend a sandbox's lifetime by id. */
  static async setTimeout(
    this: void,
    sandboxId: string,
    timeoutMs: number,
    opts: ConnectionOpts = {},
  ): Promise<void> {
    const sandbox = await new ArcBox(opts.connection).connect(sandboxId);
    await sandbox.setLifecycle({ ttlMs: timeoutMs });
  }

  /**
   * Whether the sandbox is running.
   *
   * `false` covers a missing sandbox too, matching `e2b`, where a killed
   * sandbox reports not-running rather than raising.
   */
  async isRunning(): Promise<boolean> {
    try {
      const info = await this.#sandbox.info();
      return info.state === "ready" || info.state === "running";
    } catch (error) {
      if (error instanceof NotFoundError) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Re-arm the sandbox's lifetime, measured from now.
   *
   * `e2b` only ever extends; ArcBox replaces, so a shorter value here
   * genuinely shortens the sandbox's life.
   */
  async setTimeout(timeoutMs: number): Promise<void> {
    await this.#sandbox.setLifecycle({ ttlMs: timeoutMs });
  }

  /** Kill the sandbox. Resolves `false` when it was already gone. */
  async kill(): Promise<boolean> {
    try {
      await this.#sandbox.kill();
      return true;
    } catch (error) {
      if (error instanceof NotFoundError) {
        return false;
      }
      throw error;
    }
  }

  /** Pause the sandbox, checkpointing it under the same id. */
  async pause(): Promise<boolean> {
    await this.#sandbox.pause();
    return true;
  }

  /** Deprecated `e2b` alias for {@link pause}. */
  async betaPause(): Promise<boolean> {
    return this.pause();
  }

  /**
   * Resume the sandbox and return this handle.
   *
   * Routed through the entry point's connect, which settles a pausing
   * checkpoint, resumes a paused one, and waits out a starting boot.
   */
  async connect(): Promise<this> {
    await this.#client.connect(this.sandboxId);
    return this;
  }

  /** Current state of the sandbox, in `e2b`'s shape. */
  async getInfo(): Promise<SandboxInfo> {
    const info = await this.#sandbox.info();
    const out: SandboxInfo = {
      sandboxId: info.id,
      templateId: info.template,
      metadata: info.labels,
      state: info.state,
    };
    if (info.createdAt !== undefined) {
      out.startedAt = info.createdAt;
    }
    if (info.ttlDeadline !== undefined) {
      out.endAt = info.ttlDeadline;
    }
    return out;
  }

  /**
   * Publish a sandbox port onto the host and return its `host:port`.
   *
   * The one real divergence from `e2b`, which serves every sandbox port
   * through an edge proxy at `{port}-{id}.e2b.app` and so can answer
   * synchronously without being told. ArcBox forwards a port only once
   * it is asked to, which is what this awaits.
   */
  async exposePort(port: number): Promise<string> {
    const exposed = await this.#sandbox.ports.expose(port);
    const host = `127.0.0.1:${String(exposed.hostPort)}`;
    this.#hosts.set(port, host);
    return host;
  }

  /** Withdraw a port published by {@link exposePort}. */
  async unexposePort(port: number): Promise<void> {
    await this.#sandbox.ports.unexpose(port);
    this.#hosts.delete(port);
  }

  /**
   * `host:port` for a port already published by {@link exposePort}.
   *
   * Synchronous, like `e2b`'s — but a port this handle has not exposed
   * throws instead of returning a plausible address that nothing is
   * listening on.
   */
  getHost(port: number): string {
    const host = this.#hosts.get(port);
    if (host === undefined) {
      unsupported(
        "getHost",
        `port ${String(port)} is not published — await sandbox.exposePort(${String(port)}) first, since ArcBox forwards ports on request rather than through an edge proxy`,
      );
    }
    return host;
  }

  /** Unsupported: cloud snapshots that outlive their sandbox. */
  createSnapshot(): never {
    unsupported(
      "createSnapshot",
      "ArcBox snapshots are local; use @arcbox/sandbox's checkpoint()/restore() directly",
    );
  }

  /** Unsupported: forking needs the cloud's copy-on-write sandbox pool. */
  fork(): never {
    unsupported("fork", "no local equivalent");
  }

  /** Unsupported: per-sandbox metrics are a cloud service. */
  getMetrics(): never {
    unsupported("getMetrics", "no local equivalent");
  }

  /** Unsupported: signed URLs are served by the E2B edge. */
  uploadUrl(): never {
    unsupported("uploadUrl", "use files.write instead");
  }

  /** Unsupported: signed URLs are served by the E2B edge. */
  downloadUrl(): never {
    unsupported("downloadUrl", "use files.read instead");
  }

  /** Unsupported: the MCP gateway is a cloud service. */
  getMcpUrl(): never {
    unsupported("getMcpUrl", "no local equivalent");
  }
}

/**
 * `e2b`'s default template is `'base'`; ArcBox spells its built-in
 * minimal template `''`, so the two names converge here rather than
 * failing to resolve a template nobody published.
 */
function normalizeTemplate(template: string | undefined): string {
  return template === undefined || template === "base" ? "" : template;
}
