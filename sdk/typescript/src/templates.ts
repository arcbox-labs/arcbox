import type { Client } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";

import { toArcBoxError } from "./errors";
import type {
  Template as TemplateProto,
  TemplateDefaults as TemplateDefaultsProto,
} from "./gen/arcbox/sandbox/v1/template_pb";
import { TemplateService } from "./gen/arcbox/sandbox/v1/template_pb";
import type { ConnectionOptions } from "./connection";
import type { ClientContext } from "./transport";
import { createClientContext, unaryOptions } from "./transport";
import type { TemplateInfo } from "./types";
import { templateInfoFromProto } from "./types";

type TemplateClient = Client<typeof TemplateService>;

/**
 * What to build a template's rootfs from — exactly one source.
 *
 * - `docker`: a local Docker image reference, converted in-guest.
 * - `dockerfile`: inline Dockerfile content, built in-guest; the build
 *   context holds only the Dockerfile, so `COPY`/`ADD` of local paths fails.
 * - `snapshot`: promote an existing checkpoint — it becomes the template's
 *   warm start point (`prewarm` is ignored for this source).
 */
export type TemplateSource =
  | { docker: string }
  | { dockerfile: string }
  | { snapshot: string };

/** Default configuration a template applies to sandboxes created from it. */
export interface TemplateDefaults {
  /** Default vCPUs (omit = daemon default). */
  vcpus?: number;
  /** Default memory in MiB (omit = daemon default). */
  memoryMib?: number;
  /** Default initial command. */
  cmd?: string[];
  /** Default environment for the initial command. */
  env?: Record<string, string>;
  /** Advisory: ports the workload is expected to listen on. */
  exposedPorts?: number[];
  /** Gate READY on a TCP listener or a command exiting 0. */
  readyProbe?: ReadyProbe;
}

/** Readiness probe run inside a sandbox after boot. */
export type ReadyProbe =
  | { port: number; timeoutSeconds?: number }
  | { command: string[]; timeoutSeconds?: number };

/** Options for {@link Template.build}. */
export interface BuildTemplateOptions {
  defaults?: TemplateDefaults;
  labels?: Record<string, string>;
  /**
   * Also boot the built rootfs once and checkpoint it at READY, so creates
   * restore the snapshot for sub-second starts. Ignored for snapshot
   * sources (warm by construction).
   */
  prewarm?: boolean;
  connection?: ConnectionOptions;
}

/** Options carrying only a connection override. */
export interface TemplateConnectOptions {
  connection?: ConnectionOptions;
}

/** Options for {@link Template.list}. */
export interface ListTemplatesOptions {
  /** Keep only templates carrying all of these labels. */
  labels?: Record<string, string>;
  connection?: ConnectionOptions;
}

function templateClient(connection?: ConnectionOptions): {
  ctx: ClientContext;
  client: TemplateClient;
} {
  const ctx = createClientContext(connection ?? {});
  return { ctx, client: createClient(TemplateService, ctx.transport) };
}

function defaultsToProto(defaults?: TemplateDefaults): {
  limits?: { vcpus: number; memoryMib: bigint };
  cmd: string[];
  env: Record<string, string>;
  exposedPorts: number[];
  readyProbe?: TemplateDefaultsProto["readyProbe"];
} {
  const probe = defaults?.readyProbe;
  return {
    ...((defaults?.vcpus !== undefined ||
      defaults?.memoryMib !== undefined) && {
      limits: {
        vcpus: defaults.vcpus ?? 0,
        memoryMib: BigInt(defaults.memoryMib ?? 0),
      },
    }),
    cmd: defaults?.cmd ?? [],
    env: defaults?.env ?? {},
    exposedPorts: defaults?.exposedPorts ?? [],
    ...(probe !== undefined && {
      readyProbe: {
        timeoutSeconds: probe.timeoutSeconds ?? 0,
        probe:
          "port" in probe
            ? { case: "port" as const, value: probe.port }
            : {
                case: "command" as const,
                value: { cmd: probe.command },
              },
      } as TemplateDefaultsProto["readyProbe"],
    }),
  };
}

/**
 * A catalog template: a named, versioned, reproducible sandbox base.
 *
 * `Sandbox.create` accepts an instance directly; the reference it pins is
 * `name:version` for published versions and the bare name for drafts.
 */
export class Template {
  readonly #ctx: ClientContext;
  readonly #client: TemplateClient;
  /** Template name, unique in the catalog. */
  readonly name: string;
  /** Published version ("" = unpublished draft). */
  readonly version: string;
  /** Content digest pinning this version's artifacts. */
  readonly digest: string;
  /** Full catalog row. */
  readonly info: TemplateInfo;

  private constructor(
    ctx: ClientContext,
    client: TemplateClient,
    proto: TemplateProto,
  ) {
    this.#ctx = ctx;
    this.#client = client;
    this.info = templateInfoFromProto(proto);
    this.name = this.info.name;
    this.version = this.info.version;
    this.digest = this.info.digest;
  }

  /** The `name[:version]` reference this instance addresses. */
  get reference(): string {
    return this.version === "" ? this.name : `${this.name}:${this.version}`;
  }

  /**
   * Build a template from a source and register it as the catalog draft.
   * Blocks until the build completes (image export, rootfs conversion, and
   * the optional prewarm boot) — no client timeout is applied.
   */
  static async build(
    this: void,
    name: string,
    source: TemplateSource,
    opts: BuildTemplateOptions = {},
  ): Promise<Template> {
    const { ctx, client } = templateClient(opts.connection);
    try {
      const proto = await client.build({
        name,
        source:
          "docker" in source
            ? { case: "dockerRef", value: source.docker }
            : "dockerfile" in source
              ? { case: "dockerfile", value: source.dockerfile }
              : { case: "snapshotId", value: source.snapshot },
        defaults: defaultsToProto(opts.defaults),
        labels: opts.labels ?? {},
        prewarm: opts.prewarm ?? false,
      });
      return new Template(ctx, client, proto);
    } catch (error) {
      throw toArcBoxError(error, "templates.build");
    }
  }

  /** Resolve a `name[:version]` reference (bare name = newest published, else draft). */
  static async get(
    this: void,
    reference: string,
    opts: TemplateConnectOptions = {},
  ): Promise<Template> {
    const { ctx, client } = templateClient(opts.connection);
    try {
      const proto = await client.get({ reference }, unaryOptions(ctx));
      return new Template(ctx, client, proto);
    } catch (error) {
      throw toArcBoxError(error, "templates.get");
    }
  }

  /** List catalog templates — one row per version, drafts included (auto-paginating). */
  static async *list(
    this: void,
    opts: ListTemplatesOptions = {},
  ): AsyncIterable<TemplateInfo> {
    const { ctx, client } = templateClient(opts.connection);
    try {
      let pageToken = "";
      do {
        // eslint-disable-next-line no-await-in-loop -- sequential by design: each request needs the previous page's token
        const page = await client.list(
          { labels: opts.labels ?? {}, pageToken },
          unaryOptions(ctx),
        );
        yield* page.templates.map(templateInfoFromProto);
        pageToken = page.nextPageToken;
      } while (pageToken !== "");
    } catch (error) {
      throw toArcBoxError(error, "templates.list");
    }
  }

  /**
   * Delete by reference: a bare `name` drops the template with every
   * version and its on-disk artifacts; `name:version` drops one version.
   * Sandboxes already created from it are unaffected.
   */
  static async delete(
    this: void,
    reference: string,
    opts: TemplateConnectOptions = {},
  ): Promise<void> {
    const { ctx, client } = templateClient(opts.connection);
    try {
      await client.delete({ reference }, unaryOptions(ctx));
    } catch (error) {
      throw toArcBoxError(error, "templates.delete");
    }
  }

  /** Freeze the current draft as immutable `version` and return it. */
  async publish(version: string): Promise<Template> {
    try {
      const proto = await this.#client.publish(
        { name: this.name, version },
        unaryOptions(this.#ctx),
      );
      return new Template(this.#ctx, this.#client, proto);
    } catch (error) {
      throw toArcBoxError(error, "templates.publish");
    }
  }

  /** Delete this exact version (or the whole template for a draft handle). */
  async delete(): Promise<void> {
    try {
      await this.#client.delete(
        { reference: this.reference },
        unaryOptions(this.#ctx),
      );
    } catch (error) {
      throw toArcBoxError(error, "templates.delete");
    }
  }
}
