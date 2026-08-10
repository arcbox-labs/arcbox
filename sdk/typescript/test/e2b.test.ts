// The places where e2b's contract and ArcBox's disagree.
//
// Everything else is a rename the type checker already guards. These
// cover the behavioural inversions — throw-on-nonzero, push-callback
// output, the port model — plus the honest refusals.
//

import { create } from "@bufbuild/protobuf";
import { EmptySchema } from "@bufbuild/protobuf/wkt";
import type { Transport } from "@connectrpc/connect";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it, vi } from "vitest";

import { NotFoundError as ArcBoxNotFoundError } from "../src/errors";

import {
  ExecutionEventSchema,
  ExecutionSchema,
  ExecutionState,
  SandboxProcessService,
  StdioChannel,
} from "../src/gen/arcbox/sandbox/v1/process_pb";
import {
  ExposePortResponseSchema,
  SandboxInfoSchema,
  SandboxService,
  SandboxState as SandboxStateProto,
} from "../src/gen/arcbox/sandbox/v1/sandbox_pb";
import type {
  CreateSandboxRequest,
  SetLifecycleRequest,
} from "../src/gen/arcbox/sandbox/v1/sandbox_pb";
import {
  FileKind,
  FsEventKind,
  ListDirResponseSchema,
  SandboxFilesystemService,
  WatchDirResponseSchema,
} from "../src/gen/arcbox/sandbox/v1/filesystem_pb";

import {
  CommandExitError,
  NotFoundError,
  permissionString,
  Sandbox,
  SandboxError,
  UnsupportedError,
} from "../src/e2b/index";

/** A daemon answering just enough to exercise the shim. */
class MockDaemon {
  /** Exit code the one mock command reports. */
  exitCode = 0;
  /** Output the mock command replays, in order. */
  chunks: Array<[StdioChannel, string]> = [];
  /** Host port ExposePort allocates. */
  hostPort = 49152;
  /** Events the mock WatchDir stream replays. */
  watchFrames: Array<{ kind: FsEventKind; path: string }> = [];
  readonly creates: CreateSandboxRequest[] = [];
  readonly lifecycles: SetLifecycleRequest[] = [];
  readonly transport: Transport;

  constructor() {
    this.transport = createRouterTransport(({ service }) => {
      service(SandboxService, {
        create: (req) => {
          this.creates.push(req);
          return {};
        },
        inspect: () =>
          create(SandboxInfoSchema, {
            id: "sb-1",
            state: SandboxStateProto.READY,
            template: "base",
          }),
        setLifecycle: (req) => {
          this.lifecycles.push(req);
          return create(EmptySchema);
        },
        exposePort: () =>
          create(ExposePortResponseSchema, { hostPort: this.hostPort }),
        remove: () => create(EmptySchema),
        list: () => ({ sandboxes: [], nextPageToken: "" }),
      });
      service(SandboxProcessService, {
        startExecution: () => create(ExecutionSchema, { id: "cmd" }),
        waitExecution: () =>
          create(ExecutionSchema, {
            id: "cmd",
            state: ExecutionState.EXITED,
            exitStatus: { status: { case: "code", value: this.exitCode } },
          }),
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator; this one serves from memory
        attachExecution: async function* (this: MockDaemon) {
          const encoder = new TextEncoder();
          const next = new Map<StdioChannel, bigint>();
          for (const [channel, text] of this.chunks) {
            const offset = next.get(channel) ?? 0n;
            const data = encoder.encode(text);
            next.set(channel, offset + BigInt(data.byteLength));
            yield create(ExecutionEventSchema, {
              event: { case: "output", value: { channel, offset, data } },
            });
          }
          yield create(ExecutionEventSchema, {
            event: {
              case: "exited",
              value: {
                execution: create(ExecutionSchema, {
                  id: "cmd",
                  state: ExecutionState.EXITED,
                  exitStatus: {
                    status: { case: "code", value: this.exitCode },
                  },
                }),
              },
            },
          });
        }.bind(this),
      });
      service(SandboxFilesystemService, {
        listDir: () =>
          create(ListDirResponseSchema, {
            entries: [
              {
                name: "a.txt",
                kind: FileKind.FILE,
                size: 3n,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
              },
              { name: "sub", kind: FileKind.DIRECTORY, mode: 0o755 },
            ],
          }),
        stat() {
          throw new ConnectError("no such file", Code.NotFound);
        },
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator; this one serves from memory
        watchDir: async function* (this: MockDaemon) {
          for (const frame of this.watchFrames) {
            yield create(WatchDirResponseSchema, {
              payload: { case: "event", value: frame },
            });
          }
        }.bind(this),
      });
    });
  }

  sandbox(): Promise<Sandbox> {
    return Sandbox.connect("sb-1", {
      connection: { transport: this.transport },
    });
  }
}

describe("commands.run", () => {
  it("throws CommandExitError on a non-zero exit, unlike ArcBox", async () => {
    const daemon = new MockDaemon();
    daemon.exitCode = 3;
    const sandbox = await daemon.sandbox();

    const error = await sandbox.commands.run("false").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(CommandExitError);
    expect((error as CommandExitError).exitCode).toBe(3);
  });

  it("returns the result on a zero exit", async () => {
    const daemon = new MockDaemon();
    daemon.chunks = [[StdioChannel.STDOUT, "hi\n"]];
    const sandbox = await daemon.sandbox();

    const result = await sandbox.commands.run("echo hi");

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("hi\n");
  });

  it("pushes output into onStdout/onStderr rather than an iterator", async () => {
    const daemon = new MockDaemon();
    daemon.chunks = [
      [StdioChannel.STDOUT, "out"],
      [StdioChannel.STDERR, "err"],
    ];
    const sandbox = await daemon.sandbox();
    const out: string[] = [];
    const err: string[] = [];

    await sandbox.commands.run("echo", {
      onStdout(data) {
        out.push(data);
      },
      onStderr(data) {
        err.push(data);
      },
    });

    expect(out.join("")).toBe("out");
    expect(err.join("")).toBe("err");
  });
});

describe("ports", () => {
  it("resolves a host only after the port is exposed", async () => {
    const daemon = new MockDaemon();
    const sandbox = await daemon.sandbox();

    // e2b answers getHost synchronously for any port because its edge
    // proxy fronts them all; ArcBox forwards on request, so an
    // un-exposed port must fail loudly rather than return a dead host.
    expect(() => sandbox.getHost(8080)).toThrow(UnsupportedError);

    const host = await sandbox.exposePort(8080);

    expect(host).toBe("127.0.0.1:49152");
    expect(sandbox.getHost(8080)).toBe(host);
  });
});

describe("create", () => {
  it("translates e2b's names and treats 'base' as the built-in template", async () => {
    const daemon = new MockDaemon();

    await Sandbox.create("base", {
      timeoutMs: 60000,
      metadata: { app: "demo" },
      envs: { KEY: "value" },
      connection: { transport: daemon.transport },
    });

    const request = daemon.creates.at(-1);
    expect(request?.template).toBe("");
    expect(request?.ttlSeconds).toBe(60);
    expect(request?.labels).toEqual({ app: "demo" });
    expect(request?.env).toEqual({ KEY: "value" });
  });

  it("applies e2b's default timeout when none is given", async () => {
    const daemon = new MockDaemon();

    await Sandbox.create({ connection: { transport: daemon.transport } });

    expect(daemon.creates.at(-1)?.ttlSeconds).toBe(300);
  });
});

describe("list", () => {
  it("is awaitable AND paginator-shaped, for both e2b styles", async () => {
    const daemon = new MockDaemon();

    // v1 style: await the listing directly.
    const rows = await Sandbox.list({
      connection: { transport: daemon.transport },
    });
    expect(rows).toEqual([]);

    // v2 style: hold the paginator, page through it.
    const paginator = Sandbox.list({
      connection: { transport: daemon.transport },
    });
    expect(paginator.hasNext).toBe(true);
    expect(await paginator.nextItems()).toEqual([]);
    expect(paginator.hasNext).toBe(false);
    expect(await paginator.nextItems()).toEqual([]);
  });
});

describe("setTimeout", () => {
  it("re-arms only the ttl, leaving the idle knobs alone", async () => {
    const daemon = new MockDaemon();
    const sandbox = await daemon.sandbox();

    await sandbox.setTimeout(120000);

    const request = daemon.lifecycles.at(-1);
    expect(request?.ttlSeconds).toBe(120);
    expect(request?.idleTimeoutSeconds).toBeUndefined();
  });
});

describe("files", () => {
  it("reports e2b's entry shape, including the ls-style permissions", async () => {
    const daemon = new MockDaemon();
    const sandbox = await daemon.sandbox();

    const entries = await sandbox.files.list("/tmp");

    expect(entries[0]).toMatchObject({
      name: "a.txt",
      path: "/tmp/a.txt",
      type: "file",
      permissions: "-rw-r--r--",
      owner: "1000",
    });
    expect(entries[1]).toMatchObject({
      type: "dir",
      permissions: "drwxr-xr-x",
    });
  });

  it("watchDir pushes e2b-shaped events with dir-relative names", async () => {
    const daemon = new MockDaemon();
    daemon.watchFrames = [
      { kind: FsEventKind.CREATED, path: "/tmp/w/a.bin" },
      { kind: FsEventKind.MODIFIED, path: "/tmp/w/a.bin" },
      { kind: FsEventKind.RENAMED, path: "/tmp/w/a.bin" },
      { kind: FsEventKind.REMOVED, path: "/tmp/w/a.bin" },
    ];
    const sandbox = await daemon.sandbox();
    const seen: Array<[string, string]> = [];
    let ended = false;

    const watch = await sandbox.files.watchDir(
      "/tmp/w",
      (event) => {
        seen.push([event.type, event.name]);
      },
      {
        onExit() {
          ended = true;
        },
      },
    );
    await vi.waitFor(() => {
      expect(ended).toBe(true);
    });
    await watch.stop();

    expect(seen).toEqual([
      ["create", "a.bin"],
      ["write", "a.bin"],
      ["rename", "a.bin"],
      ["remove", "a.bin"],
    ]);
  });
});

describe("permissionString", () => {
  it("renders the usual bit patterns", () => {
    expect(permissionString(0o644, false)).toBe("-rw-r--r--");
    expect(permissionString(0o755, true)).toBe("drwxr-xr-x");
    expect(permissionString(0o000, false)).toBe("----------");
    expect(permissionString(0o777, false)).toBe("-rwxrwxrwx");
  });
});

describe("errors", () => {
  it("aliases the classes so an ArcBox error matches an e2b catch", () => {
    // A fresh `class NotFoundError extends ArcBoxError` would sit beside
    // what the SDK throws and never match it.
    const thrown = new ArcBoxNotFoundError("gone");

    expect(thrown).toBeInstanceOf(NotFoundError);
    expect(thrown).toBeInstanceOf(SandboxError);
  });

  it("names the unsupported surface instead of failing quietly", async () => {
    const daemon = new MockDaemon();
    const sandbox = await daemon.sandbox();

    const calls = [
      () => sandbox.fork(),
      () => sandbox.getMetrics(),
      () => sandbox.uploadUrl(),
      () => sandbox.downloadUrl(),
      () => sandbox.getMcpUrl(),
      () => sandbox.createSnapshot(),
      () => sandbox.git.dangerouslyAuthenticate(),
    ];

    for (const call of calls) {
      expect(call).toThrow(UnsupportedError);
    }
  });
});
