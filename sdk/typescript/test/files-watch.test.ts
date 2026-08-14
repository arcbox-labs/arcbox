// files.watch() against a mock daemon.
//
// The contracts under test: typed FsEvent mapping with rename pairing,
// keepalive filtering, the clean server-side end (the daemon's
// SandboxFileWatchEnd) terminating the iterator, the overflow error
// surfacing with its re-list-and-re-watch guidance (never retried,
// never reshaped into a connection error), and a mid-stream transport
// drop becoming ConnectionLostError — watch events cannot be replayed,
// so the SDK never auto-reconnects.

import { create } from "@bufbuild/protobuf";
import type { Transport } from "@connectrpc/connect";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import {
  ArcBoxError,
  ConnectionFailedError,
  ConnectionLostError,
} from "../src/errors";
import type { WatchDirRequest } from "../src/gen/arcbox/sandbox/v1/filesystem_pb";
import {
  FsEventKind,
  SandboxFilesystemService,
  WatchDirResponseSchema,
} from "../src/gen/arcbox/sandbox/v1/filesystem_pb";
import { Files } from "../src/files";

function eventFrame(kind: FsEventKind, path: string, renamedTo = "") {
  return create(WatchDirResponseSchema, {
    payload: { case: "event", value: { kind, path, renamedTo } },
  });
}

const keepAlive = create(WatchDirResponseSchema, {
  payload: { case: "keepAlive", value: {} },
});

function filesOn(transport: Transport): Files {
  return new Files({ transport }, "sb-1");
}

describe("files.watch", () => {
  it("yields typed events, pairs renames, and filters keepalives; a clean end ends the loop", async () => {
    let seen: WatchDirRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator
        async *watchDir(req) {
          seen = req;
          yield keepAlive; // the establishment confirmation
          yield eventFrame(FsEventKind.CREATED, "/tmp/w/a.bin");
          yield eventFrame(FsEventKind.MODIFIED, "/tmp/w/a.bin");
          yield keepAlive;
          yield eventFrame(FsEventKind.RENAMED, "/tmp/w/a.bin", "/tmp/w/b.bin");
          yield eventFrame(FsEventKind.REMOVED, "/tmp/w/b.bin");
          // Generator end = the daemon's clean SandboxFileWatchEnd.
        },
      });
    });
    const events = [];
    for await (const event of filesOn(mock).watch("/tmp/w", {
      recursive: true,
    })) {
      events.push(event);
    }
    expect(seen?.id).toBe("sb-1");
    expect(seen?.path).toBe("/tmp/w");
    expect(seen?.recursive).toBe(true);
    expect(events).toEqual([
      { kind: "created", path: "/tmp/w/a.bin" },
      { kind: "modified", path: "/tmp/w/a.bin" },
      { kind: "renamed", path: "/tmp/w/a.bin", renamedTo: "/tmp/w/b.bin" },
      { kind: "removed", path: "/tmp/w/b.bin" },
    ]);
  });

  it('a kind this SDK predates maps to "unknown"', async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator
        async *watchDir() {
          yield eventFrame(99 as FsEventKind, "/tmp/w/x");
        },
      });
    });
    const events = [];
    for await (const event of filesOn(mock).watch("/tmp/w")) {
      events.push(event);
    }
    expect(events).toEqual([{ kind: "unknown", path: "/tmp/w/x" }]);
  });

  it("the overflow error surfaces with its rescan guidance, not as a connection error", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator
        async *watchDir() {
          yield eventFrame(FsEventKind.CREATED, "/tmp/w/a");
          // The daemon's documented overflow shape: the guest fails the
          // stream rather than silently streaming a wrong view.
          throw new ConnectError(
            "watch overflowed: the kernel dropped events; re-list and re-watch",
            Code.Internal,
          );
        },
      });
    });
    const consume = async () => {
      for await (const event of filesOn(mock).watch("/tmp/w")) {
        void event;
      }
    };
    const failing = consume();
    await expect(failing).rejects.toBeInstanceOf(ArcBoxError);
    await expect(failing).rejects.not.toBeInstanceOf(ConnectionFailedError);
    await expect(failing).rejects.toThrow("re-list and re-watch");
  });

  it("a drop after frames flowed is the stream-death error", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator
        async *watchDir() {
          yield keepAlive;
          throw new ConnectError("stream reset", Code.Unavailable);
        },
      });
    });
    const consume = async () => {
      for await (const event of filesOn(mock).watch("/tmp/w")) {
        void event;
      }
    };
    await expect(consume()).rejects.toBeInstanceOf(ConnectionLostError);
  });

  it("a dial failure before any frame stays an unreachable-daemon error", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        // eslint-disable-next-line @typescript-eslint/require-await, require-yield -- a server-streaming handler is an async generator; this one only fails
        async *watchDir() {
          throw new ConnectError("daemon gone", Code.Unavailable);
        },
      });
    });
    const consume = async () => {
      for await (const event of filesOn(mock).watch("/tmp/w")) {
        void event;
      }
    };
    const failing = consume();
    await expect(failing).rejects.toBeInstanceOf(ConnectionFailedError);
    await expect(failing).rejects.not.toBeInstanceOf(ConnectionLostError);
  });
});
