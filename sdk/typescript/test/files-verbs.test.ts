// The filesystem path verbs against a mock daemon.
//
// The contracts under test: DTO mapping (wire FileStat → numbers/Date,
// kind names, absent-field elision), the exact request fields each verb
// sends (mode 0 = daemon default, the recursive flag, from/to), and the
// registry-typed errors the daemon documents — FILE_NOT_FOUND with the
// path in context, FAILED_PRECONDITION for a non-recursive remove of a
// non-empty directory.

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import type { Transport } from "@connectrpc/connect";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { FileNotFoundError, SandboxStateError } from "../src/errors";
import {
  ErrorCode,
  ErrorInfoSchema,
} from "../src/gen/arcbox/sandbox/v1/errors_pb";
import type {
  ListDirRequest,
  MakeDirRequest,
  MoveEntryRequest,
  RemoveEntryRequest,
  StatFileRequest,
} from "../src/gen/arcbox/sandbox/v1/filesystem_pb";
import {
  FileKind,
  FileStatSchema,
  ListDirResponseSchema,
  SandboxFilesystemService,
} from "../src/gen/arcbox/sandbox/v1/filesystem_pb";
import { Files } from "../src/files";

const MODIFIED = new Date("2026-08-01T12:00:00Z");

const wireStat = create(FileStatSchema, {
  name: "a.bin",
  kind: FileKind.FILE,
  size: 18n,
  mode: 0o644,
  modifiedAt: timestampFromDate(MODIFIED),
  uid: 1000,
  gid: 1000,
});

function filesOn(transport: Transport): Files {
  return new Files({ transport }, "sb-1");
}

describe("files.stat", () => {
  it("maps the wire FileStat to numbers and Date", async () => {
    let seen: StatFileRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        stat(req) {
          seen = req;
          return wireStat;
        },
      });
    });
    const stat = await filesOn(mock).stat("/tmp/a.bin");
    expect(seen?.id).toBe("sb-1");
    expect(seen?.path).toBe("/tmp/a.bin");
    expect(stat).toEqual({
      name: "a.bin",
      kind: "file",
      size: 18,
      mode: 0o644,
      modifiedAt: MODIFIED,
      uid: 1000,
      gid: 1000,
    });
  });

  it("reports a symlink with its target, and elides absent fields", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        stat: () =>
          create(FileStatSchema, {
            name: "link",
            kind: FileKind.SYMLINK,
            symlinkTarget: "/etc/hosts",
          }),
      });
    });
    const stat = await filesOn(mock).stat("/tmp/link");
    expect(stat.kind).toBe("symlink");
    expect(stat.symlinkTarget).toBe("/etc/hosts");
    expect(stat.modifiedAt).toBeUndefined();
    expect(stat.size).toBe(0);
  });

  it('a kind this SDK predates maps to "unknown"', async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        stat: () => create(FileStatSchema, { name: "x", kind: 99 as FileKind }),
      });
    });
    expect((await filesOn(mock).stat("/x")).kind).toBe("unknown");
  });

  it("a missing path is FileNotFoundError with the path in context", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        stat() {
          // The daemon's documented shape: NOT_FOUND + the FILE_NOT_FOUND
          // registry detail carrying the path (app/arcbox-api error.rs).
          throw new ConnectError(
            "path not found: /gone",
            Code.NotFound,
            undefined,
            [
              {
                desc: ErrorInfoSchema,
                value: {
                  code: ErrorCode.FILE_NOT_FOUND,
                  suggestion:
                    "check the path with `Stat` or `ListDir` on its parent directory",
                  context: { path: "/gone" },
                },
              },
            ],
          );
        },
      });
    });
    const failing = filesOn(mock).stat("/gone");
    await expect(failing).rejects.toBeInstanceOf(FileNotFoundError);
    await expect(failing).rejects.toMatchObject({
      code: "FILE_NOT_FOUND",
      context: { path: "/gone" },
      operation: "files.stat",
    });
  });
});

describe("files.list", () => {
  it("maps every entry and preserves the daemon's order", async () => {
    let seen: ListDirRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        listDir(req) {
          seen = req;
          return create(ListDirResponseSchema, {
            entries: [
              wireStat,
              create(FileStatSchema, {
                name: "sub",
                kind: FileKind.DIRECTORY,
                mode: 0o755,
              }),
            ],
          });
        },
      });
    });
    const entries = await filesOn(mock).list("/tmp");
    expect(seen?.path).toBe("/tmp");
    expect(entries.map((e) => [e.name, e.kind])).toEqual([
      ["a.bin", "file"],
      ["sub", "directory"],
    ]);
  });
});

describe("files.mkdir", () => {
  it("defaults mode to 0 on the wire (the daemon's 0755 default)", async () => {
    const requests: MakeDirRequest[] = [];
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        makeDir(req) {
          requests.push(req);
          return {};
        },
      });
    });
    const files = filesOn(mock);
    await files.mkdir("/tmp/a/b");
    await files.mkdir("/tmp/c", { mode: 0o700 });
    expect(requests.map((r) => [r.path, r.mode])).toEqual([
      ["/tmp/a/b", 0],
      ["/tmp/c", 0o700],
    ]);
  });
});

describe("files.remove", () => {
  it("sends the recursive flag exactly as requested", async () => {
    const requests: RemoveEntryRequest[] = [];
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        remove(req) {
          requests.push(req);
          return {};
        },
      });
    });
    const files = filesOn(mock);
    await files.remove("/tmp/file");
    await files.remove("/tmp/tree", { recursive: true });
    expect(requests.map((r) => [r.path, r.recursive])).toEqual([
      ["/tmp/file", false],
      ["/tmp/tree", true],
    ]);
  });

  it("a non-recursive remove of a non-empty directory is the precondition error", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        remove() {
          // The daemon's documented shape: DirectoryNotEmpty → 412 →
          // FAILED_PRECONDITION, no ErrorInfo detail.
          throw new ConnectError(
            "directory not empty: /full",
            Code.FailedPrecondition,
          );
        },
      });
    });
    const failing = filesOn(mock).remove("/full");
    await expect(failing).rejects.toBeInstanceOf(SandboxStateError);
    await expect(failing).rejects.toMatchObject({ operation: "files.remove" });
  });
});

describe("files.move", () => {
  it("sends from/to as fromPath/toPath", async () => {
    let seen: MoveEntryRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxFilesystemService, {
        move(req) {
          seen = req;
          return {};
        },
      });
    });
    await filesOn(mock).move("/tmp/a", "/tmp/b");
    expect(seen?.fromPath).toBe("/tmp/a");
    expect(seen?.toPath).toBe("/tmp/b");
  });
});
