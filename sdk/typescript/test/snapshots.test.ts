// Snapshot catalog against a mock daemon: sandbox.checkpoint(),
// ArcBox.restore()/listSnapshots()/deleteSnapshot().
//
// The contracts under test: the checkpoint result is the catalog row
// (response id + creation time, request-echoed name and labels), restore
// mints the new sandbox id client-side and hands back a handle on it,
// listSnapshots auto-paginates, and errors carry the snapshots.*
// operation names.

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { NotFoundError } from "../src/errors";
import type {
  DeleteSnapshotRequest,
  ListSnapshotsRequest,
  RestoreRequest,
} from "../src/gen/arcbox/sandbox/v1/snapshot_pb";
import {
  CheckpointResponseSchema,
  ListSnapshotsResponseSchema,
  RestoreResponseSchema,
  SandboxSnapshotService,
} from "../src/gen/arcbox/sandbox/v1/snapshot_pb";
import { ArcBox, Sandbox } from "../src/sandbox";

const CREATED = new Date("2026-08-10T08:00:00Z");

const RE_UUID = /^[0-9a-f-]{36}$/;

describe("sandbox.checkpoint", () => {
  it("returns the catalog row the daemon recorded", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxSnapshotService, {
        checkpoint(req) {
          expect(req.sandboxId).toBe("sb-1");
          expect(req.name).toBe("warm-base");
          expect(req.labels).toEqual({ tier: "warm" });
          return create(CheckpointResponseSchema, {
            snapshotId: "snap-1",
            createdAt: timestampFromDate(CREATED),
          });
        },
      });
    });
    const sandbox = new Sandbox({ transport: mock }, "sb-1");
    expect(
      await sandbox.checkpoint({ name: "warm-base", labels: { tier: "warm" } }),
    ).toEqual({
      id: "snap-1",
      sandboxId: "sb-1",
      name: "warm-base",
      labels: { tier: "warm" },
      createdAt: CREATED,
    });
  });

  it("wraps daemon errors naming the operation", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxSnapshotService, {
        checkpoint() {
          throw new ConnectError(
            "sandbox is not READY",
            Code.FailedPrecondition,
          );
        },
      });
    });
    const sandbox = new Sandbox({ transport: mock }, "sb-1");
    await expect(sandbox.checkpoint()).rejects.toMatchObject({
      operation: "sandbox.checkpoint",
    });
  });
});

describe("arcbox.restore", () => {
  it("mints the new sandbox id client-side and hands back its handle", async () => {
    let seen: RestoreRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxSnapshotService, {
        restore(req) {
          seen = req;
          return create(RestoreResponseSchema, {
            id: req.id,
            ipAddress: "192.168.64.7",
          });
        },
      });
    });
    const sandbox = await new ArcBox({ transport: mock }).restore("snap-1", {
      ttlMs: 90500,
      labels: { origin: "snap-1" },
      freshNetwork: true,
    });
    expect(seen?.snapshotId).toBe("snap-1");
    expect(seen?.labels).toEqual({ origin: "snap-1" });
    expect(seen?.networkOverride).toBe(true);
    // Milliseconds round UP to whole wire seconds.
    expect(seen?.ttlSeconds).toBe(91);
    // The id is minted client-side (idempotent retries) and is the
    // handle's identity.
    expect(sandbox.id).toBe(seen?.id);
    expect(sandbox.id).toMatch(RE_UUID);
  });

  it("wraps a missing snapshot as NotFoundError with the operation", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxSnapshotService, {
        restore() {
          throw new ConnectError("snapshot snap-9 not found", Code.NotFound);
        },
      });
    });
    const restoring = new ArcBox({ transport: mock }).restore("snap-9");
    await expect(restoring).rejects.toBeInstanceOf(NotFoundError);
    await expect(restoring).rejects.toMatchObject({
      operation: "snapshots.restore",
    });
  });
});

describe("arcbox.listSnapshots", () => {
  it("auto-paginates and maps rows", async () => {
    const requests: ListSnapshotsRequest[] = [];
    const mock = createRouterTransport(({ service }) => {
      service(SandboxSnapshotService, {
        listSnapshots(req) {
          requests.push(req);
          if (req.pageToken === "") {
            return create(ListSnapshotsResponseSchema, {
              snapshots: [
                {
                  id: "snap-1",
                  sandboxId: "sb-1",
                  name: "warm-base",
                  labels: { tier: "warm" },
                  createdAt: timestampFromDate(CREATED),
                },
              ],
              nextPageToken: "page-2",
            });
          }
          return create(ListSnapshotsResponseSchema, {
            snapshots: [{ id: "snap-2", sandboxId: "sb-2" }],
          });
        },
      });
    });
    const rows = [];
    for await (const snapshot of new ArcBox({
      transport: mock,
    }).listSnapshots({ sandboxId: "sb-1", labels: { tier: "warm" } })) {
      rows.push(snapshot);
    }
    expect(rows).toEqual([
      {
        id: "snap-1",
        sandboxId: "sb-1",
        name: "warm-base",
        labels: { tier: "warm" },
        createdAt: CREATED,
      },
      { id: "snap-2", sandboxId: "sb-2", name: "", labels: {} },
    ]);
    expect(requests.map((request) => request.pageToken)).toEqual([
      "",
      "page-2",
    ]);
    expect(requests[0]?.sandboxId).toBe("sb-1");
    expect(requests[0]?.labels).toEqual({ tier: "warm" });
  });
});

describe("arcbox.deleteSnapshot", () => {
  it("names the snapshot to delete", async () => {
    let seen: DeleteSnapshotRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxSnapshotService, {
        deleteSnapshot(req) {
          seen = req;
          return {};
        },
      });
    });
    await new ArcBox({ transport: mock }).deleteSnapshot("snap-1");
    expect(seen?.snapshotId).toBe("snap-1");
  });

  it("wraps daemon errors naming the operation", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxSnapshotService, {
        deleteSnapshot() {
          throw new ConnectError("snapshot snap-1 not found", Code.NotFound);
        },
      });
    });
    await expect(
      new ArcBox({ transport: mock }).deleteSnapshot("snap-1"),
    ).rejects.toMatchObject({ operation: "snapshots.delete" });
  });
});
