// events(), setLifecycle(), and the capabilities handshake against a
// mock daemon.
//
// setLifecycle's tri-state is the contract that matters: an omitted
// knob must be ABSENT on the wire (unchanged), null must be an explicit
// zero/UNSPECIFIED (restore the default), and a value must replace.
// Getting presence wrong silently rewrites deadlines the caller never
// touched.

import { create } from "@bufbuild/protobuf";
import { EmptySchema } from "@bufbuild/protobuf/wkt";
import type { Transport } from "@connectrpc/connect";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { ConnectionLostError, NotFoundError } from "../src/errors";
import type { SetLifecycleRequest } from "../src/gen/arcbox/sandbox/v1/sandbox_pb";
import {
  GetCapabilitiesResponseSchema,
  IdleAction,
  KeepAliveSchema,
  SandboxEventKind,
  SandboxEventSchema,
  SandboxService,
  WatchEventsResponseSchema,
} from "../src/gen/arcbox/sandbox/v1/sandbox_pb";
import { ArcBox, Sandbox } from "../src/sandbox";

function eventFrame(
  kind: SandboxEventKind,
  attributes: Record<string, string> = {},
) {
  return create(WatchEventsResponseSchema, {
    payload: {
      case: "event",
      value: create(SandboxEventSchema, {
        sandboxId: "sb-1",
        kind,
        attributes,
      }),
    },
  });
}

const keepAlive = create(WatchEventsResponseSchema, {
  payload: { case: "keepAlive", value: create(KeepAliveSchema) },
});

/** A Sandbox handle on a mock transport (no lifecycle routing involved). */
function sandboxOn(transport: Transport): Sandbox {
  return new Sandbox({ transport }, "sb-1");
}

describe("sandbox.events", () => {
  it("yields typed events and filters keepalives; a clean end ends the loop", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxService, {
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator
        async *events(req) {
          expect(req.sandboxId).toBe("sb-1");
          yield keepAlive;
          yield eventFrame(SandboxEventKind.CREATED);
          yield eventFrame(SandboxEventKind.READY);
          yield keepAlive;
          yield eventFrame(SandboxEventKind.PAUSING, {
            reason: "idle_timeout",
          });
          yield eventFrame(SandboxEventKind.PAUSED);
        },
      });
    });
    const sandbox = sandboxOn(mock);
    const seen: string[] = [];
    let reason = "";
    for await (const event of sandbox.events()) {
      seen.push(event.kind);
      if (event.kind === "pausing") {
        reason = event.attributes.reason ?? "";
      }
    }
    expect(seen).toEqual(["created", "ready", "pausing", "paused"]);
    expect(reason).toBe("idle_timeout");
  });

  it("a drop after frames flowed is the stream-death error", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxService, {
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator
        async *events() {
          yield eventFrame(SandboxEventKind.READY);
          throw new ConnectError("stream reset", Code.Unavailable);
        },
      });
    });
    const sandbox = sandboxOn(mock);
    const consume = async () => {
      for await (const event of sandbox.events()) {
        void event;
      }
    };
    await expect(consume()).rejects.toBeInstanceOf(ConnectionLostError);
  });

  it("a daemon-typed stream error keeps its own class", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxService, {
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator
        async *events() {
          yield eventFrame(SandboxEventKind.READY);
          throw new ConnectError("gone", Code.NotFound);
        },
      });
    });
    const sandbox = sandboxOn(mock);
    const consume = async () => {
      for await (const event of sandbox.events()) {
        void event;
      }
    };
    await expect(consume()).rejects.toBeInstanceOf(NotFoundError);
  });
});

function lifecycleProbe() {
  const requests: SetLifecycleRequest[] = [];
  const mock = createRouterTransport(({ service }) => {
    service(SandboxService, {
      setLifecycle(req) {
        requests.push(req);
        return create(EmptySchema);
      },
    });
  });
  return { sandbox: sandboxOn(mock), requests };
}

describe("sandbox.setLifecycle tri-state", () => {
  it("an empty update sends every knob absent (all unchanged)", async () => {
    const { sandbox, requests } = lifecycleProbe();
    await sandbox.setLifecycle({});
    expect(requests[0]?.ttlSeconds).toBeUndefined();
    expect(requests[0]?.idleTimeoutSeconds).toBeUndefined();
    expect(requests[0]?.onIdle).toBeUndefined();
  });

  it("values replace: ttl re-arms from now, idle window swaps", async () => {
    const { sandbox, requests } = lifecycleProbe();
    await sandbox.setLifecycle({ ttlMs: 5000, idleTimeoutMs: 30000 });
    expect(requests[0]?.ttlSeconds).toBe(5);
    expect(requests[0]?.idleTimeoutSeconds).toBe(30);
    expect(requests[0]?.onIdle).toBeUndefined();
  });

  it("null restores the default: explicit zero / UNSPECIFIED on the wire", async () => {
    const { sandbox, requests } = lifecycleProbe();
    await sandbox.setLifecycle({ ttlMs: null, onIdle: null });
    expect(requests[0]?.ttlSeconds).toBe(0);
    expect(requests[0]?.idleTimeoutSeconds).toBeUndefined();
    expect(requests[0]?.onIdle).toBe(IdleAction.UNSPECIFIED);
  });

  it("onIdle maps the policy names", async () => {
    const { sandbox, requests } = lifecycleProbe();
    await sandbox.setLifecycle({ onIdle: "pause" });
    expect(requests[0]?.onIdle).toBe(IdleAction.PAUSE);
    await sandbox.setLifecycle({ onIdle: "kill" });
    expect(requests[1]?.onIdle).toBe(IdleAction.KILL);
  });
});

function capsTransport(counter: { calls: number }, failFirst = false) {
  return createRouterTransport(({ service }) => {
    service(SandboxService, {
      getCapabilities() {
        counter.calls += 1;
        if (failFirst && counter.calls === 1) {
          throw new ConnectError("starting up", Code.Unavailable);
        }
        return create(GetCapabilitiesResponseSchema, {
          daemonVersion: "0.9.0",
          protocol: 1,
          features: ["pause_resume", "auto_resume"],
          nestedVirt: { supported: false, reason: "requires M3 or newer" },
        });
      },
    });
  });
}

describe("arcbox.capabilities", () => {
  it("maps the handshake and caches it per client", async () => {
    const counter = { calls: 0 };
    const box = new ArcBox({ transport: capsTransport(counter) });
    const caps = await box.capabilities();
    expect(caps).toEqual({
      daemonVersion: "0.9.0",
      protocol: 1,
      features: ["pause_resume", "auto_resume"],
      nestedVirt: { supported: false, reason: "requires M3 or newer" },
    });
    await box.capabilities();
    expect(counter.calls).toBe(1);
  });

  it("does not cache a failed fetch", async () => {
    const counter = { calls: 0 };
    const box = new ArcBox({ transport: capsTransport(counter, true) });
    await expect(box.capabilities()).rejects.toThrow("starting up");
    const caps = await box.capabilities();
    expect(caps.protocol).toBe(1);
    expect(counter.calls).toBe(2);
  });
});
