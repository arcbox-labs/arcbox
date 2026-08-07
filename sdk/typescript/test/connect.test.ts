// connect() lifecycle routing against a mock daemon.
//
// The PAUSING case is the regression that matters: a pausing sandbox's
// next stop is PAUSED — never READY — so connect must poll the
// checkpoint out and then resume, not wait on readiness events that
// cannot arrive.

import { create } from "@bufbuild/protobuf";
import { EmptySchema } from "@bufbuild/protobuf/wkt";
import type { Transport } from "@connectrpc/connect";
import { createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import {
  KeepAliveSchema,
  SandboxInfoSchema,
  SandboxService,
  SandboxState as SandboxStateProto,
  WatchEventsResponseSchema,
} from "../src/gen/arcbox/sandbox/v1/sandbox_pb.js";
import { ArcBox } from "../src/sandbox.js";

/** Serves Inspect from a state script, counting every call it answers. */
class MockLifecycle {
  resumes = 0;
  /**
   * The settle poll is witnessed by this count: `resume` rewrites
   * `states` unconditionally, so the post-state is `[READY]` whether or
   * not a second Inspect ever ran.
   */
  inspects = 0;
  /** Readiness subscriptions opened. A PAUSING connect must open none. */
  eventStreams = 0;

  /** Consumed one per Inspect; the last entry repeats. */
  constructor(public states: SandboxStateProto[]) {}

  transport(): Transport {
    return createRouterTransport(({ service }) => {
      service(SandboxService, {
        inspect: () => {
          this.inspects += 1;
          const state = this.states[0] ?? SandboxStateProto.UNSPECIFIED;
          if (this.states.length > 1) {
            this.states = this.states.slice(1);
          }
          return create(SandboxInfoSchema, { id: "sb-1", state });
        },
        resume: () => {
          this.resumes += 1;
          this.states = [SandboxStateProto.READY];
          return create(EmptySchema);
        },
        // What the daemon serves a pausing sandbox: keepalives and no
        // state change, because READY is not where it is headed. The
        // real stream never ends; ending it here makes a connect that
        // wrongly waits on readiness fail fast, and say why, instead of
        // hanging until the suite's timeout.
        // eslint-disable-next-line @typescript-eslint/require-await -- a server-streaming handler is an async generator; this double serves from memory and has nothing to await
        events: async function* (this: MockLifecycle) {
          this.eventStreams += 1;
          yield create(WatchEventsResponseSchema, {
            payload: { case: "keepAlive", value: create(KeepAliveSchema) },
          });
        }.bind(this),
      });
    });
  }
}

function connectAgainst(daemon: MockLifecycle): ArcBox {
  return new ArcBox({ transport: daemon.transport() });
}

describe("ArcBox.connect lifecycle routing", () => {
  it("resumes a PAUSED sandbox without re-inspecting", async () => {
    const daemon = new MockLifecycle([SandboxStateProto.PAUSED]);
    const sandbox = await connectAgainst(daemon).connect("sb-1");
    expect(sandbox.id).toBe("sb-1");
    // The negative that gives the PAUSING count below its meaning: an
    // already-settled state routes off the first Inspect.
    expect(daemon.inspects).toBe(1);
    expect(daemon.resumes).toBe(1);
  });

  it("settles a PAUSING sandbox to PAUSED, then resumes", async () => {
    const daemon = new MockLifecycle([
      SandboxStateProto.PAUSING,
      SandboxStateProto.PAUSED,
    ]);
    const sandbox = await connectAgainst(daemon).connect("sb-1");
    expect(sandbox.id).toBe("sb-1");
    // The checkpoint was polled out — a second Inspect ran — and exactly
    // one Resume followed. No readiness subscription was ever opened:
    // that is the regression, since READY is not where a pausing
    // sandbox is headed.
    expect(daemon.inspects).toBe(2);
    expect(daemon.eventStreams).toBe(0);
    expect(daemon.resumes).toBe(1);
  });
});
