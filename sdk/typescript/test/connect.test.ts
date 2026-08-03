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
  SandboxInfoSchema,
  SandboxService,
  SandboxState as SandboxStateProto,
} from "../src/gen/arcbox/sandbox/v1/sandbox_pb.js";
import { ArcBox } from "../src/sandbox.js";

/** Serves Inspect from a state script and records Resume calls. */
class MockLifecycle {
  resumes = 0;

  /** Consumed one per Inspect; the last entry repeats. */
  constructor(public states: SandboxStateProto[]) {}

  transport(): Transport {
    return createRouterTransport(({ service }) => {
      service(SandboxService, {
        inspect: () => {
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
      });
    });
  }
}

function connectAgainst(daemon: MockLifecycle): ArcBox {
  return new ArcBox({ transport: daemon.transport() });
}

describe("ArcBox.connect lifecycle routing", () => {
  it("resumes a PAUSED sandbox", async () => {
    const daemon = new MockLifecycle([SandboxStateProto.PAUSED]);
    const sandbox = await connectAgainst(daemon).connect("sb-1");
    expect(sandbox.id).toBe("sb-1");
    expect(daemon.resumes).toBe(1);
  });

  it("settles a PAUSING sandbox to PAUSED, then resumes", async () => {
    const daemon = new MockLifecycle([
      SandboxStateProto.PAUSING,
      SandboxStateProto.PAUSED,
    ]);
    const sandbox = await connectAgainst(daemon).connect("sb-1");
    expect(sandbox.id).toBe("sb-1");
    // The checkpoint was polled out (a second Inspect ran) and exactly
    // one Resume followed — not a readiness-event wait that never ends.
    expect(daemon.states).toEqual([SandboxStateProto.READY]);
    expect(daemon.resumes).toBe(1);
  });
});
