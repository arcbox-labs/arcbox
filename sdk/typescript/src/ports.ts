import type { Client } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";

import {
  InvalidArgumentError,
  RequestTimeoutError,
  TimeoutError,
  toArcBoxError,
} from "./errors";
import { SandboxProcessService } from "./gen/arcbox/sandbox/v1/process_pb";
import type { ClientContext } from "./transport";

/** Daemon default wait budget when no timeout is given (`process.proto`). */
const DEFAULT_WAIT_FOR_PORT_SECONDS = 30;

/**
 * Daemon cap on the wait budget — longer requests are clamped
 * server-side (each wait pins a guest exec-channel slot).
 */
const MAX_WAIT_FOR_PORT_SECONDS = 600;

/** Options for {@link Ports.waitForPort}. */
export interface WaitForPortOptions {
  /**
   * Give up after this long. Must be positive and finite; omit it for
   * the daemon's 30 s default (the wire reserves 0 for that default,
   * so a literal zero budget is not expressible). The wire's
   * granularity is whole seconds, so a fractional budget rounds UP to
   * the next second — never down toward the reserved 0. Values past
   * the daemon's 600 s cap are clamped to it. On expiry a
   * {@link TimeoutError} naming this knob is thrown.
   */
  timeoutMs?: number;
}

type ProcessClient = Client<typeof SandboxProcessService>;

/**
 * The `sandbox.ports` namespace: network readiness of one sandbox.
 */
export class Ports {
  readonly #client: ProcessClient;
  readonly #sandboxId: string;

  constructor(ctx: ClientContext, sandboxId: string) {
    this.#client = createClient(SandboxProcessService, ctx.transport);
    this.#sandboxId = sandboxId;
  }

  /**
   * Wait until something inside the sandbox listens on the given TCP
   * port. The guest agent watches its own listen table — no client-side
   * polling, no shelled-out probes. Resolves as soon as a listener is
   * up; throws {@link TimeoutError} when the budget elapses first.
   */
  async waitForPort(
    port: number,
    opts: WaitForPortOptions = {},
  ): Promise<void> {
    // Validate at the boundary: 0 would silently collide with the
    // wire's use-the-default sentinel (a 30 s wait, not an immediate
    // check), and negative/NaN/Infinity would reach the timer and
    // protobuf layers as raw invalid values.
    if (
      opts.timeoutMs !== undefined &&
      (!(opts.timeoutMs > 0) || !Number.isFinite(opts.timeoutMs))
    ) {
      throw new InvalidArgumentError(
        "waitForPort timeoutMs must be a positive finite number of " +
          "milliseconds (omit it for the daemon's 30 s default)",
        {
          context: { timeoutMs: String(opts.timeoutMs) },
          operation: "ports.waitForPort",
        },
      );
    }
    // 0 on the wire = the daemon default; the daemon clamps anything
    // past its cap, so the effective budget is known client-side too.
    const requested =
      opts.timeoutMs === undefined ? 0 : Math.ceil(opts.timeoutMs / 1000);
    const effective =
      requested === 0
        ? DEFAULT_WAIT_FOR_PORT_SECONDS
        : Math.min(requested, MAX_WAIT_FOR_PORT_SECONDS);
    const portLabel = String(port);
    const effectiveLabel = String(effective);
    try {
      await this.#client.waitForPort(
        { sandboxId: this.#sandboxId, port, timeoutSeconds: requested },
        // Exempt from requestTimeoutMs: this unary deliberately parks
        // server-side for the whole budget; grant it that long plus
        // grace, so the daemon's own deadline answers first.
        { timeoutMs: (effective + 5) * 1000 },
      );
    } catch (error) {
      const mapped = toArcBoxError(error, "ports.waitForPort");
      // A deadline expiry here is THIS wait's budget (the daemon's
      // DEADLINE_EXCEEDED, or the grace bound above), not the per-RPC
      // knob — name the right one, mirroring connect()'s discipline.
      if (mapped instanceof RequestTimeoutError) {
        throw new TimeoutError(
          `waitForPort(timeoutMs) elapsed before port ${portLabel} was listening`,
          {
            suggestion:
              "increase the waitForPort timeoutMs option, or check that " +
              "the workload actually binds this port",
            operation: "ports.waitForPort",
            cause: error,
            context: {
              port: portLabel,
              timeoutSeconds: effectiveLabel,
            },
          },
        );
      }
      throw mapped;
    }
  }
}
