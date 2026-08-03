import { timestampDate } from "@bufbuild/protobuf/wkt";

import type {
  SandboxInfo as SandboxInfoProto,
  SandboxSummary as SandboxSummaryProto,
} from "./gen/arcbox/sandbox/v1/sandbox_pb.js";
import {
  IdleAction,
  SandboxState as SandboxStateProto,
} from "./gen/arcbox/sandbox/v1/sandbox_pb.js";

/** Lifecycle state of a sandbox. See `sandbox.proto` for the state machine. */
export type SandboxState =
  | "unknown"
  | "starting"
  | "ready"
  | "running"
  | "stopping"
  | "stopped"
  | "failed"
  | "pausing"
  | "paused";

/** What the daemon does when the idle timeout expires. */
export type IdlePolicy = "kill" | "pause";

/** Full sandbox state, always fetched fresh — never a cached mirror. */
export interface SandboxInfo {
  id: string;
  state: SandboxState;
  labels: Record<string, string>;
  /** Template reference the sandbox was created from ("" = built-in minimal). */
  template: string;
  /** Effective vCPU count, when reported. */
  vcpus?: number;
  /** Effective memory in MiB, when reported. */
  memoryMib?: number;
  ipAddress?: string;
  createdAt?: Date;
  readyAt?: Date;
  pausedAt?: Date;
  failedAt?: Date;
  /** Failure reason; set exactly when state is "failed". */
  error?: string;
  /** When the hard maximum lifetime fires (unset = no limit). */
  ttlDeadline?: Date;
  /** Idle timeout in milliseconds (unset = no idle detection). */
  idleTimeoutMs?: number;
  /** Action applied when the idle timeout expires (unset = daemon default). */
  onIdle?: IdlePolicy;
  /** On-disk footprint of retained state; paused sandboxes keep paying this. */
  storageBytes: number;
}

/** One row of a sandbox listing. */
export interface SandboxSummary {
  id: string;
  state: SandboxState;
  labels: Record<string, string>;
  ipAddress?: string;
  createdAt?: Date;
  readyAt?: Date;
  pausedAt?: Date;
  failedAt?: Date;
  storageBytes: number;
}

const STATE_NAMES: Partial<Record<SandboxStateProto, SandboxState>> = {
  [SandboxStateProto.STARTING]: "starting",
  [SandboxStateProto.READY]: "ready",
  [SandboxStateProto.RUNNING]: "running",
  [SandboxStateProto.STOPPING]: "stopping",
  [SandboxStateProto.STOPPED]: "stopped",
  [SandboxStateProto.FAILED]: "failed",
  [SandboxStateProto.PAUSING]: "pausing",
  [SandboxStateProto.PAUSED]: "paused",
};

/** Wire state → public state ("unknown" for values this SDK predates). */
export function sandboxStateFromProto(state: SandboxStateProto): SandboxState {
  return STATE_NAMES[state] ?? "unknown";
}

const STATE_VALUES: Record<SandboxState, SandboxStateProto> = {
  unknown: SandboxStateProto.UNSPECIFIED,
  starting: SandboxStateProto.STARTING,
  ready: SandboxStateProto.READY,
  running: SandboxStateProto.RUNNING,
  stopping: SandboxStateProto.STOPPING,
  stopped: SandboxStateProto.STOPPED,
  failed: SandboxStateProto.FAILED,
  pausing: SandboxStateProto.PAUSING,
  paused: SandboxStateProto.PAUSED,
};

/** Public state filter → wire state. */
export function sandboxStateToProto(state: SandboxState): SandboxStateProto {
  return STATE_VALUES[state];
}

function optionalDate(
  ts: Parameters<typeof timestampDate>[0] | undefined,
): Date | undefined {
  return ts === undefined ? undefined : timestampDate(ts);
}

/** Map the Inspect response to the public DTO. */
export function sandboxInfoFromProto(info: SandboxInfoProto): SandboxInfo {
  const out: SandboxInfo = {
    id: info.id,
    state: sandboxStateFromProto(info.state),
    labels: info.labels,
    template: info.template,
    storageBytes: Number(info.storageBytes),
  };
  if (info.limits !== undefined && info.limits.vcpus !== 0) {
    out.vcpus = info.limits.vcpus;
  }
  if (info.limits !== undefined && info.limits.memoryMib !== 0n) {
    out.memoryMib = Number(info.limits.memoryMib);
  }
  if (info.network !== undefined && info.network.ipAddress !== "") {
    out.ipAddress = info.network.ipAddress;
  }
  assignIfSet(out, "createdAt", optionalDate(info.createdAt));
  assignIfSet(out, "readyAt", optionalDate(info.readyAt));
  assignIfSet(out, "pausedAt", optionalDate(info.pausedAt));
  assignIfSet(out, "failedAt", optionalDate(info.failedAt));
  assignIfSet(out, "ttlDeadline", optionalDate(info.ttlDeadline));
  if (info.error !== "") {
    out.error = info.error;
  }
  if (info.idleTimeoutSeconds !== 0) {
    out.idleTimeoutMs = info.idleTimeoutSeconds * 1000;
    if (info.onIdle === IdleAction.KILL) {
      out.onIdle = "kill";
    } else if (info.onIdle === IdleAction.PAUSE) {
      out.onIdle = "pause";
    }
  }
  return out;
}

/** Map one List row to the public DTO. */
export function sandboxSummaryFromProto(
  summary: SandboxSummaryProto,
): SandboxSummary {
  const out: SandboxSummary = {
    id: summary.id,
    state: sandboxStateFromProto(summary.state),
    labels: summary.labels,
    storageBytes: Number(summary.storageBytes),
  };
  if (summary.ipAddress !== "") {
    out.ipAddress = summary.ipAddress;
  }
  assignIfSet(out, "createdAt", optionalDate(summary.createdAt));
  assignIfSet(out, "readyAt", optionalDate(summary.readyAt));
  assignIfSet(out, "pausedAt", optionalDate(summary.pausedAt));
  assignIfSet(out, "failedAt", optionalDate(summary.failedAt));
  return out;
}

function assignIfSet<T, K extends keyof T>(
  target: T,
  key: K,
  value: T[K] | undefined,
): void {
  if (value !== undefined) {
    target[key] = value;
  }
}
