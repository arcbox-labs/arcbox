import { timestampDate } from "@bufbuild/protobuf/wkt";

import type {
  ExposedPort as ExposedPortProto,
  GetCapabilitiesResponse,
  SandboxEvent as SandboxEventProto,
  SandboxInfo as SandboxInfoProto,
  SandboxSummary as SandboxSummaryProto,
} from "./gen/arcbox/sandbox/v1/sandbox_pb";
import {
  IdleAction,
  PortProtocol as PortProtocolProto,
  SandboxEventKind as SandboxEventKindProto,
  SandboxState as SandboxStateProto,
} from "./gen/arcbox/sandbox/v1/sandbox_pb";
import type {
  CheckpointResponse,
  SnapshotSummary as SnapshotSummaryProto,
} from "./gen/arcbox/sandbox/v1/snapshot_pb";
import type { Template as TemplateProto } from "./gen/arcbox/sandbox/v1/template_pb";

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
  /**
   * On-disk footprint of retained state, in every lifecycle state: the
   * COW disk overlay while running, plus the pause checkpoint while
   * paused. Paused sandboxes keep paying this until resumed or removed.
   */
  storageBytes: number;
}

/**
 * Kind of a sandbox lifecycle event. `"idle"` fires when an execution
 * exits and the sandbox returns to ready; `"pausing"`/`"resumed"` carry
 * a `reason` attribute distinguishing client calls from automation
 * (`idle_timeout` / `auto_resume`).
 */
export type SandboxEventKind =
  | "created"
  | "ready"
  | "running"
  | "idle"
  | "stopping"
  | "stopped"
  | "failed"
  | "removed"
  | "pausing"
  | "paused"
  | "resumed"
  | "unknown";

/** One sandbox lifecycle event, as delivered by {@link Sandbox.events}. */
export interface SandboxEvent {
  sandboxId: string;
  kind: SandboxEventKind;
  /** When it happened (daemon clock). */
  time?: Date;
  /**
   * Per-kind context: `exit_code`/`signal` on `"idle"`, `error` on
   * `"failed"`, `reason` on `"pausing"`/`"resumed"`.
   */
  attributes: Record<string, string>;
  /**
   * Monotonic sequence number: 1-based, global across all sandboxes of
   * the emitting daemon, and stamped before the per-sandbox filter
   * {@link Sandbox.events} subscribes with. On that stream a gap is
   * therefore inconclusive — other sandboxes' events consumed numbers
   * too — while contiguous sequences prove nothing for this sandbox was
   * missed, and a sequence running backwards reveals a daemon restart.
   * When in doubt, re-derive state from {@link Sandbox.info}. `0` means
   * the daemon predates sequencing. Carried as a `number` (the SDK's
   * convention for `uint64` fields): a single daemon would need ~2^53
   * lifecycle events to reach the precision limit.
   */
  sequence: number;
}

/** Nested-virtualization support on this host. */
export interface NestedVirtCapability {
  /** True when sandboxes can run (M3+ hardware, VZ backend). */
  supported: boolean;
  /** The daemon's authoritative reason, when unsupported. */
  reason?: string;
}

/** What the daemon can do — the {@link ArcBox.capabilities} handshake. */
export interface Capabilities {
  /** Daemon version string (informational). */
  daemonVersion: string;
  /** Sandbox API protocol level. */
  protocol: number;
  /** Append-only named feature flags (e.g. "pause_resume"). */
  features: string[];
  /** Whether this host can run sandboxes at all. */
  nestedVirt: NestedVirtCapability;
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
  /**
   * On-disk footprint of retained state; see {@link SandboxInfo.storageBytes},
   * with which a listing agrees.
   */
  storageBytes: number;
}

/** Transport protocol of an exposed port. */
export type PortProtocol = "tcp" | "udp";

/** One host listener currently forwarding into a sandbox. */
export interface ExposedPort {
  /** Port the workload listens on inside the sandbox. */
  sandboxPort: number;
  /** Loopback host port where the service is reachable. */
  hostPort: number;
  protocol: PortProtocol;
}

/** One checkpointed sandbox image in the snapshot catalog. */
export interface Snapshot {
  id: string;
  /** The sandbox this snapshot was checkpointed from. */
  sandboxId: string;
  /** Human-readable name recorded at checkpoint time. */
  name: string;
  /** Labels recorded at checkpoint time, filterable in listings. */
  labels: Record<string, string>;
  createdAt?: Date;
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

const EVENT_KIND_NAMES: Partial<
  Record<SandboxEventKindProto, SandboxEventKind>
> = {
  [SandboxEventKindProto.CREATED]: "created",
  [SandboxEventKindProto.READY]: "ready",
  [SandboxEventKindProto.RUNNING]: "running",
  [SandboxEventKindProto.IDLE]: "idle",
  [SandboxEventKindProto.STOPPING]: "stopping",
  [SandboxEventKindProto.STOPPED]: "stopped",
  [SandboxEventKindProto.FAILED]: "failed",
  [SandboxEventKindProto.REMOVED]: "removed",
  [SandboxEventKindProto.PAUSING]: "pausing",
  [SandboxEventKindProto.PAUSED]: "paused",
  [SandboxEventKindProto.RESUMED]: "resumed",
};

/** Map one Events frame to the public DTO ("unknown" for kinds this SDK predates). */
export function sandboxEventFromProto(event: SandboxEventProto): SandboxEvent {
  const out: SandboxEvent = {
    sandboxId: event.sandboxId,
    kind: EVENT_KIND_NAMES[event.kind] ?? "unknown",
    attributes: event.attributes,
    sequence: Number(event.sequence),
  };
  assignIfSet(out, "time", optionalDate(event.time));
  return out;
}

/** Public protocol → wire enum (never UNSPECIFIED — "tcp" is explicit). */
export function portProtocolToProto(protocol: PortProtocol): PortProtocolProto {
  return protocol === "udp" ? PortProtocolProto.UDP : PortProtocolProto.TCP;
}

/** Wire protocol → public name (the wire reserves UNSPECIFIED for TCP). */
export function portProtocolFromProto(
  protocol: PortProtocolProto,
): PortProtocol {
  return protocol === PortProtocolProto.UDP ? "udp" : "tcp";
}

/** Map one ListExposedPorts row to the public DTO. */
export function exposedPortFromProto(port: ExposedPortProto): ExposedPort {
  return {
    sandboxPort: port.sandboxPort,
    hostPort: port.hostPort,
    protocol: portProtocolFromProto(port.protocol),
  };
}

/** A catalog template row (one per version; drafts have `version === ""`). */
export interface TemplateInfo {
  name: string;
  /** Published version ("" = unpublished draft). */
  version: string;
  /** Content digest pinning this version's artifacts. */
  digest: string;
  /** Whether the template carries a pre-warmed boot-to-ready snapshot. */
  warm: boolean;
  /** On-disk footprint of the version's artifacts. */
  sizeBytes: number;
  labels: Record<string, string>;
  createdAt?: Date;
}

/** Map one Template message to the public DTO. */
export function templateInfoFromProto(proto: TemplateProto): TemplateInfo {
  const out: TemplateInfo = {
    name: proto.name,
    version: proto.version,
    digest: proto.digest,
    warm: proto.warmSnapshotId !== "",
    sizeBytes: Number(proto.sizeBytes),
    labels: proto.labels,
  };
  assignIfSet(out, "createdAt", optionalDate(proto.createdAt));
  return out;
}

/** Map one ListSnapshots row to the public DTO. */
export function snapshotFromProto(summary: SnapshotSummaryProto): Snapshot {
  const out: Snapshot = {
    id: summary.id,
    sandboxId: summary.sandboxId,
    name: summary.name,
    labels: summary.labels,
  };
  assignIfSet(out, "createdAt", optionalDate(summary.createdAt));
  return out;
}

/**
 * Build the catalog row a Checkpoint response describes. The response
 * carries only id + creation time; name and labels echo the request,
 * which is exactly what the catalog recorded.
 */
export function snapshotFromCheckpoint(
  response: CheckpointResponse,
  sandboxId: string,
  name: string,
  labels: Record<string, string>,
): Snapshot {
  const out: Snapshot = { id: response.snapshotId, sandboxId, name, labels };
  assignIfSet(out, "createdAt", optionalDate(response.createdAt));
  return out;
}

/** Map the GetCapabilities response to the public DTO. */
export function capabilitiesFromProto(
  response: GetCapabilitiesResponse,
): Capabilities {
  const nestedVirt: NestedVirtCapability = {
    supported: response.nestedVirt?.supported ?? false,
  };
  const reason = response.nestedVirt?.reason;
  if (reason !== undefined && reason !== "") {
    nestedVirt.reason = reason;
  }
  return {
    daemonVersion: response.daemonVersion,
    protocol: response.protocol,
    features: response.features,
    nestedVirt,
  };
}
