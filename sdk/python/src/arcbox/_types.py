"""Hand-written public shapes and their wire mappings.

Generated types never appear in a public signature — these DTOs are
mapped from the wire messages at the transport boundary. Shared by the
async and sync trees (nothing here is async).

Time units follow the Python convention of this SDK: seconds as floats,
no unit suffix (the TypeScript SDK uses ``*Ms`` milliseconds).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final, Literal, final

from arcbox._gen import filesystem_pb2, process_pb2, sandbox_pb2, snapshot_pb2, template_pb2
from arcbox.errors import ArcBoxError, CommandFailedError, SandboxDiedError

if TYPE_CHECKING:
    from google.protobuf import timestamp_pb2

#: Lifecycle state of a sandbox. See `sandbox.proto` for the state machine.
SandboxState = Literal[
    "unknown",
    "starting",
    "ready",
    "running",
    "stopping",
    "stopped",
    "failed",
    "pausing",
    "paused",
]

#: What the daemon does when the idle timeout expires.
IdlePolicy = Literal["kill", "pause"]

#: Transport protocol of an exposed port.
PortProtocol = Literal["tcp", "udp"]

#: Kind of a sandbox lifecycle event. "idle" fires when an execution
#: exits and the sandbox returns to ready; "pausing"/"resumed" carry a
#: "reason" attribute distinguishing client calls from automation
#: ("idle_timeout" / "auto_resume").
SandboxEventKind = Literal[
    "created",
    "ready",
    "running",
    "idle",
    "stopping",
    "stopped",
    "failed",
    "removed",
    "pausing",
    "paused",
    "resumed",
    "unknown",
]


@final
class Unchanged:
    """Sentinel type for ``set_lifecycle``: leave this knob as it is.

    ``UNCHANGED`` is its only instance and the default for every knob,
    so passing it explicitly (e.g. from a conditional update) is
    equivalent to omitting the argument.
    """

    def __repr__(self) -> str:
        return "UNCHANGED"


#: The single :class:`Unchanged` sentinel.
UNCHANGED: Final = Unchanged()

#: Signals deliverable to a command's process group.
SignalName = Literal["SIGTERM", "SIGKILL", "SIGINT", "SIGHUP", "SIGQUIT"]

SIGNAL_VALUES: dict[SignalName, process_pb2.Signal] = {
    "SIGHUP": process_pb2.SIGNAL_SIGHUP,
    "SIGINT": process_pb2.SIGNAL_SIGINT,
    "SIGQUIT": process_pb2.SIGNAL_SIGQUIT,
    "SIGKILL": process_pb2.SIGNAL_SIGKILL,
    "SIGTERM": process_pb2.SIGNAL_SIGTERM,
}

#: One chunk of command output.
OutputChannel = Literal["stdout", "stderr", "pty"]

#: Per-file transfer cap enforced by the daemon (`filesystem.proto`).
MAX_FILE_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class OutputChunk:
    """One chunk of command output."""

    channel: OutputChannel
    data: bytes


@dataclass(frozen=True)
class PtySize:
    """Terminal geometry for a PTY command."""

    #: Terminal width in columns.
    cols: int
    #: Terminal height in rows.
    rows: int


@dataclass(frozen=True)
class StdinStatus:
    """Stdin acceptance state of a command, as reported by the daemon."""

    #: Bytes accepted and forwarded so far — the offset the next stdin
    #: write starts at.
    bytes_written: int
    #: Whether stdin has been closed.
    closed: bool


@dataclass(frozen=True)
class CommandResult:
    """A finished command. Non-zero exit is data, not an exception —
    :meth:`expect` is the opt-in raise."""

    #: Process exit code. When the process was killed by a signal this is
    #: ``128 + signal`` (shell convention) and :attr:`signal` is set.
    exit_code: int
    stdout: str
    #: Stderr content — warnings land here too; it is not "errors".
    stderr: str
    #: Signal name when killed by a signal (e.g. "SIGKILL").
    signal: str | None = None
    #: True when the daemon's output retention (8 MiB per channel)
    #: dropped bytes before they were collected — :attr:`stdout` /
    #: :attr:`stderr` then hold only the newest retained output.
    truncated: bool = False

    def expect(self) -> CommandResult:
        """Raise :class:`arcbox.errors.CommandFailedError` on non-zero exit."""
        if self.exit_code != 0:
            raise CommandFailedError(self)
        return self


#: What kind of filesystem object a path is. "other" covers device
#: nodes, FIFOs, and sockets; "unknown" covers kinds this SDK predates.
FileKind = Literal["file", "directory", "symlink", "other", "unknown"]


@dataclass(frozen=True)
class FileStat:
    """Metadata of one filesystem entry (``files.stat`` / ``files.list``)."""

    #: Base name of the entry (the final path component).
    name: str
    #: Kind of entry (symlinks are reported as "symlink", not followed).
    kind: FileKind
    #: Size in bytes (regular files; 0 otherwise).
    size: int
    #: Unix permission bits (the low 12 bits of st_mode).
    mode: int
    #: Owning user ID.
    uid: int
    #: Owning group ID.
    gid: int
    #: Last modification time.
    modified_at: datetime | None = None
    #: Symlink target (set only when kind is "symlink").
    symlink_target: str | None = None


#: Lifecycle state of a command (execution).
CommandState = Literal["running", "exited"]


@dataclass(frozen=True)
class CommandInfo:
    """One row of a command listing — the summary ``commands.list()``
    returns. Exit is data, mirroring :class:`CommandResult`: a signal
    death reports ``128 + signal`` with :attr:`signal` set; an execution
    that ended without an observed exit carries :attr:`error` instead."""

    #: Execution id — feed it to ``commands.get()`` for a live handle.
    command_id: str
    #: Whether the process runs on a pseudo-TTY.
    tty: bool
    state: CommandState
    #: When the process was dispatched.
    started_at: datetime | None = None
    #: When the process terminated (None while running).
    exited_at: datetime | None = None
    #: Exit code (``128 + signal`` for signal deaths), set on an observed exit.
    exit_code: int | None = None
    #: Signal name when killed by a signal (e.g. "SIGKILL").
    signal: str | None = None
    #: Set when the execution ended without an observed exit.
    error: str | None = None


#: Kind of a filesystem event. "unknown" covers kinds this SDK predates.
FsEventKind = Literal["created", "modified", "removed", "renamed", "unknown"]


@dataclass(frozen=True)
class FsEvent:
    """One filesystem event, as delivered by ``files.watch()``."""

    #: What happened.
    kind: FsEventKind
    #: Absolute path of the affected entry (the old path for "renamed").
    path: str
    #: New absolute path (set only for "renamed").
    renamed_to: str | None = None


@dataclass(frozen=True)
class SandboxInfo:
    """Full sandbox state, always fetched fresh — never a cached mirror."""

    id: str
    state: SandboxState
    labels: dict[str, str] = field(default_factory=dict[str, str])
    #: Template reference the sandbox was created from ("" = built-in minimal).
    template: str = ""
    #: Effective vCPU count, when reported.
    vcpus: int | None = None
    #: Effective memory in MiB, when reported.
    memory_mib: int | None = None
    ip_address: str | None = None
    created_at: datetime | None = None
    ready_at: datetime | None = None
    paused_at: datetime | None = None
    failed_at: datetime | None = None
    #: Failure reason; set exactly when state is "failed".
    error: str | None = None
    #: When the hard maximum lifetime fires (None = no limit).
    ttl_deadline: datetime | None = None
    #: Idle timeout in seconds (None = no idle detection).
    idle_timeout: float | None = None
    #: Action applied when the idle timeout expires (None = daemon default).
    on_idle: IdlePolicy | None = None
    #: On-disk footprint of retained state; paused sandboxes keep paying this.
    storage_bytes: int = 0


@dataclass(frozen=True)
class SandboxEvent:
    """One sandbox lifecycle event, as delivered by ``sandbox.events()``."""

    sandbox_id: str
    kind: SandboxEventKind
    #: When it happened (daemon clock).
    time: datetime | None = None
    #: Per-kind context: "exit_code"/"signal" on "idle", "error" on
    #: "failed", "reason" on "pausing"/"resumed".
    attributes: dict[str, str] = field(default_factory=dict[str, str])


@dataclass(frozen=True)
class NestedVirtCapability:
    """Nested-virtualization support on this host."""

    #: True when sandboxes can run (M3+ hardware, VZ backend).
    supported: bool
    #: The daemon's authoritative reason, when unsupported.
    reason: str | None = None


@dataclass(frozen=True)
class Capabilities:
    """What the daemon can do — the ``arcbox.capabilities()`` handshake."""

    #: Daemon version string (informational).
    daemon_version: str
    #: Sandbox API protocol level.
    protocol: int
    #: Append-only named feature flags (e.g. "pause_resume").
    features: list[str]
    #: Whether this host can run sandboxes at all.
    nested_virt: NestedVirtCapability


@dataclass(frozen=True)
class SandboxSummary:
    """One row of a sandbox listing."""

    id: str
    state: SandboxState
    labels: dict[str, str] = field(default_factory=dict[str, str])
    ip_address: str | None = None
    created_at: datetime | None = None
    ready_at: datetime | None = None
    paused_at: datetime | None = None
    failed_at: datetime | None = None
    storage_bytes: int = 0


@dataclass(frozen=True)
class ExposedPort:
    """One host listener currently forwarding into a sandbox."""

    #: Port the workload listens on inside the sandbox.
    sandbox_port: int
    #: Loopback host port where the service is reachable.
    host_port: int
    protocol: PortProtocol = "tcp"


@dataclass(frozen=True)
class TemplateInfo:
    """One catalog template row (one per version; drafts have version == "")."""

    name: str
    #: Published version ("" = unpublished draft).
    version: str
    #: Content digest pinning this version's artifacts.
    digest: str
    #: Whether the template carries a pre-warmed boot-to-ready snapshot.
    warm: bool = False
    #: On-disk footprint of the version's artifacts.
    size_bytes: int = 0
    labels: dict[str, str] = field(default_factory=dict[str, str])
    created_at: datetime | None = None


@dataclass(frozen=True)
class Snapshot:
    """One checkpointed sandbox image in the snapshot catalog."""

    id: str
    #: The sandbox this snapshot was checkpointed from.
    sandbox_id: str
    #: Human-readable name recorded at checkpoint time.
    name: str = ""
    #: Labels recorded at checkpoint time, filterable in listings.
    labels: dict[str, str] = field(default_factory=dict[str, str])
    created_at: datetime | None = None


_STATE_VALUES: dict[SandboxState, sandbox_pb2.SandboxState] = {
    "unknown": sandbox_pb2.SANDBOX_STATE_UNSPECIFIED,
    "starting": sandbox_pb2.SANDBOX_STATE_STARTING,
    "ready": sandbox_pb2.SANDBOX_STATE_READY,
    "running": sandbox_pb2.SANDBOX_STATE_RUNNING,
    "stopping": sandbox_pb2.SANDBOX_STATE_STOPPING,
    "stopped": sandbox_pb2.SANDBOX_STATE_STOPPED,
    "failed": sandbox_pb2.SANDBOX_STATE_FAILED,
    "pausing": sandbox_pb2.SANDBOX_STATE_PAUSING,
    "paused": sandbox_pb2.SANDBOX_STATE_PAUSED,
}

_STATE_NAMES: dict[int, SandboxState] = {
    value: name for name, value in _STATE_VALUES.items() if name != "unknown"
}


def sandbox_state_from_proto(state: int) -> SandboxState:
    """Wire state -> public state ("unknown" for values this SDK predates)."""
    return _STATE_NAMES.get(state, "unknown")


def sandbox_state_to_proto(state: SandboxState) -> sandbox_pb2.SandboxState:
    """Public state filter -> wire state."""
    return _STATE_VALUES[state]


def _optional_time(msg: timestamp_pb2.Timestamp, present: bool) -> datetime | None:
    return msg.ToDatetime(tzinfo=timezone.utc) if present else None


def sandbox_info_from_proto(info: sandbox_pb2.SandboxInfo) -> SandboxInfo:
    """Map the Inspect response to the public DTO."""
    limits = info.limits
    idle_timeout = float(info.idle_timeout_seconds) if info.idle_timeout_seconds != 0 else None
    on_idle: IdlePolicy | None = None
    if idle_timeout is not None:
        if info.on_idle == sandbox_pb2.IDLE_ACTION_KILL:
            on_idle = "kill"
        elif info.on_idle == sandbox_pb2.IDLE_ACTION_PAUSE:
            on_idle = "pause"
    return SandboxInfo(
        id=info.id,
        state=sandbox_state_from_proto(info.state),
        labels=dict(info.labels),
        template=info.template,
        vcpus=limits.vcpus if limits.vcpus != 0 else None,
        memory_mib=int(limits.memory_mib) if limits.memory_mib != 0 else None,
        ip_address=info.network.ip_address or None,
        created_at=_optional_time(info.created_at, info.HasField("created_at")),
        ready_at=_optional_time(info.ready_at, info.HasField("ready_at")),
        paused_at=_optional_time(info.paused_at, info.HasField("paused_at")),
        failed_at=_optional_time(info.failed_at, info.HasField("failed_at")),
        error=info.error or None,
        ttl_deadline=_optional_time(info.ttl_deadline, info.HasField("ttl_deadline")),
        idle_timeout=idle_timeout,
        on_idle=on_idle,
        storage_bytes=int(info.storage_bytes),
    )


_FILE_KIND_NAMES: dict[int, FileKind] = {
    filesystem_pb2.FILE_KIND_FILE: "file",
    filesystem_pb2.FILE_KIND_DIRECTORY: "directory",
    filesystem_pb2.FILE_KIND_SYMLINK: "symlink",
    filesystem_pb2.FILE_KIND_OTHER: "other",
}


def file_stat_from_proto(stat: filesystem_pb2.FileStat) -> FileStat:
    """Map one wire FileStat to the public DTO ("unknown" for kinds this
    SDK predates)."""
    return FileStat(
        name=stat.name,
        kind=_FILE_KIND_NAMES.get(stat.kind, "unknown"),
        size=int(stat.size),
        mode=stat.mode,
        uid=stat.uid,
        gid=stat.gid,
        modified_at=_optional_time(stat.modified_at, stat.HasField("modified_at")),
        symlink_target=stat.symlink_target or None,
    )


_FS_EVENT_KIND_NAMES: dict[int, FsEventKind] = {
    filesystem_pb2.FS_EVENT_KIND_CREATED: "created",
    filesystem_pb2.FS_EVENT_KIND_MODIFIED: "modified",
    filesystem_pb2.FS_EVENT_KIND_REMOVED: "removed",
    filesystem_pb2.FS_EVENT_KIND_RENAMED: "renamed",
}


def fs_event_from_proto(event: filesystem_pb2.FsEvent) -> FsEvent:
    """Map one WatchDir frame to the public DTO ("unknown" for kinds
    this SDK predates)."""
    return FsEvent(
        kind=_FS_EVENT_KIND_NAMES.get(event.kind, "unknown"),
        path=event.path,
        renamed_to=event.renamed_to or None,
    )


def sandbox_summary_from_proto(summary: sandbox_pb2.SandboxSummary) -> SandboxSummary:
    """Map one List row to the public DTO."""
    return SandboxSummary(
        id=summary.id,
        state=sandbox_state_from_proto(summary.state),
        labels=dict(summary.labels),
        ip_address=summary.ip_address or None,
        created_at=_optional_time(summary.created_at, summary.HasField("created_at")),
        ready_at=_optional_time(summary.ready_at, summary.HasField("ready_at")),
        paused_at=_optional_time(summary.paused_at, summary.HasField("paused_at")),
        failed_at=_optional_time(summary.failed_at, summary.HasField("failed_at")),
        storage_bytes=int(summary.storage_bytes),
    )


def port_protocol_to_proto(protocol: PortProtocol) -> sandbox_pb2.PortProtocol:
    """Public protocol -> wire enum (never UNSPECIFIED — "tcp" is explicit)."""
    return sandbox_pb2.PORT_PROTOCOL_UDP if protocol == "udp" else sandbox_pb2.PORT_PROTOCOL_TCP


def port_protocol_from_proto(protocol: int) -> PortProtocol:
    """Wire protocol -> public name (the wire reserves UNSPECIFIED for TCP)."""
    return "udp" if protocol == sandbox_pb2.PORT_PROTOCOL_UDP else "tcp"


def exposed_port_from_proto(port: sandbox_pb2.ExposedPort) -> ExposedPort:
    """Map one ListExposedPorts row to the public DTO."""
    return ExposedPort(
        sandbox_port=port.sandbox_port,
        host_port=port.host_port,
        protocol=port_protocol_from_proto(port.protocol),
    )


def template_info_from_proto(proto: template_pb2.Template) -> TemplateInfo:
    """Map one Template message to the public DTO."""
    return TemplateInfo(
        name=proto.name,
        version=proto.version,
        digest=proto.digest,
        warm=proto.warm_snapshot_id != "",
        size_bytes=proto.size_bytes,
        labels=dict(proto.labels),
        created_at=_optional_time(proto.created_at, proto.HasField("created_at")),
    )


def snapshot_from_proto(summary: snapshot_pb2.SnapshotSummary) -> Snapshot:
    """Map one ListSnapshots row to the public DTO."""
    return Snapshot(
        id=summary.id,
        sandbox_id=summary.sandbox_id,
        name=summary.name,
        labels=dict(summary.labels),
        created_at=_optional_time(summary.created_at, summary.HasField("created_at")),
    )


def snapshot_from_checkpoint(
    response: snapshot_pb2.CheckpointResponse,
    sandbox_id: str,
    name: str,
    labels: dict[str, str],
) -> Snapshot:
    """Build the catalog row a Checkpoint response describes. The
    response carries only id + creation time; name and labels echo the
    request, which is exactly what the catalog recorded."""
    return Snapshot(
        id=response.snapshot_id,
        sandbox_id=sandbox_id,
        name=name,
        labels=labels,
        created_at=_optional_time(response.created_at, response.HasField("created_at")),
    )


_EVENT_KIND_NAMES: dict[int, SandboxEventKind] = {
    sandbox_pb2.SANDBOX_EVENT_KIND_CREATED: "created",
    sandbox_pb2.SANDBOX_EVENT_KIND_READY: "ready",
    sandbox_pb2.SANDBOX_EVENT_KIND_RUNNING: "running",
    sandbox_pb2.SANDBOX_EVENT_KIND_IDLE: "idle",
    sandbox_pb2.SANDBOX_EVENT_KIND_STOPPING: "stopping",
    sandbox_pb2.SANDBOX_EVENT_KIND_STOPPED: "stopped",
    sandbox_pb2.SANDBOX_EVENT_KIND_FAILED: "failed",
    sandbox_pb2.SANDBOX_EVENT_KIND_REMOVED: "removed",
    sandbox_pb2.SANDBOX_EVENT_KIND_PAUSING: "pausing",
    sandbox_pb2.SANDBOX_EVENT_KIND_PAUSED: "paused",
    sandbox_pb2.SANDBOX_EVENT_KIND_RESUMED: "resumed",
}


def sandbox_event_from_proto(event: sandbox_pb2.SandboxEvent) -> SandboxEvent:
    """Map one Events frame to the public DTO ("unknown" for kinds this
    SDK predates)."""
    return SandboxEvent(
        sandbox_id=event.sandbox_id,
        kind=_EVENT_KIND_NAMES.get(event.kind, "unknown"),
        time=_optional_time(event.time, event.HasField("time")),
        attributes=dict(event.attributes),
    )


def capabilities_from_proto(response: sandbox_pb2.GetCapabilitiesResponse) -> Capabilities:
    """Map the GetCapabilities response to the public DTO."""
    nested = response.nested_virt
    return Capabilities(
        daemon_version=response.daemon_version,
        protocol=response.protocol,
        features=list(response.features),
        nested_virt=NestedVirtCapability(supported=nested.supported, reason=nested.reason or None),
    )


def signal_display_name(value: int) -> str:
    """Map a POSIX signal number to its conventional name."""
    try:
        name = process_pb2.Signal.Name(value)
    except ValueError:
        return f"SIG{value}"
    if name == "SIGNAL_UNSPECIFIED":
        return f"SIG{value}"
    return name.removeprefix("SIGNAL_")


def command_info_from_proto(execution: process_pb2.Execution) -> CommandInfo:
    """Map one Execution row to the public summary DTO."""
    exit_code: int | None = None
    signal: str | None = None
    status = execution.exit_status.WhichOneof("status")
    if status == "code":
        exit_code = execution.exit_status.code
    elif status == "signal":
        value = execution.exit_status.signal
        exit_code = 128 + value
        signal = signal_display_name(value)
    return CommandInfo(
        command_id=execution.id,
        tty=execution.tty,
        state="exited" if execution.state == process_pb2.EXECUTION_STATE_EXITED else "running",
        started_at=_optional_time(execution.started_at, execution.HasField("started_at")),
        exited_at=_optional_time(execution.exited_at, execution.HasField("exited_at")),
        exit_code=exit_code,
        signal=signal,
        error=execution.error or None,
    )


def command_result_from_execution(
    execution: process_pb2.Execution,
    stdout: str,
    stderr: str,
    truncated: bool = False,
) -> CommandResult:
    """Build the exit-as-data result from a terminal execution.

    An execution that ended without an observed exit (session broke,
    sandbox stopped) raises :class:`SandboxDiedError` instead — that is
    not an exit.
    """
    if execution.error != "":
        raise SandboxDiedError(
            f"command ended without an exit: {execution.error}",
            context={"execution_id": execution.id, "error": execution.error},
        )
    status = execution.exit_status.WhichOneof("status")
    if status == "code":
        return CommandResult(execution.exit_status.code, stdout, stderr, None, truncated)
    if status == "signal":
        value = execution.exit_status.signal
        return CommandResult(128 + value, stdout, stderr, signal_display_name(value), truncated)
    raise ArcBoxError(
        "execution exited without an exit status",
        context={"execution_id": execution.id},
    )
