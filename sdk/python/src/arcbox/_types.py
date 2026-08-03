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
from typing import TYPE_CHECKING, Literal

from arcbox._gen import process_pb2, sandbox_pb2
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


def signal_display_name(value: int) -> str:
    """Map a POSIX signal number to its conventional name."""
    try:
        name = process_pb2.Signal.Name(value)
    except ValueError:
        return f"SIG{value}"
    if name == "SIGNAL_UNSPECIFIED":
        return f"SIG{value}"
    return name.removeprefix("SIGNAL_")


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
