"""arcbox — run isolated microVM sandboxes on the local ArcBox daemon.

Two mirrored surfaces: the sync classes (`Sandbox`, `ArcBox`, ...) and
their `Async*` counterparts. Public shapes are hand-written and mapped
at the transport boundary; everything under `arcbox._gen` is generated
wire code and is deliberately NOT exported. The error hierarchy lives
in :mod:`arcbox.errors`.
"""

from importlib.metadata import PackageNotFoundError, version

from arcbox._async._client import AsyncConnectClient
from arcbox._async.commands import AsyncCommandHandle, AsyncCommands, AsyncOutputStream
from arcbox._async.files import AsyncFiles, AsyncFileWatch
from arcbox._async.ports import AsyncPorts
from arcbox._async.sandbox import AsyncArcBox, AsyncEventStream, AsyncSandbox
from arcbox._async.templates import AsyncTemplate
from arcbox._connection import Connection
from arcbox._sync._client import ConnectClient
from arcbox._sync.commands import CommandHandle, Commands, OutputStream
from arcbox._sync.files import Files, FileWatch
from arcbox._sync.ports import Ports
from arcbox._sync.sandbox import ArcBox, EventStream, Sandbox
from arcbox._sync.templates import Template
from arcbox._types import (
    MAX_FILE_BYTES,
    UNCHANGED,
    Capabilities,
    CommandInfo,
    CommandResult,
    CommandState,
    ExposedPort,
    FileKind,
    FileStat,
    FsEvent,
    FsEventKind,
    IdlePolicy,
    NestedVirtCapability,
    OutputChannel,
    OutputChunk,
    PortProtocol,
    PtySize,
    SandboxEvent,
    SandboxEventKind,
    SandboxInfo,
    SandboxState,
    SandboxSummary,
    SignalName,
    Snapshot,
    StdinStatus,
    TemplateInfo,
    Unchanged,
)

try:
    __version__ = version("arcbox")
except PackageNotFoundError:
    # An uninstalled source tree carries no distribution metadata; a
    # fixed dev sentinel beats parsing pyproject.toml on every import.
    __version__ = "0.0.0.dev0"

__all__ = [
    "MAX_FILE_BYTES",
    "UNCHANGED",
    "ArcBox",
    "AsyncArcBox",
    "AsyncCommandHandle",
    "AsyncCommands",
    "AsyncConnectClient",
    "AsyncEventStream",
    "AsyncFileWatch",
    "AsyncFiles",
    "AsyncOutputStream",
    "AsyncPorts",
    "AsyncSandbox",
    "AsyncTemplate",
    "Capabilities",
    "CommandHandle",
    "CommandInfo",
    "CommandResult",
    "CommandState",
    "Commands",
    "ConnectClient",
    "Connection",
    "EventStream",
    "ExposedPort",
    "FileKind",
    "FileStat",
    "FileWatch",
    "Files",
    "FsEvent",
    "FsEventKind",
    "IdlePolicy",
    "NestedVirtCapability",
    "OutputChannel",
    "OutputChunk",
    "OutputStream",
    "PortProtocol",
    "Ports",
    "PtySize",
    "Sandbox",
    "SandboxEvent",
    "SandboxEventKind",
    "SandboxInfo",
    "SandboxState",
    "SandboxSummary",
    "SignalName",
    "Snapshot",
    "StdinStatus",
    "Template",
    "TemplateInfo",
    "Unchanged",
]
