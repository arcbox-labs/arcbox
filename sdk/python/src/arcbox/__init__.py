"""arcbox — run isolated microVM sandboxes on the local ArcBox daemon.

Two mirrored surfaces: the sync classes (`Sandbox`, `ArcBox`, ...) and
their `Async*` counterparts. Public shapes are hand-written and mapped
at the transport boundary; everything under `arcbox._gen` is generated
wire code and is deliberately NOT exported. The error hierarchy lives
in :mod:`arcbox.errors`.
"""

from arcbox._async._client import AsyncConnectClient
from arcbox._async.commands import AsyncCommandHandle, AsyncCommands
from arcbox._async.files import AsyncFiles
from arcbox._async.sandbox import AsyncArcBox, AsyncSandbox
from arcbox._connection import Connection
from arcbox._sync._client import ConnectClient
from arcbox._sync.commands import CommandHandle, Commands
from arcbox._sync.files import Files
from arcbox._sync.sandbox import ArcBox, Sandbox
from arcbox._types import (
    MAX_FILE_BYTES,
    CommandResult,
    IdlePolicy,
    OutputChannel,
    OutputChunk,
    SandboxInfo,
    SandboxState,
    SandboxSummary,
    SignalName,
)

__all__ = [
    "MAX_FILE_BYTES",
    "ArcBox",
    "AsyncArcBox",
    "AsyncCommandHandle",
    "AsyncCommands",
    "AsyncConnectClient",
    "AsyncFiles",
    "AsyncSandbox",
    "CommandHandle",
    "CommandResult",
    "Commands",
    "ConnectClient",
    "Connection",
    "Files",
    "IdlePolicy",
    "OutputChannel",
    "OutputChunk",
    "Sandbox",
    "SandboxInfo",
    "SandboxState",
    "SandboxSummary",
    "SignalName",
]
