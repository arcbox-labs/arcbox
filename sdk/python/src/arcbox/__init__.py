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
from arcbox._async.files import AsyncFiles
from arcbox._async.sandbox import AsyncArcBox, AsyncSandbox
from arcbox._connection import Connection
from arcbox._sync._client import ConnectClient
from arcbox._sync.commands import CommandHandle, Commands, OutputStream
from arcbox._sync.files import Files
from arcbox._sync.sandbox import ArcBox, Sandbox
from arcbox._types import (
    MAX_FILE_BYTES,
    CommandResult,
    IdlePolicy,
    OutputChannel,
    OutputChunk,
    PtySize,
    SandboxInfo,
    SandboxState,
    SandboxSummary,
    SignalName,
    StdinStatus,
)

try:
    __version__ = version("arcbox")
except PackageNotFoundError:
    # An uninstalled source tree carries no distribution metadata; a
    # fixed dev sentinel beats parsing pyproject.toml on every import.
    __version__ = "0.0.0.dev0"

__all__ = [
    "MAX_FILE_BYTES",
    "ArcBox",
    "AsyncArcBox",
    "AsyncCommandHandle",
    "AsyncCommands",
    "AsyncConnectClient",
    "AsyncFiles",
    "AsyncOutputStream",
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
    "OutputStream",
    "PtySize",
    "Sandbox",
    "SandboxInfo",
    "SandboxState",
    "SandboxSummary",
    "SignalName",
    "StdinStatus",
]
