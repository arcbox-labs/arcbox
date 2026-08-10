"""``arcbox.e2b`` — the ``e2b`` SDK's surface, served by a local ArcBox
daemon instead of the E2B cloud.

Swap the import and keep the code::

    from arcbox.e2b import Sandbox  # was: from e2b import Sandbox

Both flavors are exported, as in ``e2b``: ``Sandbox`` is synchronous and
``AsyncSandbox`` is not. What is not covered — fork, volumes, signed
URLs, metrics, MCP, and the template build DSL — raises
:class:`UnsupportedException` rather than failing quietly; the README
lists it.
"""

from arcbox.e2b._async.commands import (
    AsyncCommandHandle,
    AsyncCommands,
    AsyncPty,
)
from arcbox.e2b._async.filesystem import AsyncFilesystem, AsyncWatchHandle
from arcbox.e2b._async.git import AsyncGit
from arcbox.e2b._async.sandbox import AsyncSandbox
from arcbox.e2b._sync.commands import CommandHandle, Commands, Pty
from arcbox.e2b._sync.filesystem import Filesystem, WatchHandle
from arcbox.e2b._sync.git import Git
from arcbox.e2b._sync.sandbox import Sandbox
from arcbox.e2b._types import (
    DEFAULT_SANDBOX_TIMEOUT_MS,
    CommandResult,
    EntryInfo,
    FilesystemEvent,
    FilesystemEventType,
    FileType,
    ProcessInfo,
    PtySize,
    SandboxInfo,
    WriteInfo,
    permission_string,
)
from arcbox.e2b.errors import (
    AuthenticationException,
    BuildException,
    CommandExitException,
    FileNotFoundException,
    FileUploadException,
    GitAuthException,
    GitUpstreamException,
    InvalidArgumentException,
    NotEnoughSpaceException,
    NotFoundException,
    RateLimitException,
    SandboxException,
    SandboxNotFoundException,
    TemplateException,
    TimeoutException,
    UnsupportedException,
    VolumeException,
)

__all__ = [
    "DEFAULT_SANDBOX_TIMEOUT_MS",
    "AsyncCommandHandle",
    "AsyncCommands",
    "AsyncFilesystem",
    "AsyncGit",
    "AsyncPty",
    "AsyncSandbox",
    "AsyncWatchHandle",
    "AuthenticationException",
    "BuildException",
    "CommandExitException",
    "CommandHandle",
    "CommandResult",
    "Commands",
    "EntryInfo",
    "FileNotFoundException",
    "FileType",
    "FileUploadException",
    "Filesystem",
    "FilesystemEvent",
    "FilesystemEventType",
    "Git",
    "GitAuthException",
    "GitUpstreamException",
    "InvalidArgumentException",
    "NotEnoughSpaceException",
    "NotFoundException",
    "ProcessInfo",
    "Pty",
    "PtySize",
    "RateLimitException",
    "Sandbox",
    "SandboxException",
    "SandboxInfo",
    "SandboxNotFoundException",
    "TemplateException",
    "TimeoutException",
    "UnsupportedException",
    "VolumeException",
    "WatchHandle",
    "WriteInfo",
    "permission_string",
]
