"""Shapes ``e2b`` exposes, and the mappings onto arcbox's.

Nothing here is async, so both flavors share it.

Time units are ``e2b``'s throughout: milliseconds, named ``*_ms``. The
arcbox SDK uses seconds as floats, so every boundary in this package
divides — that conversion is the single most common way a shim like this
silently misbehaves, so it lives in one place (:func:`seconds`).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arcbox import CommandResult as ArcBoxCommandResult
    from arcbox import FileStat, FsEvent

from .errors import CommandExitException

#: ``e2b``'s default sandbox timeout.
DEFAULT_SANDBOX_TIMEOUT_MS = 300_000


def seconds(milliseconds: float | None) -> float | None:
    """Convert ``e2b``'s milliseconds to arcbox's seconds."""
    return None if milliseconds is None else milliseconds / 1000


class FileType(str, Enum):
    """Kind of a filesystem entry, as ``e2b`` names them."""

    FILE = "file"
    DIR = "dir"


@dataclass(frozen=True)
class WriteInfo:
    """What ``e2b`` reports for a written file."""

    name: str
    path: str
    type: FileType = FileType.FILE


@dataclass(frozen=True)
class EntryInfo:
    """One entry of a directory listing."""

    name: str
    path: str
    type: FileType
    size: int
    mode: int
    #: Permissions rendered the way ``ls -l`` does, e.g. ``-rw-r--r--``.
    permissions: str
    owner: str
    group: str
    modified_time: datetime | None = None
    symlink_target: str | None = None


@dataclass(frozen=True)
class CommandResult:
    """A finished command, as ``e2b`` reports it."""

    stdout: str
    stderr: str
    exit_code: int
    #: Signal name when the process was killed by one.
    error: str | None = None


@dataclass(frozen=True)
class PtySize:
    """Terminal size, as ``e2b`` names it."""

    cols: int
    rows: int


@dataclass(frozen=True)
class ProcessInfo:
    """One running command, as ``e2b`` lists them.

    The daemon reports execution ids and states, not argv: ``cmd``,
    ``args``, ``envs``, and ``cwd`` are empty rather than invented."""

    #: Execution id. ``e2b`` names it ``pid``; arcbox ids are not OS pids.
    pid: str
    cmd: str = ""
    args: tuple[str, ...] = ()
    envs: dict[str, str] | None = None
    cwd: str | None = None


class FilesystemEventType(str, Enum):
    """Kind of a filesystem event, as ``e2b`` names them."""

    CREATE = "create"
    WRITE = "write"
    REMOVE = "remove"
    RENAME = "rename"


@dataclass(frozen=True)
class FilesystemEvent:
    """One filesystem event delivered by ``files.watch_dir``."""

    #: Path of the affected entry, relative to the watched directory.
    name: str
    type: FilesystemEventType


_EVENT_TYPES: dict[str, FilesystemEventType] = {
    "created": FilesystemEventType.CREATE,
    "modified": FilesystemEventType.WRITE,
    "removed": FilesystemEventType.REMOVE,
    "renamed": FilesystemEventType.RENAME,
}


def to_filesystem_event(event: FsEvent, prefix: str) -> FilesystemEvent | None:
    """Map an arcbox event onto ``e2b``'s shape.

    ``None`` for kinds ``e2b`` has no name for. ``prefix`` is the
    watched directory with a trailing slash; paths under it are made
    relative, matching ``e2b``'s ``name`` field."""
    kind = _EVENT_TYPES.get(event.kind)
    if kind is None:
        return None
    name = event.path[len(prefix) :] if event.path.startswith(prefix) else event.path
    return FilesystemEvent(name=name, type=kind)


@dataclass(frozen=True)
class SandboxInfo:
    """One row of a sandbox listing, in ``e2b``'s shape."""

    sandbox_id: str
    template_id: str
    metadata: dict[str, str]
    state: str
    started_at: datetime | None = None
    end_at: datetime | None = None


def permission_string(mode: int, is_directory: bool) -> str:
    """Render permission bits the way ``ls -l`` does.

    ``e2b`` exposes this string and some callers match on it, so it is
    computed rather than left blank."""
    triples = "".join(
        f"{'r' if bits & 0b100 else '-'}"
        f"{'w' if bits & 0b010 else '-'}"
        f"{'x' if bits & 0b001 else '-'}"
        for bits in ((mode >> 6) & 0b111, (mode >> 3) & 0b111, mode & 0b111)
    )
    return f"{'d' if is_directory else '-'}{triples}"


def to_entry_info(info: FileStat, directory: str) -> EntryInfo:
    """Map an arcbox ``FileStat`` onto ``e2b``'s entry shape."""
    is_directory = info.kind == "directory"
    separator = "" if directory.endswith("/") else "/"
    return EntryInfo(
        name=info.name,
        path=f"{directory}{separator}{info.name}",
        type=FileType.DIR if is_directory else FileType.FILE,
        size=info.size,
        mode=info.mode,
        permissions=permission_string(info.mode, is_directory),
        # The daemon reports numeric ids only; e2b reports names.
        # Showing the number is honest — inventing a name would not be.
        owner=str(info.uid),
        group=str(info.gid),
        modified_time=info.modified_at,
        symlink_target=info.symlink_target,
    )


def to_result(result: ArcBoxCommandResult) -> CommandResult:
    """Map an arcbox result onto ``e2b``'s shape."""
    return CommandResult(
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
        error=result.signal,
    )


def expect_zero_exit(result: ArcBoxCommandResult) -> CommandResult:
    """Raise ``e2b``'s exception on a non-zero exit; map it otherwise."""
    if result.exit_code != 0:
        raise CommandExitException(result)
    return to_result(result)


def normalize_template(template: str | None) -> str:
    """``e2b``'s default template is ``'base'``; arcbox spells its
    built-in minimal template ``''``, so the two names converge here
    rather than failing to resolve a template nobody published."""
    return "" if template is None or template == "base" else template
