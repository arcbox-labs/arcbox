"""The exception classes ``e2b`` exports.

Most are **aliases** of the ``arcbox`` class that already means the same
thing, not new subclasses. That is the load-bearing choice: the errors
your code catches are raised by the underlying SDK, so a fresh
``class SandboxException(ArcBoxError)`` would sit beside them and never
match. Aliasing keeps ``except SandboxException`` behaving exactly as it
did against ``e2b``.

The rest fall into two groups, both documented per class: those this
shim raises itself (:class:`CommandExitException`,
:class:`UnsupportedException`), and those kept only so
``from arcbox.e2b import …`` still resolves — a local daemon has no rate
limiter, no registry build, and no volumes, so nothing can raise them.
"""

from __future__ import annotations

from typing import NoReturn

from arcbox.errors import (
    ArcBoxError,
    AuthenticationError,
    CommandFailedError,
    FileNotFoundError,
    InvalidArgumentError,
    NotFoundError,
    SandboxNotFoundError,
    TemplateNotFoundError,
    TimeoutError,
)

#: Base of every sandbox failure.
SandboxException = ArcBoxError
TimeoutException = TimeoutError
InvalidArgumentException = InvalidArgumentError
NotFoundException = NotFoundError
FileNotFoundException = FileNotFoundError
SandboxNotFoundException = SandboxNotFoundError
AuthenticationException = AuthenticationError
#: ``e2b``'s is the broader "something about the template" class; arcbox
#: only ever fails to resolve one.
TemplateException = TemplateNotFoundError


class CommandExitException(CommandFailedError):
    """A command exited non-zero.

    ``e2b`` raises this from ``run()`` and ``wait()`` rather than
    returning the result, and reads the result's fields off the
    exception. Subclasses ``CommandFailedError`` so arcbox-side handlers
    still catch it."""

    @property
    def exit_code(self) -> int:
        """Exit code — non-zero, or ``128 + signal`` for signal death."""
        return self.result.exit_code

    @property
    def error(self) -> str | None:
        """Signal name when the process was killed by one."""
        return self.result.signal

    @property
    def stdout(self) -> str:
        return self.result.stdout

    @property
    def stderr(self) -> str:
        return self.result.stderr


class UnsupportedException(ArcBoxError):
    """Part of the ``e2b`` surface this shim does not implement.

    Raised eagerly, never silently ignored: the operations behind it —
    fork, volumes, signed upload/download URLs, sandbox metrics, the MCP
    gateway, and the template build DSL — address E2B cloud services
    with no local equivalent, so a no-op would corrupt whatever the
    caller does next. The README lists them."""


def unsupported(operation: str, reason: str) -> NoReturn:
    """Raise :class:`UnsupportedException`, so call sites stay one line."""
    raise UnsupportedException(
        f"{operation} is not supported by arcbox-e2b: {reason}",
        operation=operation,
        suggestion=(
            "this runs against a local ArcBox daemon rather than the E2B cloud — "
            "see the arcbox-e2b README"
        ),
    )


class NotEnoughSpaceException(ArcBoxError):
    """The sandbox ran out of disk.

    Never raised: the daemon does not distinguish a full disk from any
    other write failure. Exported so the import resolves."""


class RateLimitException(ArcBoxError):
    """The caller is being rate limited.

    Never raised: a local daemon has no quota."""


class GitAuthException(ArcBoxError):
    """A git operation could not authenticate against its remote.

    Never raised: ``git`` runs as an ordinary command inside the
    sandbox, so an auth failure arrives as a non-zero exit like any
    other."""


class GitUpstreamException(ArcBoxError):
    """A git operation failed against its upstream.

    Never raised, for the same reason as :class:`GitAuthException`."""


class BuildException(ArcBoxError):
    """A template build failed.

    Never raised: the build DSL is unsupported."""


class FileUploadException(ArcBoxError):
    """A template build's file upload failed.

    Never raised, for the same reason as :class:`BuildException`."""


class VolumeException(ArcBoxError):
    """A volume operation failed.

    Never raised: volumes are unsupported."""
