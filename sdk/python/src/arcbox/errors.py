"""Typed error hierarchy for the ArcBox Sandbox SDK.

Every error raised by this SDK derives from :class:`ArcBoxError` and
carries the machine-readable ``code`` from the daemon's error registry
(``arcbox.sandbox.v1.ErrorCode``) when one was attached, an actionable
``suggestion``, structured ``context``, and the failed ``operation``.

The registry-driven mapping lives at the single transport boundary
(:func:`error_from_wire`): call sites never inspect Connect errors
themselves.

Two class names deliberately shadow builtins (``FileNotFoundError``,
``TimeoutError``) — the hierarchy is shared verbatim with the TypeScript
SDK, and both subclass :class:`ArcBoxError`, not ``OSError``. Import
them with an alias when the builtin is also in scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from arcbox._gen import errors_pb2

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "ArcBoxError",
    "AuthenticationError",
    "CapabilityError",
    "CommandFailedError",
    "CommandFailure",
    "CommandNotFoundError",
    "CommandTimeoutError",
    "ConnectionFailedError",
    "ConnectionLostError",
    "FileNotFoundError",
    "FileTooLargeError",
    "InvalidArgumentError",
    "NotFoundError",
    "ProtocolMismatchError",
    "RequestTimeoutError",
    "SandboxDiedError",
    "SandboxNotFoundError",
    "SandboxStateError",
    "SandboxTtlError",
    "TemplateNotFoundError",
    "TimeoutError",
]

DAEMON_START_SUGGESTION = "run `abctl daemon start` (or launch the ArcBox app)"


class ArcBoxError(Exception):
    """Base class of every error raised by this SDK."""

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        suggestion: str | None = None,
        context: Mapping[str, str] | None = None,
        operation: str | None = None,
    ) -> None:
        super().__init__(message)
        #: Machine-readable cause from the daemon's error registry
        #: (`errors.proto`), or the coarse Connect code when no
        #: `ErrorInfo` detail rode along.
        self.code = code
        #: Actionable fix, phrased for direct display
        #: ("run `abctl daemon start`").
        self.suggestion = suggestion
        #: Structured facts about the failure (which limit, which state, ...).
        self.context: dict[str, str] = dict(context) if context else {}
        #: The SDK operation that failed (e.g. "commands.run"); stamped by
        #: the call site that surfaced the error.
        self.operation = operation


class InvalidArgumentError(ArcBoxError):
    """A request was rejected at the boundary: unknown, contradictory, or malformed input."""


class ConnectionFailedError(ArcBoxError):
    """The daemon is unreachable (socket missing, connection refused, ...)."""


class ConnectionLostError(ConnectionFailedError):
    """A live stream died mid-flow — and, where the SDK re-attaches
    (command output), could not be re-established within the retry
    budget. ``__cause__`` carries the underlying transport failure."""


class AuthenticationError(ArcBoxError):
    """Authentication is required or was rejected. Reserved for the remote tier (CORE-63)."""


class ProtocolMismatchError(ArcBoxError):
    """SDK and daemon protocol levels are incompatible."""


class NotFoundError(ArcBoxError):
    """The addressed resource does not exist."""


class SandboxNotFoundError(NotFoundError):
    """The addressed sandbox does not exist."""


class TemplateNotFoundError(NotFoundError):
    """The addressed template does not exist."""


class CommandNotFoundError(NotFoundError):
    """The addressed command (execution) does not exist."""


class FileNotFoundError(NotFoundError):
    """The addressed path does not exist inside the sandbox."""


class CapabilityError(ArcBoxError):
    """This host cannot run sandboxes (e.g. no nested virtualization; CORE-13)."""


class SandboxStateError(ArcBoxError):
    """The sandbox is in a state that does not permit the operation."""


class SandboxDiedError(SandboxStateError):
    """The sandbox died out from under the operation; context carries the terminal state."""


class TimeoutError(ArcBoxError):
    """A timeout fired. Subclasses name exactly which knob."""


class SandboxTtlError(TimeoutError):
    """The sandbox's hard maximum lifetime (`ttl`) expired and the daemon destroyed it."""


class CommandTimeoutError(TimeoutError):
    """A per-command timeout (`run(timeout=...)`) fired and the process group was killed."""


class RequestTimeoutError(TimeoutError):
    """A per-RPC deadline (`Connection.request_timeout`) fired."""


class FileTooLargeError(ArcBoxError):
    """A file transfer exceeded the per-file size cap; context carries the limit."""


class CommandFailure(Protocol):
    """Shape of a finished command, as carried by :class:`CommandFailedError`."""

    @property
    def exit_code(self) -> int: ...
    @property
    def signal(self) -> str | None: ...
    @property
    def stdout(self) -> str: ...
    @property
    def stderr(self) -> str: ...


class CommandFailedError(ArcBoxError):
    """Raised ONLY by ``CommandResult.expect()`` / ``run(check=True)``.

    Non-zero exit is data everywhere else. Carries the full result.
    """

    def __init__(self, result: CommandFailure, *, operation: str | None = None) -> None:
        what = (
            f"exit code {result.exit_code}" if result.signal is None else f"signal {result.signal}"
        )
        super().__init__(f"command failed with {what}", operation=operation)
        self.result = result


_ERROR_CODE_PREFIX = "ERROR_CODE_"

# The registry-driven mapping (`errors.proto` -> class), applied when the
# daemon attached `ErrorInfo`. STDIN_CLOSED and RESOURCE_EXHAUSTED_HOST
# stay on the base class: the preserved `code` string is their precise
# identity.
_REGISTRY_CLASSES: dict[int, type[ArcBoxError]] = {
    errors_pb2.ERROR_CODE_SANDBOX_NOT_FOUND: SandboxNotFoundError,
    errors_pb2.ERROR_CODE_TEMPLATE_NOT_FOUND: TemplateNotFoundError,
    errors_pb2.ERROR_CODE_EXECUTION_NOT_FOUND: CommandNotFoundError,
    errors_pb2.ERROR_CODE_FILE_NOT_FOUND: FileNotFoundError,
    errors_pb2.ERROR_CODE_SANDBOX_PAUSED: SandboxStateError,
    errors_pb2.ERROR_CODE_SANDBOX_NOT_READY: SandboxStateError,
    errors_pb2.ERROR_CODE_SANDBOX_FAILED: SandboxStateError,
    errors_pb2.ERROR_CODE_TTL_EXPIRED: SandboxTtlError,
    errors_pb2.ERROR_CODE_COMMAND_TIMEOUT: CommandTimeoutError,
    errors_pb2.ERROR_CODE_NESTED_VIRT_UNSUPPORTED: CapabilityError,
    errors_pb2.ERROR_CODE_TEMPLATE_INVALID: InvalidArgumentError,
    errors_pb2.ERROR_CODE_FILE_TOO_LARGE: FileTooLargeError,
    errors_pb2.ERROR_CODE_TTY_REQUIRED: InvalidArgumentError,
    errors_pb2.ERROR_CODE_PORT_IN_USE: InvalidArgumentError,
    errors_pb2.ERROR_CODE_AUTH_REQUIRED: AuthenticationError,
    errors_pb2.ERROR_CODE_PROTOCOL_MISMATCH: ProtocolMismatchError,
}

# Fallback routing on the coarse Connect code (the wire's snake_case
# string) when no `ErrorInfo` detail rode along.
_CONNECT_CODE_CLASSES: dict[str, type[ArcBoxError]] = {
    "not_found": NotFoundError,
    "invalid_argument": InvalidArgumentError,
    "failed_precondition": SandboxStateError,
    "deadline_exceeded": RequestTimeoutError,
    "unavailable": ConnectionFailedError,
    "unauthenticated": AuthenticationError,
}

_CONNECT_CODE_SUGGESTIONS: dict[str, str] = {
    "deadline_exceeded": "increase Connection.request_timeout",
    "unavailable": DAEMON_START_SUGGESTION,
}


def error_code_name(code: int) -> str:
    """`ErrorCode` numeric value -> its registry name (e.g. "SANDBOX_NOT_FOUND")."""
    try:
        name = errors_pb2.ErrorCode.Name(code)
    except ValueError:
        return f"{_ERROR_CODE_PREFIX}{code}"
    return name.removeprefix(_ERROR_CODE_PREFIX)


def error_from_wire(
    connect_code: str,
    message: str,
    info: errors_pb2.ErrorInfo | None,
    operation: str | None = None,
) -> ArcBoxError:
    """Map one daemon error to the typed hierarchy.

    Precedence: an `ErrorInfo` detail (the daemon's error registry) wins;
    otherwise the coarse Connect code routes. Unknown registry codes stay
    on the base class with the raw code preserved.
    """
    if info is None:
        cls = _CONNECT_CODE_CLASSES.get(connect_code, ArcBoxError)
        return cls(
            message,
            code=connect_code,
            suggestion=_CONNECT_CODE_SUGGESTIONS.get(connect_code),
            operation=operation,
        )
    cls = _REGISTRY_CLASSES.get(info.code, ArcBoxError)
    return cls(
        message,
        code=error_code_name(info.code),
        suggestion=info.suggestion or None,
        context=dict(info.context),
        operation=operation,
    )
