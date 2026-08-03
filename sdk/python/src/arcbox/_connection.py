"""Connection configuration for reaching an ArcBox daemon.

Resolution order for every field: explicit option > environment > default.
The default tier is the local daemon's Unix socket; setting an API URL
(option or ``ARCBOX_API_URL``) selects the remote tier instead (CORE-63,
reserved — no cloud front door exists yet).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from arcbox.errors import InvalidArgumentError

if TYPE_CHECKING:
    from collections.abc import Mapping

    import httpx

#: Placeholder authority for Unix-socket requests. httpx dials the
#: transport's ``uds`` path and uses the URL only for the Host header
#: and request path, so any stable name works here.
UDS_BASE_URL = "http://arcbox"


@dataclass(frozen=True)
class Connection:
    """Connection options accepted by every SDK entry point."""

    #: Unix socket path of the local daemon (env: ``ARCBOX_SOCKET``).
    socket_path: str | None = None
    #: Base URL of a remote daemon / cloud front door (env:
    #: ``ARCBOX_API_URL``). Reserved (CORE-63).
    api_url: str | None = None
    #: Bearer credential attached as an ``Authorization`` header when set
    #: (env: ``ARCBOX_API_KEY``). Unused by the local daemon, which
    #: trusts socket file permissions instead.
    api_key: str | None = None
    #: Per-RPC deadline in seconds for unary calls. Streams are exempt.
    request_timeout: float | None = None
    #: Injected httpx client, replacing socket/URL resolution entirely —
    #: the mock/testing seam. The async surface requires an
    #: ``httpx.AsyncClient``; the sync surface an ``httpx.Client``.
    http_client: httpx.AsyncClient | httpx.Client | None = None


@dataclass(frozen=True)
class ResolvedConnection:
    """A fully resolved connection target."""

    #: Base URL handed to the transport. On the Unix-socket tier this is
    #: the :data:`UDS_BASE_URL` placeholder.
    base_url: str
    #: Unix socket to dial; ``None`` on the remote (TCP) tier.
    socket_path: str | None
    #: Bearer credential to attach, when set.
    api_key: str | None
    #: Per-unary-RPC deadline in seconds, when set.
    request_timeout: float | None


def _profile_data_dir_name(profile: str | None) -> str:
    """``ARCBOX_PROFILE`` -> default data dir name.

    Parsing mirrors the daemon's ``ArcboxProfile::from_str`` (trimmed,
    case-insensitive, ``development``/``dev``) with unknown values
    falling back to production, exactly like ``from_env_or_default``.
    """
    parsed = (profile or "").strip().lower()
    return ".arcbox-dev" if parsed in ("development", "dev") else ".arcbox"


def _default_socket_path(env: Mapping[str, str]) -> str:
    """Default socket location relative to the daemon data dir.

    Mirrors arcbox-constants paths.rs (``HostLayout::resolve_for_profile_from_env``):
    ``<data_dir>/run/arcbox.sock``, data dir from a non-empty
    ``ARCBOX_DATA_DIR``, else the ``ARCBOX_PROFILE`` default —
    ``~/.arcbox``, or ``~/.arcbox-dev`` for the development profile.
    """
    data_dir = env.get("ARCBOX_DATA_DIR") or str(
        Path.home() / _profile_data_dir_name(env.get("ARCBOX_PROFILE"))
    )
    return str(Path(data_dir) / "run" / "arcbox.sock")


def resolve_connection(options: Connection | None, env: Mapping[str, str]) -> ResolvedConnection:
    """Resolve connection options against the environment.

    Tier selection: an explicit ``socket_path`` and an explicit
    ``api_url`` are contradictory and rejected. At the environment level
    ``ARCBOX_API_URL`` wins over ``ARCBOX_SOCKET`` — setting it selects
    the remote tier.
    """
    options = options or Connection()
    if options.socket_path is not None and options.api_url is not None:
        raise InvalidArgumentError(
            "Connection.socket_path and Connection.api_url are mutually "
            "exclusive: a connection dials either the local Unix socket "
            "or a remote URL"
        )

    api_key = options.api_key if options.api_key is not None else env.get("ARCBOX_API_KEY")
    request_timeout = options.request_timeout

    if options.socket_path is not None:
        return ResolvedConnection(UDS_BASE_URL, options.socket_path, api_key, request_timeout)
    if options.api_url is not None:
        return ResolvedConnection(options.api_url, None, api_key, request_timeout)
    if env.get("ARCBOX_API_URL"):
        return ResolvedConnection(env["ARCBOX_API_URL"], None, api_key, request_timeout)
    socket_path = env.get("ARCBOX_SOCKET") or _default_socket_path(env)
    return ResolvedConnection(UDS_BASE_URL, socket_path, api_key, request_timeout)
