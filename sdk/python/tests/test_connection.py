"""Connection resolution: explicit option > environment > default.

Mirrors the TypeScript SDK's connection tests case for case.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arcbox._connection import UDS_BASE_URL, Connection, resolve_connection
from arcbox.errors import InvalidArgumentError


def test_defaults_to_home_arcbox_socket() -> None:
    conn = resolve_connection(None, {})
    assert conn.base_url == UDS_BASE_URL
    assert conn.socket_path == str(Path.home() / ".arcbox" / "run" / "arcbox.sock")
    assert conn.api_key is None


def test_data_dir_relocates_the_default_socket() -> None:
    conn = resolve_connection(None, {"ARCBOX_DATA_DIR": "/tmp/abx"})
    assert conn.socket_path == "/tmp/abx/run/arcbox.sock"


@pytest.mark.parametrize("profile", ["development", "dev", " Development "])
def test_profile_selects_arcbox_dev_like_the_daemon(profile: str) -> None:
    conn = resolve_connection(None, {"ARCBOX_PROFILE": profile})
    assert conn.socket_path == str(Path.home() / ".arcbox-dev" / "run" / "arcbox.sock")


def test_unknown_profiles_fall_back_to_production() -> None:
    conn = resolve_connection(None, {"ARCBOX_PROFILE": "staging"})
    assert conn.socket_path == str(Path.home() / ".arcbox" / "run" / "arcbox.sock")


def test_non_empty_data_dir_beats_the_profile_and_empty_is_unset() -> None:
    beats = resolve_connection(None, {"ARCBOX_DATA_DIR": "/tmp/abx", "ARCBOX_PROFILE": "dev"})
    assert beats.socket_path == "/tmp/abx/run/arcbox.sock"
    empty = resolve_connection(None, {"ARCBOX_DATA_DIR": "", "ARCBOX_PROFILE": "dev"})
    assert empty.socket_path == str(Path.home() / ".arcbox-dev" / "run" / "arcbox.sock")


def test_socket_env_overrides_the_data_dir_default() -> None:
    conn = resolve_connection(None, {"ARCBOX_DATA_DIR": "/tmp/abx", "ARCBOX_SOCKET": "/tmp/x.sock"})
    assert conn.socket_path == "/tmp/x.sock"


def test_explicit_socket_path_beats_every_environment_variable() -> None:
    conn = resolve_connection(
        Connection(socket_path="/opt/d.sock"),
        {"ARCBOX_SOCKET": "/tmp/x.sock", "ARCBOX_API_URL": "https://cloud.example"},
    )
    assert conn.socket_path == "/opt/d.sock"
    assert conn.base_url == UDS_BASE_URL


def test_api_url_env_selects_the_remote_tier_over_the_socket() -> None:
    conn = resolve_connection(
        None, {"ARCBOX_API_URL": "https://cloud.example", "ARCBOX_SOCKET": "/tmp/x.sock"}
    )
    assert conn.base_url == "https://cloud.example"
    assert conn.socket_path is None


def test_explicit_api_url_selects_the_remote_tier() -> None:
    conn = resolve_connection(Connection(api_url="https://cloud.example"), {})
    assert conn.base_url == "https://cloud.example"
    assert conn.socket_path is None


def test_rejects_socket_path_together_with_api_url() -> None:
    with pytest.raises(InvalidArgumentError):
        resolve_connection(
            Connection(socket_path="/tmp/x.sock", api_url="https://cloud.example"), {}
        )


def test_resolves_the_api_key_from_option_over_environment() -> None:
    assert resolve_connection(Connection(api_key="opt"), {"ARCBOX_API_KEY": "env"}).api_key == "opt"
    assert resolve_connection(None, {"ARCBOX_API_KEY": "env"}).api_key == "env"
