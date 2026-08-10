"""The sync tree is a mechanical mirror of the async core.

Two independent guards (both CI-enforced):

1. Lockstep — rerunning the unasync transform reproduces the committed
   `arcbox/_sync` byte for byte, so the tree cannot drift silently.
2. Surface parity — every public class pair exposes identical method
   sets and signatures modulo async markers, catching skew even if a
   file escaped the transform.
"""

from __future__ import annotations

import inspect
import subprocess
import sys
from pathlib import Path

import pytest

from arcbox import (
    ArcBox,
    AsyncArcBox,
    AsyncCommandHandle,
    AsyncCommands,
    AsyncConnectClient,
    AsyncEventStream,
    AsyncFiles,
    AsyncOutputStream,
    AsyncSandbox,
    CommandHandle,
    Commands,
    ConnectClient,
    EventStream,
    Files,
    OutputStream,
    Sandbox,
    e2b,
)

SDK_ROOT = Path(__file__).resolve().parent.parent

PAIRS = [
    (AsyncArcBox, ArcBox),
    (AsyncSandbox, Sandbox),
    (AsyncCommands, Commands),
    (AsyncCommandHandle, CommandHandle),
    (AsyncOutputStream, OutputStream),
    (AsyncEventStream, EventStream),
    (AsyncFiles, Files),
    (AsyncConnectClient, ConnectClient),
    # The e2b compatibility surface mirrors through the same transform.
    (e2b.AsyncSandbox, e2b.Sandbox),
    (e2b.AsyncCommands, e2b.Commands),
    (e2b.AsyncCommandHandle, e2b.CommandHandle),
    (e2b.AsyncPty, e2b.Pty),
    (e2b.AsyncFilesystem, e2b.Filesystem),
    (e2b.AsyncWatchHandle, e2b.WatchHandle),
    (e2b.AsyncGit, e2b.Git),
]


def test_sync_tree_is_in_lockstep_with_the_async_core() -> None:
    result = subprocess.run(
        [sys.executable, str(SDK_ROOT / "scripts" / "gen_sync.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"sync tree drifted:\n{result.stdout}{result.stderr}"


def _public_members(cls: type) -> dict[str, object]:
    return {
        name: member
        for name, member in inspect.getmembers(cls)
        if not name.startswith("_") or name in ("__enter__", "__exit__", "__aenter__", "__aexit__")
    }


def _normalize(signature: inspect.Signature) -> str:
    return str(signature).replace("Async", "")


def _normalize_name(name: str) -> str:
    return (
        name.replace("__aenter__", "__enter__")
        .replace("__aexit__", "__exit__")
        .replace("aclose", "close")
    )


@pytest.mark.parametrize(("async_cls", "sync_cls"), PAIRS, ids=lambda cls: cls.__name__)
def test_public_surfaces_are_identical_modulo_async_markers(
    async_cls: type, sync_cls: type
) -> None:
    async_members = _public_members(async_cls)
    sync_members = _public_members(sync_cls)
    assert sorted(_normalize_name(n) for n in async_members) == sorted(sync_members)

    for name, member in async_members.items():
        counterpart = sync_members[_normalize_name(name)]
        if isinstance(member, property):
            assert isinstance(counterpart, property), name
            assert member.fget is not None and counterpart.fget is not None
            assert _normalize(inspect.signature(member.fget)) == _normalize(
                inspect.signature(counterpart.fget)
            ), name
        elif callable(member) and callable(counterpart):
            assert _normalize(inspect.signature(member)) == _normalize(
                inspect.signature(counterpart)
            ), name


def test_the_sync_flavor_has_no_coroutine_methods() -> None:
    for _async_cls, sync_cls in PAIRS:
        for name, member in inspect.getmembers(sync_cls, inspect.isfunction):
            assert not inspect.iscoroutinefunction(member), f"{sync_cls.__name__}.{name}"
