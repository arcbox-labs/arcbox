"""The ``sandbox.git`` namespace.

``e2b`` implements this as sugar over its command runner — its ``Git``
takes nothing but a ``Commands`` — so this shim does the same, shelling
out to the ``git`` already in the sandbox image. A sandbox without
``git`` surfaces the usual non-zero exit.
"""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from arcbox.e2b.errors import unsupported

if TYPE_CHECKING:
    from collections.abc import Sequence

    from arcbox.e2b._types import CommandResult

    from .commands import AsyncCommands


def _git(path: str, args: Sequence[str]) -> str:
    """``git -C <path> …``, the form every verb below uses."""
    return shlex.join(["git", "-C", path, *args])


class AsyncGit:
    """Run git operations inside one sandbox."""

    def __init__(self, commands: AsyncCommands) -> None:
        self._commands = commands

    async def clone(
        self,
        url: str,
        path: str,
        *,
        branch: str | None = None,
        depth: int | None = None,
    ) -> CommandResult:
        """Clone a repository."""
        args = ["git", "clone"]
        if branch is not None:
            args += ["--branch", branch]
        if depth is not None:
            args += ["--depth", str(depth)]
        args += [url, path]
        return await self._commands.run(shlex.join(args))

    async def init(self, path: str) -> CommandResult:
        """Initialize a repository."""
        return await self._commands.run(shlex.join(["git", "init", path]))

    async def remote_add(self, path: str, name: str, url: str) -> CommandResult:
        """Add a remote."""
        return await self._commands.run(_git(path, ["remote", "add", name, url]))

    async def remote_get(self, path: str, name: str) -> CommandResult:
        """Read a remote's URL."""
        return await self._commands.run(_git(path, ["remote", "get-url", name]))

    async def status(self, path: str) -> CommandResult:
        """Porcelain status of the working tree."""
        return await self._commands.run(_git(path, ["status", "--porcelain=v1"]))

    async def branches(self, path: str) -> tuple[str | None, list[str]]:
        """List branches, with the current one called out."""
        listing = await self._commands.run(_git(path, ["branch", "--format=%(refname:short)"]))
        branches = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
        head = await self._commands.run(_git(path, ["rev-parse", "--abbrev-ref", "HEAD"]))
        current = head.stdout.strip()
        return (current or None), branches

    async def create_branch(self, path: str, name: str) -> CommandResult:
        """Create a branch."""
        return await self._commands.run(_git(path, ["branch", name]))

    async def checkout_branch(self, path: str, name: str) -> CommandResult:
        """Check out a branch."""
        return await self._commands.run(_git(path, ["checkout", name]))

    async def delete_branch(self, path: str, name: str) -> CommandResult:
        """Delete a branch."""
        return await self._commands.run(_git(path, ["branch", "-D", name]))

    async def add(self, path: str, paths: Sequence[str] | None = None) -> CommandResult:
        """Stage paths (all of them when ``paths`` is empty)."""
        targets = list(paths) if paths else ["."]
        return await self._commands.run(_git(path, ["add", *targets]))

    async def commit(
        self, path: str, message: str, *, author: tuple[str, str] | None = None
    ) -> CommandResult:
        """Commit the staged tree."""
        args = ["commit", "-m", message]
        if author is not None:
            args += ["--author", f"{author[0]} <{author[1]}>"]
        return await self._commands.run(_git(path, args))

    async def push(
        self, path: str, remote: str = "origin", branch: str | None = None
    ) -> CommandResult:
        """Push to a remote."""
        args = ["push", remote]
        if branch is not None:
            args.append(branch)
        return await self._commands.run(_git(path, args))

    async def pull(
        self, path: str, remote: str = "origin", branch: str | None = None
    ) -> CommandResult:
        """Pull from a remote."""
        args = ["pull", remote]
        if branch is not None:
            args.append(branch)
        return await self._commands.run(_git(path, args))

    async def set_config(
        self, path: str, key: str, value: str, *, scope: str = "local"
    ) -> CommandResult:
        """Set a config value in the given scope (default ``local``)."""
        flag = "--global" if scope == "global" else "--local"
        return await self._commands.run(_git(path, ["config", flag, key, value]))

    async def get_config(self, path: str, key: str) -> CommandResult:
        """Read a config value."""
        return await self._commands.run(_git(path, ["config", "--get", key]))

    async def configure_user(self, path: str, name: str, email: str) -> CommandResult:
        """Set ``user.name`` and ``user.email`` for the repository."""
        await self.set_config(path, "user.name", name)
        return await self.set_config(path, "user.email", email)

    def dangerously_authenticate(self, *args: object, **kwargs: object) -> None:
        """Unsupported: ``e2b`` stores the credential in its cloud
        credential helper, which has no local counterpart.

        Configure a credential helper or an SSH key inside the sandbox
        instead — ``git`` there is an ordinary program."""
        del args, kwargs
        unsupported(
            "git.dangerously_authenticate",
            "there is no cloud credential store; configure git credentials inside the sandbox",
        )
