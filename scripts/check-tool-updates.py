#!/usr/bin/env python3
"""Check for Docker toolchain updates and patch assets.lock.

Compares pinned versions in assets.lock against upstream releases, downloads
both architectures to compute SHA-256, and rewrites the lockfile in-place.

Outputs a Markdown summary to stdout.  Exit code 0 = updates applied,
exit code 2 = already up to date, exit code 1 = error.

Usage:
    python3 scripts/check-tool-updates.py          # uses GH_TOKEN env
    GH_TOKEN=ghp_xxx python3 scripts/check-tool-updates.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.request

# Network timeout in seconds (per request, not total).
HTTP_TIMEOUT = 60

if sys.version_info < (3, 11):
    sys.exit("Python 3.11+ required (tomllib)")

import tomllib

LOCKFILE = "assets.lock"

# Each tool: (lockfile name, upstream version source, URL templates per arch).
# URL templates use {version} placeholder.
TOOLS: list[dict] = [
    {
        "name": "docker",
        "repo": "moby/moby",
        "urls": {
            "arm64": "https://download.docker.com/mac/static/stable/aarch64/docker-{version}.tgz",
            "x86_64": "https://download.docker.com/mac/static/stable/x86_64/docker-{version}.tgz",
        },
    },
    {
        "name": "docker-buildx",
        "repo": "docker/buildx",
        "urls": {
            "arm64": "https://github.com/docker/buildx/releases/download/v{version}/buildx-v{version}.darwin-arm64",
            "x86_64": "https://github.com/docker/buildx/releases/download/v{version}/buildx-v{version}.darwin-amd64",
        },
    },
    {
        "name": "docker-compose",
        "repo": "docker/compose",
        "urls": {
            "arm64": "https://github.com/docker/compose/releases/download/v{version}/docker-compose-darwin-aarch64",
            "x86_64": "https://github.com/docker/compose/releases/download/v{version}/docker-compose-darwin-x86_64",
        },
    },
    {
        "name": "docker-credential-osxkeychain",
        "repo": "docker/docker-credential-helpers",
        "urls": {
            "arm64": "https://github.com/docker/docker-credential-helpers/releases/download/v{version}/docker-credential-osxkeychain-v{version}.darwin-arm64",
            "x86_64": "https://github.com/docker/docker-credential-helpers/releases/download/v{version}/docker-credential-osxkeychain-v{version}.darwin-amd64",
        },
    },
    {
        "name": "kubectl",
        "repo": None,  # uses dl.k8s.io/release/stable.txt
        "urls": {
            "arm64": "https://dl.k8s.io/release/v{version}/bin/darwin/arm64/kubectl",
            "x86_64": "https://dl.k8s.io/release/v{version}/bin/darwin/amd64/kubectl",
        },
    },
]


def gh_api(path: str) -> dict:
    """Call GitHub API with token from GH_TOKEN env."""
    token = os.environ.get("GH_TOKEN", "")
    req = urllib.request.Request(
        f"https://api.github.com/{path}",
        headers={
            "Accept": "application/vnd.github+json",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read())


def latest_version(tool: dict) -> str:
    """Fetch the latest stable version for a tool."""
    if tool["repo"] is None:
        # kubectl: plain text endpoint
        with urllib.request.urlopen(
            "https://dl.k8s.io/release/stable.txt", timeout=HTTP_TIMEOUT
        ) as resp:
            return resp.read().decode().strip().lstrip("v")
    data = gh_api(f"repos/{tool['repo']}/releases/latest")
    return data["tag_name"].lstrip("v")


def sha256_url(url: str) -> str:
    """Download a URL and return its SHA-256 hex digest."""
    req = urllib.request.Request(url)
    h = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        while chunk := resp.read(1 << 16):
            h.update(chunk)
    return h.hexdigest()


def current_versions(lockfile: str) -> dict[str, str]:
    """Parse assets.lock and return {name: version} for all tools."""
    with open(lockfile, "rb") as f:
        data = tomllib.load(f)
    return {t["name"]: t["version"] for t in data.get("tools", [])}


def update_lockfile(lockfile: str, name: str, version: str, arm_sha: str, x86_sha: str) -> None:
    """Rewrite a single tool entry in assets.lock, preserving comments."""
    text = open(lockfile).read()
    pat = (
        r"(\[\[tools\]\]\nname = \"" + re.escape(name) + r"\"\ngroup = \"[^\"]+\"\n)"
        r"version = \"[^\"]+\"\n"
        r"arch\.arm64\.sha256 = \"[^\"]+\"\n"
        r"arch\.x86_64\.sha256 = \"[^\"]+\""
    )
    repl = (
        rf'\g<1>version = "{version}"\n'
        rf'arch.arm64.sha256 = "{arm_sha}"\n'
        rf'arch.x86_64.sha256 = "{x86_sha}"'
    )
    text, n = re.subn(pat, repl, text)
    if n != 1:
        sys.exit(f"ERROR: expected 1 replacement for {name}, got {n}")
    with open(lockfile, "w") as f:
        f.write(text)


def main() -> None:
    cur_versions = current_versions(LOCKFILE)
    updates: list[str] = []

    for tool in TOOLS:
        name = tool["name"]
        cur = cur_versions.get(name)
        if cur is None:
            print(f"  {name}: not found in {LOCKFILE}, skipping", file=sys.stderr)
            continue

        new = latest_version(tool)
        if cur == new:
            print(f"  {name}: {cur} (up to date)", file=sys.stderr)
            continue

        print(f"  {name}: {cur} -> {new}  (downloading checksums...)", file=sys.stderr)
        arm_sha = sha256_url(tool["urls"]["arm64"].format(version=new))
        x86_sha = sha256_url(tool["urls"]["x86_64"].format(version=new))
        update_lockfile(LOCKFILE, name, new, arm_sha, x86_sha)
        updates.append(f"- `{name}`: {cur} -> {new}")

    if not updates:
        print("All tools are up to date.", file=sys.stderr)
        sys.exit(2)

    # Print Markdown summary to stdout (consumed by the workflow).
    print("\n".join(updates))


if __name__ == "__main__":
    main()
