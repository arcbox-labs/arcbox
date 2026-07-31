# Sandbox image for Claude Code.
#
# Pinned deliberately: the image tag is a hash of this file, so bumping the
# version below is what invalidates both the Docker build cache and the
# exported image layout.
#
# Debian rather than Alpine: the npm package resolves a per-platform native
# binary through optional dependencies, and the musl variants additionally
# need libgcc/libstdc++/ripgrep wired up by hand.
FROM node:22-slim

# git is what the agent uses to get code in and out of the sandbox; ripgrep is
# what it searches with; ca-certificates is required for TLS to the API.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        less \
        procps \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Optional dependencies must stay enabled: this package ships the CLI as a
# per-platform native binary (…-linux-arm64) resolved that way, with no
# JavaScript fallback if it is skipped.
RUN npm install -g @anthropic-ai/claude-code@2.1.220

# Claude Code refuses to skip permission prompts while running as root, and
# skipping them is the point of running inside a microVM. The node images
# already ship a uid-1000 `node` user, so reuse it rather than adding a second
# one (useradd --uid 1000 would fail with "UID already in use").
RUN mkdir -p /workspace && chown node:node /workspace

# Only the filesystem is converted into the sandbox rootfs — image config is
# not carried over, so USER/WORKDIR/ENV here document intent and keep
# `docker run` on this image usable. The sandbox identity, working directory
# and environment are set per session by the caller.
USER node
WORKDIR /workspace
