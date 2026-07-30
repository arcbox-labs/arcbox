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
# skipping them is the point of running inside a microVM.
RUN useradd --create-home --uid 1000 --shell /bin/bash agent \
    && mkdir -p /workspace \
    && chown agent:agent /workspace

USER agent
WORKDIR /workspace
