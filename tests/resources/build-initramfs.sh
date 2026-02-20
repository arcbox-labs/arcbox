#!/usr/bin/env bash
# Wrapper: delegates to the canonical initramfs build script in arcbox-labs/boot-assets.
#
# Local dev: auto-detects the sibling boot-assets repo (arcboxd/boot-assets).
# CI: set BOOT_ASSETS_DIR to the checked-out boot-assets repository path.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -n "${BOOT_ASSETS_DIR:-}" ]]; then
    BOOT_ASSETS="$BOOT_ASSETS_DIR"
else
    # Local dev layout: arcboxd/arcbox/tests/resources -> arcboxd/boot-assets
    BOOT_ASSETS="$(cd "$SCRIPT_DIR/../../../boot-assets" && pwd)"
fi

if [[ ! -f "$BOOT_ASSETS/scripts/build-initramfs.sh" ]]; then
    echo "error: boot-assets not found at $BOOT_ASSETS" >&2
    echo "  Set BOOT_ASSETS_DIR or checkout arcbox-labs/boot-assets as a sibling repo." >&2
    exit 1
fi

exec "$BOOT_ASSETS/scripts/build-initramfs.sh" \
    --agent-bin      "$SCRIPT_DIR/../../target/aarch64-unknown-linux-musl/release/arcbox-agent" \
    --base-initramfs "$SCRIPT_DIR/initramfs-arm64" \
    --modloop        "$SCRIPT_DIR/modloop-lts" \
    --output         "$SCRIPT_DIR/initramfs-arcbox"
