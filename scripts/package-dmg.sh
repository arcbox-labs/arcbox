#!/usr/bin/env bash
# package-dmg.sh — Build ArcBox.app + DMG from Rust daemon + Swift desktop
#
# Usage:
#   scripts/package-dmg.sh [--sign IDENTITY] [--notarize]
#
# Environment:
#   DESKTOP_REPO       Path to arcbox-desktop-swift repo (default: ../arcbox-desktop-swift)
#   BOOT_ASSET_DIR     Pre-downloaded boot-assets directory (optional)
#   BOOT_ASSET_VERSION Override boot-asset version (default: from boot-assets.lock)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCBOX_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
DESKTOP_REPO="${DESKTOP_REPO:-$(cd "$ARCBOX_DIR/../arcbox-desktop-swift" 2>/dev/null && pwd || echo "")}"
SIGN_IDENTITY=""
NOTARIZE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign)
            SIGN_IDENTITY="$2"; shift 2 ;;
        --notarize)
            NOTARIZE=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--sign IDENTITY] [--notarize]"
            echo "Env: DESKTOP_REPO, BOOT_ASSET_DIR, BOOT_ASSET_VERSION"
            exit 0 ;;
        *)
            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Validate
if [[ -z "$DESKTOP_REPO" || ! -d "$DESKTOP_REPO" ]]; then
    echo "Error: arcbox-desktop-swift repo not found." >&2
    echo "Set DESKTOP_REPO or place it at ../arcbox-desktop-swift" >&2
    exit 1
fi

# Read boot-asset version from lock file
BOOT_LOCK="$ARCBOX_DIR/boot-assets.lock"
if [[ -z "${BOOT_ASSET_VERSION:-}" ]]; then
    BOOT_ASSET_VERSION=$(grep '^version' "$BOOT_LOCK" | sed 's/.*= *"\(.*\)"/\1/')
fi
echo "==> Boot-asset version: $BOOT_ASSET_VERSION"

# Determine build directory
BUILD_DIR="$ARCBOX_DIR/target/dmg-staging"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

DAEMON_NAME="io.arcbox.desktop.daemon"
ENTITLEMENTS="$ARCBOX_DIR/tests/resources/entitlements.plist"

# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Build Rust binaries
# ──────────────────────────────────────────────────────────────────────────────
echo "==> Building Rust binaries (release)..."
cargo build --release --locked -p arcbox-cli -p arcbox-daemon --manifest-path "$ARCBOX_DIR/Cargo.toml"

RUST_RELEASE="$ARCBOX_DIR/target/release"

# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Build Swift app
# ──────────────────────────────────────────────────────────────────────────────
echo "==> Building Swift app..."
XCODE_BUILD_DIR="$BUILD_DIR/xcode-build"

# Build without code signing — we'll sign everything together at the end
xcodebuild build \
    -project "$DESKTOP_REPO/arcbox-desktop-swift.xcodeproj" \
    -scheme "arcbox-desktop-swift" \
    -configuration Release \
    -derivedDataPath "$XCODE_BUILD_DIR" \
    CODE_SIGN_IDENTITY=- \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGNING_ALLOWED=NO \
    ARCBOX_SKIP_RUST_BUILD=1 \
    ENABLE_USER_SCRIPT_SANDBOXING=NO \
    2>&1 | tail -5

# Find the .app
APP_PATH=$(find "$XCODE_BUILD_DIR" -name "ArcBox Desktop.app" -type d | head -1)
if [[ -z "$APP_PATH" ]]; then
    echo "Error: ArcBox Desktop.app not found in build output" >&2
    exit 1
fi
echo "==> Built app at: $APP_PATH"

# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Assemble the app bundle
# ──────────────────────────────────────────────────────────────────────────────
echo "==> Assembling app bundle..."

HELPERS_DIR="$APP_PATH/Contents/Helpers"
RESOURCES_DIR="$APP_PATH/Contents/Resources"
mkdir -p "$HELPERS_DIR" "$RESOURCES_DIR"

# Copy Rust daemon as the SMAppService-expected name
cp -f "$RUST_RELEASE/arcbox-daemon" "$HELPERS_DIR/$DAEMON_NAME"

# Copy Rust CLI
cp -f "$RUST_RELEASE/arcbox" "$HELPERS_DIR/arcbox"

# Copy boot-assets.lock into Resources
cp -f "$BOOT_LOCK" "$RESOURCES_DIR/boot-assets.lock"

# ──────────────────────────────────────────────────────────────────────────────
# Step 4: Embed boot-assets
# ──────────────────────────────────────────────────────────────────────────────
BOOT_DEST="$RESOURCES_DIR/boot/$BOOT_ASSET_VERSION"
mkdir -p "$BOOT_DEST"

if [[ -n "${BOOT_ASSET_DIR:-}" && -d "$BOOT_ASSET_DIR" ]]; then
    echo "==> Copying boot-assets from $BOOT_ASSET_DIR..."
    cp -f "$BOOT_ASSET_DIR"/* "$BOOT_DEST/"
elif [[ -d "$ARCBOX_DIR/boot-assets/dev" ]]; then
    echo "==> Copying boot-assets from dev directory..."
    cp -f "$ARCBOX_DIR/boot-assets/dev"/* "$BOOT_DEST/"
else
    echo "==> Downloading boot-assets via CLI..."
    "$RUST_RELEASE/arcbox" boot prefetch --asset-version "$BOOT_ASSET_VERSION"
    CACHE_DIR="$HOME/.arcbox/boot/$BOOT_ASSET_VERSION"
    if [[ -d "$CACHE_DIR" ]]; then
        cp -f "$CACHE_DIR"/* "$BOOT_DEST/"
    else
        echo "Warning: boot-assets not found after prefetch" >&2
    fi
fi

echo "==> Boot-assets embedded:"
ls -lh "$BOOT_DEST/" 2>/dev/null || echo "  (none)"

# ──────────────────────────────────────────────────────────────────────────────
# Step 5: Sign inner binaries (must happen before create-dmg signs the .app)
# ──────────────────────────────────────────────────────────────────────────────
echo "==> Signing inner binaries..."

if [[ -n "$SIGN_IDENTITY" ]]; then
    SIGN_FLAGS=(--force --options runtime --sign "$SIGN_IDENTITY" --timestamp)
else
    SIGN_FLAGS=(--force --sign -)
fi

# Daemon needs the virtualization entitlement
codesign "${SIGN_FLAGS[@]}" \
    --identifier "$DAEMON_NAME" \
    --entitlements "$ENTITLEMENTS" \
    "$HELPERS_DIR/$DAEMON_NAME"

# CLI
codesign "${SIGN_FLAGS[@]}" \
    --identifier "io.arcbox.cli" \
    "$HELPERS_DIR/arcbox"

# Frameworks (if any)
if [[ -d "$APP_PATH/Contents/Frameworks" ]]; then
    find "$APP_PATH/Contents/Frameworks" \( -name "*.dylib" -o -name "*.framework" \) | while read -r fw; do
        codesign "${SIGN_FLAGS[@]}" "$fw"
    done
fi

# Sign the .app itself
codesign "${SIGN_FLAGS[@]}" "$APP_PATH"

echo "==> Verifying signature..."
codesign --verify --deep --strict "$APP_PATH"

# ──────────────────────────────────────────────────────────────────────────────
# Step 6: Create DMG via create-dmg
# ──────────────────────────────────────────────────────────────────────────────

# Ensure create-dmg is available
if ! command -v create-dmg &>/dev/null; then
    echo "==> Installing create-dmg..."
    brew install create-dmg
fi

APP_NAME="$(basename "$APP_PATH")"
CARGO_VERSION=$(grep '^version' "$ARCBOX_DIR/Cargo.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')
DMG_NAME="ArcBox-${CARGO_VERSION}-arm64.dmg"
DMG_PATH="$ARCBOX_DIR/target/$DMG_NAME"

# Stage the .app in a clean directory (create-dmg uses srcfolder contents)
DMG_STAGING="$BUILD_DIR/dmg-content"
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"
cp -R "$APP_PATH" "$DMG_STAGING/"

echo "==> Creating DMG..."

# Build create-dmg flags
CREATE_DMG_FLAGS=(
    --volname "ArcBox"
    --window-size 600 400
    --icon-size 100
    --icon "$APP_NAME" 150 190
    --app-drop-link 450 190
    --hide-extension "$APP_NAME"
    --no-internet-enable
)

if [[ -n "$SIGN_IDENTITY" ]]; then
    CREATE_DMG_FLAGS+=(--codesign "$SIGN_IDENTITY")
fi

if [[ "$NOTARIZE" == true && -n "$SIGN_IDENTITY" ]]; then
    CREATE_DMG_FLAGS+=(--notarize "arcbox-notarize")
fi

# Remove old DMG if it exists (create-dmg won't overwrite)
rm -f "$DMG_PATH"

create-dmg "${CREATE_DMG_FLAGS[@]}" "$DMG_PATH" "$DMG_STAGING"

echo "==> Done!"
echo "    DMG: $DMG_PATH"
echo "    Size: $(ls -lh "$DMG_PATH" | awk '{print $5}')"
echo "    SHA256: $(shasum -a 256 "$DMG_PATH" | cut -d' ' -f1)"
