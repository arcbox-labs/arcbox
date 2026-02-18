#!/bin/bash
# Setup development boot assets
# This script ensures that development boot assets are available locally

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEV_BOOT_DIR="$PROJECT_DIR/boot-assets/dev"
KERNEL_REPO_DIR="${ARCBOX_KERNEL_DIR:-$PROJECT_DIR/../arcbox-kernel}"
KERNEL_OUTPUT_DIR="$KERNEL_REPO_DIR/output"
BOOT_ASSET_VERSION_DEFAULT="$(awk -F '\"' '/pub const BOOT_ASSET_VERSION/ {print $2; exit}' "$PROJECT_DIR/crates/arcbox-core/src/boot_assets.rs")"
if [[ -z "$BOOT_ASSET_VERSION_DEFAULT" ]]; then
    echo "Failed to resolve BOOT_ASSET_VERSION from crates/arcbox-core/src/boot_assets.rs" >&2
    exit 1
fi
BOOT_ASSET_VERSION="${ARCBOX_BOOT_ASSET_VERSION:-$BOOT_ASSET_VERSION_DEFAULT}"
if [[ "$OSTYPE" == darwin* ]]; then
    DEFAULT_DATA_DIR="$HOME/Library/Application Support/arcbox"
else
    DEFAULT_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/arcbox"
fi
DATA_DIR="${ARCBOX_DATA_DIR:-$DEFAULT_DATA_DIR}"
USER_BOOT_DIR="$DATA_DIR/boot/$BOOT_ASSET_VERSION"
BOOT_SOURCE="${ARCBOX_DEV_BOOT_SOURCE:-release}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

setup_from_kernel_repo() {
    log_info "Looking for boot assets in arcbox-kernel output..."

    if [[ ! -d "$KERNEL_REPO_DIR" ]]; then
        log_warn "arcbox-kernel repo not found: $KERNEL_REPO_DIR"
        return 1
    fi

    if [[ ! -f "$KERNEL_OUTPUT_DIR/kernel-arm64" ]] || [[ ! -f "$KERNEL_OUTPUT_DIR/initramfs-arm64.cpio.gz" ]]; then
        log_warn "arcbox-kernel output incomplete: $KERNEL_OUTPUT_DIR"
        log_warn "Expected: kernel-arm64 + initramfs-arm64.cpio.gz"
        return 1
    fi

    mkdir -p "$DEV_BOOT_DIR"
    cp "$KERNEL_OUTPUT_DIR/kernel-arm64" "$DEV_BOOT_DIR/kernel"
    cp "$KERNEL_OUTPUT_DIR/initramfs-arm64.cpio.gz" "$DEV_BOOT_DIR/initramfs.cpio.gz"
    if [[ -f "$KERNEL_OUTPUT_DIR/manifest.json" ]]; then
        cp "$KERNEL_OUTPUT_DIR/manifest.json" "$DEV_BOOT_DIR/manifest.json"
        log_info "Copied manifest.json from arcbox-kernel output"
    fi

    log_info "Copied kernel/initramfs from arcbox-kernel output"
    return 0
}

check_dev_assets() {
    if [[ -f "$DEV_BOOT_DIR/kernel" ]] && [[ -f "$DEV_BOOT_DIR/initramfs.cpio.gz" ]] && [[ -f "$DEV_BOOT_DIR/manifest.json" ]]; then
        if grep -Eq "\"asset_version\"[[:space:]]*:[[:space:]]*\"$BOOT_ASSET_VERSION\"" "$DEV_BOOT_DIR/manifest.json"; then
            return 0
        fi
        log_warn "Dev manifest version does not match expected $BOOT_ASSET_VERSION, refreshing..."
    fi
    return 1
}

setup_from_user_cache() {
    log_info "Looking for boot assets in user cache..."

    if [[ ! -d "$USER_BOOT_DIR" ]]; then
        log_error "User boot cache not found: $USER_BOOT_DIR"
        log_error "Please run 'arcbox daemon' first to download boot assets"
        return 1
    fi

    mkdir -p "$DEV_BOOT_DIR"

    # Copy kernel
    if [[ -f "$USER_BOOT_DIR/kernel" ]]; then
        cp "$USER_BOOT_DIR/kernel" "$DEV_BOOT_DIR/"
        log_info "Copied kernel"
    else
        log_error "Kernel not found in user cache"
        return 1
    fi

    if [[ -f "$USER_BOOT_DIR/initramfs.cpio.gz" ]]; then
        cp "$USER_BOOT_DIR/initramfs.cpio.gz" "$DEV_BOOT_DIR/"
        log_info "Copied initramfs"
    else
        log_error "Initramfs not found in user cache"
        return 1
    fi

    if [[ -f "$USER_BOOT_DIR/manifest.json" ]]; then
        cp "$USER_BOOT_DIR/manifest.json" "$DEV_BOOT_DIR/manifest.json"
        log_info "Copied manifest.json"
    else
        log_error "manifest.json not found in user cache"
        log_error "Run: arcbox boot prefetch --force"
        return 1
    fi

    return 0
}

print_info() {
    echo ""
    echo "Development Boot Assets"
    echo "======================="
    echo "Location: $DEV_BOOT_DIR"
    echo "Version:  $BOOT_ASSET_VERSION"
    echo "Source:   $BOOT_SOURCE"
    echo ""

    if [[ -f "$DEV_BOOT_DIR/kernel" ]]; then
        local kernel_size
        kernel_size=$(ls -lh "$DEV_BOOT_DIR/kernel" | awk '{print $5}')
        echo "Kernel:     $kernel_size"
    fi

    if [[ -f "$DEV_BOOT_DIR/initramfs.cpio.gz" ]]; then
        local initramfs_size
        initramfs_size=$(ls -lh "$DEV_BOOT_DIR/initramfs.cpio.gz" | awk '{print $5}')
        echo "Initramfs:  $initramfs_size"
    fi
    if [[ -f "$DEV_BOOT_DIR/manifest.json" ]]; then
        echo "Manifest:   $(ls -lh "$DEV_BOOT_DIR/manifest.json" | awk '{print $5}')"
    else
        echo "Manifest:   missing"
    fi

    echo ""
    echo "These assets are used by test scripts and will not be"
    echo "automatically updated. To update, delete the files and"
    echo "run this script again."
    echo ""
}

main() {
    echo "================================"
    echo "ArcBox Dev Boot Assets Setup"
    echo "================================"
    echo ""

    if check_dev_assets; then
        log_info "Development boot assets already exist"
        print_info
        exit 0
    fi

    log_info "Setting up development boot assets..."

    case "$BOOT_SOURCE" in
        release)
            if setup_from_user_cache; then
                log_info "Development boot assets ready"
                print_info
                exit 0
            fi
            ;;
        kernel-output)
            if setup_from_kernel_repo; then
                log_info "Development boot assets ready"
                print_info
                exit 0
            fi
            ;;
        *)
            log_error "Invalid ARCBOX_DEV_BOOT_SOURCE: $BOOT_SOURCE"
            log_error "Expected one of: release, kernel-output"
            exit 1
            ;;
    esac

    log_error "Failed to setup development boot assets"
    exit 1
}

main "$@"
