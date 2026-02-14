#!/bin/bash
# Setup development boot assets
# This script ensures that development boot assets are available locally

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEV_BOOT_DIR="$PROJECT_DIR/boot-assets/dev"
USER_BOOT_DIR="$HOME/.arcbox/boot/0.0.1-alpha.2"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_dev_assets() {
    if [[ -f "$DEV_BOOT_DIR/kernel" ]] && [[ -f "$DEV_BOOT_DIR/initramfs.cpio.gz" ]]; then
        return 0
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

    # Prefer bak7 initramfs if available (known working version)
    if [[ -f "$USER_BOOT_DIR/initramfs.cpio.gz.bak7" ]]; then
        cp "$USER_BOOT_DIR/initramfs.cpio.gz.bak7" "$DEV_BOOT_DIR/initramfs.cpio.gz"
        log_info "Copied initramfs (bak7 - known working)"
    elif [[ -f "$USER_BOOT_DIR/initramfs.cpio.gz" ]]; then
        cp "$USER_BOOT_DIR/initramfs.cpio.gz" "$DEV_BOOT_DIR/"
        log_warn "Copied current initramfs (may not be stable)"
    else
        log_error "Initramfs not found in user cache"
        return 1
    fi

    return 0
}

print_info() {
    echo ""
    echo "Development Boot Assets"
    echo "======================="
    echo "Location: $DEV_BOOT_DIR"
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

    if setup_from_user_cache; then
        log_info "Development boot assets ready"
        print_info
        exit 0
    fi

    log_error "Failed to setup development boot assets"
    exit 1
}

main "$@"
