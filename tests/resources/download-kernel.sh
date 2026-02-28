#!/bin/bash
# Downloads a minimal ARM64 Linux kernel for LOCAL DEVELOPMENT AND TESTING ONLY.
# Uses Alpine Linux's kernel as it's small and fast to boot.
#
# NOTE: This script is NOT used in production boot flow.
# Production boot assets are built and released from the arcbox-labs/boot-assets
# repository and consumed via `arcbox boot prefetch`. See PLAN.md for details.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="${SCRIPT_DIR}"
KERNEL_VERSION="6.6.63-0-lts"
KERNEL_URL="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/netboot/vmlinuz-lts"

echo "Downloading ARM64 Linux kernel for testing..."

# Download kernel
if [ ! -f "${KERNEL_DIR}/vmlinuz-arm64" ]; then
    echo "Downloading kernel..."
    curl -L -o "${KERNEL_DIR}/vmlinuz-arm64" "${KERNEL_URL}"
    echo "Kernel downloaded to ${KERNEL_DIR}/vmlinuz-arm64"
else
    echo "Kernel already exists at ${KERNEL_DIR}/vmlinuz-arm64"
fi

echo "Done! Test resources ready."
echo ""
echo "Kernel: ${KERNEL_DIR}/vmlinuz-arm64"
