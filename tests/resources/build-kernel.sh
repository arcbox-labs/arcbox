#!/bin/bash
# Build Linux kernel with Firecracker microvm config for ARM64
# Uses Docker (Alpine) to cross-compile

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_VERSION="6.1.115"
OUTPUT="${SCRIPT_DIR}/Image-microvm"

echo "=== Building Linux Kernel with microvm config ==="
echo "Version: $KERNEL_VERSION"

# Build in Docker using Alpine
docker run --rm -v "$SCRIPT_DIR:/out" -w /build alpine:latest sh -c "
set -e
apk add --no-cache build-base bc bison flex openssl-dev elfutils-dev perl curl xz cpio linux-headers

# Install cross-compiler for aarch64
apk add --no-cache gcc-aarch64-none-elf || apk add --no-cache aarch64-none-elf-gcc || {
    # If no cross-compiler, use native (works on ARM64 hosts)
    echo 'No cross-compiler, using native build'
    export CROSS_COMPILE=''
}

# Download kernel
echo 'Downloading kernel...'
curl -sL https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz | tar -xJ
cd linux-${KERNEL_VERSION}

# Download Firecracker microvm config
echo 'Downloading microvm config...'
curl -sL 'https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/guest_configs/microvm-kernel-ci-aarch64-6.1.config' -o .config

# Enable virtio PCI (required for Virtualization.framework)
cat >> .config << 'EOF'
CONFIG_PCI=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_PCI_MODERN=y
CONFIG_VIRTIO_PCI_MODERN_DEV=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_HVC_DRIVER=y
CONFIG_VSOCK=y
CONFIG_VIRTIO_VSOCK=y
EOF

# Update config
make ARCH=arm64 CROSS_COMPILE=\${CROSS_COMPILE:-aarch64-none-elf-} olddefconfig

# Build
echo 'Building kernel...'
make ARCH=arm64 CROSS_COMPILE=\${CROSS_COMPILE:-aarch64-none-elf-} -j\$(nproc) Image

# Copy output
cp arch/arm64/boot/Image /out/Image-microvm
echo 'Kernel built successfully!'
"

ls -lh "$OUTPUT"
echo "Done: $OUTPUT"
