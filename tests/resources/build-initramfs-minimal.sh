#!/bin/bash
# Build minimal initramfs with arcbox-agent for microvm kernel
# No external modules needed - virtio drivers are built-in

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_BIN="${SCRIPT_DIR}/../../target/aarch64-unknown-linux-musl/release/arcbox-agent"
OUTPUT="${SCRIPT_DIR}/initramfs-microvm"
WORK_DIR="/tmp/initramfs-microvm-$$"

echo "=== Building Minimal Initramfs ==="

if [ ! -f "$AGENT_BIN" ]; then
    echo "Error: Agent binary not found at $AGENT_BIN"
    echo "Build it with: cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release"
    exit 1
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"/{bin,sbin,dev,proc,sys,etc,tmp}

# Copy agent
cp "$AGENT_BIN" "$WORK_DIR/sbin/arcbox-agent"
chmod 755 "$WORK_DIR/sbin/arcbox-agent"

# Create minimal /dev nodes (kernel will populate via devtmpfs)
cd "$WORK_DIR/dev"
mknod -m 622 console c 5 1 2>/dev/null || true
mknod -m 666 null c 1 3 2>/dev/null || true

# Create init script
cat > "$WORK_DIR/init" << 'EOF'
#!/bin/sh
# Minimal init for ArcBox microvm

# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Set hostname
hostname arcbox-vm

# Boot message
echo "=================================="
echo "  ArcBox VM (microvm kernel)"
echo "=================================="
echo "Kernel: $(uname -r)"
echo ""

# Check virtio console
if [ -e /dev/hvc0 ]; then
    echo "Console: /dev/hvc0 available"
else
    echo "Console: /dev/hvc0 NOT found"
    ls -la /dev/hvc* /dev/tty* 2>/dev/null | head -5
fi

# Check vsock
if [ -e /dev/vsock ]; then
    echo "Vsock: /dev/vsock available"
else
    echo "Vsock: /dev/vsock NOT found (checking /dev/vhost-vsock...)"
    if [ -e /dev/vhost-vsock ]; then
        echo "  Found /dev/vhost-vsock"
    fi
fi
echo ""

# Show loaded modules (should be empty - everything is built-in)
echo "Modules:"
cat /proc/modules 2>/dev/null | head -5 || echo "  (none - all built-in)"
echo ""

# Start agent
echo "Starting arcbox-agent on vsock port 1024..."
echo "=================================="
exec /sbin/arcbox-agent
EOF
chmod 755 "$WORK_DIR/init"

# Build cpio archive
cd "$WORK_DIR"
find . | cpio -o -H newc 2>/dev/null | gzip > "$OUTPUT"

rm -rf "$WORK_DIR"

echo ""
echo "Done: $OUTPUT"
ls -lh "$OUTPUT"
