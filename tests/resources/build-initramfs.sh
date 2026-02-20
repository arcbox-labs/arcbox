#!/bin/bash
# Build a minimal initramfs with arcbox-agent for LOCAL DEVELOPMENT AND TESTING ONLY.
#
# NOTE: This script is NOT used in production boot flow.
# Production initramfs (with arcbox-agent) is built and released from the
# arcbox-labs/boot-assets repository. See PLAN.md for details.
#
# This creates an initramfs that:
# 1. Uses Alpine Linux's base initramfs
# 2. Adds arcbox-agent binary
# 3. Starts agent on boot

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/initramfs-work"
AGENT_BIN="${SCRIPT_DIR}/../../target/aarch64-unknown-linux-musl/release/arcbox-agent"
BASE_INITRAMFS="${SCRIPT_DIR}/initramfs-arm64"
MODLOOP="${SCRIPT_DIR}/modloop-lts"
OUTPUT="${SCRIPT_DIR}/initramfs-arcbox"

echo "=== Building ArcBox Initramfs ==="

# Check dependencies
REQUIRED_CMDS=(curl gunzip cpio unsquashfs gzip)
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found"
        echo "Install dependencies and retry (macOS example: brew install cpio squashfs)"
        exit 1
    fi
done

if [ ! -f "$AGENT_BIN" ]; then
    echo "Error: Agent binary not found at $AGENT_BIN"
    echo "Build it with: cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release"
    exit 1
fi

if [ ! -f "$BASE_INITRAMFS" ]; then
    echo "Error: Base initramfs not found at $BASE_INITRAMFS"
    echo "Run: ./download-kernel.sh first"
    exit 1
fi

if [ ! -f "$MODLOOP" ]; then
    echo "Downloading modloop for vsock modules..."
    curl -L -o "$MODLOOP" "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/netboot/modloop-lts"
fi

# Clean up previous work
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

echo "Extracting base initramfs..."
cd "$WORK_DIR"

# Extract base initramfs (gzip compressed cpio)
gunzip -c "$BASE_INITRAMFS" | cpio -idm 2>/dev/null || {
    # Try as uncompressed cpio
    cpio -idm < "$BASE_INITRAMFS" 2>/dev/null
}

echo "Adding arcbox-agent..."
cp "$AGENT_BIN" "$WORK_DIR/sbin/arcbox-agent"
chmod 755 "$WORK_DIR/sbin/arcbox-agent"

# Extract vsock modules from modloop
echo "Adding vsock kernel modules..."
MODLOOP_EXTRACT="/tmp/modloop-extract-$$"
rm -rf "$MODLOOP_EXTRACT"
unsquashfs -f -d "$MODLOOP_EXTRACT" "$MODLOOP" >/dev/null

# Find the kernel version in the initramfs
KERNEL_VERSION=$(ls "$WORK_DIR/lib/modules/" 2>/dev/null | head -1)
if [ -z "$KERNEL_VERSION" ]; then
    KERNEL_VERSION=$(ls "$MODLOOP_EXTRACT/modules/" 2>/dev/null | head -1)
fi
echo "  Kernel version: $KERNEL_VERSION"

# Create modules directory if needed
mkdir -p "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/net/vmw_vsock"

# Copy vsock modules
VSOCK_SRC="$MODLOOP_EXTRACT/modules/$KERNEL_VERSION/kernel/net/vmw_vsock"
if [ -d "$VSOCK_SRC" ]; then
    cp "$VSOCK_SRC/vsock.ko" "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/net/vmw_vsock/" 2>/dev/null || true
    cp "$VSOCK_SRC/vmw_vsock_virtio_transport_common.ko" "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/net/vmw_vsock/" 2>/dev/null || true
    cp "$VSOCK_SRC/vmw_vsock_virtio_transport.ko" "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/net/vmw_vsock/" 2>/dev/null || true
    echo "  Copied vsock modules"
    ls -la "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/net/vmw_vsock/"
else
    echo "  Warning: vsock modules not found in modloop"
fi

# Copy fuse/virtiofs modules
echo "Adding fuse/virtiofs kernel modules..."
FUSE_SRC="$MODLOOP_EXTRACT/modules/$KERNEL_VERSION/kernel/fs/fuse"
mkdir -p "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/fs/fuse"
if [ -d "$FUSE_SRC" ]; then
    cp "$FUSE_SRC/fuse.ko" "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/fs/fuse/" 2>/dev/null || true
    cp "$FUSE_SRC/virtiofs.ko" "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/fs/fuse/" 2>/dev/null || true
    echo "  Copied fuse/virtiofs modules"
    ls -la "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/fs/fuse/"
else
    echo "  Warning: fuse modules not found in modloop"
fi

# Copy virtio_net module (needed for guest networking)
echo "Adding virtio_net kernel module..."
VIRTIO_NET_SRC="$MODLOOP_EXTRACT/modules/$KERNEL_VERSION/kernel/drivers/net/virtio_net.ko"
mkdir -p "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/drivers/net"
if [ -f "$VIRTIO_NET_SRC" ]; then
    cp "$VIRTIO_NET_SRC" "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/drivers/net/" 2>/dev/null || true
    echo "  Copied virtio_net module"
elif [ -f "${VIRTIO_NET_SRC}.gz" ]; then
    cp "${VIRTIO_NET_SRC}.gz" "$WORK_DIR/lib/modules/$KERNEL_VERSION/kernel/drivers/net/" 2>/dev/null || true
    echo "  Copied virtio_net module (compressed)"
else
    echo "  Warning: virtio_net module not found in modloop"
fi

# Update modules.dep for the new modules
echo "kernel/net/vmw_vsock/vsock.ko:" >> "$WORK_DIR/lib/modules/$KERNEL_VERSION/modules.dep"
echo "kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko: kernel/net/vmw_vsock/vsock.ko" >> "$WORK_DIR/lib/modules/$KERNEL_VERSION/modules.dep"
echo "kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko: kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko" >> "$WORK_DIR/lib/modules/$KERNEL_VERSION/modules.dep"
echo "kernel/fs/fuse/fuse.ko:" >> "$WORK_DIR/lib/modules/$KERNEL_VERSION/modules.dep"
echo "kernel/fs/fuse/virtiofs.ko: kernel/fs/fuse/fuse.ko" >> "$WORK_DIR/lib/modules/$KERNEL_VERSION/modules.dep"
echo "kernel/drivers/net/virtio_net.ko:" >> "$WORK_DIR/lib/modules/$KERNEL_VERSION/modules.dep"

# Cleanup modloop extract
rm -rf "$MODLOOP_EXTRACT"

# Create init script that starts the agent
echo "Creating init script..."
cat > "$WORK_DIR/init" << 'INIT_EOF'
#!/bin/sh
# ArcBox init script

# Mount essential filesystems
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /dev/pts
/bin/busybox mount -t devpts -o gid=5,mode=0620,noexec,nosuid devpts /dev/pts
/bin/busybox mkdir -p /dev/shm
/bin/busybox mount -t tmpfs -o nodev,nosuid,noexec shm /dev/shm

# Mount cgroup2 unified hierarchy (required by dockerd/containerd)
/bin/busybox mkdir -p /sys/fs/cgroup
/bin/busybox mount -t cgroup2 cgroup2 /sys/fs/cgroup

# Writable tmpfs for /tmp and /run
/bin/busybox mount -t tmpfs tmpfs /tmp
/bin/busybox mount -t tmpfs tmpfs /run
/bin/busybox mkdir -p /run/containerd /var/run /var/log /var/lib

# Set hostname
/bin/busybox hostname arcbox-vm

# Print boot message
echo "=================================="
echo "  ArcBox Guest VM Starting..."
echo "=================================="
echo ""

# Check kernel version
echo "Kernel: $(/bin/busybox uname -r)"
echo ""

# Load fuse/virtiofs modules first (needed for VirtioFS mount)
echo "Loading fuse/virtiofs modules..."
/sbin/modprobe fuse 2>/dev/null && echo "  Loaded: fuse" || echo "  Failed: fuse"
/sbin/modprobe virtiofs 2>/dev/null && echo "  Loaded: virtiofs" || echo "  Failed: virtiofs"
/sbin/modprobe overlay 2>/dev/null && echo "  Loaded: overlay" || echo "  Failed: overlay"
echo ""

# Mount VirtioFS share for host data (/arcbox)
echo "Mounting VirtioFS..."
/bin/busybox mkdir -p /arcbox
if /bin/busybox mount -t virtiofs arcbox /arcbox; then
    echo "  VirtioFS mounted at /arcbox"
    /bin/busybox ls -la /arcbox 2>/dev/null | /bin/busybox head -5
else
    echo "  VirtioFS mount FAILED"
fi
echo ""

# Load vsock modules in correct order
echo "Loading vsock modules..."
/sbin/modprobe vsock 2>/dev/null && echo "  Loaded: vsock" || echo "  Failed: vsock"
/sbin/modprobe vmw_vsock_virtio_transport_common 2>/dev/null && echo "  Loaded: vmw_vsock_virtio_transport_common" || echo "  Failed: vmw_vsock_virtio_transport_common"
/sbin/modprobe vmw_vsock_virtio_transport 2>/dev/null && echo "  Loaded: vmw_vsock_virtio_transport" || echo "  Failed: vmw_vsock_virtio_transport"
echo ""

# Give kernel time to create device
/bin/busybox sleep 1

# Check if vsock device exists
if [ -e /dev/vsock ]; then
    echo "vsock device: /dev/vsock exists"
else
    echo "vsock device: /dev/vsock NOT found"
    # Try to create it
    if [ -c /dev/vhost-vsock ]; then
        echo "  Found /dev/vhost-vsock"
    fi
fi
echo ""

# List loaded modules
echo "Loaded modules:"
/bin/busybox cat /proc/modules | /bin/busybox head -10
echo ""

# Network setup
echo "Setting up network..."
/sbin/modprobe virtio_net 2>/dev/null && echo "  Loaded: virtio_net" || echo "  Failed: virtio_net"

# Wait for the network interface to appear
RETRY=0
while [ ! -e /sys/class/net/eth0 ] && [ $RETRY -lt 5 ]; do
    /bin/busybox sleep 0.2
    RETRY=$((RETRY + 1))
done

if [ ! -e /sys/class/net/eth0 ]; then
    echo "  ERROR: eth0 not found after loading virtio_net"
    /bin/busybox ip link show
else
    echo "  eth0 device found"
    
    # Bring up eth0
    /bin/busybox ip link set eth0 up 2>/dev/null || echo "  WARNING: Failed to bring up eth0"
    
    # Setup udhcpc with a custom script to handle DHCP response
    mkdir -p /usr/share/udhcpc
    cat > /usr/share/udhcpc/default.script <<'UDHCP_EOF'
#!/bin/sh
case "$1" in
    bound|renew)
        /bin/busybox ip addr add "$ip/24" dev "$interface" 2>/dev/null
        if [ -n "$router" ]; then
            /bin/busybox ip route add default via "$router" 2>/dev/null
        fi
        # Dynamic DNS from DHCP server
        {
            for ns in $dns; do
                echo "nameserver $ns"
            done
        } > /etc/resolv.conf
        echo "DHCP: $interface got $ip from $server_name"
        ;;
    deconfig)
        /bin/busybox ip addr flush dev "$interface" 2>/dev/null
        ;;
esac
EOF
    chmod +x /usr/share/udhcpc/default.script
    
    # Run udhcpc with timeout
    if /bin/busybox timeout 5 /sbin/udhcpc -i eth0 -t 5 -n 2>/dev/null; then
        echo "  DHCP: success"
        /bin/busybox cat /etc/resolv.conf | /bin/busybox head -3
    else
        echo "  DHCP: timeout or failed, trying fallback static config"
        /bin/busybox ip addr add 192.168.64.2/24 dev eth0 2>/dev/null || true
        /bin/busybox ip route add default via 192.168.64.1 2>/dev/null || true
        echo "nameserver 192.168.64.1" > /etc/resolv.conf
    fi
fi

# host.docker.internal support
echo "192.168.64.1 host.docker.internal" >> /etc/hosts

# Log network IP for host-side detection
/bin/busybox mkdir -p /var/log
/bin/busybox ip addr show dev eth0 2>/dev/null | /bin/busybox grep "inet " | /bin/busybox awk '{print $2}' | /bin/busybox cut -d/ -f1 > /var/log/network.log 2>/dev/null || true
echo ""

# Start arcbox-agent in foreground with debug output
echo "Starting arcbox-agent on vsock port 1024..."
echo "=================================="

# Persist agent logs to host-mounted share for debugging.
echo "Agent logs: /arcbox/agent.log"
exec /sbin/arcbox-agent >> /arcbox/agent.log 2>&1
INIT_EOF
chmod 755 "$WORK_DIR/init"

# Create the new initramfs
echo "Creating initramfs..."
cd "$WORK_DIR"
find . | cpio -o -H newc 2>/dev/null | gzip > "$OUTPUT"

# Cleanup
rm -rf "$WORK_DIR"

echo ""
echo "Done! Created: $OUTPUT"
ls -lh "$OUTPUT"
echo ""
echo "To use:"
echo "  ./target/release/examples/boot_vm $SCRIPT_DIR/Image-arm64 $OUTPUT --vsock"
