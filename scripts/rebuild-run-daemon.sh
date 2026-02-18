#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROFILE="${PROFILE:-debug}"
DEFAULT_KERNEL="$ROOT/boot-assets/dev/kernel"
DEFAULT_INITRAMFS="$ROOT/boot-assets/dev/initramfs.cpio.gz"
KERNEL="${KERNEL:-$DEFAULT_KERNEL}"
INITRAMFS="${INITRAMFS:-$DEFAULT_INITRAMFS}"
SOCKET="${SOCKET:-/tmp/arcbox.sock}"
GRPC_SOCKET="${GRPC_SOCKET:-/tmp/arcbox-grpc.sock}"
DATA_DIR="${DATA_DIR:-/tmp/arcbox-data}"
CONTAINER_BACKEND="${CONTAINER_BACKEND:-guest-docker}"
CONTAINER_PROVISION="${CONTAINER_PROVISION:-bundled-assets}"
GUEST_DOCKER_VSOCK_PORT="${GUEST_DOCKER_VSOCK_PORT:-2375}"
SIGN="${SIGN:-1}"
ENTITLEMENTS="${ENTITLEMENTS:-$ROOT/tests/resources/entitlements.plist}"

cd "$ROOT"

if [[ "$PROFILE" == "release" ]]; then
  cargo build -p arcbox-cli --release
  BIN="$ROOT/target/release/arcbox"
else
  cargo build -p arcbox-cli
  BIN="$ROOT/target/debug/arcbox"
fi

if [[ "$KERNEL" == "$DEFAULT_KERNEL" && "$INITRAMFS" == "$DEFAULT_INITRAMFS" ]]; then
  "$ROOT/scripts/setup-dev-boot-assets.sh"
fi

if [[ ! -f "$KERNEL" ]]; then
  echo "Kernel not found: $KERNEL" >&2
  exit 1
fi

if [[ ! -f "$INITRAMFS" ]]; then
  echo "Initramfs not found: $INITRAMFS" >&2
  exit 1
fi

if [[ "$SIGN" == "1" ]]; then
  codesign --force --options runtime \
    --entitlements "$ENTITLEMENTS" \
    -s - "$BIN"
  if ! codesign -d --entitlements :- "$BIN" 2>/dev/null | grep -q "com.apple.security.virtualization"; then
    echo "Missing com.apple.security.virtualization entitlement on $BIN" >&2
    exit 1
  fi
fi

exec "$BIN" daemon \
  --socket "$SOCKET" \
  --grpc-socket "$GRPC_SOCKET" \
  --data-dir "$DATA_DIR" \
  --kernel "$KERNEL" \
  --initramfs "$INITRAMFS" \
  --container-backend "$CONTAINER_BACKEND" \
  --container-provision "$CONTAINER_PROVISION" \
  --guest-docker-vsock-port "$GUEST_DOCKER_VSOCK_PORT"
