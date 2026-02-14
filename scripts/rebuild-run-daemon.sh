#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROFILE="${PROFILE:-debug}"
KERNEL="${KERNEL:-$ROOT/tests/resources/Image-arm64}"
INITRAMFS="${INITRAMFS:-$ROOT/tests/resources/initramfs-arcbox}"
SOCKET="${SOCKET:-/tmp/arcbox.sock}"
GRPC_SOCKET="${GRPC_SOCKET:-/tmp/arcbox-grpc.sock}"
DATA_DIR="${DATA_DIR:-/tmp/arcbox-data}"
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

cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release

"$ROOT/tests/resources/build-initramfs.sh"

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
  --initramfs "$INITRAMFS"
