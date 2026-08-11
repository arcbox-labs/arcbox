#!/usr/bin/env bash
# Regenerate the committed descriptor set for arcbox-connect, plus the hash of
# the .proto sources it was built from.
#
# arcbox-connect's protos live in arcbox-protocol. Cargo packages are
# directory-scoped, so a build script reading ../arcbox-protocol/proto produced
# a crate that built in the workspace and failed from crates.io. The descriptor
# set is committed instead, and is the code generator's input everywhere.
#
# Run via `make refresh-connect-descriptor` after editing any proto below.
set -euo pipefail

cd "$(dirname "$0")/.."

PROTO_DIR="../arcbox-protocol/proto"
OUT="descriptor/arcbox_connect.protoset"
HASH="descriptor/protos.sha256"

# Keep in step with PROTOS in build.rs.
PROTOS=(
  common.proto
  machine.proto
  macos.proto
  container.proto
  image.proto
  agent.proto
  api.proto
  kubernetes.proto
  stats.proto
  arcbox/sandbox/v1/sandbox.proto
  arcbox/sandbox/v1/process.proto
  arcbox/sandbox/v1/filesystem.proto
  arcbox/sandbox/v1/snapshot.proto
  arcbox/sandbox/v1/template.proto
  arcbox/sandbox/v1/errors.proto
)

PROTOC="${PROTOC:-protoc}"

# --experimental_allow_proto3_optional: older protoc still on some CI runners
# requires it and newer ones ignore it — the same stance as
# arcbox-protocol/build.rs. --include_imports makes the set self-contained so
# no import has to be resolved at build time; --include_source_info carries the
# comments through into the generated docs.
"$PROTOC" \
  --experimental_allow_proto3_optional \
  --include_imports \
  --include_source_info \
  "--descriptor_set_out=$OUT" \
  "--proto_path=$PROTO_DIR" \
  "${PROTOS[@]}"

# Hash the sources, not the descriptor: protoc versions do not agree
# byte-for-byte on their output, and that difference is not drift.
{
  for name in $(printf '%s\n' "${PROTOS[@]}" | sort); do
    printf '%s\0' "$name"
    cat "$PROTO_DIR/$name"
  done
} | shasum -a 256 | awk '{print $1}' > "$HASH"

echo "descriptor: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes)"
echo "sources:    $(cat "$HASH")"
