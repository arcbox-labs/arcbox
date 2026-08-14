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
LIST="descriptor/protos.txt"

# The one list, shared with build.rs. A second copy here would be a second
# thing to forget when a proto is added, and the build would then fail with a
# stale-descriptor message pointing at the wrong cause.
#
# One list is only half of it: the two readers have to agree on how to read it,
# or the same failure returns through a different door. The rule below is
# exactly build.rs's — trim, skip blank, skip a line whose first character is
# '#' — with no inline comments and no internal whitespace stripping, because
# those are things one parser can do and the other cannot.
#
# `|| [ -n "$line" ]` is the load-bearing part: `read` returns non-zero on a
# final line with no trailing newline and bash would drop it, while Rust's
# `str::lines()` keeps it. Strip the newline off protos.txt and without this
# the last proto vanishes from protoc and the hash while build.rs still counts
# it — the assert fires, and the refresh it names regenerates the mismatch.
PROTOS=()
while IFS= read -r line || [ -n "$line" ]; do
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  case "$line" in
    '' | '#'*) continue ;;
  esac
  PROTOS+=("$line")
done < "$LIST"

PROTOC="${PROTOC:-protoc}"

# build.rs hashes with the sha2 crate; this has to produce the same digest, and
# the two platforms disagree about which tool exists. A mismatch is loud (the
# build fails telling you to refresh), not silent.
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 | awk '{print $1}'; }
else
  echo "need sha256sum or shasum on PATH" >&2
  exit 1
fi

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
#
# `LC_ALL=C` is not decoration. build.rs sorts with `sort_unstable()`, which is
# byte-lexicographic unconditionally, while bare `sort` collates by locale — so
# on a machine whose locale disagrees, the shell would hash one order and
# build.rs another, and the assert would send you to a refresh that reproduces
# the mismatch. Today's names collate identically either way; that is luck, not
# a property to depend on.
{
  for name in $(printf '%s\n' "${PROTOS[@]}" | LC_ALL=C sort); do
    printf '%s\0' "$name"
    cat "$PROTO_DIR/$name"
  done
} | sha256 > "$HASH"

echo "descriptor: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes)"
echo "sources:    $(cat "$HASH")"
