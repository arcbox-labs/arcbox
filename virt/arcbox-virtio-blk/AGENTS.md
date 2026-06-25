# arcbox-virtio-blk Agent Guidance

This crate is the source of truth for virtio-blk feature semantics.

## Feature Implementation Rule

If this crate advertises a virtio-blk feature bit, the feature must be implemented and tested in every block I/O path that can handle the request:

- the generic `VirtioBlock::process_descriptor_chain` path in this crate;
- the macOS HV async worker path in `virt/arcbox-vmm/src/blk_worker.rs` when the feature can reach P0 macOS;
- any future fast path that parses block requests without delegating to `VirtioBlock`.

Do not add or keep an advertised feature as a best-effort placeholder. If a path cannot honor a feature, do not advertise it for devices that use that path.

## Request Parsing

Guest-controlled request fields must be validated before host I/O:

- concatenate scatter-gather payload descriptors before parsing structs that may cross descriptor boundaries;
- reject malformed lengths, reserved flags, out-of-bounds descriptors, arithmetic overflow, and ranges beyond device capacity;
- enforce the advertised per-request limits (`max_discard_sectors`, `max_write_zeroes_sectors`, segment counts, and alignment) in every path;
- treat partial host reads/writes as I/O errors unless a caller has a documented EOF policy.

## Tests

Tests for a new or changed block feature must cover the real request path, not only a leaf helper. For P0 macOS behavior, include coverage for the HV worker parser/executor in `arcbox-vmm` as well as the generic handler here.
