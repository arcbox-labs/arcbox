# arcbox-virtio-blk

VirtIO block device implementation for ArcBox.

This crate owns the virtio-blk wire contract: feature bits, config fields, request headers, status values, generic descriptor-chain handling, and shared host-file primitives such as sparse hole punching and zeroing.

## Current I/O Paths

ArcBox has more than one block I/O path:

- **Generic path** — `VirtioBlock::process_descriptor_chain` parses and handles virtqueue descriptors directly.
- **macOS HV worker path** — `arcbox-vmm::blk_worker` parses descriptors on the vCPU side and performs async host I/O on a worker thread. This is the P0 macOS path.

Any advertised virtio-blk feature must be correct in both paths. A feature implemented only in the generic path is not implemented for ArcBox's primary platform.

## DISCARD and WRITE_ZEROES

- `DISCARD` is advisory: ArcBox validates the request shape, then punches aligned host-file holes where possible. Host punch failure is logged and reported as success because the guest has already freed the blocks logically.
- `WRITE_ZEROES` is mandatory: ArcBox must make the requested range read back as zero. The shared `zero_range` primitive punches the aligned interior for sparseness and writes zeros on unaligned edges; if punching fails, it falls back to writing zeros.

Both operations use the same range-list parser and checked sector-to-byte conversion. Keep that shared validation in sync with the macOS HV worker.

## Review Checklist

Before changing a virtio-blk feature:

1. Is the feature bit advertised only when every active path can honor it?
2. Are descriptor payloads concatenated before parsing structs that may be split across descriptors?
3. Are sector arithmetic, capacity bounds, flags, limits, and short I/O checked?
4. Do tests cover both generic handling and the macOS HV worker path?
