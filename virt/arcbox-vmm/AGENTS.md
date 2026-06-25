# arcbox-vmm Agent Guidance

## macOS HV Block Worker Contract

`src/blk_worker.rs` is an independent virtio-blk request parser and executor for the macOS HV backend. It does not automatically inherit behavior from `arcbox-virtio-blk::VirtioBlock`.

When adding, advertising, or changing a virtio-blk feature, keep the HV worker in lockstep with `virt/arcbox-virtio-blk`:

- parse the same request types;
- validate the same guest-controlled fields, flags, limits, and capacity bounds;
- preserve the same read/write/flush ordering guarantees;
- report malformed mandatory requests as I/O errors instead of silently succeeding;
- add tests that exercise the worker parser/executor, not just shared leaf helpers.

If the worker cannot honor a feature on P0 macOS, do not advertise that feature for devices using this backend.
