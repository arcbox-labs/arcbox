//! Guest memory RX injection engine for VirtIO-net.
//!
//! Receives raw Ethernet frames via a crossbeam channel and injects
//! them into a guest virtio-net RX queue by writing directly to
//! guest memory (mmap'd region). Runs on a dedicated OS thread,
//! completely independent of the tokio async runtime.

pub mod inject;
pub mod inline_conn;
pub mod irq;
pub mod notify;
pub mod queue;

/// Back-compat re-export: `GuestMemWriter` moved to `arcbox-virtio` so it
/// can be shared by every VirtIO device, not just RX injection.
pub mod guest_mem {
    pub use arcbox_virtio::GuestMemWriter;
}
