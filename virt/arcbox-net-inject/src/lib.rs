//! Guest memory RX injection engine for VirtIO-net.
//!
//! Receives raw Ethernet frames via a crossbeam channel and injects
//! them into a guest virtio-net RX queue through the unified
//! `arcbox_virtio::SplitQueue`. Runs on a dedicated OS thread,
//! completely independent of the tokio async runtime.

pub mod inject;
pub mod inline_conn;
pub mod irq;
pub mod queue;
