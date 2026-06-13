//! Datapath primitives, re-exported from the extracted `arcbox-datapath` crate
//! plus the packet types from `arcbox-packet`. Preserves the
//! `arcbox_net::datapath::*` paths for existing callers.

pub use arcbox_datapath::*;
pub use arcbox_packet::packet;
pub use packet::{PacketMetadata, Protocol, ZeroCopyPacket};
