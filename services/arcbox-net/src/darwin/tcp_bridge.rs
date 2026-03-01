//! TCP bridge: smoltcp socket pool ↔ host `TcpStream` bidirectional relay.
//!
//! Manages outbound and inbound TCP connections through smoltcp's TCP socket
//! implementation, bridging each to a host-side `TcpStream` for actual network
//! I/O.
//!
//! This module replaces the hand-rolled TCP state machine in `socket_proxy.rs`
//! with smoltcp's battle-tested TCP implementation, providing proper flow
//! control, retransmission, window management, and congestion control.
//!
//! # Architecture
//!
//! ```text
//! Guest VM
//!     ↕ smoltcp tcp::Socket (rx/tx buffers, flow control)
//! TcpBridge
//!     ↕ relay_bidirectional()
//! Host TcpStream (non-blocking)
//!     ↕
//! Remote server
//! ```
//!
//! # Implementation phases
//!
//! - Phase 2: Outbound TCP (listen pool, connection detection, host bridge)
//! - Phase 3: Inbound TCP (active connect to guest, host accept bridge)

// TODO(phase-2): Implement outbound TCP bridge
// TODO(phase-3): Implement inbound TCP bridge
