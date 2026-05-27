//! Bridges the net-direct `ConnSink` trait (no inject dep) to the
//! inject crate's `InlineConn` crossbeam channel.
//!
//! The VMM layer depends on both `arcbox_net` and `arcbox_net_inject`,
//! so the adapter lives here to avoid pulling inject into `arcbox_net`.

/// Bridges `arcbox_net::direct_rx::ConnSink` (type-erased, no inject dep)
/// to the `arcbox_net_inject::InlineConn` crossbeam channel.
pub(super) struct InlineConnSinkAdapter {
    pub(super) tx: crossbeam_channel::Sender<arcbox_net_inject::inline_conn::InlineConn>,
}

impl arcbox_net::direct_rx::ConnSink for InlineConnSinkAdapter {
    fn send_conn(&self, conn: arcbox_net::direct_rx::PromotedConn) -> bool {
        let inline = arcbox_net_inject::inline_conn::InlineConn {
            stream: conn.stream,
            remote_ip: conn.remote_ip,
            guest_ip: conn.guest_ip,
            remote_port: conn.remote_port,
            guest_port: conn.guest_port,
            our_seq: conn.our_seq,
            last_ack: conn.last_ack,
            gw_mac: conn.gw_mac,
            guest_mac: conn.guest_mac,
            host_eof: false,
        };
        self.tx.try_send(inline).is_ok()
    }
}
