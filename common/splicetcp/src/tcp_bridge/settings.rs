use super::{
    INBOUND_EPHEMERAL_END, INBOUND_EPHEMERAL_START, SYN_GATE_CONNECT_TIMEOUT_SECS, SynFlowKey,
    TcpBridge,
};
use std::net::Ipv4Addr;

impl TcpBridge {
    /// Configures proxy-aware connection support.
    ///
    /// When set, `handle_outbound_syn` uses the DNS log to resolve destination
    /// IPs to domain names and connect via system proxy (HTTP CONNECT / SOCKS5)
    /// when available. Without this, all connections use direct
    /// `TcpStream::connect`. Installs a `DefaultEgress` resolver carrying the
    /// detected proxy environment.
    pub fn set_proxy_awareness(
        &mut self,
        dns_log: arcbox_fakeip::dns_log::DnsResolutionLog,
        proxy_env: arcbox_fakeip::proxy_detect::ProxyEnvironment,
    ) {
        self.dns_log = Some(dns_log);
        self.egress = std::sync::Arc::new(crate::egress::DefaultEgress::new(
            self.gateway_ip,
            Some(proxy_env),
            SYN_GATE_CONNECT_TIMEOUT_SECS,
        ));
    }

    /// Replaces the egress resolver with a custom policy. Lets a consumer
    /// (e.g. an Inbound/Router/Outbound host) inject its own decide+dial logic.
    pub fn set_egress_resolver(
        &mut self,
        egress: std::sync::Arc<dyn crate::egress::EgressResolver>,
    ) {
        self.egress = egress;
    }

    /// Installs a per-flow byte accounting observer, fired once per fast-path
    /// flow at teardown with its up/down totals (mirrors [`set_egress_resolver`]).
    /// Lets a consumer account the traffic the bridge spliced.
    ///
    /// [`set_egress_resolver`]: Self::set_egress_resolver
    pub fn set_flow_observer(&mut self, observer: std::sync::Arc<dyn crate::egress::FlowObserver>) {
        self.observer = Some(observer);
    }

    /// Attaches a DNS resolution log used to recover destination domains
    /// (`FlowMeta::domain`), independently of the egress resolver. Lets a
    /// consumer inject a custom resolver via [`set_egress_resolver`] while still
    /// having the bridge populate domains from DNS observations — without going
    /// through [`set_proxy_awareness`], which would also install a
    /// `DefaultEgress` and overwrite the injected resolver.
    ///
    /// [`set_egress_resolver`]: Self::set_egress_resolver
    /// [`set_proxy_awareness`]: Self::set_proxy_awareness
    pub fn set_dns_log(&mut self, dns_log: arcbox_fakeip::dns_log::DnsResolutionLog) {
        self.dns_log = Some(dns_log);
    }

    /// Allocates the next inbound ephemeral port, wrapping at the end of
    /// the reserved 61000–65535 range.
    fn allocate_ephemeral(&mut self) -> u16 {
        let port = self.next_ephemeral;
        self.next_ephemeral = if self.next_ephemeral == INBOUND_EPHEMERAL_END {
            INBOUND_EPHEMERAL_START
        } else {
            self.next_ephemeral + 1
        };
        port
    }

    /// Registers an inbound port-forward connection as an ActiveOpen
    /// handshake. The SYN toward the guest is emitted on the next
    /// `poll_handshakes()` call.
    ///
    /// Called by the datapath when `InboundListenerManager` accepts a new
    /// host connection.
    pub fn initiate_inbound(
        &mut self,
        container_port: u16,
        stream: tokio::net::TcpStream,
        guest_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
    ) {
        let Ok(std_stream) = stream.into_std() else {
            tracing::warn!(
                "TCP bridge: inbound stream into_std() failed for guest:{container_port}"
            );
            return;
        };

        let eph_port = self.allocate_ephemeral();
        let flow_key = SynFlowKey {
            src_ip: guest_ip,
            src_port: container_port,
            dst_ip: gateway_ip,
            dst_port: eph_port,
        };

        let gw_mac = self.fast_path_gateway_mac;
        let gmac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
        self.initiate_active_handshake(flow_key, std_stream, gw_mac, gmac);

        tracing::debug!(
            "TCP bridge: inbound ActiveOpen registered gw:{eph_port} → guest:{container_port}"
        );
    }
}
