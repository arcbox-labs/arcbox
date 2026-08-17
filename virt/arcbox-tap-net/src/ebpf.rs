//! eBPF (TCX) invariant-NAT datapath (CORE-83).
//!
//! Loads the committed `bpf/sandbox_nat.bpf.o` object once per process and
//! attaches its two TCX programs to each invariant sandbox TAP. Per TAP that
//! costs two `bpf(BPF_LINK_CREATE)` syscalls plus one map update — replacing
//! the seven iptables rules, the fwmark fib rule, and the per-sandbox routing
//! table of the CORE-81 path — and the translation itself is stateless and
//! O(1) per packet instead of an O(active sandboxes) chain traversal through
//! conntrack.
//!
//! Steering needs no policy routing: the egress program rewrites the pool
//! destination only *after* routing, so the main table's per-TAP route
//! delivers every to-sandbox packet. The kernel's own peer route
//! (`pool_ip dev tapX`, from `SIOCSIFDSTADDR`) would ARP for the pool IP —
//! which the invariant guest does not own and never answers — so activation
//! replaces it with `pool_ip via GUEST_IP dev tapX onlink`
//! ([`super::rtnetlink::replace_gateway_route`]): the neighbor-resolution
//! target becomes the fixed guest IP, which every invariant guest answers.
//!
//! TCX links are plain file descriptors: they detach when dropped and die
//! with the process, so a crashed agent leaves no kernel state behind beyond
//! the TAP itself (which the reconcile sweep already removes). The route dies
//! with the TAP. Nothing is pinned.
//!
//! Kernel prerequisites (all verified in the System VM kernel config):
//! `BPF_SYSCALL`, `BPF_JIT_ALWAYS_ON`, and `NET_XGRESS` (selected by
//! `NET_SCH_INGRESS` on >= 6.6) for the TCX attach point. `NET_CLS_BPF` is
//! absent, so classic tc filters are not an option — the loader attaches
//! exclusively through TCX links and never falls back to netlink tc.

use std::net::Ipv4Addr;

/// Compiled TCX object, embedded at build time. Rebuilt by
/// `cargo xtask dev bpf`; `tests/bpf_object.rs` pins source/object coherence
/// and the ELF shape.
#[cfg(target_os = "linux")]
const OBJECT: &[u8] = include_bytes!("../bpf/sandbox_nat.bpf.o");

/// `ifindex (host order) -> pool IP (network order)` hash map.
#[cfg(target_os = "linux")]
const NAT_MAP: &str = "SANDBOX_NAT";
/// 3-element array: pool network, netmask, gateway (network order).
#[cfg(target_os = "linux")]
const POOL_MAP: &str = "SANDBOX_NAT_POOL";
#[cfg(target_os = "linux")]
const INGRESS_PROG: &str = "sandbox_nat_ingress";
#[cfg(target_os = "linux")]
const EGRESS_PROG: &str = "sandbox_nat_egress";

/// The `SANDBOX_NAT` map value for a pool IP: a `u32` whose in-memory bytes
/// are the address in network byte order, matching how the programs read
/// `iphdr.saddr`/`daddr` straight out of the packet.
pub fn pool_ip_value(ip: Ipv4Addr) -> u32 {
    u32::from(ip).to_be()
}

/// Outcome of an eBPF activation attempt that did not itself error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    /// Programs attached, map entry written, route replaced.
    Done,
    /// The engine failed to load earlier (warned once); the caller applies
    /// the iptables translation without further noise.
    EngineUnavailable,
}

/// The `SANDBOX_NAT_POOL` entries: `[(index, value)]` for pool network,
/// netmask, and gateway, all in network byte order. Written once at load,
/// before any program is attached — the ingress isolation check treats a
/// zero netmask as "unconfigured" and skips itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolValues([u32; 3]);

impl PoolValues {
    pub fn new(base: Ipv4Addr, prefix_len: u8, gateway: Ipv4Addr) -> Self {
        // prefix_len is validated to 1..=30 by NetworkManager::new_inner.
        let mask = !0u32 << (32 - u32::from(prefix_len.min(32)));
        Self([
            (u32::from(base) & mask).to_be(),
            mask.to_be(),
            pool_ip_value(gateway),
        ])
    }

    #[cfg(target_os = "linux")]
    fn entries(self) -> impl Iterator<Item = (u32, u32)> {
        self.0.into_iter().enumerate().map(|(i, v)| (i as u32, v))
    }
}

#[cfg(target_os = "linux")]
pub use linux::Engine;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use aya::maps::MapError;
    use aya::programs::tc::{SchedClassifierLink, TcAttachOptions};
    use aya::programs::{LinkOrder, SchedClassifier, TcAttachType};
    use tracing::warn;

    use super::{EGRESS_PROG, INGRESS_PROG, NAT_MAP, OBJECT, POOL_MAP, PoolValues, pool_ip_value};
    use crate::error::{Result, TapNetError};

    /// Process-wide loader state, initialized lazily on the first invariant
    /// TAP activation so agents that never run an eBPF-datapath sandbox pay
    /// nothing.
    pub enum Engine {
        /// No load attempted yet.
        Unloaded,
        /// Object verified and loaded; TAPs can attach.
        Ready(Box<EbpfNat>),
        /// Load failed. The warn fired once here; every TAP silently takes
        /// the iptables path for the rest of this process.
        Unavailable,
    }

    impl Engine {
        /// The loaded datapath, loading the object on first use. `None` means
        /// unavailable — the failure was logged when it happened.
        pub fn ensure_loaded(&mut self, pool: PoolValues) -> Option<&mut EbpfNat> {
            if matches!(self, Self::Unloaded) {
                *self = match EbpfNat::load(pool) {
                    Ok(nat) => Self::Ready(Box::new(nat)),
                    Err(error) => {
                        warn!(
                            %error,
                            "eBPF sandbox datapath unavailable; using iptables NAT"
                        );
                        Self::Unavailable
                    }
                };
            }
            self.loaded_mut()
        }

        /// The loaded datapath, if any, without triggering a load.
        pub fn loaded_mut(&mut self) -> Option<&mut EbpfNat> {
            match self {
                Self::Ready(nat) => Some(nat),
                Self::Unloaded | Self::Unavailable => None,
            }
        }
    }

    /// The loaded object plus the live per-TAP attachments.
    pub struct EbpfNat {
        ebpf: aya::Ebpf,
        attachments: HashMap<String, TapAttachment>,
    }

    /// Owned TCX links of one TAP; dropping them detaches the programs.
    struct TapAttachment {
        ifindex: u32,
        _ingress: SchedClassifierLink,
        _egress: SchedClassifierLink,
    }

    impl EbpfNat {
        /// Load the embedded object, write the pool constants, and verify
        /// both programs into the kernel.
        fn load(pool: PoolValues) -> Result<Self> {
            let mut ebpf = aya::Ebpf::load(OBJECT)
                .map_err(|e| TapNetError::Network(format!("load sandbox NAT BPF object: {e}")))?;
            {
                let map = ebpf.map_mut(POOL_MAP).ok_or_else(|| missing(POOL_MAP))?;
                let mut array = aya::maps::Array::<_, u32>::try_from(map)
                    .map_err(|e| TapNetError::Network(format!("map {POOL_MAP}: {e}")))?;
                for (index, value) in pool.entries() {
                    array.set(index, value, 0).map_err(|e| {
                        TapNetError::Network(format!("write {POOL_MAP}[{index}]: {e}"))
                    })?;
                }
            }
            for name in [INGRESS_PROG, EGRESS_PROG] {
                classifier(&mut ebpf, name)?
                    .load()
                    .map_err(|e| TapNetError::Network(format!("load program {name}: {e}")))?;
            }
            Ok(Self {
                ebpf,
                attachments: HashMap::new(),
            })
        }

        /// Attach both programs to `tap` via TCX links and map its ifindex to
        /// the pool IP. Self-cleaning: a partial attach detaches on drop.
        pub fn attach(&mut self, tap: &str, ifindex: u32, pool_ip: Ipv4Addr) -> Result<()> {
            let ingress = attach_one(&mut self.ebpf, INGRESS_PROG, tap, TcAttachType::Ingress)?;
            let egress = attach_one(&mut self.ebpf, EGRESS_PROG, tap, TcAttachType::Egress)?;
            let mut map = nat_map(&mut self.ebpf)?;
            map.insert(ifindex, pool_ip_value(pool_ip), 0)
                .map_err(|e| TapNetError::Network(format!("{NAT_MAP} insert for {tap}: {e}")))?;
            self.attachments.insert(
                tap.to_owned(),
                TapAttachment {
                    ifindex,
                    _ingress: ingress,
                    _egress: egress,
                },
            );
            Ok(())
        }

        /// Detach `tap`'s programs (link drop) and drop its map entry, so a
        /// recycled ifindex can never inherit a stale pool IP. Unknown TAPs
        /// are a no-op.
        pub fn detach(&mut self, tap: &str) -> Result<()> {
            let Some(attachment) = self.attachments.remove(tap) else {
                return Ok(());
            };
            let mut map = nat_map(&mut self.ebpf)?;
            match map.remove(&attachment.ifindex) {
                Ok(()) => Ok(()),
                // Absent is fine: there is nothing left to translate.
                Err(MapError::SyscallError(ref syscall))
                    if syscall.io_error.raw_os_error() == Some(libc::ENOENT) =>
                {
                    Ok(())
                }
                Err(e) => Err(TapNetError::Network(format!(
                    "{NAT_MAP} remove for {tap}: {e}"
                ))),
            }
        }
    }

    fn missing(name: &str) -> TapNetError {
        TapNetError::Network(format!("sandbox NAT object has no {name:?}"))
    }

    fn classifier<'e>(ebpf: &'e mut aya::Ebpf, name: &str) -> Result<&'e mut SchedClassifier> {
        ebpf.program_mut(name)
            .ok_or_else(|| missing(name))?
            .try_into()
            .map_err(|e| TapNetError::Network(format!("program {name}: {e}")))
    }

    fn nat_map(
        ebpf: &mut aya::Ebpf,
    ) -> Result<aya::maps::HashMap<&mut aya::maps::MapData, u32, u32>> {
        aya::maps::HashMap::try_from(ebpf.map_mut(NAT_MAP).ok_or_else(|| missing(NAT_MAP))?)
            .map_err(|e| TapNetError::Network(format!("map {NAT_MAP}: {e}")))
    }

    /// TCX-attach one program and take ownership of its link. Never falls
    /// back to netlink tc: the kernel has no `NET_CLS_BPF`, so an explicit
    /// TCX failure must surface instead of a confusing qdisc error.
    fn attach_one(
        ebpf: &mut aya::Ebpf,
        name: &str,
        tap: &str,
        attach_type: TcAttachType,
    ) -> Result<SchedClassifierLink> {
        let program = classifier(ebpf, name)?;
        let link_id = program
            .attach_with_options(
                tap,
                attach_type,
                TcAttachOptions::TcxOrder(LinkOrder::default()),
            )
            .map_err(|e| TapNetError::Network(format!("TCX attach {name} on {tap}: {e}")))?;
        program
            .take_link(link_id)
            .map_err(|e| TapNetError::Network(format!("own TCX link {name} on {tap}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The map value must lay the address out in network byte order — the
    /// programs compare it against `iphdr` fields read raw from the packet.
    #[test]
    fn pool_ip_value_bytes_are_network_order() {
        let ip: Ipv4Addr = "172.20.3.17".parse().unwrap();
        assert_eq!(pool_ip_value(ip).to_ne_bytes(), ip.octets());
    }

    #[test]
    fn pool_values_mask_the_base_and_keep_network_order() {
        let pool = PoolValues::new(
            "172.20.7.9".parse().unwrap(), // host bits deliberately set
            16,
            "172.20.0.1".parse().unwrap(),
        );
        assert_eq!(
            pool,
            PoolValues([
                u32::from_ne_bytes([172, 20, 0, 0]),
                u32::from_ne_bytes([255, 255, 0, 0]),
                u32::from_ne_bytes([172, 20, 0, 1]),
            ])
        );
    }
}
