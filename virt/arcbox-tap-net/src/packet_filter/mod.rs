//! The packet-filter seam: how the identity-invariant translation is
//! expressed in the host's netfilter framework.
//!
//! The *contract* is fixed by [`super::invariant`] and does not vary with
//! the framework: for a sandbox behind `tap` whose external identity is
//! `pool_ip`, with `mark = fwmark(pool_ip)`,
//!
//! 1. every packet entering from `tap` is marked `mark` (so post-routing
//!    NAT, which cannot match the input interface, can pick the source
//!    identity);
//! 2. every packet whose *pre-NAT* destination is `pool_ip` is marked
//!    `mark`, both forwarded (prerouting) and locally originated (output),
//!    so the fwmark fib rule routes the rewritten destination out `tap`;
//! 3. `pool_ip` is DNAT'd to [`GUEST_IP`] in prerouting and output;
//! 4. traffic from `tap` to local services is SNAT'd to `pool_ip` in the
//!    input hook, so DNS and relays keep seeing the pool identity;
//! 5. forwarded traffic with source [`GUEST_IP`] *and* mark `mark` is SNAT'd
//!    to `pool_ip` in postrouting — the source match keeps to-sandbox packets
//!    (same mark, client source) out of the rewrite.
//!
//! How that is spelled is the environment's business. The System VM ships
//! iptables-legacy and nothing else, so [`IptablesLegacy`] is the reference
//! implementation. A stock distro is usually on the nft backend, and legacy
//! and nft rulesets are mutually invisible — rules that exist but do not
//! take effect — so a composer there supplies an nftables implementation
//! rather than a path to a different `iptables` binary. Removal must
//! tolerate absence: teardown runs for partially activated and crash-
//! recovered TAPs alike.
//!
//! [`GUEST_IP`]: super::invariant::GUEST_IP

mod iptables_legacy;

use std::net::Ipv4Addr;

pub use iptables_legacy::IptablesLegacy;

use crate::error::Result;

/// Installs and removes the per-TAP translation rules of one sandbox.
///
/// Methods are synchronous; the network manager calls them on the
/// activation and teardown paths, which already run blocking netlink work.
///
/// Two obligations every implementation carries, because callers were
/// built against them:
///
/// - **Pipeline placement.** The rules are *appended* to their chains, so
///   they sit below whatever the composer installed at boot (the reference
///   guest agent's isolation DROPs) and above nothing; per-sandbox expose
///   companions are prepended above them by their own code. Rendering the
///   same rules at another position changes the pipeline even when each
///   rule is faithful.
/// - **Failure shape.** `install_translation` may fail after applying some
///   of the rules — the caller then calls `remove_translation`, which must
///   attempt every rule, tolerate ones that are already absent (partial
///   installs, crash replays, legacy TAPs), and report the failures it could
///   not clear together rather than stopping at the first. An implementation
///   whose install is atomic satisfies this trivially; one that applies
///   rules one at a time ([`IptablesLegacy`]) leaves the earlier ones in
///   place and relies on that tolerance.
pub trait PacketFilter: Send + Sync {
    /// Install the translation for `tap` ↔ `pool_ip`.
    fn install_translation(&self, tap: &str, pool_ip: Ipv4Addr) -> Result<()>;

    /// Remove the translation, tolerating rules that are already gone.
    fn remove_translation(&self, tap: &str, pool_ip: Ipv4Addr) -> Result<()>;
}

/// Tag stamped on every translation rule, marking them as arcbox-owned for
/// forensics (`iptables -S`, `nft list ruleset`).
///
/// [`IptablesLegacy`] uses it bare and deletes by exact rule spec.
const RULE_COMMENT: &str = "arcbox-nat";
