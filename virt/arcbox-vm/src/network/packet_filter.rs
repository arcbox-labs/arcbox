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

use std::net::Ipv4Addr;
use std::path::PathBuf;

use super::invariant::{GUEST_IP, fwmark};
use crate::error::{Result, VmmError};

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
/// - **Failure shape.** `install_translation` fails fast on the first rule
///   that does not apply, leaving the earlier ones in place — the caller
///   then calls `remove_translation`, which must attempt every rule,
///   tolerate ones that are already absent (partial installs, crash
///   replays, legacy TAPs), and report the failures it could not clear
///   together rather than stopping at the first.
pub trait PacketFilter: Send + Sync {
    /// Install the translation for `tap` ↔ `pool_ip`.
    fn install_translation(&self, tap: &str, pool_ip: Ipv4Addr) -> Result<()>;

    /// Remove the translation, tolerating rules that are already gone.
    fn remove_translation(&self, tap: &str, pool_ip: Ipv4Addr) -> Result<()>;
}

/// [`PacketFilter`] over iptables-legacy — the System VM's userland.
///
/// Every rule carries the `arcbox-nat` comment for forensics
/// (`iptables -S`); deletion goes by exact rule spec, not the comment.
#[derive(Debug, Clone)]
pub struct IptablesLegacy {
    iptables: PathBuf,
}

impl IptablesLegacy {
    /// Where the System VM's EROFS rootfs installs `iptables`.
    pub const DEFAULT_PATH: &'static str = "/sbin/iptables";

    /// Use the iptables binary at `iptables`.
    pub fn new(iptables: impl Into<PathBuf>) -> Self {
        Self {
            iptables: iptables.into(),
        }
    }

    /// Run one iptables verb on a rule. `tolerate_missing` treats exit
    /// status 1 — iptables-legacy's "no matching rule" — as success so
    /// teardown is idempotent; other failures (usage errors, the xtables
    /// lock timing out) still propagate.
    fn run(&self, rule: &XtRule, verb: &str, tolerate_missing: bool) -> Result<()> {
        let output = std::process::Command::new(&self.iptables)
            .args(["-w", "2", "-t", rule.table, verb, rule.chain])
            .args(&rule.spec)
            .output()
            .map_err(|e| VmmError::Network(format!("run {}: {e}", self.iptables.display())))?;
        if output.status.success() || (tolerate_missing && output.status.code() == Some(1)) {
            return Ok(());
        }
        Err(VmmError::Network(format!(
            "iptables -t {} {verb} {} {}: {}",
            rule.table,
            rule.chain,
            rule.spec.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

impl Default for IptablesLegacy {
    fn default() -> Self {
        Self::new(Self::DEFAULT_PATH)
    }
}

impl PacketFilter for IptablesLegacy {
    fn install_translation(&self, tap: &str, pool_ip: Ipv4Addr) -> Result<()> {
        for rule in translation_rules(tap, pool_ip) {
            self.run(&rule, "-A", false)?;
        }
        Ok(())
    }

    fn remove_translation(&self, tap: &str, pool_ip: Ipv4Addr) -> Result<()> {
        let mut failures = Vec::new();
        for rule in translation_rules(tap, pool_ip) {
            if let Err(error) = self.run(&rule, "-D", true) {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(VmmError::Network(failures.join("; ")))
        }
    }
}

/// Comment tag on every translation rule, marking them as arcbox-owned for
/// forensics (`iptables -S`). Deletion goes by exact rule spec, not the tag.
const RULE_COMMENT: &str = "arcbox-nat";

/// One iptables rule of the per-TAP translation set.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct XtRule {
    pub table: &'static str,
    pub chain: &'static str,
    pub spec: Vec<String>,
}

/// The complete per-TAP translation rule set, in install order — the
/// iptables rendering of the module-level contract.
pub(crate) fn translation_rules(tap: &str, pool_ip: Ipv4Addr) -> Vec<XtRule> {
    let mark = format!("{:#x}", fwmark(pool_ip));
    let pool = format!("{pool_ip}/32");
    let comment = |spec: &mut Vec<String>| {
        spec.extend(["-m", "comment", "--comment", RULE_COMMENT].map(String::from));
    };
    let mut rules = Vec::new();
    let mut rule = |table, chain, head: &[&str], tail: &[&str]| {
        let mut spec: Vec<String> = head.iter().map(|s| (*s).to_owned()).collect();
        comment(&mut spec);
        spec.extend(tail.iter().map(|s| (*s).to_owned()));
        rules.push(XtRule { table, chain, spec });
    };

    // 1. Mark sandbox-originated packets so POSTROUTING (which cannot match
    //    the input interface) can select the right source identity.
    rule(
        "mangle",
        "PREROUTING",
        &["-i", tap],
        &["-j", "MARK", "--set-mark", &mark],
    );
    // 2. Mark to-sandbox packets from their pre-NAT destination; the fwmark
    //    fib rule then routes the DNAT'd destination out this TAP.
    rule(
        "mangle",
        "PREROUTING",
        &["-d", &pool],
        &["-j", "MARK", "--set-mark", &mark],
    );
    rule(
        "mangle",
        "OUTPUT",
        &["-d", &pool],
        &["-j", "MARK", "--set-mark", &mark],
    );
    // 3. External identity → fixed guest identity, both directions.
    let guest_ip = GUEST_IP.to_string();
    rule(
        "nat",
        "PREROUTING",
        &["-d", &pool],
        &["-j", "DNAT", "--to-destination", &guest_ip],
    );
    rule(
        "nat",
        "OUTPUT",
        &["-d", &pool],
        &["-j", "DNAT", "--to-destination", &guest_ip],
    );
    // 4. Local services (DNS, relays) see the pool identity, and their
    //    replies are addressed to it — which is what makes them routable
    //    back out the right TAP (dst-based mark + fwmark table).
    rule(
        "nat",
        "INPUT",
        &["-i", tap],
        &["-j", "SNAT", "--to-source", &pool_ip.to_string()],
    );
    // 5. Forwarded sandbox-originated traffic. The source match is the
    //    definitive sandbox-origin signature at POSTROUTING (only pre-SNAT
    //    sandbox packets carry the fixed guest source); the mark picks which
    //    sandbox, keeping to-sandbox packets (marked with the same value but
    //    carrying a client source) out of this rewrite.
    rule(
        "nat",
        "POSTROUTING",
        &[
            "-s",
            &format!("{GUEST_IP}/32"),
            "-m",
            "mark",
            "--mark",
            &mark,
        ],
        &["-j", "SNAT", "--to-source", &pool_ip.to_string()],
    );
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule specs are the NAT contract; pin them exactly so drift is loud.
    #[test]
    fn translation_rules_pin_the_nat_contract() {
        let pool: Ipv4Addr = "172.20.0.2".parse().unwrap();
        let rules = translation_rules("vmtap0-2", pool);
        let rendered: Vec<String> = rules
            .iter()
            .map(|r| format!("-t {} {} {}", r.table, r.chain, r.spec.join(" ")))
            .collect();
        assert_eq!(
            rendered,
            [
                "-t mangle PREROUTING -i vmtap0-2 -m comment --comment arcbox-nat -j MARK --set-mark 0xac140002",
                "-t mangle PREROUTING -d 172.20.0.2/32 -m comment --comment arcbox-nat -j MARK --set-mark 0xac140002",
                "-t mangle OUTPUT -d 172.20.0.2/32 -m comment --comment arcbox-nat -j MARK --set-mark 0xac140002",
                "-t nat PREROUTING -d 172.20.0.2/32 -m comment --comment arcbox-nat -j DNAT --to-destination 169.254.100.2",
                "-t nat OUTPUT -d 172.20.0.2/32 -m comment --comment arcbox-nat -j DNAT --to-destination 169.254.100.2",
                "-t nat INPUT -i vmtap0-2 -m comment --comment arcbox-nat -j SNAT --to-source 172.20.0.2",
                "-t nat POSTROUTING -s 169.254.100.2/32 -m mark --mark 0xac140002 -m comment --comment arcbox-nat -j SNAT --to-source 172.20.0.2",
            ]
        );
    }

    #[test]
    fn snat_selection_never_rewrites_client_sources() {
        // The POSTROUTING SNAT must be gated on the fixed guest source, not
        // the mark alone: to-sandbox packets carry the same mark but a client
        // source, and rewriting those would hide real client IPs from guests.
        let rules = translation_rules("vmtap0-2", "172.20.0.2".parse().unwrap());
        let postrouting = rules
            .iter()
            .find(|r| r.chain == "POSTROUTING")
            .expect("POSTROUTING SNAT rule");
        assert_eq!(postrouting.spec[0], "-s");
        assert_eq!(postrouting.spec[1], format!("{GUEST_IP}/32"));
    }

    #[test]
    fn iptables_legacy_defaults_to_the_system_vm_path() {
        assert_eq!(
            IptablesLegacy::default().iptables,
            PathBuf::from(IptablesLegacy::DEFAULT_PATH)
        );
    }

    #[test]
    fn a_missing_binary_is_an_error_even_on_tolerant_removal() {
        // Tolerance covers "no matching rule" (exit 1), never "could not run
        // iptables at all": a wrong path must surface, not read as clean.
        let filter = IptablesLegacy::new("/nonexistent/arcbox-iptables");
        let err = filter
            .remove_translation("vmtap0-2", "172.20.0.2".parse().unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("run "), "{err}");
    }
}
