//! [`PacketFilter`] over iptables-legacy — the System VM's userland, and the
//! reference rendering of the seam's contract (see [`super`]).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use super::{PacketFilter, RULE_COMMENT};
use crate::error::{Result, TapNetError};
use crate::invariant::{GUEST_IP, fwmark};

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
    /// lock timing out) still propagate. The failure is the bare
    /// diagnostic text: callers wrap it into [`TapNetError::Network`] once,
    /// so a collected teardown report carries one prefix, not one per rule.
    fn run(
        &self,
        rule: &XtRule,
        verb: &str,
        tolerate_missing: bool,
    ) -> std::result::Result<(), String> {
        let output = std::process::Command::new(&self.iptables)
            .args(["-w", "2", "-t", rule.table, verb, rule.chain])
            .args(&rule.spec)
            .output()
            .map_err(|e| format!("run {}: {e}", self.iptables.display()))?;
        if output.status.success() || (tolerate_missing && output.status.code() == Some(1)) {
            return Ok(());
        }
        Err(format!(
            "iptables -t {} {verb} {} {}: {}",
            rule.table,
            rule.chain,
            rule.spec.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
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
            self.run(&rule, "-A", false).map_err(TapNetError::Network)?;
        }
        Ok(())
    }

    fn remove_translation(&self, tap: &str, pool_ip: Ipv4Addr) -> Result<()> {
        let mut failures = Vec::new();
        for rule in translation_rules(tap, pool_ip) {
            if let Err(failure) = self.run(&rule, "-D", true) {
                failures.push(failure);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(TapNetError::Network(failures.join("; ")))
        }
    }
}

/// One iptables rule of the per-TAP translation set.
#[derive(Debug, PartialEq, Eq)]
pub struct XtRule {
    pub table: &'static str,
    pub chain: &'static str,
    pub spec: Vec<String>,
}

/// The complete per-TAP translation rule set, in install order — the
/// iptables rendering of the module-level contract.
pub fn translation_rules(tap: &str, pool_ip: Ipv4Addr) -> Vec<XtRule> {
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
