//! Sandbox port forwarding via iptables DNAT.
//!
//! The macOS host cannot reach sandbox IPs (172.20.0.0/16) directly, but its
//! inbound relay can inject connections to any *guest* port. Exposing a
//! sandbox port therefore has two halves:
//!
//! ```text
//! host listener :H → inbound relay → guest:G → [iptables DNAT] → sandbox:P
//! ```
//!
//! This module owns the guest half: it allocates `G` from a reserved range
//! (40000–49999), installs the `PREROUTING` DNAT rule, and removes it on
//! request or when the host finalizes the sandbox's durable cleanup ticket.
//! `FORWARD` traffic is already accepted by the blanket sandbox subnet rules
//! installed at boot (`init.rs::setup_sandbox_forwarding`).
//!
//! How the DNAT targets the sandbox follows the identity's
//! [`HostIngress`](arcbox_vm_driver::net::HostIngress), the guest network's
//! own answer for how host-side
//! forwarding reaches that guest. This composer builds the sandbox network
//! out of `arcbox-tap-net`, so it reads that answer back as the adapter's
//! [`ExposeTarget`] — decided by the datapath applied to the sandbox's TAP
//! (CORE-81/CORE-83): the pool-IP form for legacy guests and for eBPF-datapath
//! invariant guests (whose TAP egress program rewrites the pool destination
//! after routing), or the fixed guest IP paired with a mangle `MARK` rule on
//! the same match for iptables-datapath invariant guests, so the rewritten
//! destination routes out the right TAP via the sandbox's fwmark table.

use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::process::Output;

use anyhow::{Context, Result, bail};
use arcbox_computer_runtime::SandboxNetworkIdentity;
use arcbox_computer_runtime::network::invariant;
use arcbox_tap_net::ExposeTarget;
use tokio::process::Command;

/// First port of the reserved guest relay range.
const PORT_RANGE_START: u16 = 40000;
/// Last port of the reserved guest relay range (inclusive).
const PORT_RANGE_END: u16 = 49999;
/// iptables `--comment` tag stamped on every sandbox forwarding rule, so
/// rules left behind by a crashed/restarted agent can be identified and
/// flushed (they are otherwise untracked kernel state that would misroute
/// after IP reuse).
const RULE_COMMENT_PREFIX: &str = "arcbox-sbx:";
const LEGACY_RULE_COMMENT: &str = "arcbox-sbx";

/// Transport protocol of a forwarded port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    const fn iptables_name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One installed forwarding mapping.
struct ForwardRule {
    guest_port: u16,
    sandbox_ip: Ipv4Addr,
    cleanup_token: String,
    /// The exact nat DNAT rule spec, so removal deletes precisely this rule.
    rule_args: Vec<String>,
    /// Companion mangle `MARK` rule spec (invariant-addressed sandboxes only).
    mangle_args: Option<Vec<String>>,
}

impl ForwardRule {
    /// The `(table, spec)` halves this mapping installed, in install order.
    fn halves(&self) -> Vec<(&'static str, Vec<String>)> {
        let mut halves = Vec::with_capacity(2);
        if let Some(ref mangle) = self.mangle_args {
            halves.push(("mangle", mangle.clone()));
        }
        halves.push(("nat", self.rule_args.clone()));
        halves
    }
}

/// Manages the reserved-range forwarding mappings for all sandboxes.
#[derive(Default)]
pub struct PortForwardManager {
    /// `(sandbox_id, sandbox_port, protocol)` → installed rule.
    rules: HashMap<(String, u16, Protocol), ForwardRule>,
    /// Rotating allocation cursor within the reserved range.
    next_offset: u16,
}

impl PortForwardManager {
    /// Install (or return the existing) forwarding mapping for a sandbox port.
    ///
    /// Returns the reserved-range guest port carrying the relay.
    pub async fn forward(
        &mut self,
        sandbox_id: &str,
        identity: &SandboxNetworkIdentity,
        sandbox_port: u16,
        protocol: Protocol,
    ) -> Result<u16> {
        let key = (sandbox_id.to_owned(), sandbox_port, protocol);
        if let Some(rule) = self.rules.get(&key) {
            let same_ip = rule.sandbox_ip == identity.ip;
            let same_generation = rule.cleanup_token == identity.cleanup_token;
            if same_ip && same_generation {
                let guest_port = rule.guest_port;
                let halves = rule.halves();
                let mut repaired = false;
                for (table, spec) in halves {
                    if rule_is_installed(&prepend_table(table, "-C", &spec)).await? {
                        continue;
                    }
                    run_iptables(&prepend_table(table, "-I", &spec))
                        .await
                        .context("repairing missing forwarding rule")?;
                    repaired = true;
                }
                if repaired {
                    tracing::info!(
                        sandbox_id,
                        guest_port,
                        sandbox_port,
                        sandbox_ip = %identity.ip,
                        "sandbox port forward repaired"
                    );
                }
                return Ok(guest_port);
            }
            self.remove_keys(vec![key.clone()]).await?;
        }

        let guest_port = self.allocate_port()?;
        let (rule_args, mangle_args) =
            expose_rule_specs(identity, guest_port, sandbox_port, protocol)?;

        if let Some(ref mangle) = mangle_args {
            run_iptables(&prepend_table("mangle", "-I", mangle))
                .await
                .context("installing fwmark rule")?;
        }
        if let Err(error) = run_iptables(&prepend_table("nat", "-I", &rule_args))
            .await
            .context("installing DNAT rule")
        {
            // Roll the mangle half back so a failed install leaves no orphan.
            if let Some(ref mangle) = mangle_args {
                let _ = run_iptables(&prepend_table("mangle", "-D", mangle)).await;
            }
            return Err(error);
        }

        tracing::info!(
            sandbox_id,
            guest_port,
            sandbox_port,
            sandbox_ip = %identity.ip,
            expose = ?identity.expose,
            "sandbox port forward installed"
        );
        self.rules.insert(
            key,
            ForwardRule {
                guest_port,
                sandbox_ip: identity.ip,
                cleanup_token: identity.cleanup_token.clone(),
                rule_args,
                mangle_args,
            },
        );
        Ok(guest_port)
    }

    /// Remove one mapping. Missing mappings are not an error (idempotent).
    pub async fn remove(
        &mut self,
        sandbox_id: &str,
        cleanup_token: &str,
        sandbox_port: u16,
        protocol: Protocol,
    ) -> Result<()> {
        let key = (sandbox_id.to_owned(), sandbox_port, protocol);
        let keys = self
            .rules
            .get(&key)
            .filter(|rule| rule.cleanup_token == cleanup_token)
            .map(|_| vec![key])
            .unwrap_or_default();
        self.remove_keys(keys).await
    }

    /// Remove every mapping belonging to one exact sandbox generation.
    pub async fn remove_all_for(&mut self, sandbox_id: &str, cleanup_token: &str) -> Result<()> {
        let keys: Vec<_> = self
            .rules
            .iter()
            .filter(|((id, _, _), rule)| id == sandbox_id && rule.cleanup_token == cleanup_token)
            .map(|(key, _)| key.clone())
            .collect();
        self.remove_keys(keys).await
    }

    async fn remove_keys(&mut self, keys: Vec<(String, u16, Protocol)>) -> Result<()> {
        self.remove_keys_with(
            keys,
            |args| async move { rule_is_installed(&args).await },
            |args| async move { run_iptables(&args).await },
        )
        .await
    }

    /// Both closures receive a full iptables argv (`-t <table> -C/-D
    /// PREROUTING <spec>`); the indirection keeps the removal bookkeeping
    /// testable without a kernel.
    async fn remove_keys_with<C, CFut, D, DFut>(
        &mut self,
        keys: Vec<(String, u16, Protocol)>,
        mut check: C,
        mut delete: D,
    ) -> Result<()>
    where
        C: FnMut(Vec<String>) -> CFut,
        CFut: Future<Output = Result<bool>>,
        D: FnMut(Vec<String>) -> DFut,
        DFut: Future<Output = Result<()>>,
    {
        let mut failures = Vec::new();
        for key in keys {
            let Some(rule) = self.rules.get(&key) else {
                continue;
            };
            let halves = rule.halves();
            let guest_port = rule.guest_port;

            // Delete the kernel rules BEFORE dropping the record. A failed
            // record remains owned by this manager so a retry can remove it.
            let result = async {
                for (table, spec) in halves {
                    if check(prepend_table(table, "-C", &spec))
                        .await
                        .context("checking forwarding rule")?
                    {
                        delete(prepend_table(table, "-D", &spec))
                            .await
                            .context("removing forwarding rule")?;
                    }
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            match result {
                Ok(()) => {
                    self.rules.remove(&key);
                    tracing::info!(
                        sandbox_id = key.0,
                        guest_port,
                        "sandbox port forward removed"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        sandbox_id = key.0,
                        sandbox_port = key.1,
                        protocol = key.2.iptables_name(),
                        error = %error,
                        "failed to remove port forward"
                    );
                    failures.push(format!("{}/{}: {error:#}", key.1, key.2.iptables_name()));
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "failed to remove {} sandbox port forward(s): {}",
                failures.len(),
                failures.join("; ")
            )
        }
    }

    /// Pick a free port in the reserved range, scanning from a rotating cursor.
    fn allocate_port(&mut self) -> Result<u16> {
        let span = PORT_RANGE_END - PORT_RANGE_START + 1;
        for probe in 0..span {
            let offset = (self.next_offset + probe) % span;
            let candidate = PORT_RANGE_START + offset;
            if !self.rules.values().any(|r| r.guest_port == candidate) {
                self.next_offset = (offset + 1) % span;
                return Ok(candidate);
            }
        }
        bail!("no free port in the reserved range {PORT_RANGE_START}-{PORT_RANGE_END}")
    }
}

/// The nat DNAT spec and optional mangle `MARK` companion for one mapping,
/// selected by how the sandbox's datapath expects to be targeted.
///
/// The identity carries the port's
/// [`HostIngress`](arcbox_vm_driver::net::HostIngress); this is where it
/// becomes the TAP network's [`ExposeTarget`], because this is where it
/// becomes iptables arguments. The conversion can refuse — a variant
/// this adapter has no rendering for is a network the sandbox stack was not
/// composed over, and installing the wrong DNAT would strand the mapping
/// silently.
fn expose_rule_specs(
    identity: &SandboxNetworkIdentity,
    guest_port: u16,
    sandbox_port: u16,
    protocol: Protocol,
) -> Result<(Vec<String>, Option<Vec<String>>)> {
    let (target_ip, mangle_args) = match ExposeTarget::try_from(identity.expose)? {
        ExposeTarget::PoolIp => (identity.ip, None),
        ExposeTarget::GuestIpWithFwmark => (
            invariant::GUEST_IP,
            Some(mark_rule_args(
                guest_port,
                identity.ip,
                &identity.cleanup_token,
                protocol,
            )),
        ),
    };
    Ok((
        dnat_rule_args(
            guest_port,
            target_ip,
            &identity.cleanup_token,
            sandbox_port,
            protocol,
        ),
        mangle_args,
    ))
}

/// The protocol/port/destination spec shared by install and delete.
fn dnat_rule_args(
    guest_port: u16,
    target_ip: Ipv4Addr,
    cleanup_token: &str,
    sandbox_port: u16,
    protocol: Protocol,
) -> Vec<String> {
    vec![
        "-p".into(),
        protocol.iptables_name().into(),
        "--dport".into(),
        guest_port.to_string(),
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        format!("{RULE_COMMENT_PREFIX}{cleanup_token}"),
        "-j".into(),
        "DNAT".into(),
        "--to-destination".into(),
        format!("{target_ip}:{sandbox_port}"),
    ]
}

/// The mangle-side companion of an invariant DNAT: the same match, marking
/// the packet with the sandbox's fwmark so the rewritten (fixed-guest)
/// destination routes out this sandbox's TAP.
///
/// Deliberately has no `-d` guard: relay ports accept traffic addressed to
/// any of the System VM's local addresses (that is the feature), so there
/// is no single destination to pin. The mark therefore lands on every
/// packet hitting `guest_port` — safe ONLY because the per-sandbox fwmark
/// table holds exactly one route (`GUEST_IP/32`, see
/// `invariant::fib_table_routes`); any other destination misses it and
/// falls through to `main`. Adding a second route to that table would
/// silently widen this rule's blast radius — don't.
fn mark_rule_args(
    guest_port: u16,
    pool_ip: Ipv4Addr,
    cleanup_token: &str,
    protocol: Protocol,
) -> Vec<String> {
    vec![
        "-p".into(),
        protocol.iptables_name().into(),
        "--dport".into(),
        guest_port.to_string(),
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        format!("{RULE_COMMENT_PREFIX}{cleanup_token}"),
        "-j".into(),
        "MARK".into(),
        "--set-mark".into(),
        format!("{:#x}", invariant::fwmark(pool_ip)),
    ]
}

/// If `line` belongs to the exact quarantined generation, return the argv
/// that deletes it from `table`'s PREROUTING chain.
///
/// Tokenized rules are matched by their unique generation comment alone —
/// their DNAT target differs by addressing mode (pool IP for legacy,
/// the fixed guest IP for invariant sandboxes) and the mangle MARK half has
/// no target at all. Pre-token rules carry only the bare legacy comment, so
/// they are additionally gated on the pool-IP target.
fn orphan_delete_args(
    table: &'static str,
    line: &str,
    sandbox_ip: Ipv4Addr,
    cleanup_token: &str,
) -> Option<Vec<String>> {
    let spec = line.strip_prefix("-A PREROUTING ")?;
    let fields: Vec<_> = spec
        .split_whitespace()
        .map(unquote_iptables_field)
        .collect();
    let comment = format!("{RULE_COMMENT_PREFIX}{cleanup_token}");
    let exact = fields
        .windows(2)
        .any(|pair| pair[0] == "--comment" && pair[1] == comment);
    let legacy = fields
        .windows(2)
        .any(|pair| pair[0] == "--comment" && pair[1] == LEGACY_RULE_COMMENT);
    let destination_prefix = format!("{sandbox_ip}:");
    let targets_ip = fields
        .windows(2)
        .any(|pair| pair[0] == "--to-destination" && pair[1].starts_with(&destination_prefix));
    if !(exact || (legacy && targets_ip)) {
        return None;
    }
    Some(prepend_table(table, "-D", &fields))
}

fn unquote_iptables_field(field: &str) -> String {
    field
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(field)
        .to_owned()
}

fn legacy_orphan_delete_args(line: &str) -> Option<Vec<String>> {
    let spec = line.strip_prefix("-A PREROUTING ")?;
    let fields: Vec<_> = spec
        .split_whitespace()
        .map(unquote_iptables_field)
        .collect();
    let legacy = fields
        .windows(2)
        .any(|pair| pair == ["--comment", LEGACY_RULE_COMMENT]);
    if !legacy {
        return None;
    }
    Some(prepend_table("nat", "-D", &fields))
}

/// Delete kernel forwarding state for one exact quarantined generation after
/// the host has removed its listeners. This also covers agent restart, where
/// the process-local rule registry is empty. Sweeps both the nat DNAT rules
/// and the mangle MARK companions of invariant sandboxes.
pub async fn remove_orphan_rules_for(sandbox_ip: Ipv4Addr, cleanup_token: &str) -> Result<()> {
    let mut removed = 0usize;
    let mut failures = Vec::new();
    for table in ["nat", "mangle"] {
        let listing = list_prerouting(table).await?;
        for line in listing.lines() {
            if let Some(args) = orphan_delete_args(table, line, sandbox_ip, cleanup_token) {
                match run_iptables(&args).await {
                    Ok(()) => removed += 1,
                    Err(error) => failures.push(error.to_string()),
                }
            }
        }
    }
    if removed > 0 {
        tracing::info!(
            removed,
            %sandbox_ip,
            "removed quarantined sandbox forwarding rules"
        );
    }
    if !failures.is_empty() {
        bail!(
            "failed to remove {} quarantined forwarding rule(s): {}",
            failures.len(),
            failures.join("; ")
        );
    }
    Ok(())
}

/// Remove only pre-token sandbox rules during the startup handshake. Tokenized
/// generations remain quarantined until their individual tickets finalize.
/// Pre-token rules predate the mangle companions, so only nat is swept.
pub async fn remove_legacy_orphan_rules() -> Result<()> {
    let listing = list_prerouting("nat").await?;
    let mut failures = Vec::new();
    for args in listing.lines().filter_map(legacy_orphan_delete_args) {
        if let Err(error) = run_iptables(&args).await {
            failures.push(error.to_string());
        }
    }
    if !failures.is_empty() {
        bail!(
            "failed to remove {} legacy DNAT rule(s): {}",
            failures.len(),
            failures.join("; ")
        );
    }
    Ok(())
}

async fn list_prerouting(table: &str) -> Result<String> {
    let output = Command::new("/sbin/iptables")
        .args(["-t", table, "-S", "PREROUTING"])
        .output()
        .await
        .context("listing sandbox forwarding rules")?;
    if !output.status.success() {
        bail!(
            "iptables -t {table} -S PREROUTING failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn prepend_table(table: &str, verb: &str, tail: &[String]) -> Vec<String> {
    ["-t", table, verb, "PREROUTING"]
        .iter()
        .map(|s| (*s).to_owned())
        .chain(tail.iter().cloned())
        .collect()
}

async fn run_iptables(args: &[String]) -> Result<()> {
    let output = Command::new("/sbin/iptables")
        .args(args)
        .output()
        .await
        .context("failed to run iptables")?;
    if !output.status.success() {
        bail!(
            "iptables {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

async fn rule_is_installed(check_args: &[String]) -> Result<bool> {
    let output = Command::new("/sbin/iptables")
        .args(["-w", "2"])
        .args(check_args)
        .output()
        .await
        .context("failed to run iptables")?;
    classify_rule_check(output, check_args)
}

fn classify_rule_check(output: Output, args: &[String]) -> Result<bool> {
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    bail!(
        "iptables {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt as _;

    use arcbox_vm_driver::net::HostIngress;

    use super::*;

    #[test]
    fn dnat_spec_is_symmetric_and_tagged() {
        let args = dnat_rule_args(
            40000,
            Ipv4Addr::new(172, 20, 0, 2),
            "generation",
            8080,
            Protocol::Tcp,
        );
        assert_eq!(
            args,
            [
                "-p",
                "tcp",
                "--dport",
                "40000",
                "-m",
                "comment",
                "--comment",
                "arcbox-sbx:generation",
                "-j",
                "DNAT",
                "--to-destination",
                "172.20.0.2:8080"
            ]
        );
    }

    #[test]
    fn mark_spec_shares_the_dnat_match_and_carries_the_fwmark() {
        let pool: Ipv4Addr = "172.20.0.2".parse().unwrap();
        let args = mark_rule_args(40000, pool, "generation", Protocol::Tcp);
        assert_eq!(
            args,
            [
                "-p",
                "tcp",
                "--dport",
                "40000",
                "-m",
                "comment",
                "--comment",
                "arcbox-sbx:generation",
                "-j",
                "MARK",
                "--set-mark",
                "0xac140002"
            ]
        );
        // Same match prefix as the DNAT half — the two rules must classify
        // the identical packets.
        let dnat = dnat_rule_args(
            40000,
            invariant::GUEST_IP,
            "generation",
            8080,
            Protocol::Tcp,
        );
        assert_eq!(args[..8], dnat[..8]);
    }

    fn identity(expose: HostIngress) -> SandboxNetworkIdentity {
        SandboxNetworkIdentity {
            ip: "172.20.0.2".parse().unwrap(),
            cleanup_token: "generation".into(),
            expose,
        }
    }

    /// Pool-IP expose (legacy guests and eBPF-datapath invariant guests):
    /// DNAT to the pool IP with no mangle companion — the TAP route delivers
    /// and, on the eBPF path, the egress program does the rewrite.
    #[test]
    fn pool_ip_expose_targets_the_pool_ip_without_a_mangle_companion() {
        let (dnat, mangle) = expose_rule_specs(
            &identity(HostIngress::PoolAddress),
            40000,
            8080,
            Protocol::Tcp,
        )
        .unwrap();
        assert!(mangle.is_none());
        assert_eq!(dnat.last().unwrap(), "172.20.0.2:8080");
    }

    /// Fwmark expose (iptables-datapath invariant guests): DNAT to the fixed
    /// guest IP plus the mark companion that routes it out the right TAP.
    /// The mark on the wire is the one this composer derives from the pool
    /// address, not the one the ingress carried: the two agree over the TAP
    /// network (`invariant::fwmark(pool_ip)` is what its `host_ingress`
    /// mints), and the derivation is what the per-sandbox routing table is
    /// keyed by.
    #[test]
    fn fwmark_expose_targets_the_guest_ip_with_the_mark_companion() {
        let (dnat, mangle) = expose_rule_specs(
            &identity(HostIngress::GuestAddress {
                fwmark: invariant::fwmark("172.20.0.2".parse().unwrap()),
            }),
            40000,
            8080,
            Protocol::Tcp,
        )
        .unwrap();
        assert_eq!(
            dnat.last().unwrap(),
            &format!("{}:8080", invariant::GUEST_IP)
        );
        let mangle = mangle.expect("the fwmark form needs its mangle companion");
        assert_eq!(mangle.last().unwrap(), "0xac140002");
    }

    #[test]
    fn orphan_delete_targets_only_tagged_prerouting_rules() {
        // A tagged arcbox rule (as `iptables -S` prints it, with the implicit
        // `-m tcp`) is converted from -A to a -D argv.
        let line = "-A PREROUTING -p tcp -m tcp --dport 40000 -m comment \
                    --comment \"arcbox-sbx:generation\" -j DNAT \
                    --to-destination 172.20.0.2:8080";
        let args = orphan_delete_args("nat", line, "172.20.0.2".parse().unwrap(), "generation")
            .expect("tagged rule should match");
        assert_eq!(args[..4], ["-t", "nat", "-D", "PREROUTING"]);
        assert_eq!(args.last().unwrap(), "172.20.0.2:8080");
        assert!(args.iter().any(|a| a == "arcbox-sbx:generation"));
        assert!(!args.iter().any(|a| a.contains('"')));
        assert!(orphan_delete_args("nat", line, "172.20.0.2".parse().unwrap(), "old").is_none());
        // The exact generation token is unique, so it alone identifies the
        // rule — a mismatched pool IP no longer shields a tokenized rule.
        assert!(
            orphan_delete_args("nat", line, "172.20.0.3".parse().unwrap(), "generation").is_some()
        );

        // A foreign rule (e.g. Docker's) is left untouched.
        let docker = "-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT \
                      --to-destination 172.17.0.2:80";
        assert!(
            orphan_delete_args("nat", docker, "172.20.0.2".parse().unwrap(), "generation")
                .is_none()
        );

        // A non-PREROUTING line is ignored.
        assert!(
            orphan_delete_args(
                "nat",
                "-N DOCKER",
                "172.20.0.2".parse().unwrap(),
                "generation"
            )
            .is_none()
        );

        let legacy = "-A PREROUTING -p tcp --dport 40000 -m comment \
                      --comment \"arcbox-sbx\" -j DNAT \
                      --to-destination 172.20.0.2:8080";
        assert!(
            orphan_delete_args("nat", legacy, "172.20.0.2".parse().unwrap(), "generation")
                .is_some()
        );
        // Pre-token rules stay gated on the pool-IP target.
        assert!(
            orphan_delete_args("nat", legacy, "172.20.0.3".parse().unwrap(), "generation")
                .is_none()
        );
        assert!(legacy_orphan_delete_args(legacy).is_some());
        assert!(legacy_orphan_delete_args(line).is_none());
    }

    #[test]
    fn orphan_delete_matches_invariant_dnat_and_mark_rules() {
        // Invariant DNAT targets the fixed guest IP; the token must still
        // claim it for this generation's cleanup.
        let dnat = "-A PREROUTING -p tcp -m tcp --dport 40000 -m comment \
                    --comment \"arcbox-sbx:generation\" -j DNAT \
                    --to-destination 169.254.100.2:8080";
        assert!(
            orphan_delete_args("nat", dnat, "172.20.0.2".parse().unwrap(), "generation").is_some()
        );

        // The mangle MARK companion has no --to-destination at all.
        let mark = "-A PREROUTING -p tcp -m tcp --dport 40000 -m comment \
                    --comment \"arcbox-sbx:generation\" -j MARK --set-xmark 0xac140002/0xffffffff";
        let args = orphan_delete_args("mangle", mark, "172.20.0.2".parse().unwrap(), "generation")
            .expect("tokenized mangle rule should match");
        assert_eq!(args[..4], ["-t", "mangle", "-D", "PREROUTING"]);
        assert!(
            orphan_delete_args("mangle", mark, "172.20.0.2".parse().unwrap(), "other").is_none()
        );
    }

    fn test_rule(port: u16, token: &str, mangle: bool) -> ForwardRule {
        ForwardRule {
            guest_port: PORT_RANGE_START + port,
            sandbox_ip: "172.20.0.2".parse().unwrap(),
            cleanup_token: token.into(),
            rule_args: vec![port.to_string()],
            mangle_args: mangle.then(|| vec![format!("mark-{port}")]),
        }
    }

    #[test]
    fn allocator_skips_used_ports_and_wraps() {
        let mut mgr = PortForwardManager::default();
        let first = mgr.allocate_port().unwrap();
        assert_eq!(first, PORT_RANGE_START);
        // Simulate the first port being taken.
        mgr.rules.insert(
            ("a".into(), 80, Protocol::Tcp),
            ForwardRule {
                guest_port: PORT_RANGE_START + 1,
                sandbox_ip: "172.20.0.2".parse().unwrap(),
                cleanup_token: "generation".into(),
                rule_args: vec![],
                mangle_args: None,
            },
        );
        let second = mgr.allocate_port().unwrap();
        assert_eq!(second, PORT_RANGE_START + 2);
    }

    #[tokio::test]
    async fn bulk_remove_keeps_failed_rules_and_removes_the_rest() {
        let mut mgr = PortForwardManager::default();
        for (id, port) in [("target", 80), ("target", 81), ("other", 82)] {
            let token = if id == "target" {
                "generation"
            } else {
                "other-generation"
            };
            mgr.rules.insert(
                (id.into(), port, Protocol::Tcp),
                test_rule(port, token, false),
            );
        }

        let keys = mgr
            .rules
            .keys()
            .filter(|(id, _, _)| id == "target")
            .cloned()
            .collect();
        let error = mgr
            .remove_keys_with(
                keys,
                |_| async { Ok(true) },
                |args| async move {
                    if args.last().is_some_and(|arg| arg == "80") {
                        bail!("simulated iptables failure");
                    }
                    Ok(())
                },
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("80/tcp"));
        assert!(
            mgr.rules
                .contains_key(&("target".into(), 80, Protocol::Tcp))
        );
        assert!(
            !mgr.rules
                .contains_key(&("target".into(), 81, Protocol::Tcp))
        );
        assert!(mgr.rules.contains_key(&("other".into(), 82, Protocol::Tcp)));

        let retry = mgr
            .rules
            .keys()
            .filter(|(id, _, _)| id == "target")
            .cloned()
            .collect();
        mgr.remove_keys_with(retry, |_| async { Ok(true) }, |_| async { Ok(()) })
            .await
            .unwrap();
        assert!(!mgr.rules.keys().any(|(id, _, _)| id == "target"));
    }

    #[tokio::test]
    async fn bulk_remove_deletes_both_halves_of_an_invariant_mapping() {
        let mut mgr = PortForwardManager::default();
        mgr.rules.insert(
            ("target".into(), 80, Protocol::Tcp),
            test_rule(80, "generation", true),
        );
        let deleted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&deleted);
        mgr.remove_keys_with(
            vec![("target".into(), 80, Protocol::Tcp)],
            |_| async { Ok(true) },
            move |args| {
                let sink = std::sync::Arc::clone(&sink);
                async move {
                    sink.lock().unwrap().push(args);
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        let deleted = deleted.lock().unwrap();
        assert_eq!(deleted.len(), 2, "both the mangle and nat halves");
        assert_eq!(deleted[0][..4], ["-t", "mangle", "-D", "PREROUTING"]);
        assert_eq!(deleted[1][..4], ["-t", "nat", "-D", "PREROUTING"]);
        assert!(mgr.rules.is_empty());
    }

    #[tokio::test]
    async fn bulk_remove_drops_records_for_rules_already_absent() {
        let mut mgr = PortForwardManager::default();
        mgr.rules.insert(
            ("target".into(), 80, Protocol::Tcp),
            test_rule(80, "generation", false),
        );
        let keys = vec![("target".into(), 80, Protocol::Tcp)];
        mgr.remove_keys_with(
            keys,
            |_| async { Ok(false) },
            |_| async { bail!("delete must not run for an absent rule") },
        )
        .await
        .unwrap();
        assert!(mgr.rules.is_empty());
    }

    #[test]
    fn rule_check_only_treats_exit_one_as_absent() {
        let output = |code| Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: b"check failed".to_vec(),
        };

        assert!(classify_rule_check(output(0), &[]).unwrap());
        assert!(!classify_rule_check(output(1), &[]).unwrap());
        assert!(classify_rule_check(output(4), &[]).is_err());
    }
}
