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
//! request or when the sandbox stops (event-driven cleanup in the sandbox
//! dispatcher). `FORWARD` traffic is already accepted by the blanket sandbox
//! subnet rules installed at boot (`init.rs::setup_sandbox_forwarding`).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

/// First port of the reserved guest relay range.
const PORT_RANGE_START: u16 = 40000;
/// Last port of the reserved guest relay range (inclusive).
const PORT_RANGE_END: u16 = 49999;
/// iptables `--comment` tag stamped on every sandbox DNAT rule, so rules left
/// behind by a crashed/restarted agent can be identified and flushed (they are
/// otherwise untracked kernel state that would misroute after IP reuse).
const RULE_COMMENT: &str = "arcbox-sbx";

/// Transport protocol of a forwarded port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// Parse a wire protocol string; empty selects TCP.
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "" | "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => bail!("unsupported protocol '{other}' (expected tcp or udp)"),
        }
    }

    const fn iptables_name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One installed DNAT mapping.
struct ForwardRule {
    guest_port: u16,
    /// The exact iptables rule spec, so removal deletes precisely this rule.
    rule_args: Vec<String>,
}

/// Manages the reserved-range DNAT mappings for all sandboxes.
#[derive(Default)]
pub struct PortForwardManager {
    /// `(sandbox_id, sandbox_port, protocol)` → installed rule.
    rules: HashMap<(String, u16, Protocol), ForwardRule>,
    /// Rotating allocation cursor within the reserved range.
    next_offset: u16,
}

impl PortForwardManager {
    /// Install (or return the existing) DNAT mapping for a sandbox port.
    ///
    /// Returns the reserved-range guest port carrying the relay.
    pub async fn forward(
        &mut self,
        sandbox_id: &str,
        sandbox_ip: Ipv4Addr,
        sandbox_port: u16,
        protocol: Protocol,
    ) -> Result<u16> {
        let key = (sandbox_id.to_owned(), sandbox_port, protocol);
        if let Some(rule) = self.rules.get(&key) {
            return Ok(rule.guest_port);
        }

        let guest_port = self.allocate_port()?;
        let rule_args = dnat_rule_args(guest_port, sandbox_ip, sandbox_port, protocol);

        run_iptables(&prepend(&["-t", "nat", "-I", "PREROUTING"], &rule_args))
            .await
            .context("installing DNAT rule")?;

        tracing::info!(
            sandbox_id,
            guest_port,
            sandbox_port,
            %sandbox_ip,
            "sandbox port forward installed"
        );
        self.rules.insert(
            key,
            ForwardRule {
                guest_port,
                rule_args,
            },
        );
        Ok(guest_port)
    }

    /// Remove one mapping. Missing mappings are not an error (idempotent).
    pub async fn remove(
        &mut self,
        sandbox_id: &str,
        sandbox_port: u16,
        protocol: Protocol,
    ) -> Result<()> {
        let key = (sandbox_id.to_owned(), sandbox_port, protocol);
        let Some(rule) = self.rules.get(&key) else {
            return Ok(()); // idempotent: nothing to remove
        };
        let del_args = prepend(&["-t", "nat", "-D", "PREROUTING"], &rule.rule_args);
        let guest_port = rule.guest_port;

        // Delete the kernel rule BEFORE dropping the record. If the delete fails
        // (e.g. transient lock contention) the record is kept so a retry can
        // still remove the rule instead of leaking it and reporting success.
        run_iptables(&del_args)
            .await
            .context("removing DNAT rule")?;
        self.rules.remove(&key);
        tracing::info!(sandbox_id, guest_port, "sandbox port forward removed");
        Ok(())
    }

    /// Remove every mapping belonging to `sandbox_id` (stop/remove/TTL).
    pub async fn remove_all_for(&mut self, sandbox_id: &str) {
        let keys: Vec<_> = self
            .rules
            .keys()
            .filter(|(id, _, _)| id == sandbox_id)
            .cloned()
            .collect();
        for (id, port, proto) in keys {
            if let Err(e) = self.remove(&id, port, proto).await {
                tracing::warn!(sandbox_id, port, error = %e, "failed to remove port forward");
            }
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

/// The protocol/port/destination spec shared by install and delete.
fn dnat_rule_args(
    guest_port: u16,
    sandbox_ip: Ipv4Addr,
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
        RULE_COMMENT.into(),
        "-j".into(),
        "DNAT".into(),
        "--to-destination".into(),
        format!("{sandbox_ip}:{sandbox_port}"),
    ]
}

/// If `line` (an `iptables -t nat -S PREROUTING` entry) is an arcbox sandbox
/// DNAT rule, return the argv that deletes it. Used by [`flush_orphan_rules`]
/// to reap rules a previous agent left behind.
fn orphan_delete_args(line: &str) -> Option<Vec<String>> {
    let spec = line.strip_prefix("-A PREROUTING ")?;
    if !spec.contains(RULE_COMMENT) {
        return None;
    }
    let mut args = vec![
        "-t".to_owned(),
        "nat".to_owned(),
        "-D".to_owned(),
        "PREROUTING".to_owned(),
    ];
    args.extend(spec.split_whitespace().map(str::to_owned));
    Some(args)
}

/// Delete every arcbox sandbox DNAT rule left in `PREROUTING` by a previous
/// agent process.
///
/// In-memory [`PortForwardManager`] state is authoritative and is empty at
/// startup, so any tagged rule still in the kernel is an orphan: the sandbox it
/// pointed at was torn down by the crash-recovery sweep, and leaving the rule
/// would misroute traffic once its `172.20.x` IP is reassigned. Best-effort —
/// a missing `iptables` (no rules to leak) or an individual delete failure only
/// degrades cleanup.
pub async fn flush_orphan_rules() {
    let output = match Command::new("/sbin/iptables")
        .args(["-t", "nat", "-S", "PREROUTING"])
        .output()
        .await
    {
        Ok(o) if o.status.success() => o,
        _ => return,
    };
    let listing = String::from_utf8_lossy(&output.stdout);
    let mut removed = 0usize;
    for line in listing.lines() {
        if let Some(args) = orphan_delete_args(line)
            && run_iptables(&args).await.is_ok()
        {
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::info!(
            removed,
            "flushed orphaned sandbox DNAT rules from a previous agent"
        );
    }
}

fn prepend(head: &[&str], tail: &[String]) -> Vec<String> {
    head.iter()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_parses_and_defaults_to_tcp() {
        assert_eq!(Protocol::parse("").unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::parse("TCP").unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::parse("udp").unwrap(), Protocol::Udp);
        assert!(Protocol::parse("sctp").is_err());
    }

    #[test]
    fn dnat_spec_is_symmetric_and_tagged() {
        let args = dnat_rule_args(40000, Ipv4Addr::new(172, 20, 0, 2), 8080, Protocol::Tcp);
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
                "arcbox-sbx",
                "-j",
                "DNAT",
                "--to-destination",
                "172.20.0.2:8080"
            ]
        );
    }

    #[test]
    fn orphan_delete_targets_only_tagged_prerouting_rules() {
        // A tagged arcbox rule (as `iptables -S` prints it, with the implicit
        // `-m tcp`) is converted from -A to a -D argv.
        let line = "-A PREROUTING -p tcp -m tcp --dport 40000 -m comment \
                    --comment arcbox-sbx -j DNAT --to-destination 172.20.0.2:8080";
        let args = orphan_delete_args(line).expect("tagged rule should match");
        assert_eq!(args[..4], ["-t", "nat", "-D", "PREROUTING"]);
        assert_eq!(args.last().unwrap(), "172.20.0.2:8080");
        assert!(args.iter().any(|a| a == "arcbox-sbx"));

        // A foreign rule (e.g. Docker's) is left untouched.
        let docker = "-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT \
                      --to-destination 172.17.0.2:80";
        assert!(orphan_delete_args(docker).is_none());

        // A non-PREROUTING line is ignored.
        assert!(orphan_delete_args("-N DOCKER").is_none());
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
                rule_args: vec![],
            },
        );
        let second = mgr.allocate_port().unwrap();
        assert_eq!(second, PORT_RANGE_START + 2);
    }
}
