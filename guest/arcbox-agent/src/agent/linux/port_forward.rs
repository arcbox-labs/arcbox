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

use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::process::Output;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

/// First port of the reserved guest relay range.
const PORT_RANGE_START: u16 = 40000;
/// Last port of the reserved guest relay range (inclusive).
const PORT_RANGE_END: u16 = 49999;
/// iptables `--comment` tag stamped on every sandbox DNAT rule, so rules left
/// behind by a crashed/restarted agent can be identified and flushed (they are
/// otherwise untracked kernel state that would misroute after IP reuse).
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

/// One installed DNAT mapping.
struct ForwardRule {
    guest_port: u16,
    sandbox_ip: Ipv4Addr,
    cleanup_token: String,
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
        cleanup_token: &str,
        sandbox_port: u16,
        protocol: Protocol,
    ) -> Result<u16> {
        let key = (sandbox_id.to_owned(), sandbox_port, protocol);
        if let Some(rule) = self.rules.get(&key) {
            let guest_port = rule.guest_port;
            let rule_args = rule.rule_args.clone();
            if rule.sandbox_ip == sandbox_ip && rule.cleanup_token == cleanup_token {
                if rule_is_installed(&rule_args).await? {
                    return Ok(guest_port);
                }
                run_iptables(&prepend(&["-t", "nat", "-I", "PREROUTING"], &rule_args))
                    .await
                    .context("repairing missing DNAT rule")?;
                tracing::info!(
                    sandbox_id,
                    guest_port,
                    sandbox_port,
                    %sandbox_ip,
                    "sandbox port forward repaired"
                );
                return Ok(guest_port);
            }
            self.remove_keys(vec![key.clone()]).await?;
        }

        let guest_port = self.allocate_port()?;
        let rule_args = dnat_rule_args(
            guest_port,
            sandbox_ip,
            cleanup_token,
            sandbox_port,
            protocol,
        );

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
                sandbox_ip,
                cleanup_token: cleanup_token.to_owned(),
                rule_args,
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
            let rule_args = rule.rule_args.clone();
            let del_args = prepend(&["-t", "nat", "-D", "PREROUTING"], &rule.rule_args);
            let guest_port = rule.guest_port;

            // Delete the kernel rule BEFORE dropping the record. A failed
            // record remains owned by this manager so a retry can remove it.
            let result = match check(rule_args).await.context("checking DNAT rule") {
                Ok(false) => Ok(()),
                Ok(true) => delete(del_args).await.context("removing DNAT rule"),
                Err(error) => Err(error),
            };
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

/// The protocol/port/destination spec shared by install and delete.
fn dnat_rule_args(
    guest_port: u16,
    sandbox_ip: Ipv4Addr,
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
        format!("{sandbox_ip}:{sandbox_port}"),
    ]
}

/// If `line` belongs to the exact quarantined generation, return the argv
/// that deletes it.
fn orphan_delete_args(
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
    let destination_prefix = format!("{sandbox_ip}:");
    let tagged = fields.windows(2).any(|pair| {
        pair[0] == "--comment" && (pair[1] == comment || pair[1] == LEGACY_RULE_COMMENT)
    });
    let targets_ip = fields
        .windows(2)
        .any(|pair| pair[0] == "--to-destination" && pair[1].starts_with(&destination_prefix));
    if !tagged || !targets_ip {
        return None;
    }
    let mut args = vec![
        "-t".to_owned(),
        "nat".to_owned(),
        "-D".to_owned(),
        "PREROUTING".to_owned(),
    ];
    args.extend(fields);
    Some(args)
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
    let mut args = vec![
        "-t".to_owned(),
        "nat".to_owned(),
        "-D".to_owned(),
        "PREROUTING".to_owned(),
    ];
    args.extend(fields);
    Some(args)
}

/// Delete kernel DNAT state for one exact quarantined generation after the
/// host has removed its listeners. This also covers agent restart, where the
/// process-local rule registry is empty.
pub async fn remove_orphan_rules_for(sandbox_ip: Ipv4Addr, cleanup_token: &str) -> Result<()> {
    let output = Command::new("/sbin/iptables")
        .args(["-t", "nat", "-S", "PREROUTING"])
        .output()
        .await
        .context("listing sandbox DNAT rules")?;
    if !output.status.success() {
        bail!(
            "iptables -t nat -S PREROUTING failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    let mut removed = 0usize;
    let mut failures = Vec::new();
    for line in listing.lines() {
        if let Some(args) = orphan_delete_args(line, sandbox_ip, cleanup_token) {
            match run_iptables(&args).await {
                Ok(()) => removed += 1,
                Err(error) => failures.push(error.to_string()),
            }
        }
    }
    if removed > 0 {
        tracing::info!(
            removed,
            %sandbox_ip,
            "removed quarantined sandbox DNAT rules"
        );
    }
    if !failures.is_empty() {
        bail!(
            "failed to remove {} quarantined DNAT rule(s): {}",
            failures.len(),
            failures.join("; ")
        );
    }
    Ok(())
}

/// Remove only pre-token sandbox rules during the startup handshake. Tokenized
/// generations remain quarantined until their individual tickets finalize.
pub async fn remove_legacy_orphan_rules() -> Result<()> {
    let output = Command::new("/sbin/iptables")
        .args(["-t", "nat", "-S", "PREROUTING"])
        .output()
        .await
        .context("listing legacy sandbox DNAT rules")?;
    if !output.status.success() {
        bail!(
            "iptables -t nat -S PREROUTING failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let listing = String::from_utf8_lossy(&output.stdout);
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

async fn rule_is_installed(rule_args: &[String]) -> Result<bool> {
    let args = prepend(&["-t", "nat", "-C", "PREROUTING"], rule_args);
    let output = Command::new("/sbin/iptables")
        .args(["-w", "2"])
        .args(&args)
        .output()
        .await
        .context("failed to run iptables")?;
    classify_rule_check(output, &args)
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
    fn orphan_delete_targets_only_tagged_prerouting_rules() {
        // A tagged arcbox rule (as `iptables -S` prints it, with the implicit
        // `-m tcp`) is converted from -A to a -D argv.
        let line = "-A PREROUTING -p tcp -m tcp --dport 40000 -m comment \
                    --comment \"arcbox-sbx:generation\" -j DNAT \
                    --to-destination 172.20.0.2:8080";
        let args = orphan_delete_args(line, "172.20.0.2".parse().unwrap(), "generation")
            .expect("tagged rule should match");
        assert_eq!(args[..4], ["-t", "nat", "-D", "PREROUTING"]);
        assert_eq!(args.last().unwrap(), "172.20.0.2:8080");
        assert!(args.iter().any(|a| a == "arcbox-sbx:generation"));
        assert!(!args.iter().any(|a| a.contains('"')));
        assert!(orphan_delete_args(line, "172.20.0.2".parse().unwrap(), "old").is_none());
        assert!(orphan_delete_args(line, "172.20.0.3".parse().unwrap(), "generation").is_none());

        // A foreign rule (e.g. Docker's) is left untouched.
        let docker = "-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT \
                      --to-destination 172.17.0.2:80";
        assert!(orphan_delete_args(docker, "172.20.0.2".parse().unwrap(), "generation").is_none());

        // A non-PREROUTING line is ignored.
        assert!(
            orphan_delete_args("-N DOCKER", "172.20.0.2".parse().unwrap(), "generation").is_none()
        );

        let legacy = "-A PREROUTING -p tcp --dport 40000 -m comment \
                      --comment \"arcbox-sbx\" -j DNAT \
                      --to-destination 172.20.0.2:8080";
        assert!(orphan_delete_args(legacy, "172.20.0.2".parse().unwrap(), "generation").is_some());
        assert!(legacy_orphan_delete_args(legacy).is_some());
        assert!(legacy_orphan_delete_args(line).is_none());
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
            },
        );
        let second = mgr.allocate_port().unwrap();
        assert_eq!(second, PORT_RANGE_START + 2);
    }

    #[tokio::test]
    async fn bulk_remove_keeps_failed_rules_and_removes_the_rest() {
        let mut mgr = PortForwardManager::default();
        for (id, port) in [("target", 80), ("target", 81), ("other", 82)] {
            mgr.rules.insert(
                (id.into(), port, Protocol::Tcp),
                ForwardRule {
                    guest_port: PORT_RANGE_START + port,
                    sandbox_ip: "172.20.0.2".parse().unwrap(),
                    cleanup_token: if id == "target" {
                        "generation".into()
                    } else {
                        "other-generation".into()
                    },
                    rule_args: vec![port.to_string()],
                },
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
    async fn bulk_remove_drops_records_for_rules_already_absent() {
        let mut mgr = PortForwardManager::default();
        mgr.rules.insert(
            ("target".into(), 80, Protocol::Tcp),
            ForwardRule {
                guest_port: PORT_RANGE_START,
                sandbox_ip: "172.20.0.2".parse().unwrap(),
                cleanup_token: "generation".into(),
                rule_args: vec!["rule".into()],
            },
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
